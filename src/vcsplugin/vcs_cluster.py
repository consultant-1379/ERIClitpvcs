##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################
from collections import defaultdict
from litp.core.exceptions import RpcExecutionException
from litp.core.rpc_commands import RpcCommandProcessorBase, reduce_errs
from litp.core.validators import ValidationError
from litp.core.execution_manager import (ConfigTask,
                                         CallbackTask,
                                         CallbackExecutionException)
from litp.core.litp_logging import LitpLogger
from litp.plan_types.deployment_plan import deployment_plan_tags
from vcsplugin.vcs_base_helper import (VcsBaseHelper,
                                       property_updated,
                                       is_clustered_service_redeploy_required,
                                       is_failover_standby_node_updated)
from vcsplugin.vcs_cmd_api import VcsCmdApi, VcsRPC
from vcsplugin.vcs_config import VCSConfig
from vcsplugin.vcs_exceptions import VCSConfigException, VcsCmdApiException
from vcsplugin.vcs_model import VCSModel
from vcsplugin.vcs_utils import (TimeoutParameters, VcsUtils, is_ipv6,
                                 strip_prefixlen,
                                 select_nodes_from_cluster,
                                 is_os_reinstall_on_peer_nodes)
from vcs_extension.vcs_extension import VcsExtension
from bootmgr_extension.bootmgr_extension import BootManagerExtension

import uuid

log = LitpLogger()

MAX_WAITING_TIME_FOR_NODE = 60 * 5
MAX_WAITING_TIME_FOR_CLUSTER = 60 * 10

ERROR_VCS_SEED_THRESHOLD_EXCEED_NODE_COUNT = ("Property 'vcs_seed_threshold' "
                                 "must be set to a value from 1 up to the "
                                 "number of nodes in the cluster ({0} nodes).")


class VcsCluster(VcsBaseHelper):
    """
    LITP vcs plugin
    """

    def __init__(self, plugin):
        self.config = VCSConfig()
        super(VcsCluster, self).__init__(plugin)

    def validate_model(self, plugin_api_context):
        """
        Validate that:

        - there are at least two nodes in the cluster,
        - cluster IDs are unique,
        - heartbeat networks are not linked to the same network,
        - management and heartbeats are not linked to the same network,
        - management network interface is defined,
        - no high-priority network-interfaces can be removed
        - no low-priority  network-interfaces can be removed
        - no network-interface, that is monitored \
        by a dependent service group - can be removed
        """
        errors = []
        clusters = plugin_api_context.query("vcs-cluster")
        clusters_by_id = {}
        for cluster in clusters:
            clusters_by_id.setdefault(cluster.cluster_id, []).append(cluster)

            nodes = [node for node in cluster.nodes if not
                     node.is_for_removal()]
            hb_nets = self.get_hb_networks_for_cluster(cluster)

            for node in nodes:
                net_names = [net_iface.network_name for net_iface in
                             node.network_interfaces]
                for hb_net in hb_nets:
                    if hb_net not in net_names:
                        errors.append(ValidationError(
                                                  item_path=node.get_vpath(),
                                    error_message="Network {0} does not exist"
                                                " on node {1}".format(hb_net,
                                                             node.hostname)))

                llt_nets = self.get_hb_networks_for_cluster(cluster, False)
                hb_interfaces = self.get_nics_per_node_for_networks(node,
                                                                    llt_nets)
                for interface in hb_interfaces:
                    if interface.ipaddress or interface.ipv6address:
                        errors.append(
                            ValidationError(
                                item_path=interface.get_vpath(),
                                error_message="Interface is used for VCS"
                                " llt. It should not have an IP address"))

            # validate that llt & hb nics cannot be removed
            errors.extend(self._validate_interfaces_for_removal(cluster))

            errors.extend(self._validate_critical_service(cluster))

            errors.extend(self._validate_triggers(cluster))

            if len(cluster.fencing_disks) > 0:
                errors.extend(
                  self._validate_no_node_removal_on_cluster_with_fencing_disks(
                                                                      cluster))

            errors.extend(self._validate_not_all_nodes_removed(cluster))

            if not cluster.is_for_removal():
                if cluster.vcs_seed_threshold:
                    errors.extend(self._validate_vcs_seed_threshold(cluster))

        for _, clusters in clusters_by_id.iteritems():
            if len(clusters) > 1:
                for cluster in clusters:
                    errors.append(ValidationError(
                        item_path=cluster.get_vpath(),
                        error_message="Cluster IDs must be unique."))

        return errors

    @staticmethod
    def is_uplift_plan(cluster):
        return (cluster and is_os_reinstall_on_peer_nodes(cluster))

    def _get_node_ids_for_uplift(self, cluster):
        node_ids = dict()
        uplift_nodes = [unode for unode in cluster.nodes
                        if not unode.is_applied()]

        if not uplift_nodes:
            return uplift_nodes, node_ids

        sample_uplift_node = uplift_nodes[0]
        node_ids = self._get_vcs_node_ids(sample_uplift_node)

        nodes = sorted(uplift_nodes,
                       key=lambda x: [k for k, v in node_ids.items()
                                      if v == x.hostname][0])
        return nodes, node_ids

    def create_configuration(self, plugin_api_context, cluster):
        # pylint: disable=unused-argument
        """
        The VCS Plugin provides support for the installation, \
        configuration and management of the VCS software.

        The VCS Plugin uses ERIClitpvcsapi extension.

        **NOTE:**  *The user has specify an ID.*
        **Example CLI for this plugin when Storage Foundation HA is used:**

        .. code-block:: bash

            litp create -p /deployments/test \
                        -t deployment
            litp create -p /deployments/test/clusters/cluster1 \
                        -t vcs-cluster  \
                        -o cluster_type=sfha  \
                           cluster_id=<Integer in range 1-65535>

        **Example CLI for this plugin when Veritas Cluster is used:**

        .. code-block:: bash

            litp create -p /deployments/test \
                        -t deployment
            litp create -p /deployments/test/clusters/cluster1 \
                        -t vcs-cluster  \
                        -o cluster_type=vcs  \
                           cluster_id=<Integer in range 1-65535>
        """

        ms_tasks = []
        node_tasks = []
        cluster_tasks = []
        node_delete_tasks = []
        nodes = None
        node_ids = None

        service = BootManagerExtension._get_cobbler_service(plugin_api_context)
        cluster_type = cluster.cluster_type
        try:
            rpm_list = self.config.read_plugin_config(
                cluster_type, "rpms")
        except VCSConfigException as e:
            log.trace.error("Can't get list of RPMs from VCS config"
                            "Exception occurred:" + str(e))
            raise

        if VcsCluster.is_uplift_plan(cluster):
            nodes, node_ids = self._get_node_ids_for_uplift(cluster)

        if not node_ids:
            # Get list of all nodes to be installed for a new cluster
            nodes, node_ids = self._get_nodes(cluster)

        log.trace.debug(("Nodes:{0}, node-ids:{1}").format(nodes, node_ids))
        # Configure license based on cluster type
        veritas_lic = self._get_license(cluster_type)

        cluster_id = cluster.cluster_id

        if cluster.is_initial() and not cluster.ha_manager:
            log.trace.info('Set "ha_manager" property to "vcs"')
            cluster.ha_manager = 'vcs'

        cluster_uuid = VcsCluster._gen_uuid(cluster.item_id, cluster_id)
        fencing_disks = [fencing_disk for fencing_disk in cluster.
                         fencing_disks]
        coordinator_dg_name = self.get_vx_fencing_disk_group_name(
            fencing_disks, cluster_id)

        manage_vxfencing = False
        if fencing_disks and self.is_cluster_expansion(cluster):
            # Pass True into the ConfigTask so that fencing config is handled
            manage_vxfencing = True

        if cluster.vcs_seed_threshold:
            vcs_seed_threshold = cluster.vcs_seed_threshold
        else:
            vcs_seed_threshold = str(self._get_vcs_seed_threshold(cluster))

        for node in nodes:
            log.trace.debug("Node:{0}".format(node))
            is_rack_node = VCSModel._is_node_server_type_rack(cluster, node)
            hb_macs, hb_saps = VCSModel._hb_networks_info_for_node(
                cluster, node, inc_low_prio=False, is_rack_node=is_rack_node)

            mgmt_mac, mgmt_sap = VCSModel.mgmt_network_info_for_node(
                cluster, node, is_rack_node=is_rack_node)
            if not node.is_for_removal():
                vcs_sw_task = ConfigTask(node, node,
                                  'Configure "%s" software on node "%s"'
                                  % (cluster_type, node.hostname),
                                  call_type="vcs::configure",
                                  call_id=str(cluster.item_id),
                                  rpm_list=rpm_list,
                                  cluster_name=cluster.item_id,
                                  clust_type=cluster_type,
                                  license_key=veritas_lic,
                                  cluster_ID=cluster_id,
                                  cluster_UUID=str(cluster_uuid),
                                  number_of_nodes=vcs_seed_threshold,
                                  hostname=node.hostname,
                                  hostnames=node_ids,
                                  heartbeats_MACs=hb_macs,
                                  managment_MAC=mgmt_mac,
                                  fencing_dg_name=coordinator_dg_name,
                                  manage_vxfencing=manage_vxfencing,
                                  base_os=node.os.version,
                                  heartbeats_SAPs=hb_saps,
                                  management_SAP=mgmt_sap,
                                  boot_mode=service.boot_mode
                                  )

                log.trace.debug(("Task: call_id:{0}, cluster_name:{1}, "
                                 "cluster_ID:{2}, number_of_nodes:{3}, "
                                 "hostnames:{4}").format(
                                     str(cluster.item_id), cluster.item_id,
                                     cluster_id, vcs_seed_threshold, node_ids))

                vcs_sw_task.requires.add(node.storage_profile)
                vcs_sw_task.model_items.add(cluster)
                for config in node.query('firewall-node-config'):
                    vcs_sw_task.requires.add(config)
                    for rule in config.query('firewall-rule'):
                        vcs_sw_task.requires.add(rule)
                for interface in node.network_interfaces:
                    vcs_sw_task.requires.add(interface)
                    vcs_sw_task.model_items.add(interface)
                node_tasks.append([vcs_sw_task])

            if fencing_disks and is_os_reinstall_on_peer_nodes(cluster):
                task = CallbackTask(
                    node,
                    'Start VCS on VX Fencing on node "{0}"'
                        .format(node.hostname),
                    self.plugin().callback_method,
                    callback_class=self.__class__.__name__,
                    callback_func="start_vx_io_fencing",
                    hostname=node.hostname,
                    tag_name=deployment_plan_tags.NODE_TAG)
                task.requires.add(vcs_sw_task)
                node_tasks.append([task])

            if cluster_type == 'sfha' and not node.is_for_removal():
                # TORF-573068: II solution, see package plugin for UG solution.
                rm_debug_task = CallbackTask(
                    node,
                    'Remove unused debug files on node "{0}"'
                        .format(node.hostname),
                    self.plugin().callback_method,
                    callback_class=self.__class__.__name__,
                    callback_func="remove_unused_debug_files_cb",
                    hostname=node.hostname)

                rm_debug_task.requires.add(vcs_sw_task)
                node_tasks.append([rm_debug_task])

        trig_node_tasks, trig_cluster_tasks = \
            self._get_trigger_tasks(cluster, node_tasks)
        node_tasks.extend(trig_node_tasks)
        cluster_tasks.extend(trig_cluster_tasks)

        vcs_poll_task = None
        if (len(cluster.nodes) and cluster.is_initial()) or nodes:
            nodes_hostnames = [
                node.hostname
                for node in cluster.nodes
                if not node.is_for_removal()]
            if not cluster.is_for_removal():
                vcs_poll_task = self._create_vcs_poll_task(nodes_hostnames,
                                                           cluster)
                cluster_tasks.append(vcs_poll_task)

        if (cluster.app_agent_num_threads and (
                property_updated(cluster, "app_agent_num_threads") or
                not cluster.applied_properties_determinable or
                is_os_reinstall_on_peer_nodes(cluster))):
            cluster_tasks.append(self.
                create_vcs_app_agent_num_threads_task(
                cluster, cluster.app_agent_num_threads, vcs_poll_task))

        deleted_nodes = [node for node in cluster.nodes
                         if node.is_for_removal()]
        for node in deleted_nodes:
            task = CallbackTask(
                cluster,
                'Remove node "{0}" from cluster "{1}"'.format(
                    node.item_id, cluster.item_id),
                self.plugin().callback_method,
                callback_class=self.__class__.__name__,
                callback_func="remove_node_from_cluster_cb",
                cluster_vpath=cluster.get_vpath(),
                node=node.hostname,
                cluster_removal=cluster.is_for_removal(),
                tag_name=deployment_plan_tags.PRE_NODE_CLUSTER_TAG)
            node_delete_tasks.append(task)
        return (ms_tasks, node_tasks, cluster_tasks, node_delete_tasks)

    def start_vx_io_fencing(self, callback_api, hostname):
        # Start vx fencing on node.
        # pylint: disable=unused-argument
        self.nodes = hostname
        log.event.info('Starting Vx Fencing on node "{0}"'.format(
            hostname))
        self.vcs_api.set_node(hostname)
        self.vcs_api.start_vx_fencing()

    def remove_unused_debug_files_cb(self, callback_api, hostname):
        log.trace.debug('Node {0}. Check for debug files'.format(hostname))
        pkgs = ["VRTSvxvm", "VRTSaslapm"]
        greps = ["/opt", ".debug"]
        for pkg in pkgs:
            rpm_content = VcsExtension.get_package_file_info(
                callback_api, hostname, pkg, greps)
            log.trace.debug("Node {0}: Retrieved the following debug files "
                            "from package {1} - {2}".format(hostname, pkg,
                                                         rpm_content))
            VcsExtension.remove_unused_vrts_debug_files(callback_api, hostname,
                                                    rpm_content)

    def _validate_critical_service(self, cluster):
        """
        Validate that if critical_service is defined:
            - cluster_type is sfha
            - the number of nodes is 2
            - the service defined like being critical service is a valid id
                of the service
            - the service defined like being critical service is failover
        """
        if cluster.critical_service is None:
            return []

        errors = []
        NOT_SFHA = ('The "critical_service" property can only be defined for '
                    '"vcs-cluster" of type "sfha".')
        WRONG_SERVICE_ID = ('The vcs-clustered-service "{0}" in cluster "{1}" '
                            'does not exist.')
        NOT_FAILOVER = ('The vcs-clustered-service "{0}" must have active=1 '
                        'standby=1 to be a critical service.')
        CANNOT_REMOVE = ('The vcs-clustered-service "{0}" cannot be '
                         'removed as it is a critical service.')

        cluster_path = cluster.get_vpath()

        # Validate that cluster_type has 'sfha' type.
        if cluster.cluster_type != 'sfha':
            errors.append(ValidationError(
                item_path=cluster_path, error_message=NOT_SFHA))

        # Check that critical service is failover
        for service in cluster.services:
            if service.item_id == cluster.critical_service:
                if service.is_for_removal():
                    errors.append(
                        ValidationError(
                            item_path=service.get_vpath(),
                            error_message=CANNOT_REMOVE.format(
                                service.item_id)))
                if not service.active == service.standby == '1':
                    # The service is not failover.
                    errors.append(
                        ValidationError(
                            item_path=cluster_path,
                            error_message=NOT_FAILOVER.format(
                                cluster.critical_service)))
                break
        else:
            # The name of the vcs-clustered-service is not present under
            # cluster.
            errors.append(ValidationError(
                item_path=cluster_path,
                error_message=WRONG_SERVICE_ID.format(
                    cluster.critical_service, cluster.item_id)))

        return errors

    def _validate_nofailover_trigger(self, service, trigger):
        """
        Validate for a trigger with trigger_type 'nofailover'
            - service_id is not populated
            - service_argument is not populated
            - the service is a failover service
        """
        errors = []
        trigger_vpath = trigger.get_vpath()
        if trigger.service_id:
            msg = ('Property "service_id" is not supported for '
                   'nofailover trigger type.')
            errors.append(ValidationError(item_path=trigger_vpath,
                                          error_message=msg))
        if trigger.service_argument:
            msg = ('Property "service_argument" is not supported for '
                   'nofailover trigger type.')
            errors.append(ValidationError(item_path=trigger_vpath,
                                          error_message=msg))
        if int(service.standby) == 0:
            msg = ('nofailover trigger type is only applicable to failover '
                   'vcs-clustered-services.')
            errors.append(ValidationError(item_path=trigger_vpath,
                                          error_message=msg))
        return errors

    def _validate_postonline_trigger(self, service, trigger):
        """
        Validate for a trigger with trigger_type 'postonline'
            - service_id is not populated
            - service_argument is not populated
            - the service is a failover service
        """
        errors = []
        trigger_vpath = trigger.get_vpath()
        if trigger.service_id:
            msg = ('Property "service_id" is not supported for '
                   'postonline trigger type.')
            errors.append(ValidationError(item_path=trigger_vpath,
                                          error_message=msg))
        if trigger.service_argument:
            msg = ('Property "service_argument" is not supported for '
                   'postonline trigger type.')
            errors.append(ValidationError(item_path=trigger_vpath,
                                          error_message=msg))
        num_ipv6_ips = 0
        for ip in service.ipaddresses:
            if is_ipv6(ip.ipaddress):
                num_ipv6_ips += 1
        if num_ipv6_ips != 1:
            msg = ('postonline trigger type is only applicable to '
                   'vcs-clustered-services with exactly one IPv6 VIP.')
            errors.append(ValidationError(item_path=trigger_vpath,
                                          error_message=msg))
        return errors

    def _validate_triggers(self, cluster):
        """
        Validate vcs-triggers for each service
        """
        errors = []
        for service in cluster.services:
            num_nofailover_triggers = 0
            num_postonline_triggers = 0
            for trigger in service.triggers:
                if trigger.is_for_removal():
                    continue
                if trigger.trigger_type == 'nofailover':
                    num_nofailover_triggers += 1
                    errors.extend(self._validate_nofailover_trigger(service,
                                                                    trigger))
                if trigger.trigger_type == 'postonline':
                    num_postonline_triggers += 1
                    errors.extend(self._validate_postonline_trigger(service,
                                                                    trigger))
            if num_nofailover_triggers > 1:
                msg = ('Only one nofailover trigger type is allowed for '
                       'each vcs-clustered-service.')
                errors.append(ValidationError(item_path=service.get_vpath(),
                                              error_message=msg))
            if num_postonline_triggers > 1:
                msg = ('Only one postonline trigger type is allowed for '
                       'each vcs-clustered-service.')
                errors.append(ValidationError(item_path=service.get_vpath(),
                                              error_message=msg))

        return errors

    def _validate_no_node_removal_on_cluster_with_fencing_disks(self, cluster):
        """
        Validate against nodes being removed from a cluster with Fencing Disks
        """
        errors = []
        for node in cluster.nodes:
            if node.is_for_removal():
                msg = ('Removal of node "{node}" from cluster "{cluster}" is '
                       'not supported because this cluster has fencing disks.'
                       ).format(node=node.hostname, cluster=cluster.item_id)
                errors.append(ValidationError(item_path=node.get_vpath(),
                                              error_message=msg))

        return errors

    def _validate_not_all_nodes_removed(self, cluster):
        """
        Validate against all nodes being removed from cluster
        """
        errors = []
        if not cluster.is_for_removal() and not cluster.is_initial():
            for node in cluster.nodes:
                if not node.is_for_removal() and not node.is_initial():
                    return errors
            msg = ('Removing all nodes from cluster "{0}" is '
                   'not supported.').format(cluster.item_id)
            errors.append(ValidationError(item_path=cluster.get_vpath(),
                                          error_message=msg))
        return errors

    def _validate_interfaces_for_removal(self, cluster):
        """
        Check that network-interfaces marked for removal
        are not being used by LLT or low priority networks
        """
        errors = []

        priority_networks = self.get_hb_networks_for_cluster(cluster)
        for node in cluster.nodes:
            llt_nics_for_removal = [nic for nic in node.network_interfaces
                                    if nic.network_name in priority_networks
                                    and nic.is_for_removal()
                                    and not node.is_for_removal()]
            for nic in llt_nics_for_removal:
                errors.append(ValidationError(
                    item_path=nic.get_vpath(),
                    error_message="Device_name: '{0}' on node: '{1}'"
                                  " - cannot be removed. No network-interfaces"
                                  " used for high or low priority network "
                                  "can be removed."
                    .format(nic.device_name,
                            node.hostname,
                            nic.network_name)
                ))
        return errors

    @staticmethod
    def _validate_vcs_seed_threshold(cluster):
        """
        Validate against 'vcs_seed_threshold' bigger than the number of nodes.
        update_model method assures the property is always set.
        """
        errors = []
        node_count = len([node for node in cluster.nodes
                          if not node.is_for_removal()])
        vcs_seed_threshold = int(cluster.vcs_seed_threshold)
        if vcs_seed_threshold < 1 or vcs_seed_threshold > node_count:
            msg = ERROR_VCS_SEED_THRESHOLD_EXCEED_NODE_COUNT.format(node_count)
            errors.append(ValidationError(item_path=cluster.get_vpath(),
                                                          error_message=msg))
        return errors

    @staticmethod
    def _get_vcs_seed_threshold(cluster):
        node_count = len([node for node in cluster.nodes
                          if not node.is_for_removal()])
        if node_count > 2:
            return int(node_count / 2) + 1
        else:
            return 1

    def _get_nodes(self, cluster):
        """
        Returns a tuple with two elements: list of nodes for given cluster
        that need to be configured, and the vcs node ids.
        Nodes to configure are:
          - Nodes of initial cluster
          - Nodes part of an expansion
          - Nodes whose llt net macs has been updated
        """
        existing_nodes = []
        removed_nodes = []
        new_nodes = []
        node_ids = dict()

        if cluster.is_initial():
            new_nodes = [node for node in cluster.nodes
                         if not node.is_for_removal()]
        else:
            for node in cluster.nodes:
                if node.is_applied() or node.is_updated():
                    existing_nodes.append(node)
                elif node.is_initial():
                    new_nodes.append(node)
                elif node.is_for_removal():
                    removed_nodes.append(node)

        # Initial installation
        vcs_seed_threshold_updated = property_updated(cluster,
                                                      "vcs_seed_threshold")

        if new_nodes and not existing_nodes:
            for node in new_nodes:
                node_ids[str(len(node_ids))] = node.hostname
            log.trace.debug(("New-nodes and no existing-nodes; "
                             "new-nodes: {0}, node-ids: {1}").format(new_nodes,
                                                                     node_ids))
            return new_nodes, node_ids
        # Cluster Expansion/Contraction or update to seed threshold
        elif existing_nodes and \
                   (new_nodes or removed_nodes or vcs_seed_threshold_updated):
            log.trace.debug(("Existing-nodes: {0}, new-nodes: {1}, "
                             "removed-nodes: {2}, "
                             "vcs-see-threshold updated: {3}").format(
                              existing_nodes, new_nodes, removed_nodes,
                              vcs_seed_threshold_updated))

            node_ids = self._get_vcs_node_ids(existing_nodes[0])
            used_node_ids = [int(nid) for nid in node_ids.keys()]
            available = set(range(max(used_node_ids) + len(new_nodes) + 1)) \
                        - set(used_node_ids)
            for node in new_nodes:
                if node.hostname not in node_ids.values():
                    node_id = min(available)
                    available.remove(node_id)
                    node_ids[str(node_id)] = node.hostname
            removed_nids = set()
            for node in removed_nodes:
                if node.hostname in node_ids.values():
                    removed_nids.add(next(nid for nid, host in node_ids.items()
                                          if host == node.hostname))
            for nid in removed_nids:
                node_ids.pop(nid)
            nodes = [n for n in new_nodes + existing_nodes
                     if not n in removed_nodes]
            log.trace.debug(("Nodes: {0}, node-ids: {1}").format(nodes,
                                                                 node_ids))
            return nodes, node_ids
        else:
            # Check llt config updated (only MAC is allowed)
            # this is for the blade replacement scenario, in which the MAC
            # has been updated. Might also fit in the Torf-209699 scenario.
            nodes_to_update = []
            llt_networks = [cluster.low_prio_net] + cluster.llt_nets.split(',')
            for node in cluster.nodes:
                for iface in node.network_interfaces:
                    # properties non determinable ONLY if item is not in inital
                    iface_state_unknown = not iface.is_initial() and \
                        not iface.applied_properties_determinable
                    iface_mac_updated = hasattr(iface, 'macaddress') and \
                        property_updated(iface, 'macaddress')
                    if iface.network_name in llt_networks and \
                            (iface_state_unknown or iface_mac_updated):
                        # Add node only if the MAC was updated or if we cannot
                        # know if the MAC was updated. Core will filter
                        # the task if it is there already.
                        nodes_to_update.append(node)
                        break
            if nodes_to_update:
                if cluster.is_for_removal():
                    log.trace.debug("Setting node ids to empty list")
                    node_ids = dict()
                else:
                    log.trace.debug("Setting node ids")
                    node_ids = self._get_vcs_node_ids(existing_nodes[0])

            log.trace.debug(("Nodes-to-update: {0}, "
                            "node-ids: {1}").format(nodes_to_update, node_ids))
            return nodes_to_update, node_ids

    @staticmethod
    def _get_vcs_node_ids(node):
        """
        During expansion we need to know the Node IDs for the existing
        nodes in the cluster to avoid conflicts. The node_id property from the
        model can not be used as it is not mandatory.
        This function will retrieve the /etc/llthosts file from a cluster node
        and build dictionary from it
        """
        node_ids = dict()
        vcs_cmd_api = VcsCmdApi(node.hostname)
        try:
            ret, out, err = vcs_cmd_api.get_etc_llthosts()
            if ret != 0:
                err_msg = ('Failed to retrieve /etc/llthosts '
                           'from node "{0}"').format(node.hostname)
                log.event.error(err_msg)
                raise VCSConfigException(err_msg)
            else:
                llt_host_lines = out.split('\n')
                llt_host_lines = [line for line in llt_host_lines if line]
                for node_line in llt_host_lines:
                    node_id, node_name = node_line.split()
                    node_ids[node_id] = node_name
        except (KeyError, ValueError) as err:
            err_msg = ("Invalid output from /etc/llthosts "
                       "retrieval: {0}").format(str(err))
            log.event.error(err_msg)
            raise VCSConfigException(err_msg)

        log.trace.debug("Node-ids from /etc/llthosts: {0}".format(node_ids))
        return node_ids

    @staticmethod
    def get_hb_networks_for_cluster(cluster, inc_low_priority=True):
        """
        Get names of low_prio_net and llt_nets specified under cluster
        @return: list of network names used for llt and low_prior
        """
        priority_nets = cluster.llt_nets.split(",")
        if inc_low_priority:
            priority_nets.append(cluster.low_prio_net)
        return priority_nets

    @staticmethod
    def get_nics_per_node_for_networks(node, nets_names):
        """
        Get a list of nics used by 'nets_names' networks on the 'node'
        @params: node - node to perform the check of nics
        @params: nets_names - network names: list
        """
        return [nic for nic in node.network_interfaces if
                    nic.network_name in nets_names]

    def _create_vcs_poll_task(self, nodes, cluster):
        """
        Check VCS engine is running on a cluster
        """
        task = CallbackTask(
            cluster,
            'Check VCS engine is running on cluster "{0}"'.format(
                cluster.item_id),
            self.plugin().callback_method,
            callback_class=self.__class__.__name__,
            callback_func="vcs_poll_callback",
            nodes=nodes)
        return task

    def vcs_poll_callback(self, callback_api, nodes):
        # pylint: disable=unused-argument
        timing_parameters = TimeoutParameters(
            max_wait=MAX_WAITING_TIME_FOR_NODE)
        if not VcsUtils.wait_on_state(callback_api, self._vcs_poll,
                                      timing_parameters, nodes):
            raise CallbackExecutionException(
                '"VCS" engine has not come up within {0} seconds'.format(
                    timing_parameters.max_wait))

    def _vcs_poll(self, nodes):
        vcs_rpc = VcsRPC(nodes[0])
        ret, out, err = vcs_rpc.cluster_ready(','.join(nodes))
        log.event.debug("Check cluster online response:{0} {1} {2}".format(
            ret, out, err))
        return ret == 0

    @staticmethod
    def _get_license(cluster_type):
        # Set Veritas license based on the cluster type setting
        if cluster_type == "sfha":
            return "ENTERPRISE"
        elif cluster_type == "vcs":
            return "AVAILABILITY"

    @staticmethod
    def _gen_uuid(cluster_item_id, cluster_id):
        """
        The _gen_UUID() method generates a UUID based on the name and ID
        of the cluster. That means for a given cluster name and ID
        the generated UUID will be the same each time plugin is executed.

        """
        name_for_uuid = "{0} - {1}".format(cluster_item_id, cluster_id)
        uuid_num = uuid.uuid3(uuid.NAMESPACE_X500, name_for_uuid)
        return uuid_num

    @staticmethod
    def _is_valid_id(plugin_api_context, num):
        clusters = plugin_api_context.query("vcs-cluster")
        ids = [cluster.cluster_id for cluster in clusters]
        if num not in ids:
            return True
        else:
            return False

    def create_vcs_app_agent_num_threads_task(self, cluster,
                                              app_agent_num_threads,
                                              vcs_poll_task=None):
        if cluster.is_initial():
            nodes_hostnames = [node.hostname for node in cluster.nodes]
        else:
            nodes_hostnames = [node.hostname for node in cluster.nodes
                               if not node.is_for_removal() and
                               not node.is_initial()]
        task = CallbackTask(
            cluster,
            'Update "app_agent_num_threads" property on cluster "{0}"'.format(
                cluster.item_id),
            self.plugin().callback_method,
            callback_class=self.__class__.__name__,
            callback_func="vcs_app_agent_num_threads_callback",
            nodes=nodes_hostnames,
            app_agent_num_threads=app_agent_num_threads)

        if not cluster.is_initial():
            task.tag_name = deployment_plan_tags.PRE_NODE_CLUSTER_TAG
        elif vcs_poll_task:
            # Ensure that the VCS property is set after cluster is running
            task.requires.add(vcs_poll_task)

        return task

    def vcs_app_agent_num_threads_callback(self, callback_api, nodes,
                                           app_agent_num_threads):
        # pylint: disable=unused-argument
        self.nodes = nodes
        with self.vcs_api.readable_conf():
            self.vcs_api.cluster_app_agent_num_threads(app_agent_num_threads)

    def _get_trigger_tasks(self, cluster, node_tasks):
        cluster_tasks = []
        valid_trigger_types = ['nofailover', 'postonline']
        node_trigger_tasks = []
        for trig_type in valid_trigger_types:
            nodes_w_triggers_removed = set()
            nodes_w_triggers_added = set()
            node_trigger_maps = defaultdict(list)
            node_trigger_deps = defaultdict(list)
            for service in cluster.services:
                group_name = self.get_group_name(service.item_id,
                                                 cluster.item_id)
                nodes = service.node_list.split(',')
                triggers = [trigger for trigger in service.triggers
                            if trigger.trigger_type == trig_type]
                for_removal = [trigger for trigger in triggers
                               if trigger.is_for_removal() or
                               is_clustered_service_redeploy_required(service)
                               or is_failover_standby_node_updated(cluster,
                                                                   service)]
                for_deploy = [trigger for trigger in triggers
                              if not trigger.is_for_removal()]
                if for_removal:
                    # only generate remove task if not creating new trigger
                    # with the same trigger_type
                    trigger = for_removal[0]
                    if not service.applied_properties.get('node_list') \
                            and not service.applied_properties_determinable:
                        app_nodes = service.node_list.split(',')
                    else:
                        app_nodes = service.applied_properties.get(
                            'node_list').split(',')
                    for node in app_nodes:
                        nodes_w_triggers_removed.add(node)
                        node_trigger_deps[node].append(trigger)
                    if (not service.is_for_removal() and
                        not is_clustered_service_redeploy_required(service)):
                        task = self._create_trigger_task(trigger, service,
                                                         group_name,
                                                         delete=True)
                        cluster_tasks.append(task)
                for trigger in for_deploy:
                    if (trigger.is_initial()
                        or (trigger.is_updated() and
                            not trigger.applied_properties_determinable)
                        or is_clustered_service_redeploy_required(service)
                        or is_failover_standby_node_updated(cluster,
                                                            service)):
                        task = self._create_trigger_task(trigger, service,
                                                         group_name)
                        for app in service.applications:
                            task.requires.add(app)
                        for node in service.node_list.split(','):
                            nodes_w_triggers_added.add(node)
                        cluster_tasks.append(task)
                        for node in nodes:
                            node_trigger_deps[node].append(trigger)
                    # generate the trigger data for all triggers (initial
                    # and applied) as the whole file may need to be recreated
                    ip6_info = self._get_ip6_info(cluster, service)
                    for node in nodes:
                        record = [group_name, trigger.service_argument]
                        if ip6_info[node]:
                            record.extend(ip6_info[node])
                        node_trigger_maps[node].append(record)

            node_trigger_tasks.extend(self._get_trigger_script_tasks(
                    cluster,
                    trig_type,
                    nodes_w_triggers_removed,
                    nodes_w_triggers_added,
                    node_trigger_maps,
                    node_tasks,
                    node_trigger_deps))
        return node_trigger_tasks, cluster_tasks

    def _get_ip6_info(self, cluster, service):
        node_ip6_info = defaultdict(list)
        for ip_addr in service.ipaddresses:
            if is_ipv6(ip_addr.ipaddress):
                for node in cluster.nodes:
                    for intf in node.network_interfaces:
                        if intf.network_name == ip_addr.network_name:
                            node_ip6_info[node.item_id].append(
                                intf.device_name)
                            node_ip6_info[node.item_id].append(
                                strip_prefixlen(ip_addr.ipaddress))
                            break
        return node_ip6_info

    def _get_trigger_script_tasks(self, cluster, trigger_type,
                                  nodes_w_triggers_removed,
                                  nodes_w_triggers_added,
                                  node_trigger_maps,
                                  node_tasks,
                                  node_trigger_deps):
        if trigger_type == 'nofailover':
            CALL_TYPE_REMOVE = 'vcs::remove_nofailover_trigger'
            CALL_TYPE_ADD = 'vcs::configure_nofailover_trigger'
            CALL_ID = str(cluster.item_id)
        if trigger_type == 'postonline':
            CALL_TYPE_REMOVE = 'vcs::remove_postonline_trigger'
            CALL_TYPE_ADD = 'vcs::configure_postonline_trigger'
            CALL_ID = str(cluster.item_id)
        node_trigger_tasks = []
        nodes_w_triggers = set(node_trigger_maps.keys())
        nodes_w_all_removed = nodes_w_triggers_removed - nodes_w_triggers
        nodes_w_updated_scripts = ((nodes_w_triggers_removed |
                                    nodes_w_triggers_added) -
                                   nodes_w_all_removed)

        disable_nodes = [node for node in cluster.nodes
                         if node.item_id in nodes_w_all_removed]
        for node in disable_nodes:
            trigger_task = ConfigTask(node, node,
                                      'Remove {0} trigger on '
                                      'node "{1}"'.format(trigger_type,
                                                          node.hostname),
                                      call_type=CALL_TYPE_REMOVE,
                                      call_id=CALL_ID)
            trigger_task.replaces.add((CALL_TYPE_ADD, CALL_ID))
            trigger_task.model_items.update(node_trigger_deps[node.item_id])
            node_trigger_tasks.append([trigger_task])

        update_nodes = [node for node in cluster.nodes
                         if node.item_id in nodes_w_updated_scripts]
        for node in update_nodes:
            trigger_map = node_trigger_maps[node.item_id]
            description = 'Configure {0} trigger on node "{1}"'.format(
                trigger_type, node.hostname)
            trigger_task = ConfigTask(node, node,
                                      description,
                                      call_type=CALL_TYPE_ADD,
                                      call_id=CALL_ID,
                                      trigger_map=trigger_map)
            trigger_task.replaces.add((CALL_TYPE_REMOVE, CALL_ID))
            for node_task in node_tasks:
                if hasattr(node_task[0], 'node') and node_task[0].node == node:
                    trigger_task.requires.add(node_task[0])
            trigger_deps = node_trigger_deps[node.item_id]
            trigger_task.model_items.update(set(trigger_deps))
            for trig in trigger_deps:
                clustered_service = \
                    VcsUtils.get_parent_with_type(trig,
                                                  "vcs-clustered-service")
                trigger_task.model_items.add(clustered_service)
            node_trigger_tasks.append([trigger_task])
        return node_trigger_tasks

    def _create_trigger_task(self, trigger, service,
                             group_name, delete=False):
        action = "Disable" if delete else "Enable"
        cluster = service.get_cluster()
        callback = self.enable_or_disable_trigger_cb.__name__
        task = CallbackTask(trigger,
                            '{0} {1} trigger for VCS service group '
                            '"{2}"'.format(action, trigger.trigger_type,
                                           group_name),
                            self.plugin().callback_method,
                            callback_class=self.__class__.__name__,
                            callback_func=callback,
                            group_name=group_name,
                            cluster_vpath=cluster.get_vpath(),
                            trigger_type=trigger.trigger_type,
                            delete="True" if delete else "False"
                            )
        if delete:
            task.tag_name = deployment_plan_tags.PRE_NODE_CLUSTER_TAG
        return task

    def enable_or_disable_trigger_cb(self, callback_api, group_name,
                                      cluster_vpath, trigger_type, delete):
        cluster = callback_api.query_by_vpath(cluster_vpath)
        self.nodes = select_nodes_from_cluster(cluster)
        triggers = {'nofailover': 'NOFAILOVER',
                    'postonline': 'POSTONLINE'}
        trigger = triggers.get(trigger_type, None)
        if trigger:
            with self.vcs_api.readable_conf():
                if delete == "True":
                    self.vcs_api.hagrp_delete_in_triggers_enabled(group_name,
                                                                  trigger)
                else:
                    self.vcs_api.hagrp_add_in_triggers_enabled(group_name,
                                                               trigger)
                    if trigger == 'postonline':
                        self.vcs_api.ensure_ipv6_nodad(group_name)

    def remove_node_from_cluster_cb(self, callback_api, cluster_vpath, node,
                                    cluster_removal):
        cluster = callback_api.query_by_vpath(cluster_vpath)
        node_responsive = self.is_node_reachable(callback_api, node)
        if node_responsive and cluster_removal:
            services = ['vcs', 'puppet', 'mcollective']
            for service in services:
                try:
                    bcp = RpcCommandProcessorBase()
                    _, errors = bcp.execute_rpc_and_process_result(
                        callback_api, [node], "core",
                        "set_chkconfig", {'service_name': service,
                                          'enable': 'off'}
                    )
                except RpcExecutionException as e:
                    raise CallbackExecutionException(e)
                if errors:
                    raise CallbackExecutionException(','.join(reduce_errs(
                        errors)))

                if 'vcs' == service:
                    self.stop_vcs_on_node(callback_api,
                                          cluster_vpath,
                                          node)
                else:
                    self.stop_service_cb(callback_api, node, service)
        elif not node_responsive and cluster_removal:
            return
        elif not cluster_removal:
            self.nodes = select_nodes_from_cluster(cluster)
            with self.vcs_api.readable_conf():
                self.vcs_api.hasys_delete(node)

    def stop_vcs_on_node(self, callback_api, cluster_vpath, node):
        cluster = callback_api.query_by_vpath(cluster_vpath)
        self.nodes = [node]
        self.vcs_api.haconf("dump", read_only="True")
        log.trace.info("Stopping VCS on node '{0}'".format(node))
        self.vcs_api.stop_vcs(ignore_vcs_stop_err=True, sys=node)

        timing_parameters = TimeoutParameters(
            max_wait=MAX_WAITING_TIME_FOR_CLUSTER)
        if not VcsUtils.wait_on_state(callback_api,
                                      self._check_vcs_stopped_on_node,
                                      timing_parameters, node):
            raise CallbackExecutionException(
                "Failed to stop VCS on node '{node}' after '{max_wait}' "
                "seconds".format(node=node,
                                 max_wait=timing_parameters.max_wait))

        log.event.info("Successfully stopped VCS on node '{0}' in "
                       "cluster '{1}'".format(node, cluster))

    def stop_service_cb(self, callback_api, hostname, service_name):
        call_args = ['service', service_name, 'stop', '-y']
        callback_api.rpc_application([hostname], call_args)

    def _check_vcs_stopped_on_node(self, node):
        """ Return True if node is stopped """
        vcs_rpc = VcsRPC(node)
        try:
            ret, out, err = vcs_rpc.cluster_stopped()
            if ret != 0:
                log.event.debug('VCS is not stopped on node "{0}", '
                                'error: "{1}", output: "{2}"'
                                .format(node, err, out))
                return False
        except VcsCmdApiException as ex:
            log.event.debug('VCS is not stopped on node "{0}", error: '
                            '"{1}"'.format(node, ex))
            return False
        return True

    def is_node_reachable(self, callback_api, node):
        result = callback_api.rpc_command(
            [node], "rpcutil", "ping", timeout=4)
        if result:
            try:
                if not result[node]['errors']:
                    return True
            except KeyError as e:
                log.trace.warning("No {0} in command output. {1}".format(
                    node, str(e)))
                return False
        return False
