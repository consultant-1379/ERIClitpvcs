#############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from litp.core.plugin import Plugin, PluginError
from litp.core.task import OrderedTaskList, CallbackTask
from litp.core.litp_logging import LitpLogger
from litp.core.execution_manager import CallbackExecutionException
from litp.core.constants import BASE_RPC_NO_ANSWER
from litp.core.rpc_commands import PuppetMcoProcessor
from litp.plan_types.restore_snapshot import restore_snapshot_tags
from vcsplugin.vcs_cluster import VcsCluster
from vcsplugin.vcs_sg_helper import VcsServiceGroupHelper
from vcsplugin.vcs_nic_sg_helper import (
    VcsNICServiceGroupHelper,
    VCSNICServiceGroupUpdateHelper)
from vcsplugin.vcs_online_helper import VcsSGOnlineHelper
from vcsplugin.vcs_exceptions import VCSRuntimeException
from vcsplugin.legacy import LegacyVcsNetworkResource
from vcsplugin.legacy.vcs_app_resource import VcsApplicationLegacyResource
from vcsplugin.app_resource import ApplicationResource
from vcsplugin.legacy.vcs_mount_resource import VcsMountLegacyResource
from vcsplugin.network_resource import NetworkResourceHelper
from vcsplugin.mount_resource import MountResource
from vcsplugin.vcs_io_fencing_helper import VcsIOFencingHelper

from .vcs_exceptions import VcsCmdApiException
from .vcs_cmd_api import VcsCmdApi, VcsRPC
from .vcs_base_helper import (VcsBaseHelper,
                              is_clustered_service_redeploy_required,
                              is_failover_standby_node_updated,
                              get_applied_node_list)
from .vcs_utils import VcsUtils
from .vcs_utils import TimeoutParameters, is_os_reinstall_on_peer_nodes,\
    is_pre_os_reinstall_on_peer_nodes, is_ha_manager_only_on_nodes
from .vcs_constants import (COMMAND_NOT_FOUND, LOCK_FUDGE_FACTOR,
                            OFFLINE_TIMEOUT)


log = LitpLogger()


# Helper classes tasks will be implemented in the order (left to right)
# There is a requirement that the INSTALL_HELPER_CLASSES is only a ConfigTask
INSTALL_HELPER_CLASSES = (VcsCluster,)
UPGRADE_HELPER_CLASSES = (VCSNICServiceGroupUpdateHelper,)
CLUSTER_HELPER_CLASSES = (VcsIOFencingHelper, VcsNICServiceGroupHelper)
# Order dependecy: VcsApplicationResource has to be after VcsNetworkResource
SERVICE_GROUP_HELPER_CLASSES = (VcsServiceGroupHelper,
                                VcsMountLegacyResource,
                                NetworkResourceHelper,
                                LegacyVcsNetworkResource,
                                ApplicationResource,
                                MountResource,
                                VcsApplicationLegacyResource,
                                VcsSGOnlineHelper)
VIP_UPDATE_HELPER_CLASSES = (NetworkResourceHelper,)
SERVICE_GROUP_DELETION_CLASSES = (VcsServiceGroupHelper,)
PLUGIN_SPECIFIC_UPDATE_MODEL_CLASSES = (VcsServiceGroupHelper,)

# A padding constant (in seconds) for how long the lock task should wait on
# top of the timeouts declared in the clustered-service
TIMEOUT_FOR_STOP_ALL_NODES = 60 * 30
ENGINE_WAIT_TIMEOUT = 60 * 5
CANT_COMMUNICATE_WITH_ENGINE = "VCS ERROR V-16-1-10600"
NIC_WAIT_TIMEOUT = 70
PER_NET_HOST_TIMEOUT = 10
SWITCH_TIMEOUT = 60


class VcsPlugin(Plugin):
    """
    LITP VCS Plugin for VCS installation, configuration and management

    Update reconfiguration actions are supported for this plugin \
    (with some exceptions)

    """
    def _create_class(self, cl):
        inst = cl(VcsPlugin)
        return inst

    def __init__(self):
        super(VcsPlugin, self).__init__()
        self.helper_obj = dict()
        for cl in (INSTALL_HELPER_CLASSES + UPGRADE_HELPER_CLASSES +
                   CLUSTER_HELPER_CLASSES + SERVICE_GROUP_HELPER_CLASSES):
            inst = self._create_class(cl)
            self.helper_obj[cl.__name__] = inst

    def update_model(self, plugin_api_context):
        """
        Make any plugin specific updates to model items, before validation and
        create_configuration
        """
        for h in PLUGIN_SPECIFIC_UPDATE_MODEL_CLASSES:
            self.helper_obj[h.__name__].update_model(plugin_api_context)

    def validate_model(self, plugin_api_context):
        """
        Validate that:

        - there are at least two nodes in the cluster

        - The number of nodes matches the number of active plus standby nodes

        - The number of standby nodes is 0 or 1, if 1 then active must be 1

        - cluster IDs are unique

        - there is either 0 or 3 fencing disks defined for the cluster

        - heartbeat networks are not linked to the same network

        - management and heartbeats are not linked to the same network

        - management network interface is defined

        - service names are unique

        - services are not started on overlapping sets of nodes

        - services must have 1 runtime defined

        """
        errors = []
        for h in (INSTALL_HELPER_CLASSES + UPGRADE_HELPER_CLASSES +
                  CLUSTER_HELPER_CLASSES + SERVICE_GROUP_HELPER_CLASSES):
            errors.extend(self.helper_obj[h.__name__].
                          validate_model(plugin_api_context))
        return errors

    @staticmethod
    def _remove_dependencies_first(pre_node_deconfigure_tasks):
        """
        Ensure remove dependency tasks are done before other
        non-deconfigure tasks, deconfigure task being one where the model_item
        is removed.
        """
        remove_dep_tasks = [task for task in pre_node_deconfigure_tasks
                            if task.kwargs['callback_func'] ==
                                'update_remove_dependencies_callback']
        non_deconfig_tasks = (task for task in pre_node_deconfigure_tasks
                              if not task.is_deconfigure()
                              and not task in remove_dep_tasks)
        for task in non_deconfig_tasks:
            task.requires.update(remove_dep_tasks)
        return pre_node_deconfigure_tasks

    def create_configuration(self, plugin_api_context):
        """
        The VCS Plugin provides support for the installation, \
        configuration and management of the VCS software.

        The VCS Plugin uses ERIClitpvcsapi extension.

        **Example CLI for this plugin when Storage Foundation HA is used:**

        .. code-block:: bash

            litp create -t deployment -p /deployments/d1
            litp create -t vcs-cluster -p /deployments/d1/clusters/cluster1 \
-o cluster_type=sfha cluster_id=<Integer in range 1-65535> \
llt_nets="heartbeat1,heartbeat2" low_prio_net="mgmt"


        **Example CLI for this plugin when Veritas Cluster is used:**

        .. code-block:: bash

            litp create -t deployment -p /deployments/d1
            litp create -t vcs-cluster -p /deployments/d1/clusters/cluster1 \
-o cluster_type=vcs cluster_id=<Integer in range 1-65535> \
llt_nets="heartbeat1,heartbeat2" low_prio_net="mgmt"

        **Example CLI for this plugin to manage an application and its \
            required resources with Veritas Cluster in failover mode:**

        .. code-block:: bash

            litp create \
-t vcs-clustered-service \
-p /deployments/d1/clusters/cluster1/services/service1 \
-o active=1 standby=1 name=cs1 online_timeout=20 \
node_list="node1,node2"
            litp create \
-t service \
-p /software/services/service1 \
-o service_name=httpd \
cleanup_command="/opt/ericsson/cleanup_apache.sh"
            litp inherit \
-p /deployments/d1/clusters/cluster1/services/service1/applications/service1 \
-s /software/services/service1
            litp create -t vip \
-p /deployments/d1/clusters/cluster1/services/service1/ipaddresses/vip1 \
-o ipaddress=<ip address in mgmt subnet> network_name=mgmt

        The timeout for the VCS unlock task is the maximum value of the \
        online_timeout property across all the vcs-clustered-services in a \
        VCS cluster.

        **Example CLI for this plugin to manage an application and its \
            required resources with Veritas Cluster in parallel mode:**

        .. code-block:: bash

            litp create -t vcs-clustered-service \
-p /deployments/d1/clusters/cluster1/services/service1 \
-o active=2 standby=0 name=cs1 \
node_list="node1,node2"
            litp create -t service \
-p /software/services/service1 \
-o service_name=httpd \
cleanup_command="/opt/ericsson/cleanup_apache.sh"
            litp inherit \
-p /deployments/d1/clusters/cluster1/services/service1/applications/service1 \
-s /software/services/service1
            litp create -t vip \
-p /deployments/d1/clusters/cluster1/services/service1/ipadresses/vip1 \
-o ipaddress<IP address in mgmt subnet> network_name=mgmt

        .. note::

            Example setup a vip using a IPv6 address the following command.

        .. code:: bash

        litp create -t vip \
-p /deployments/d1/clusters/cluster1/services/service1/ipaddresses/vip2 \
-o ipadress=2001:abcd:ef::32/64 network_name=traffic

        .. note::

            The order in which the nodes are specified in the node_list \
            property is used by LITP to set the priority levels of each \
            system in the vcs-clustered-service. This means that when a \
            failover vcs-clustered-service is coming online, the service is \
            brought online on the first available node in the list.

        For more information, see \
"Introduction to LITP High Availability Configuration Using VCS" \
and "Configure a VCS Service Group" \
from :ref:`LITP References <litp-references>`.

       """
        clusters = plugin_api_context.query("vcs-cluster")

        if is_ha_manager_only_on_nodes(plugin_api_context):
            return [VcsCluster.create_vcs_app_agent_num_threads_task(
                                          self.helper_obj[VcsCluster.__name__],
                                          cluster,
                                          cluster.app_agent_num_threads)
                    for cluster in clusters
                    if cluster.app_agent_num_threads]

        ordered_tasks = []
        for cluster in clusters:
            install_tasks = dict()
            for h in INSTALL_HELPER_CLASSES:
                h = self.helper_obj[h.__name__]
                install_tasks = dict(
                    zip(['ms', 'node', 'cluster', 'node_delete'],
                        h.create_configuration(plugin_api_context, cluster)))
            if install_tasks:
                ordered_tasks.extend(install_tasks['ms'])
                for node_tasks in install_tasks['node']:
                    if node_tasks:
                        ordered_tasks.append(OrderedTaskList(cluster.nodes,
                                                             node_tasks))
                # Put our node based upgrade tasks in the node phase.
                if is_pre_os_reinstall_on_peer_nodes(cluster):
                    log.trace.info("Don't add node based upgrade tasks in Pre "
                                   "Rollover OS Install plan")
                else:
                    for h in UPGRADE_HELPER_CLASSES:
                        h = self.helper_obj[h.__name__]
                        upgrade_tasks = h.create_configuration(
                            plugin_api_context, cluster)
                        if upgrade_tasks:
                            ordered_tasks.extend(upgrade_tasks)

                ordered_tasks.extend(install_tasks['cluster'])

            pre_node_tasks = []
            post_node_tasks = []
            pre_node_deconfigure_tasks = []

            for h in VIP_UPDATE_HELPER_CLASSES:
                vip_update_tasks = (
                    self.helper_obj[h.__name__].get_vip_update_tasks(
                        plugin_api_context, cluster))
                post_node_tasks.extend(vip_update_tasks)

            for h in CLUSTER_HELPER_CLASSES:
                cluster_pre_node_tasks, cluster_post_node_tasks = (
                    self.helper_obj[h.__name__].create_configuration(
                        plugin_api_context, cluster))
                pre_node_tasks.extend(cluster_pre_node_tasks)
                post_node_tasks.extend(cluster_post_node_tasks)

            ordered_sg_creation = VcsUtils().get_ordered_sg_creation(
                cluster.services)
            log.event.debug("Create Service Groups in the order: {0}".format(
                ordered_sg_creation))
            ordered_sg_removal = VcsUtils().get_ordered_sg_removal(
                cluster.services)
            log.event.debug("Remove Service Groups in the order: {0}".format(
                ordered_sg_removal))

            for service in ordered_sg_removal:
                for h in SERVICE_GROUP_DELETION_CLASSES:
                    pre_node_deconfigure_tasks.extend(
                        self.helper_obj[h.__name__].delete_configuration(
                            plugin_api_context, cluster, service))

            for service in ordered_sg_creation:
                for h in SERVICE_GROUP_HELPER_CLASSES:
                    service_pre_node_tasks, service_post_node_tasks = \
                       self.helper_obj[h.__name__].create_configuration(
                           plugin_api_context, cluster, service)
                    post_node_tasks.extend(service_post_node_tasks)
                    pre_node_tasks.extend(service_pre_node_tasks)

            if install_tasks and install_tasks['node_delete']:
                for task in install_tasks['node_delete']:
                    pre_node_tasks.append(task)

            if is_pre_os_reinstall_on_peer_nodes(cluster):
                log.trace.info("Filter out Post lock VCS tasks for Pre "
                               "Rollover OS Install plan")
            elif post_node_tasks != []:
                ordered_tasks.append(OrderedTaskList(cluster, post_node_tasks))
            if pre_node_tasks != []:
                ordered_tasks.append(OrderedTaskList(cluster, pre_node_tasks))

            if pre_node_deconfigure_tasks:
                # Plugins are not allowed to specify task dependencies
                # which cross the configuration and deconfigure
                # boundaries. Hence the tasks in pre_node_deconfigure_task
                # cannot be in an orderedlist because there is a
                # a deconfigure task and a configure task.
                pre_node_deconfigure_tasks = self._remove_dependencies_first(
                                                    pre_node_deconfigure_tasks)
                for task in pre_node_deconfigure_tasks:
                    ordered_tasks.append(task)

        return ordered_tasks

    def create_lock_tasks(self, plugin_api_context, node):
        for cluster in plugin_api_context.query('vcs-cluster'):
            if cluster.query("node", hostname=node.hostname):
                return (
                    CallbackTask(
                        node,
                        'Lock VCS on node "{0}"'.format(node.hostname),
                        self.lock_node,
                        cluster_path=cluster.get_vpath(),
                        node_path=node.get_vpath(),
                        timeout=self._get_lock_timeout(cluster),
                        switch_timeout=str(SWITCH_TIMEOUT)),
                    CallbackTask(
                        node,
                        'Unlock VCS on node "{0}"'.format(node.hostname),
                        self.unlock_node,
                        node_path=node.get_vpath(),
                        cluster_path=cluster.get_vpath(),
                        timeout=self._get_unlock_timeout(cluster))
                )

    def callback_method(self, callback_api, *args, **kwargs):
        """
        Generic callback method used by helper classes. It expects kwargs
        to include callback_class (the name of the helper class) and
        callback_func (the name of the method of the class to be called)
        :param callback_api: CallbackApi instance
        :type  callback_api: CallbackApi
        """
        try:
            callback_class_name = kwargs.pop("callback_class")
        except KeyError:
            raise VCSRuntimeException(
                "Callback expects kwarg callback_class to be defined")
        try:
            callback_object = self.helper_obj[callback_class_name]
        except KeyError:
            err_msg = ("Class {0} is not known to plugin, cannot execute "
                       "callback".format(callback_class_name))
            raise VCSRuntimeException(err_msg)

        try:
            callback_method_name = kwargs.pop('callback_func')
        except KeyError:
            err_msg = "Callback expects kwarg callback_func to be defined"
            raise VCSRuntimeException(err_msg)

        try:
            callback_method = getattr(callback_object,
                                      callback_method_name)
        except (AttributeError, TypeError) as exc:
            raise VCSRuntimeException(str(exc))

        try:
            callback_method(callback_api, *args, **kwargs)
        except VcsCmdApiException as ex:
            err_msg = "VCS callback_method: Exception occurred during "\
                      "execution of callback... " + str(ex)
            raise CallbackExecutionException(err_msg)

    def create_snapshot_plan(self, plugin_api_context):
        """
        Create a plan for ``create``, ``remove`` or ``restore``
        snapshot actions. Generates tasks for snapshot creation,
        deletion and restoration on MS and MNs for LVM and VxVM
        volumes.
        Also generates stop vcs tasks for peer servers of clusters
        containing model items of ``disk`` type.
        """
        ss_name = plugin_api_context.snapshot_name()
        snapshot = plugin_api_context.query('snapshot-base', item_id=ss_name)
        # add tasks only for restore plan
        try:
            action = plugin_api_context.snapshot_action()
        except Exception as e:
            # give a comprehensive error rather than an ugly traceback
            raise PluginError(e)
        if snapshot and action == 'restore':
            if snapshot[0].rebooted_clusters:
                rebooted_clusters = [c for c in \
                    snapshot[0].rebooted_clusters.split(",") if c]
            else:
                rebooted_clusters = []
            return self._create_restore_snapshot_tasks(plugin_api_context,
                                                    rebooted_clusters)
        else:
            return []

    def _create_restore_snapshot_tasks(self, plugin_api_context,
                                            rebooted_clusters):
        tasks = []
        tasks.extend(self._add_hastop_task(plugin_api_context,
                                           rebooted_clusters,
                                           ignore_vcs_stop_err=True,
                                           ignore_node_down=True,
                                           ignore_cmd_not_found=True,
                                           ))
        return tasks

    def _stop_service(self, callback_api, service, hostnames):
        if not hostnames:
            raise CallbackExecutionException("service {0} was requested to " \
                      "be stopped, but the node list is empty".format(service))
        call_args = ['service', service, 'stop', '-y']
        callback_api.rpc_application(hostnames, call_args)

    def _node_has_disks(self, node):
        disks = node.system.query('disk')
        if disks:
            return True
        return False

    def _add_hastop_task(self, plugin_api_context, rebooted_clusters,
                         ignore_vcs_stop_err=False, ignore_node_down=False,
                         ignore_cmd_not_found=False):
        tasks = []

        snapshot_model = plugin_api_context.snapshot_model()

        clusters = [c for c in snapshot_model.query('vcs-cluster') if
                    not c.is_initial()]

        for cluster in iter(clusters):
            if cluster.item_id not in rebooted_clusters:
                nodes = cluster.query("node")
                hostnames = [n.hostname
                             for n in nodes if (not n.is_initial() and
                                                self._node_has_disks(n))]
                if not hostnames:
                    continue

                stop_vcs_task = CallbackTask(
                    cluster,
                    'Stop VCS engine on cluster "{0}"'.format(cluster.item_id),
                    self.cb_stop_vcs,
                    hostnames,
                    ignore_vcs_stop_err,
                    ignore_node_down,
                    ignore_cmd_not_found,
                    tag_name=restore_snapshot_tags.PREPARE_VCS_TAG)
                tasks.append(stop_vcs_task)

                # If there are cluster fencing disks, ensure vxfen stopped
                fencing_disks = [f_disk for f_disk in cluster.fencing_disks
                                 if not f_disk.is_initial()]
                if fencing_disks:
                    stop_vxfen_task = CallbackTask(
                        cluster,
                        ('Stop VX fencing on cluster "{0}"'.format(
                            cluster.item_id)),
                        self.cb_stop_vxfen,
                        hostnames,
                        ignore_node_down,
                        ignore_cmd_not_found,
                        tag_name=restore_snapshot_tags.PREPARE_VCS_TAG,
                    )
                    # Can only stop vx fencing after stopping vcs
                    stop_vxfen_task.requires.add(stop_vcs_task)
                    tasks.append(stop_vxfen_task)

        return tasks

    def cb_stop_vxfen(self, callback_api, hostnames, ignore_node_down=False,
                      ignore_cmd_not_found=False):
        # pylint: disable=unused-argument

        # Run stop vx fencing command on all nodes
        for hostname in hostnames:
            log.event.info('Stopping Vx Fencing on node "{0}"'.format(
                hostname))

            vcs_api = VcsCmdApi(hostname)
            vcs_api.stop_vx_fencing(ignore_node_down=ignore_node_down,
                                    ignore_cmd_not_found=ignore_cmd_not_found)

    def cb_stop_vcs(self, callback_api, nodes,
                    ignore_vcs_stop_err=False, ignore_node_down=False,
                    ignore_cmd_not_found=False):

        # The hastop command is a cluster wide command, however the command
        # is run on all nodes in case the first node is already down
        for node in nodes:
            vcs_api = VcsCmdApi(node)
            # LITPCDS-8090: Ensure vcs configuration file is read-only
            vcs_api.haconf("dump", read_only="True",
                           ignore_vcs_stop_err=ignore_vcs_stop_err,
                           ignore_node_down=ignore_node_down,
                           ignore_node_leaving=True,
                           ignore_node_remote_build=True,
                           ignore_admin_wait=True,
                           ignore_cmd_not_found=ignore_cmd_not_found)
            vcs_api.stop_vcs(ignore_vcs_stop_err=ignore_vcs_stop_err,
                             ignore_node_down=ignore_node_down, sys=node,
                             ignore_cmd_not_found=ignore_cmd_not_found)

        timing_parameters = TimeoutParameters(
            max_wait=TIMEOUT_FOR_STOP_ALL_NODES)
        VcsUtils.wait_on_state(callback_api, self._check_offline,
                               timing_parameters, nodes,
                               ignore_node_down=ignore_node_down,
                               ignore_cmd_not_found=ignore_cmd_not_found)

    def _check_offline(self, nodes, ignore_node_down=False,
                       ignore_cmd_not_found=False):
        offline = True
        for node in nodes:
            vcs_rpc = VcsRPC(node)
            try:
                ret, out, err = vcs_rpc.cluster_stopped()
            except VcsCmdApiException as e:
                if ignore_node_down and BASE_RPC_NO_ANSWER in str(e):
                    # assume that node is fine
                    ret, out, err = 0, '', ''
                else:
                    raise

            log.event.debug("Check cluster online response:{0} {1} {2}".format(
                ret, out, err))

            if ignore_cmd_not_found and COMMAND_NOT_FOUND in err:
                # assume that vcs has not been installed on the node
                log.trace.info('Checked for VCS offline, but VCS is not '
                               'installed on node: "{0}". Message: '
                               '"{1}"'.format(node, err))
                ret, out, err = 0, '', ''

            offline &= (ret == 0)
        return offline

    def _get_prevent_failover_grps(self, cluster, node):
        prevent_failover_svcs = \
            [service for service in cluster.services
             if is_failover_standby_node_updated(cluster, service)
             and node.item_id in set(
                    get_applied_node_list(service)).intersection(
                    set(service.node_list.split(",")))]
        prevent_failover_grps = [
            VcsBaseHelper.get_group_name(svc.item_id, cluster.item_id)
            for svc in prevent_failover_svcs]
        return prevent_failover_grps

    def lock_node(self, callback_api, cluster_path, node_path,
                  timeout, switch_timeout):
        node_to_lock = VcsBaseHelper.query_by_vpath(callback_api, node_path)
        cluster = VcsBaseHelper.query_by_vpath(callback_api, cluster_path)

        prevent_failover_grps = self._get_prevent_failover_grps(cluster,
                                                                node_to_lock)

        vcs_rpc = VcsRPC(node_to_lock.hostname)

        vcs_api = VcsCmdApi(node_to_lock.hostname)
        self.toggle_nofailover_triggers(vcs_api, node_to_lock)

        timing_parameters = TimeoutParameters(max_wait=timeout,
                interruptible=False)

        vcs_rpc.lock(node_to_lock.hostname, switch_timeout,
                     ",".join(prevent_failover_grps))
        res = VcsUtils.wait_on_state(callback_api, self._check_evacuated,
                                     timing_parameters, vcs_rpc,
                                     node_to_lock.hostname)
        if not res:
            raise CallbackExecutionException(
                "Node {0} has not locked within {1} seconds".format(
                    node_to_lock.hostname, timing_parameters.max_wait))

    def _check_evacuated(self, vcs_api, node_to_lock):
        ret, out, err = vcs_api.check_evacuated(node_to_lock)
        log.event.debug("Check evacuated response: {0} {1} {2}".format(
            ret, out, err))
        return ret == 0

    def unlock_node(self, callback_api, node_path, cluster_path, timeout):
        node_to_unlock = VcsBaseHelper.query_by_vpath(callback_api, node_path)
        cluster = VcsBaseHelper.query_by_vpath(callback_api, cluster_path)

        vcs_api = VcsCmdApi(node_to_unlock.hostname)
        vcs_rpc = VcsRPC(node_to_unlock.hostname)

        self._poll_for_engine(callback_api, vcs_api, node_to_unlock.hostname)

        self._probe_nics(callback_api, vcs_api, vcs_rpc,
                         node_to_unlock.hostname)

        nic_wait_timeout = NIC_WAIT_TIMEOUT
        number_network_hosts = len([nhost for nhost in cluster.network_hosts])

        nic_wait_timeout += number_network_hosts * PER_NET_HOST_TIMEOUT

        prevent_failover_grps = self._get_prevent_failover_grps(cluster,
                                                                node_to_unlock)

        vcs_rpc.unlock(node_to_unlock.hostname, str(nic_wait_timeout),
                       ','.join(prevent_failover_grps))

        timing_parameters = TimeoutParameters(max_wait=timeout,
                interruptible=False)
        if not VcsUtils.wait_on_state(callback_api, self._check_cluster_online,
                                      timing_parameters,
                                      vcs_rpc, node_to_unlock.hostname,
                                      ','.join(prevent_failover_grps)):
            raise CallbackExecutionException(
                'Resources on node {0} have not come online in {1} seconds'
                ''.format(node_to_unlock.hostname, timing_parameters.max_wait))

        vcs_api = VcsCmdApi(node_to_unlock.hostname)
        self.toggle_nofailover_triggers(vcs_api, node_to_unlock, enable=True)
        PuppetMcoProcessor().disable_puppet([node_to_unlock.hostname])

    def _get_unlock_timeout(self, cluster):
        timeouts = [VcsUtils.get_service_online_time(service)
                    for service in cluster.services
                    if not service.is_initial()
                    or not service.applied_properties_determinable
                    or is_os_reinstall_on_peer_nodes(cluster)]

        return max(timeouts or [0]) + LOCK_FUDGE_FACTOR

    def _get_lock_timeout(self, cluster):
        # When a node is being locked, the time allowed by LITP to lock the
        # node will be the largest online time of all clustered services in
        # the cluster plus the largest value for offline_timeout of all
        # clustered services in the cluster
        serv_lock_times = [int(getattr(service, "offline_timeout",
                                       OFFLINE_TIMEOUT)) +
                           VcsUtils.get_service_online_time(service)
                           for service in cluster.services
                           if not service.is_initial()
                           or not service.applied_properties_determinable
                           or is_os_reinstall_on_peer_nodes(cluster)]

        # Add a fudge factor for the lock, just in case
        lock_timeout = max(serv_lock_times or [0]) + LOCK_FUDGE_FACTOR

        # Add in the hagrp switch timeout
        return lock_timeout + SWITCH_TIMEOUT

    def _check_cluster_online(self, vcs_rpc, node_to_unlock,
                              prevent_failover_grps):
        ret, out, err = vcs_rpc.check_cluster_online(node_to_unlock,
                                                     prevent_failover_grps)
        log.event.debug("Check cluster online response:{0} {1} {2}".format(
            ret, out, err))
        return ret == 0

    def _node_in_clustered_service(self, service, node):
        for n in service.nodes:
            if n.get_vpath() == node.get_vpath():
                return True
        return False

    def _poll_for_engine(self, callback_api, vcs_api, hostname):
        timing_parameters = TimeoutParameters(
            max_wait=ENGINE_WAIT_TIMEOUT)
        if not VcsUtils.wait_on_state(callback_api, self._vcs_poll,
                                      timing_parameters, vcs_api):
            raise CallbackExecutionException(
                '"VCS" engine has not come up within {0} seconds'.format(
                    timing_parameters.max_wait))
        if not VcsUtils.wait_on_state(callback_api, self._probe_poll,
                                      timing_parameters, vcs_api):
            raise CallbackExecutionException(
                'Have failed to probe all resources in {0} seconds'
                ''.format(timing_parameters.max_wait))
        if not VcsUtils.wait_on_state(callback_api, self._node_state_poll,
                                      timing_parameters, vcs_api, hostname):
            raise CallbackExecutionException(
                '"VCS" engine on node "{0}" has not transitioned to state '
                '"RUNNING" within {0} seconds'.format(
                    timing_parameters.max_wait))

    def _node_state_poll(self, vcs_api, hostname):
        try:
            status = vcs_api.hasys_state(hostname)
            return "RUNNING" in status
        except VcsCmdApiException:
            return False

    def _probe_poll(self, vcs_api):
        try:
            res_val = vcs_api.probes_pending()
            return not int(res_val)
        # return true if ret val is emtpy string, in case that a node
        # has no SG configured
        except ValueError:
            return not res_val

    def _vcs_poll(self, vcs_api):
        try:
            status = vcs_api.hastatus()
            return not ("VCS WARNING" in status or "VCS ERROR" in status)
        except VcsCmdApiException:
            return False

    def _probe_nics(self, callback_api, vcs_api, vcs_rpc, hostname):
        vcs_rpc.probe_all_nics(hostname)

        timing_parameters = TimeoutParameters(max_wait=ENGINE_WAIT_TIMEOUT)
        if not VcsUtils.wait_on_state(callback_api, self._probe_poll,
                                      timing_parameters, vcs_api):
            raise CallbackExecutionException(
                'Have failed to probe all resources in {0} seconds'.format(
                    timing_parameters.max_wait))

    def toggle_nofailover_triggers(self, vcs_api, node, enable=False):
        cluster = VcsUtils.get_parent_with_type(node, "vcs-cluster")

        def has_nofail(service):
            if service.is_initial() or service.is_for_removal() \
                    or service.is_removed() \
                    or is_clustered_service_redeploy_required(service):
                return False
            nofail_trig = [trig for trig in service.triggers
                           if "nofailover" == trig.trigger_type
                           and not trig.is_initial()
                           and not trig.is_for_removal()
                           and not trig.is_removed()]
            if nofail_trig:
                return True
            return False

        nofail_svcs = [service for service in cluster.services
                       if has_nofail(service) and
                       node.item_id in service.node_list.split(",")]
        with vcs_api.readable_conf():
            for svc in nofail_svcs:
                group_name = VcsBaseHelper.get_group_name(svc.item_id,
                                                          cluster.item_id)
                if enable:
                    vcs_api.hagrp_add_in_triggers_enabled(group_name,
                                                          "NOFAILOVER")
                else:
                    vcs_api.hagrp_delete_in_triggers_enabled(group_name,
                                                             "NOFAILOVER")
