##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################
from collections import defaultdict
from itertools import chain

from litp.core.execution_manager import CallbackTask
from litp.core.litp_logging import LitpLogger
from litp.core.validators import ValidationError
from litp.plan_types.deployment_plan import deployment_plan_tags

from vcsplugin.vcs_base_helper import (VcsBaseHelper,
                                       condense_name,
                                       property_updated)
from vcsplugin.vcs_model import VCSModel, State
from vcsplugin.vcs_utils import select_nodes_from_cluster


log = LitpLogger()


class NicGroup(object):
    def __init__(self, nic):
        self.nic = nic.device_name
        self.cluster_id = nic.get_cluster().item_id
        self.nodes = []

    def name(self):
        return VcsBaseHelper.get_nic_service_group_name(self.cluster_id,
                                                        self.nic)


class VcsNICServiceGroupHelper(VcsBaseHelper):
    '''
    VcsNICServiceGroupHelper Class is responsible for installing the
    VCS NIC service groups in a VCS cluster
    '''

    def validate_model(self, plugin_api_context):
        """
        Validates that:

        - no network-interface, that is monitored \
        by a dependent service group - can be removed
        - no heartbeats network-interfaces can be removed

        :param plugin_api_context: An instance of PluginApiContext through \
                which validate_model can access the Deployment Model.
        :type plugin_api_context: litp.core.plugin_context_api.PluginApiContext

        :returns:   A list of :class:`litp.core.validators.ValidationError` \
                    objects for each problem found. An empty list means the \
                    model is valid for this plugin.
        :rtype: list
        """

        clusters = plugin_api_context.query("vcs-cluster")

        errs = self._validate_each_interface_has_device_name(clusters)
        if errs:
            # If there are errors due to no device_name return errors before
            # running other validations which assume device_name present
            return errs

        errs_list = []

        for cluster in clusters:
            errs_list.append(self._validate_network_hosts_have_ips(
                cluster, plugin_api_context))
            errs_list.append(self._validate_interfaces_for_removal(cluster))
            errs_list.append(self._validate_network_hosts_for_removal(cluster))
            errs_list.append(self._validate_net_host_on_llt(cluster))
            errs_list.append(self._validate_net_host_not_duplicate(cluster))
            errs_list.append(self._validate_net_host_in_network(cluster))
            errs_list.append(self._validate_maximum_network_hosts(cluster))

        return list(chain(*errs_list))

    def _validate_each_interface_has_device_name(self, clusters):
        errors = []
        for cluster in clusters:
            for node in cluster.nodes:
                for interface in node.network_interfaces:
                    if not hasattr(interface, 'device_name'):
                        errors.append(
                            ValidationError(
                                item_path=interface.get_vpath(),
                                error_message='The interface type '
                                              '"network-interface" '
                                              'is not allowed in a VCS cluster'
                                              '. Allowed interface types are '
                                              'eth or bridge or vlan or bond'
                            ))
        return errors

    def _validate_network_hosts_have_ips(self, cluster, api):
        """
        Loop through all network-interface items on each node
        in the cluster that will be part of a NIC service group.
        Check that if the network that these network-interfaces
        belong to have a vcs-network-hosts configured then each
        network-interface must have an IP configured.
        """
        errors = []
        validation_message = (
            'Interface "{interface_name}" on node "{node_hostname}" cannot '
            'be monitored using VCS network host "{ipaddress}" '
            'as it has no ipaddress assigned')

        nic_groups = VCSModel(api).get_nic_groups(cluster)
        network_hosts = dict(
            (host.network_name, host.ip)
            for host in cluster.network_hosts)

        for node in cluster.nodes:
            for nic in node.network_interfaces:
                if not nic_groups.get(nic.device_name, {}).get(node.hostname):
                    continue
                if nic.network_name in network_hosts and not any(
                        (nic.ipaddress, nic.ipv6address)):
                    errors.append(ValidationError(
                        item_path=nic.get_vpath(),
                        error_message=validation_message.format(
                            interface_name=nic.device_name,
                            node_hostname=node.hostname,
                            ipaddress=network_hosts[nic.network_name])))
        return errors

    def _validate_interfaces_for_removal(self, cluster):
        """
        Check that network-interfaces, that are not monitored by a dependent
        service group cannot be removed.
        Throw a ValidationError - if they are marked for removal
        """
        errors = []
        networks = defaultdict(list)

        for ip in cluster.services.query('vip'):
            if not ip.is_for_removal():
                networks[ip.network_name].append(ip)

        for interface in self._get_sr_grps_nics_for_removal(cluster):
            if interface.network_name in networks.keys():
                errors.append(
                    ValidationError(
                        item_path=interface.get_vpath(),
                        error_message="This interface is in use by {0}".format(
                            ", ".join(
                                sorted([ip.get_vpath()
                                 for ip in networks[interface.network_name]])))
                    ))
        return errors

    def _validate_network_hosts_for_removal(self, cluster):
        """
        Check that there are no vcs-network-hosts in the cluster that reference
        any network for removal from the cluster.
        """
        errors = []
        network_hosts = defaultdict(list)

        for network_host in cluster.network_hosts:
            if not network_host.is_for_removal():
                network_hosts[network_host.get_vpath()] =\
                    network_host.network_name

        for node in [node for node in cluster.nodes
                     if not node.is_for_removal()]:
            for nic in self._get_all_node_nics_in_use_marked_for_removal(node):
                if nic.network_name in network_hosts.values():
                    errors.append(
                        ValidationError(
                            item_path=nic.get_vpath(),
                            error_message="The network in this interface is "
                                "being used by: {0}".format(
                                ", ".join([key for key, value in\
                                network_hosts.iteritems() if value ==\
                                nic.network_name]))
                        ))
        return errors

    def _validate_net_host_on_llt(self, cluster):
        """
        Check if any vcs-network-host item is referring to a LLT network
        """
        errors = []
        for llt_net in cluster.llt_nets.split(","):
            llt_net = llt_net.strip()
            for net_host in cluster.network_hosts:
                if net_host.network_name == llt_net:
                    errors.append(
                      ValidationError(
                        item_path=net_host.get_vpath(),
                        error_message=('Can not add a "vcs-network-host" to a '
                                       'network that belongs to a VCS LLT '
                                       'network')
                                      ))
        return errors

    def _validate_net_host_not_duplicate(self, cluster):
        """
        Check that the same network host is defined no more than once.
        For example if 2 vcs-network hosts have the same network and IP
        """
        errors = []
        net_hosts_dir = {}

        for net_host in cluster.network_hosts:
            if net_host.is_for_removal():
                continue
            # Create a tuple of (network_name, ip_address)
            # The IP address is converted to lower case for IPv6 (LITPCDS-6841)
            net_values = (net_host.network_name, net_host.ip.lower())

            if net_values in net_hosts_dir.values():
                errors.append(
                    ValidationError(
                        item_path=net_host.get_vpath(),
                        error_message='The network_name "{0}" and ip "{1}" '
                            'have already been defined in: "{2}"'.format(
                            net_host.network_name, net_host.ip.lower(),
                            (', ').join(key for key, value in net_hosts_dir.
                            iteritems() if value == net_values))
                    ))

            net_hosts_dir[net_host.get_vpath()] = net_values

        return errors

    def _validate_net_host_in_network(self, cluster):
        """
        Check if vcs-network-host network_name is valid for this cluster
        """
        errors = []
        net_names = set()
        for node in cluster.nodes:
            for net_iface in node.network_interfaces:
                net_names.add(net_iface.network_name)
        for net_host in cluster.network_hosts:
            if net_host.network_name not in net_names:
                errors.append(
                    ValidationError(
                        item_path=net_host.get_vpath(),
                        error_message="The network name for vcs-network-host "
                                      "is not present on cluster"))
        return errors

    def _validate_maximum_network_hosts(self, cluster):
        '''
        Check that there are no more than the maximum number of network hosts
        defined on one network.
        '''
        errors = []
        network_hosts_network_dir = {}
        MAXIMUM_NETWORK_HOSTS_ON_NETWORK = 10

        for network_host in cluster.network_hosts:
            if network_host.is_for_removal():
                continue
            network_hosts_network_dir[network_host.get_vpath()] = \
                network_host.network_name

            if network_hosts_network_dir.values().count(
                network_host.network_name) > MAXIMUM_NETWORK_HOSTS_ON_NETWORK:
                errors.append(
                    ValidationError(
                        item_path=network_host.get_vpath(),
                        error_message='The number of network hosts using the '
                            'network_name "{0}" has exceeded the maximum '
                            'number allowed "{1}"'.format(network_host.
                            network_name, MAXIMUM_NETWORK_HOSTS_ON_NETWORK)
                    ))
        return errors

    def _get_sr_grps_nics_for_removal(self, cluster):
        """
        Return all nics used by all service groups that are marked for removal
        if they are being used (have interface.network_name specified)
        """
        nics_for_removal = []

        nodes_seen = set()

        for sg in cluster.services:
            for node in sg.nodes:
                if node.get_vpath() not in nodes_seen:
                    nodes_seen.add(node.get_vpath())
                    nics_for_removal.extend(
                        self._get_all_node_nics_in_use_marked_for_removal(
                            node))
        return nics_for_removal

    def _get_all_node_nics_in_use_marked_for_removal(self, node):
        """
        Return all nics on a node marked for removal if they are in use
        (have a network name specified)
        """
        return [interface for interface in
                      node.network_interfaces if interface.network_name and
                                                 interface.is_for_removal()]

    def _generate_nicgrp_task(self, cluster, nic_groups):
        """
        Return the callback tasks needed to create the NIC Service Groups
        """
        tasks = []

        for nic_name, node_gw in nic_groups.items():
            hostnames = node_gw.keys()
            nic_items = get_nic_items_for_device(cluster, nic_name,
                                                 hostnames)
            gateway_found = any(node_gw.values())

            force_mii = [nic for nic in nic_items if
                         not hasattr(nic, 'ipaddress') or not nic.ipaddress]

            if force_mii or (not gateway_found and
                             cluster.default_nic_monitor == "mii"):
                mii = "1"
            else:
                mii = "0"
            task = CallbackTask(
                cluster,
                'Create VCS service group for NIC "{0}"'.format(nic_name),
                self.plugin().callback_method,
                callback_class=self.__class__.__name__,
                callback_func=self.add_nicgrp_callback.__name__,
                nic_name=nic_name,
                node_gateways=node_gw,
                mii=mii,
                cluster_item_id=cluster.item_id)

            nh_items = self._network_hosts_items(cluster, nic_items)
            task.model_items.update(nic_items + nh_items)
            tasks.append(task)
        return tasks

    def _network_hosts_items(self, cluster, nics):
        network_hosts = []
        for nic in nics:
            network_hosts.extend(cluster.query('vcs-network-host',
                                               network_name=nic.network_name))
        return network_hosts

    def _create_remove_nic_task(self, cluster, nic_group, nodes,
                                expect_faulted=False):
        """
        Return the callback tasks needed to create the NIC Service Groups
        """
        nic_items = get_nic_items_for_device(cluster, nic_group,
                                             nodes)
        task = CallbackTask(
            cluster,
            'Remove nodes "{0}" from service group for NIC "{1}"'.format(
                ", ".join(nodes), nic_group),
            self.plugin().callback_method,
            callback_class=self.__class__.__name__,
            callback_func=self._remove_node_from_nicgrp_callback.__name__,
            nic_group=nic_group,
            nodes=nodes,
            cluster_vpath=cluster.get_vpath(),
            expect_faulted=expect_faulted,
            tag_name=deployment_plan_tags.PRE_NODE_CLUSTER_TAG)
        task.model_items.update(set(nic_items))
        return task

    def _create_remove_nic_group_task(self, cluster, nic_group, offline=True):
        """
        Return the callback tasks needed to create the NIC Service Groups
        """

        nic_items = get_nic_items_for_device(cluster, nic_group)
        task = CallbackTask(
            cluster,
            'Remove VCS service group for NIC "{0}"'.format(nic_group),
            self.plugin().callback_method,
            callback_class=self.__class__.__name__,
            callback_func=self._remove_nicgrp_callback.__name__,
            nic_group=nic_group,
            cluster_vpath=cluster.get_vpath(),
            offline=offline,
            tag_name=deployment_plan_tags.PRE_NODE_CLUSTER_TAG)
        task.model_items.update(set(nic_items))
        return task

    def create_configuration(self, plugin_api_context, cluster):
        vcs_model = VCSModel(plugin_api_context)
        pre_node_tasks = []
        post_node_tasks = []

        if cluster.is_initial() or vcs_model.get_nic_groups(cluster):
            nic_groups = vcs_model.get_nic_groups(cluster)
            post_node_tasks.extend(self._generate_nicgrp_task(cluster,
                                                              nic_groups))

        if not cluster.is_initial() and not cluster.is_for_removal():
            # Create tasks for added/removed nics.
            if vcs_model.get_nic_groups(cluster, state=State.REMOVAL()):

                nics_for_removal = _get_nics_for_removal(cluster)
                for nic_group, nodes in nics_for_removal.items():
                    pre_node_tasks.append(
                        self._create_remove_nic_task(cluster,
                                                     nic_group, nodes))

                for nic_group in _get_nic_groups_for_removal(cluster):
                    pre_node_tasks.append(
                        self._create_remove_nic_group_task(cluster, nic_group))
        return pre_node_tasks, post_node_tasks

    def _remove_node_from_nicgrp_callback(
            self, callback_api, nic_group, nodes, cluster_vpath,
            expect_faulted=False):
        # pylint: disable=unused-argument
        cluster = self.query_by_vpath(callback_api, cluster_vpath)
        off_timeout = "15"
        # some of nodes might not have VCS package installed in pre-node lock
        self.nodes = select_nodes_from_cluster(cluster)
        nic_sg_name = self.get_nic_service_group_name(cluster.item_id,
                                                      nic_group)

        nodes_to_delete = [node.hostname for node in cluster.nodes
                           if node.is_for_removal]
        with self.vcs_api.readable_conf():
            for node in nodes:
                self.vcs_api.hagrp_offline(nic_sg_name, node,
                                           forced=(node in nodes_to_delete))
                self.vcs_api.check_hagrp_isoffline(
                    callback_api,
                    nic_sg_name, off_timeout, node,
                    expect_faulted=expect_faulted)
                self.vcs_api.hagrp_delete_in_system_list(
                    nic_sg_name, node)

    def _remove_nicgrp_callback(
            self, callback_api, nic_group, cluster_vpath, offline=True):
        # pylint: disable=unused-argument
        cluster = self.query_by_vpath(callback_api, cluster_vpath)
        # some of nodes might not have VCS package installed in pre-node lock
        self.nodes = select_nodes_from_cluster(cluster)
        nic_sg_name = self.get_nic_service_group_name(cluster.item_id,
                                                      nic_group)

        with self.vcs_api.readable_conf():
            if offline is True:
                self.vcs_api.hagrp_offline(nic_sg_name)
            self.vcs_api.hagrp_remove(nic_sg_name)

    def add_nicgrp_callback(self, callback_api, nic_name, node_gateways,
                            mii, cluster_item_id):
        # pylint: disable=unused-argument
        """
        Callback function for the task to install the NIC Service Group
        :param callback_api: access to security and execution manager
        :type  callback_api: class
        """
        # Needed for parent class.
        self.nodes = node_gateways.keys()
        nic_service_group_name = self.get_nic_service_group_name(
            cluster_item_id, nic_name)

        log.event.info("VCS Creating NIC service group {0}".format(
            nic_service_group_name))

        # NIC service groups are always parallel
        parallel = True
        with self.vcs_api.readable_conf():
            node_gateways_tuple = tuple(enumerate(self.nodes))
            self.vcs_api._clustered_service_set_attributes(
                nic_service_group_name, node_gateways_tuple, parallel)
            create_nic_resources(
                self.vcs_api,
                nic_service_group_name,
                nic_name,
                node_gateways,  # Mapping of node => gateway
                mii,
                cluster_item_id)


class VCSNICServiceGroupUpdateHelper(VcsNICServiceGroupHelper):
    """
    Helper class for performing updates to VCS NIC service groups.

    The reason for this class being seperate to `VcsNICServiceGroupHelper`
    is because the tasks it returns are to be run in the node phase
    of all tasks returned. This is currently no possible with the
    current layout of the helper classes in `vcs_plugin.py`.
    """
    def validate_model(self, api):
        # pylint: disable=unused-argument
        return []

    def create_configuration(self, plugin_api_context, cluster):
        """
        Currently just checks for nics updated to a slave in a bond.
        This is support for changing an eth to a slave in a bond.
        """
        vcs_model = VCSModel(plugin_api_context)
        nic_groups = vcs_model.get_nic_groups(cluster, state=State.APPLIED())
        tasks = []
        removed_nics = defaultdict(list)
        if not cluster.is_for_removal():
            for interface, node in self.get_updated_slave_nics(cluster):
                # We need to remove the nics from the group first individually.
                task = self._create_remove_nic_task(cluster,
                                                    interface.device_name,
                                                    [node.hostname],
                                                    expect_faulted=True)
                tasks.append(task)

                removed_nics[interface.device_name].append(node)

            for nic, nodes in removed_nics.items():
                # Check if all nodes removed from group and remove node.
                hostnames = [node.hostname for node in nodes]
                group_nodes = nic_groups[nic].keys()
                if not set(group_nodes).difference(hostnames):
                    task = self._create_remove_nic_group_task(
                        cluster, nic, offline=False)
                    tasks.append(task)

            tasks.extend(self.get_network_host_update_tasks(plugin_api_context,
                                                            cluster))
        return tasks

    def get_networks_to_update_nwhosts(self, cluster):
        networks_to_update = set(
                [nwhost.network_name for nwhost in cluster.network_hosts
                    if nwhost.is_initial() or nwhost.is_for_removal()])
        return networks_to_update

    def _any_nic_with_indeterminable_props(self, cluster, nic_groups):
        # Return True if any interface is indeterminable, else False
        for node in cluster.nodes:
            for intf in node.network_interfaces:
                # Don't work on interfaces that are initial
                # or for-removal
                if (intf.is_initial() or intf.is_for_removal() or
                    node.hostname not in nic_groups[intf.device_name]):
                    continue
                if not intf.applied_properties_determinable:
                    return True
        return False

    def get_network_host_update_tasks(self, api, cluster):
        tasks = []
        updated_networks = self.get_networks_to_update_nwhosts(cluster)
        # Get the applied nic groups
        nic_groups = VCSModel(api).get_nic_groups(cluster,
                                            state=State.APPLIED_OR_UPDATED())

        # Updates are used for mii and network_host_ips. NetworkHost model
        # items can be associated with the task to keep their state but mii
        # comes from default_nic_monitor in the cluster which cannot be
        # associated with the tasks model_items because it would leave it
        # with indeterminable properties which could imply that the whole
        # cluster needs to be redeployed. So if any interface detected with
        # indeterminable properties, it should apply it to all interfaces
        # that need updating, to realign the mii attribute with the value
        # in the 'cluster'

        any_intf_indeterminable = self._any_nic_with_indeterminable_props(
                                      cluster, nic_groups)

        for node in cluster.nodes:
            if node.is_initial():
                continue
            for intf in node.network_interfaces:
                # Don't work on interfaces that are initial
                # or for-removal
                if (intf.is_initial() or intf.is_for_removal()):
                    continue

                # TORF-186827
                # If the interface does not have an IP and the IP
                # has not just been removed, we do not need a task
                # to reconfigure the NIC resource.
                if not hasattr(intf, 'ipaddress') or not intf.ipaddress:
                    if not intf.applied_properties.get('ipaddress'):
                        continue
                    else:
                        force_mii = True
                else:
                    force_mii = False

                # If "default_nic_monitor" is updated, we want only
                # the interface devices in the nic_groups
                if (property_updated(cluster, 'default_nic_monitor') or
                   any_intf_indeterminable):
                    if node.hostname not in nic_groups[intf.device_name]:
                        continue
                else:
                    if intf.network_name not in updated_networks:
                        continue
                resource = _get_nic_resource_name(cluster.item_id,
                                                  intf.device_name)
                network_host_ips = nic_groups[intf.device_name][node.hostname]
                if network_host_ips is None:
                    network_host_ips = []

                if force_mii or ((cluster.default_nic_monitor == 'mii' and
                        not network_host_ips)):
                    mii = "1"
                else:
                    mii = "0"
                task = CallbackTask(
                    intf,
                    'Reconfigure NIC resource "{0}" on node "{1}"'.format(
                        resource, node.hostname),
                    self.plugin().callback_method,
                    callback_class=self.__class__.__name__,
                    callback_func=self.update_network_hosts.__name__,
                    resource=resource,
                    addresses=sorted(network_host_ips),
                    mii=mii,
                    sys=node.hostname)
                task.model_items.update([nwhost for nwhost in
                    cluster.network_hosts.query("vcs-network-host",
                        network_name=intf.network_name)])
                tasks.append(task)
        return tasks

    def _get_nic_for_network(self, node, network):
        try:
            return node.query('network-interface', network_name=network)[0]
        except IndexError:
            return None

    def update_network_hosts(self, callback_api, resource, addresses,
            mii, sys):
        # pylint: disable=unused-argument
        """
        Update the `NetworkHosts` attribute of the VCS `resource` on node `sys`
        to the values specified in `addresses`.
        """
        self.nodes = [sys]
        with self.vcs_api.readable_conf():
            log.event.info(
            'Reconfiguring NIC Resource "%s" on node "%s"'
             % (resource, sys))
            #Need to ensure Mii is local as if this rpm is used in
            #upgrade scenario, Mii would be global, so this corrects it
            self.vcs_api.hares_local(resource, "Mii")
            # Just ensure NetworkHosts are set to local, as it has been seen
            # to switch to global for an unknown reason
            self.vcs_api.hares_local(resource, "NetworkHosts")

            res_value = " ".join(addresses)
            if not res_value:
                log.event.info(
                'Removing NetworkHosts attribute of NIC resource '
                '"%s" on node "%s" as no ip addresses assigned to it'
                % (resource, sys))
                self.vcs_api.hares_modify(resource, 'NetworkHosts', "-keys",
                                            delete=True, sys=sys)
            else:
                log.event.info(
                'Setting NetworkHosts attribute of NIC resource '
                '"%s" to value "%s" on node "%s"' % (resource, res_value, sys))
                self.vcs_api.hares_modify(resource, 'NetworkHosts', res_value,
                                            sys=sys)
            self.vcs_api.hares_modify(resource, "Mii", mii, sys=sys)

    def get_updated_slave_nics(self, cluster):
        """
        Return a list of tuple (interface, node)
        where each interface is a network interface with `is_updated()`
        returning `True` and having `master` property.
        """
        updated_slave_interfaces = []
        for node in cluster.nodes:
            for interface in node.network_interfaces:
                if self.nic_is_updated_to_slave(node.network_interfaces,
                                                interface):
                    updated_slave_interfaces.append((interface, node))
        return updated_slave_interfaces

    def nic_is_updated_to_slave(self, networks, network_interface):
        """
        Return `True` if `network_interface` is in an updated state
        and has a `master` property, and the value of the `master` property
        is different to the applied value of the `master` property.
        """
        master_value = getattr(network_interface, 'master', False)
        master_value_updated = False
        if master_value and network_interface.is_updated():
            if 'master' in network_interface.applied_properties:
                if network_interface.master != \
                    network_interface.applied_properties['master']:
                    master_value_updated = True
            else:
                bridge = network_interface.applied_properties.get('bridge')
                if bridge:
                    master = networks.query(master_value)
                    if master and master[0].bridge != bridge:
                        master_value_updated = True
                else:
                    master_value_updated = True
        return master_value_updated


def _get_nics_for_removal(cluster):
    return _get_removal_info(cluster)[0]


def _get_nic_groups_for_removal(cluster):
    return _get_removal_info(cluster)[1]


def _get_removal_info(cluster):

    nics_for_removal = defaultdict(set)
    nic_groups_to_keep = set()

    for node in cluster.nodes:
        hb_macs, _ = VCSModel._hb_networks_info_for_node(cluster, node,
                                                          inc_low_prio=False)
        for interface in node.network_interfaces:
            # Ignore interfaces assigned as heartbeart networks and
            # interfaces that are assigned to bridges.
            if interface.device_name not in hb_macs.keys() and \
                    not getattr(interface, "bridge", False) and \
                    not getattr(interface, "master", False):

                nic_group = interface.device_name

                # "applied_properties_determinable" if set to
                # to True, indicates that this item task
                # finished successfully, otherwise its False
                # Run_Plan
                #  - Any item tasks finished with failures:
                #    applied_properties_determinable = False
                #  - No item tasks finished with failures:
                #    applied_properties_determinable = True
                if (interface.is_for_removal() and
                        interface.applied_properties):
                    nics_for_removal[nic_group].add(node.hostname)
                else:
                    nic_groups_to_keep.add(nic_group)

    nic_groups_for_removal = set(nics_for_removal).difference(
        nic_groups_to_keep)

    for nic_group in nic_groups_for_removal:
        del nics_for_removal[nic_group]

    return (dict((k, list(v)) for k, v in nics_for_removal.items()),
            list(nic_groups_for_removal))


def _get_nic_resource_name(cluster_item_id, nic_key):
    '''
    Returns the NIC Service Group Name in the format:
    Grp_NIC_<cluster_item_id>_<interface_name>
    For example: Res_NIC_1234_eth0
    '''
    return condense_name("Res_NIC_{0}_{1}".format(cluster_item_id, nic_key))


def _get_nic_phantom_resource_name(cluster_item_id, nic_key):
    '''
    Returns the NIC Phantom Resource Name in the format:
    Res_Phantom_NIC_<cluster_item_id>_<interface_name>
    For example: Res_Phantom_NIC_1234_eth0
    '''
    return condense_name("Res_Phantom_NIC_{0}_{1}".format(
        cluster_item_id, nic_key))


def _add_nic_sg_resources(vcs_api, nic_service_group_name, nic_name,
                          node_gateways, mii, cluster_item_id):
    '''
    Method to call each of the VCS commands needed for the NIC Service Group
    '''
    nic_resource_name = _get_nic_resource_name(cluster_item_id, nic_name)
    nic_phantom_resource_name = _get_nic_phantom_resource_name(
        cluster_item_id, nic_name)

    # hares -add Res_NIC_1234_eth0 NIC Grp_NIC_1234_eth0
    vcs_api.hares_add(nic_resource_name, "NIC", nic_service_group_name)
    # hares -modify Res_NIC_1234_eth0 Critical 1
    vcs_api.hares_modify(nic_resource_name, "Critical", "1")

    # hares -modify Res_NIC_1234_eth0 Device eth0
    vcs_api.hares_modify(nic_resource_name, "Device", nic_name)

    vcs_api.hares_local(nic_resource_name, "Mii")
    # Set `NetworkHosts` to local so we can add multiple gateway values.
    vcs_api.hares_local(nic_resource_name, "NetworkHosts")

    # Only write to NetworkHosts if the gateway IP address is available
    for hostname, gateways in node_gateways.items():
        vcs_api.hares_modify(nic_resource_name, "Mii", mii, sys=hostname)
        # hares -modify Res_NIC_1234_eth0 NetworkHosts 10.10.10.150 sys=mn1
        if gateways is not None:
            gw_line = " ".join(gateways)
            vcs_api.hares_modify(
                        nic_resource_name,
                        'NetworkHosts',
                        gw_line,
                        sys=hostname)

    # hares -add Res_Phantom_NIC_1234_eth0 Phantom NicGrp_eth0
    vcs_api.hares_add(nic_phantom_resource_name, "Phantom",
                      nic_service_group_name)
    # hares -modify Res_Phantom_NIC_1234_eth0 Critical 1
    vcs_api.hares_modify(nic_phantom_resource_name, "Critical", "1")

    # Always enable NIC Resource after the Device has been added
    # hares -modify Res_NIC_1234_eth0 Enabled 1
    vcs_api.hares_modify(nic_resource_name, "Enabled", "1")
    # hares -modify Res_Phantom_NIC_1234_eth0 Enabled 1
    vcs_api.hares_modify(nic_phantom_resource_name, "Enabled", "1")


def get_applied_nic_groups(cluster):
    nics = set()
    for node in [node for node in cluster.nodes if not node.is_for_removal()]:
        for interface in node.network_interfaces:
            if interface.is_applied():
                nics.add(interface.device_name)

    return [VcsBaseHelper.get_nic_service_group_name(cluster.item_id, nic)
            for nic in nics]


def create_nic_resources(vcs_api, nic_service_group_name, nic_name,
                         node_gateways, mii, cluster_item_id):
    '''
    Callback function for the tasks
    :param callback_api: access to security and execution manager
    :type  callback_api: class
    '''

    log.event.info("Adding NIC resources for %s", nic_service_group_name)
    _add_nic_sg_resources(vcs_api,
                          nic_service_group_name,
                          nic_name,
                          node_gateways,
                          mii,
                          cluster_item_id)


def get_nic_items_for_device(cluster, device_name, hostnames=None):
    nics = dict()
    for node in cluster.nodes:
        if not hostnames or node.hostname in hostnames:
            for interface in node.network_interfaces:
                if interface.device_name == device_name:
                    nics[node.hostname] = interface
                    break
    return [nics[host] for host in sorted(nics)]
