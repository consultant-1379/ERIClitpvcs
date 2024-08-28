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

from litp.core.litp_logging import LitpLogger
from vcsplugin.vcs_constants import MS_SAP_VALUES, NODE_SAP_VALUES

log = LitpLogger()


class State(object):
    '''
    Collection of classes representing ModelItem state.
    For use in _include_interface function
    '''
    class _State(object):
        pass

    class INITIAL(_State):
        """Respresents the Initial ModelItem state"""
        pass

    class APPLIED(_State):
        """Respresents the Applied ModelItem state"""
        pass

    class UPDATED(_State):
        """Respresents the Updated ModelItem state"""
        pass

    class REMOVAL(_State):
        """Respresents the ForRemoval ModelItem state"""
        pass

    class APPLIED_OR_UPDATED(APPLIED, UPDATED):
        """Respresents a union of the Applied and Updated ModelItem states"""
        pass


class VCSModel(object):

    def __init__(self, context_api):
        self.context_api = context_api
        self.__services__ = {}
        self.__node_tags__ = {}

    def _query(self, item_type_id, **properties):
        return self.context_api.query(item_type_id, **properties)

    def find_primary_node(self, cluster):
        for node in cluster.query("node"):
            if node.node_id == "1":
                return node
        return None

    def initial_clustered_services(self):
        ret = []
        cs_list = self._query("clustered-service")
        for cs in cs_list:
            if cs.is_initial():
                ret.append(cs)
        return ret

    def nodes_for_clustered_service(self, cs_name):
        services = self._query("clustered-service", name=cs_name)
        if not services:
            return None
        return services[0].nodes

    def packages_for_clustered_service(self, cs_name):
        services = self._query("clustered-service", name=cs_name)
        if not services:
            return None
        runtimes = services[0].runtimes
        for runtime in runtimes:
            return runtime.packages

    def get_nic_groups(self, cluster, state=State.INITIAL()):
        nic_groups = defaultdict(dict)
        net_hosts = cluster.network_hosts
        nodes = [node for node in cluster.nodes]
        for node in nodes:
            hb_macs, _ = self._hb_networks_info_for_node(
                cluster, node, inc_low_prio=False)
            hb = hb_macs.keys()
            for interface in node.network_interfaces:
                if _include_interface(interface, cluster, hb, state):
                    #if the interface is marked for removal no need to go down
                    #to get the gateway
                    if interface.is_for_removal():
                        gateway = None
                    else:
                        gateway = [
                            net_host.ip for net_host in net_hosts
                            if net_host.network_name == interface.network_name
                               and not net_host.is_for_removal()]
                        if not gateway:
                            gateway = None
                    nic_groups[interface.device_name][node.hostname] = gateway
        return nic_groups

    def _parent_node(self, qitem):
        while True:
            if qitem.get_vpath() == '/':
                return None
            if qitem.is_node():
                return qitem
            qparent_path = '/'.join(qitem.get_vpath().split('/')[:-1])
            qitem = self.context_api.query_by_vpath(qparent_path)

    @staticmethod
    def _is_node_server_type_rack(cluster, node):
        hb_nets = cluster.llt_nets.split(",")

        for net_iface in node.network_interfaces:
            for hb_net in hb_nets:
                if net_iface.network_name == hb_net.strip() and \
                    'vlan' == net_iface.item_type_id:
                    return True

    @staticmethod
    def _hb_networks_info_for_node(cluster, node, inc_low_prio=True,
                                   is_rack_node=False):
        hb_macs, hb_saps = dict(), dict()
        hb_nets = cluster.llt_nets.split(",")
        if inc_low_prio:
            hb_nets.append(cluster.low_prio_net)

        for net_iface in node.network_interfaces:
            for hb_net in hb_nets:
                if net_iface.network_name == hb_net.strip():
                    interface = net_iface.device_name
                    if is_rack_node and cluster.low_prio_net != hb_net:
                        hb_saps[interface] = NODE_SAP_VALUES[len(hb_saps)]
                    elif is_rack_node and cluster.low_prio_net == hb_net:
                        hb_saps[interface] = MS_SAP_VALUES[0]
                    else:
                        hb_macs[interface] = getattr(
                            net_iface, 'macaddress', None)

        return hb_macs, hb_saps

    @staticmethod
    def mgmt_network_info_for_node(cluster, node, is_rack_node=False):
        low_prio_macs, low_prio_saps = dict(), dict()
        low_prio_nets = [cluster.low_prio_net]

        for net_iface in node.network_interfaces:
            for low_net in low_prio_nets:
                if net_iface.network_name == low_net.strip():
                    interface = net_iface.device_name
                    if is_rack_node:
                        low_prio_saps[interface] = MS_SAP_VALUES[len(
                            low_prio_saps)]
                    else:
                        low_prio_macs[interface] = getattr(
                            net_iface, 'macaddress', None)
        return low_prio_macs, low_prio_saps


def _include_interface(interface, cluster, hb, state):
    '''
    Return boolean based on:
        interface doesn't have a bridge property, or its bridge property is
        not set. This is to ensure interfaces that are part of a bridge are not
        monitored by a nic service group
        interface doesn't have a master property, or its master property is
        not set. This is to ensure interfaces that are part of a bond are not
        monitored by a nic service group
       What the passed in state is
    '''
    return (not getattr(interface, "bridge", False) and
        not getattr(interface, "master", False) and
        (interface.device_name not in hb and
        (isinstance(state, State.INITIAL) and (interface.is_initial() or
         (cluster.is_initial() and not interface.is_for_removal())) or
         (isinstance(state, State.UPDATED) and interface.is_updated()) or
         (isinstance(state, State.REMOVAL) and interface.is_for_removal()) or
         (isinstance(state, State.APPLIED) and interface.is_applied()))))
