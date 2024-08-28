##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import binascii

from litp.core.litp_logging import LitpLogger
from vcsplugin.vcs_cmd_api import VcsCmdApi
from vcsplugin.vcs_exceptions import VCSRuntimeException
from .vcs_utils import VcsUtils, is_os_reinstall_on_peer_nodes

log = LitpLogger()


class VcsBaseHelper(object):
    '''
    A Base class for common methods used by the VCS helpers
    '''

    def __init__(self, plugin):
        '''
        Constructor
        '''
        self.plugin = plugin
        self._vcs_api = None
        self.nodes = None

    def validate_model(self, api):
        # pylint: disable=unused-argument
        return []

    @property
    def vcs_api(self):
        if self.nodes is None:
            log.trace.error("Nodes have not been initialised")
            raise VCSRuntimeException("Nodes have not been initialised")
        if self._vcs_api is None:
            self._vcs_api = VcsCmdApi(node=self.nodes[0])
        return self._vcs_api

    @staticmethod
    def get_group_name(service_item_id, cluster_item_id):
        '''
        Return group name with format
        Grp_CS_<cluster_item_id>_<service_item_id>
        '''
        return condense_name("Grp_CS_{0}_{1}".format(
            cluster_item_id,
            service_item_id,
        ))

    @staticmethod
    def get_app_res_name(cluster_id, cs_id, svc_id):
        """
        Return resource app name with format
        Res_App_{cluster-item-id}_{clustered-service-item_id}_{service-item_id}
        """
        return condense_name("Res_App_{0}_{1}_{2}".\
                                 format(cluster_id, cs_id, svc_id))

    @staticmethod
    def get_nic_service_group_name(cluster_item_id, nic_key):
        '''
        Returns the NIC Service Group Name in the format:
        Grp_NIC_<cluster_item_id>_<interface_name>
        For example: Grp_NIC_1234_eth0
        '''
        return condense_name("Grp_NIC_{0}_{1}".format(
            cluster_item_id,
            nic_key
        ))

    @staticmethod
    def query_by_vpath(callback_api, vpath):
        '''Allows to ask the model through the api for items given a vpath.
        NOTE: Can be deleted once core provides this functionality'''
        return callback_api.query_by_vpath(vpath)

    @staticmethod
    def get_vx_fencing_disk_group_name(fencing_disks, cluster_id):
        '''
        Note: This same method must go into both vcs and vol manager plugins!
        If it needs to change, please analyse the method of the same name in
        the vol manager plugin.
        Method used to generate a unique "disk group name". It includes the
        cluster id.
        Veritas Disk Groups and Volumes names are limited to 31 characters
        '''
        if not fencing_disks:
            return
        disk_group_name = 'vxfencoorddg_' + str(cluster_id)

        return condense_name(disk_group_name, size=30)

    @staticmethod
    def services_not_for_removal(plugin_api_context, **properties):
        clusters = plugin_api_context.query("vcs-cluster", **properties)
        for cluster in clusters:
            for service in cluster.services:
                if not service.is_for_removal():
                    yield service

    @staticmethod
    def services_not_for_removal_from_cluster(cluster):
        for service in cluster.services:
            if not service.is_for_removal():
                yield service

    @staticmethod
    def sfha_clusters(plugin_api_context):
        return plugin_api_context.query('vcs-cluster', cluster_type='sfha')

    @staticmethod
    def is_cluster_expansion(cluster):
        """
        Method to return True if cluster expansion is to be preformed.
        """
        nodes_initial = [node.hostname for node in cluster.nodes
                         if node.is_initial()]
        non_initial_nodes = [node.hostname for node in cluster.nodes
                             if not node.is_initial()]

        if nodes_initial and non_initial_nodes:
            return True

        return False

    @staticmethod
    def added_node_hostnames(clustered_service):
        """
        This will hold a list of nodes hostnames, in order that is specified
        in service.node_list.
        """
        if clustered_service.is_updated():
            return VcsUtils().filter_node_hostnames(
                clustered_service.nodes,
                added_nodes_item_ids(clustered_service))
        return []

    @staticmethod
    def removed_node_hostnames(clustered_service):
        """
        This will hold a list of nodes hostnames, in order that is specified
        in service.node_list.
        """
        cluster = clustered_service.get_cluster()

        return VcsUtils().filter_node_hostnames(cluster.nodes,
            removed_nodes_item_ids(clustered_service))


def condense_name(name, size=60):
    '''
    A method to condense a string, but still keep the uniqueness of the string
    The method removes the last 10 characters of the string, and replaces it
    with the crc32 hex representation of the entire string.
    It is called to ensure all VCS group and resource names are 60 characters
    or less, to improve readability for the user.
    Note: This same method must go into both vcs and vol manager plugins!
    '''
    if len(name) > size - 1:
        name = name[:size - 10] + '_' + \
            hex(binascii.crc32(name) & 0xffffffff).lstrip('0x').rstrip('L')
        # . and - are unsupported characters in VCS naming
    return name.replace(".", "_").replace("-", "_")


def is_clustered_service_redeploy_required(service):
    """
    Returns True if the service was changed from failover to parallel or
    from parallel to failover or the service is to be migrated or has
    indeterminable applied properties, but not if the cluster is initial or
    the service is for removal or the service is part of a deactivation.
    Else returns False.
    """
    cluster = service.get_cluster()
    return ((is_failover_to_parallel(service) or
            does_service_need_to_be_migrated(service)) and
            not cluster.is_initial() and
            not service.is_for_removal() and
            not is_a_deactivation_service(cluster, service))


def get_applied_node_list(service):
    """
    Returns a list of the applied nodes for the given service.
    """
    if service.applied_properties.get('node_list'):
        return service.applied_properties['node_list'].split(",")
    else:
        return []


def get_applied_nodes_in_cluster(cluster):
    """
    Gets a list of applied nodes for that cluster
    """
    return [node for node in cluster.nodes
            if not node.is_for_removal() and not node.is_initial()]


def does_service_need_to_be_migrated(service):
    """
    Returns True if the node list is completely different
    to the applied node list for that service
    """
    applied_nodes = set(get_applied_node_list(service))
    nodes = set(service.node_list.split(','))
    if (not nodes.issubset(applied_nodes)
            and not nodes.issuperset(applied_nodes)
            and not is_node_intersection(service)):
        return True
    return False


def is_failover_standby_node_updated(cluster, service):
    """
    Returns True for a failover service if one node in the node_list
    is changed and the removed node is for_removal
    """
    if (is_failover_service_group(service)
        and service.is_updated()
        and property_updated(service, "node_list")):
        applied_nodes = set(get_applied_node_list(service))
        nodes = set(service.node_list.split(','))
        removed = applied_nodes.difference(nodes)
        retained = applied_nodes.intersection(nodes)
        if len(removed) == 1 and len(retained) == 1:
            retained_node = [node for node in cluster.nodes
                             if node.item_id in retained][0]
            if (not retained_node.is_for_removal() and
                not retained_node.is_initial()):
                return True
    return False


def is_node_list_changed(service):
    if not service.is_updated():
        return False
    applied_nodes = set(get_applied_node_list(service))
    nodes = set(service.node_list.split(','))
    if applied_nodes != nodes:
        return True
    return False


def is_node_intersection(service):
    if not same_list_different_order(service, 'node_list'):
        applied_nodes = set(get_applied_node_list(service))
        nodes = set(service.node_list.split(','))
        if nodes.intersection(applied_nodes):
            return True
    return False


def added_nodes_item_ids(clustered_service):

    nodes_item_ids = clustered_service.node_list.split(',')

    if (clustered_service.is_updated() and
            not is_clustered_service_redeploy_required(clustered_service)):
        applied_nodes = get_applied_node_list(clustered_service)
        added_nodes_item_id = list(set(nodes_item_ids) -
                                    set(applied_nodes))
    else:
        added_nodes_item_id = nodes_item_ids
    return added_nodes_item_id


def is_clustered_service_expansion(service):
    """
    It is cluster expansion if :
       - the node list intersects the applied
         node list for that service
       - The node list number has increased.
    But only for parallel services
    """
    if (not is_failover_service_group(service) and
        is_node_intersection(service)):
        return len(VcsBaseHelper.added_node_hostnames(service)) != 0
    else:
        return False


def removed_nodes_item_ids(clustered_service):
    nodes_item_ids = clustered_service.node_list.split(',')

    if clustered_service.is_updated():
        applied_nodes = get_applied_node_list(clustered_service)
        removed_nodes_item_id = list(set(applied_nodes) -
                                            set(nodes_item_ids))
    else:
        removed_nodes_item_id = []
    return removed_nodes_item_id


def is_clustered_service_contraction(service):
    """
    It is cluster contraction if :
       - the node list intersects the applied
         node list for that service
       - The node list number has decreased.
    But only for parallel services
    """
    if (not is_failover_service_group(service) and
        is_node_intersection(service)):
        return len(VcsBaseHelper.removed_node_hostnames(service)) != 0
    else:
        return False


def is_failover_to_parallel(service):
    """
    Returns True if the service was changed from failover to parallel or
    from parallel to failover. Else returns False.
    """
    cluster = service.get_cluster()
    if is_os_reinstall_on_peer_nodes(cluster) and service.applied_properties:
        return service.applied_properties['standby'] != service.standby
    return ((service.is_updated() and
            service.applied_properties['standby'] != service.standby))


def is_a_deactivation_service(cluster, service):
    """
    Return True if the service is either deactivating another service or is
    being deactivated by another service.
    """
    return (is_deactivating(cluster, service) or
            is_being_deactivated(cluster, service))


def is_being_deactivated(cluster, service):
    """
    Return True if a service is being deactivated by another service.
    Return False otherwise
    """
    if service.item_id in (srv.deactivates for srv in cluster.services
                           if srv.deactivates
                           and not srv.is_for_removal()):
        return True
    return False


def is_deactivating(cluster, service):
    """
    Return True if a service is deactivating another service that exists in
    the model.
    Return False otherwise
    """
    return service.deactivates in (srv.item_id for srv in cluster.services)


def get_updated_properties(properties, item):
    """
    Return a list of updated properties from an iterable of properties for
    the given item.
    """
    return [prop for prop in properties
            if item.applied_properties.get(prop) != getattr(item, prop)]


def is_clustered_service_node_count_updated(service):
    """
    Returns True if the service is in and updated state and any of
    the properties "standby" or "active" are changed.
    """
    props = ['standby', 'active']
    return (service.is_updated() and
            get_updated_properties(props, service))


def get_service_node_counts(service):
    """
    Returns a tuple containing the current and applied node counts of the
    given service.
    """
    node_count = len(service.node_list.split(','))
    applied_node_count = len(get_applied_node_list(service))
    return (node_count, applied_node_count)


def is_clustered_service_node_count_increased(service):
    """
    Returns true if the number of nodes in the service has been increased.
    Returns false otherwise.
    """
    node_count, applied_node_count = get_service_node_counts(service)
    return node_count > applied_node_count


def is_clustered_service_node_count_decreased(service):
    """
    Returns true if the number of nodes in the service has been reduced.
    Returns false otherwise.
    """
    node_count, applied_node_count = get_service_node_counts(service)
    return node_count < applied_node_count


def same_list_different_order(item, prop):
    """
    Compare the property with value in applied_properties, and test if the
    list items are the same.This function considers and empty string '' and
    None to be equivalent properties
    :param item: Item from the model
    :type item: ModelItem
    :param property: property name
    :type item: str
    :return: bool
    """
    value = getattr(item, prop)
    app_prop_value = item.applied_properties.get(prop)
    value = '' if not value else value
    app_prop_value = '' if not app_prop_value else app_prop_value
    return set(value.split(',')) == set(app_prop_value.split(','))


def property_updated(item, prop):
    """
    Compare the property with value in applied_properties. This function
        considers and empty string '' and None to be equivalent properties
    :param item: Item from the model
    :type item: ModelItem
    :param property: property name
    :type item: str
    :return: bool
    """
    value = getattr(item, prop)
    app_prop_value = item.applied_properties.get(prop)
    value = None if value == '' else value
    app_prop_value = None if app_prop_value == '' else app_prop_value
    return value != app_prop_value


def updated_properties(item):
    """
    Return a list with all the updated properties of an item
        All Views (callable) properties are skipped.
    :param item: Item from the model
    :type item: ModelItem
    :return: list
    """
    return [p for p, v in item.properties.iteritems()
                            if not callable(v) and property_updated(item, p)]


def is_failover_service_group(clustered_service):
    return (clustered_service.active == "1" and
            clustered_service.standby == "1")


def is_one_node_service_group(clustered_service):
    return (clustered_service.active == "1" and
            clustered_service.standby == "0")


def is_serv_grp_allowed_multi_apps(clustered_service):
    return (is_failover_service_group(clustered_service) or
            is_one_node_service_group(clustered_service))


def is_service_deactivation_pair(cs_list):
    """
    Return True if cs_list contains a pair of services where one is to
    deactivate the other.
    Otherwise return False.
    """
    if len(cs_list) == 2:
        if (cs_list[0].deactivates == cs_list[1].item_id or
            cs_list[1].deactivates == cs_list[0].item_id):
            return True
    return False


def is_vip_deactivation_pair(vip_list):
    """
    Return True if vip_list contains vips for a pair of services where one
    is to deactivate the other.
    Otherwise return False.
    """
    if len(vip_list) == 2:
        cs0 = vip_list[0].get_ancestor('vcs-clustered-service')
        cs1 = vip_list[1].get_ancestor('vcs-clustered-service')
        return is_service_deactivation_pair([cs0, cs1])
    return False


def get_service_application(service):
    """
    Returns the one and only application in `service.applications`.
    """
    return next(iter(service.applications))


def get_applied_or_updated(items):
    """
    Gets only items in Applied or Updated state
    """
    return [i for i in items if i.is_applied() or i.is_updated()]
