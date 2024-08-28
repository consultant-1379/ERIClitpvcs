"""
Contains functionality for validating and configuring VCS network resources.

Could presently do with some refactoring and refinement as we are mixing
some concerns.
"""
from itertools import chain, groupby, tee
from collections import (defaultdict, namedtuple)
from operator import attrgetter
import re

import netaddr
import json

from litp.core.execution_manager import (CallbackTask,
                                         CallbackExecutionException,
                                         PlanStoppedException)
from litp.core.validators import ValidationError
from litp.plan_types.deployment_plan import deployment_plan_tags

from .vcs_base_helper import (condense_name,
                              VcsBaseHelper,
                              is_clustered_service_node_count_increased,
                              is_clustered_service_node_count_updated,
                              is_clustered_service_redeploy_required,
                              get_applied_node_list,
                              does_service_need_to_be_migrated,
                              is_vip_deactivation_pair,
                              added_nodes_item_ids,
                              property_updated,
                              get_applied_or_updated,
                              get_service_application,
                              is_failover_service_group)

from vcsplugin.vcs_utils import (is_ipv4, is_ipv6,
                                 strip_prefixlen, ipv6_prefixlen,
                                 select_nodes_from_service,
                                 select_nodes_from_cluster,
                                 get_subnet_netmask)

from vcsplugin.vcs_exceptions import VCSRuntimeException
from vcsplugin.vcs_constants import (PLAN_STOPPED_MESSAGE,
                                     DEFAULT_IPV6_PREFIXLEN,
                                     NETWORKS_MODEL_PATH,
                                     NETWORK_ITEM_TYPE)


# Timeout for VIP update MCO call per VIP (seconds)
UPDATE_VIP_API_TIMEOUT_PER_VIP = 10

# Regex to parse resource names from `hares --list`.
HA_RES_LIST_REGEX = r'(^[a-zA-Z_0-9]+)'

# Resource name templates.
NIC_RESOURCE_NAME_TEMPLATE = "Res_NIC_{cluster_id}_{interface_name}"
NIC_PROXY_NAME_TEMPLATE = ("Res_NIC_Proxy_{cluster_id}_{service_id}"
                           "_{network_name}")

IP_RESOURCE_NAME_TEMPLATE_PREFIX = "Res_IP_{cluster_id}_{service_id}"

IP_RESOURCE_NAME_TEMPLATE = (IP_RESOURCE_NAME_TEMPLATE_PREFIX +
                             "_{application_id}_{network_name}_{counter}")

IP_RESOURCE_NAME_TEMPLATE_MULTI = (IP_RESOURCE_NAME_TEMPLATE_PREFIX +
                                   "_{network_name}_{counter}")

# Constants used as arguments to VCS calls.
IP_RESOURCE_TYPE = 'IP'
CRITICAL = 'Critical'
DEVICE = 'Device'
NETMASK = 'NetMask'
ADDRESS = 'Address'
PREFIXLEN = 'PrefixLen'
ENABLED = 'Enabled'
TARGET_RESOURCE = 'TargetResName'
PROXY = 'Proxy'
ONE = '1'
IPOPTIONS = 'IPOptions'

# Error Messages
ERR_NUM_NEW_IPS = ('The number of "{ip_type}" VIP items per node for network '
                   '"{network_name}" in vcs-clustered-service "{service_name}"'
                   ' must be the same after change of active property from '
                   '"{old_active}" to "{new_active}".')

VIP_UPDATE_EXECUTION_ERROR_MSG = (
                    "An error was found when trying to update a VIP for "
                    "within the network '{network}' on the cluster "
                    "'{cluster}'. Description: '{err_msg}'")


# Utility functions.
def chunks(sequence, size):
    """
    Split a sequence in chunks of size: `size`.
    """
    sequence = list(sequence)
    for i in xrange(0, len(sequence), size):
        yield sequence[i:i + size]


def service_group_name(cluster, service):
    """
    Get the service group name for the given `service` in `cluster`.
    """
    return VcsBaseHelper.get_group_name(service.item_id, cluster.item_id)


class VIPModel(object):
    """
    Contains helper functions for items related to vips.
    Provides an abstraction layer over the LITP model
    to provide a unified interface for both `lsb-runtime`
    and `service` item types.
    NOTE: Currently this class only handles new style services not
    lsb-runtime.
    """

    def __init__(self, model_api, vcs_api):
        self.model_api = model_api
        self.vcs_api = vcs_api
        self.query = self.model_api.query

    @property
    def networks(self):
        """
        Return all networks defined in the LITP model.
        """
        return self.query('network')

    @property
    def services(self):
        """
        Return all services defined in the litp model.
        """
        return [service for service in self.query('vcs-clustered-service')
                        if not service.is_for_removal()]

    @property
    def clusters(self):
        """
        Return all vcs clusters defined in the LITP model.
        """
        return self.query('vcs-cluster')

    @property
    def llt_names(self):
        """
        Return a tuple of all llt network names in the LITP model.
        """
        return tuple(chain.from_iterable(
            cluster.llt_nets.split(',')
            for cluster in self.clusters))

    def get_netmask(self, network_name):
        """
        Get the netmask for the network with `network_name`.
        """
        network = next(iter(self.query('network', name=network_name)), None)
        if network and network.subnet:
            return get_subnet_netmask(network.subnet)
        raise ValueError('Netmask not found for network "%s"' % network.name)

    def get_vips(self, cluster=None, service=None, network_name=None):
        """
        Return vips of a VCS cluster.
        If `cluster` is not `None` the vips will all be child
        elements of the given `cluster`.
        if `service` is not `None` vips will all be child elements
        of `service`.
        if `network_name` is not `None` vips will be from the network_name
        """
        def match_network_name(ipaddress):
            if ipaddress.network_name == network_name:
                return True
            else:
                return False

        if network_name is None:
            match_network_name = lambda x: True

        if cluster is None and service is None:
            services = self.query('vcs-clustered-service')
            for service in services:
                for ipaddress in service.ipaddresses:
                    if match_network_name(ipaddress):
                        yield ipaddress
        elif service is not None:
            for ipaddress in service.ipaddresses:
                if match_network_name(ipaddress):
                    yield ipaddress
        elif cluster is not None:
            for service in cluster.services:
                if not service.is_for_removal():
                    for ipaddress in service.ipaddresses:
                        if match_network_name(ipaddress):
                            yield ipaddress

    @property
    def legacy_vips(self):
        """
        Return all vips under lsb-runtime items.
        """
        for runtime in self.query('lsb-runtime'):
            for address in runtime.ipaddresses:
                yield address

    @property
    def existing_resources(self):
        """
        Return a list of all defined VCS resource names.
        """
        text = self.vcs_api.hares_list()
        return re.findall(HA_RES_LIST_REGEX, text, re.MULTILINE)

    def resource_exists(self, resource):
        """
        Return `True` if the given named resource exists otherwise `False`.
        """
        return resource in self.existing_resources

    def link_ip_to_proxy(self, ip_name, nic_proxy_name):
        """
        Link the ip resource with name `ip_name` to nic proxy resource with
        name `nic_proxy_name`.
        """
        self.vcs_api.hares_link(ip_name, nic_proxy_name)


class BaseResource(object):
    """
    Base class for resource objects.
    """
    def nics_for_network(self, nodes, include_removed=False):
        """
        Return a mapping of node_hostname -> nic where nic is a network
        interface name configured on the network with `network_name`.
        """
        return dict(
            # pylint: disable=E1101
            (node.hostname, self.nic_for_network(
                    node,
                    self.network,
                    include_removed=include_removed))
            # pylint: disable=E1101
            for node in nodes)

    def nic_for_network(self, node, network_name, include_removed=False):
        """
        Return the network interface name on `node` that is configured
        for `network_name`.

        NOTE: nodes have a limitation of one interface per network.
        """
        interface = next(
            iter(node.query('network-interface', network_name=network_name)),
            None)
        if interface:
            if include_removed or not interface.is_for_removal():
                return interface.device_name

    def create_resources(self, vcs_api):
        """
        Create the actual resource in the cluster.
        """
        raise NotImplementedError('Implement this method in subclasses.')


class IPResources(BaseResource):
    """
    Abstraction for an set of VIPs belonging to a network.
    """

    def __init__(self, ipaddresses, cluster, service, model, allvips=False):
        self.ipaddresses = []
        self.resource_index = 0
        if allvips == True or is_clustered_service_redeploy_required(service):
            # FO to PL
            self.ipaddresses = ipaddresses
        elif is_clustered_service_node_count_updated(service):
            # Expansion
            for ipaddress in ipaddresses:
                if ipaddress.is_initial():
                    self.ipaddresses.append(ipaddress)
        else:
            # New vips added
            applied_ips = []
            for ipaddress in ipaddresses:
                if ipaddress.is_initial():
                    self.ipaddresses.append(ipaddress)
                else:
                    applied_ips.append(ipaddress)
            self.resource_index = len(applied_ips) / int(service.active)

        self.cluster = cluster
        self.service = service
        self.model = model
        self.network = self.get_network(ipaddresses)

        if len(service.applications) > 1:
            self.name_template = IP_RESOURCE_NAME_TEMPLATE_MULTI
        else:
            self.name_template = IP_RESOURCE_NAME_TEMPLATE

    @classmethod
    def from_model_new(cls, cluster, service, model):
        """
        class method for instantiating all `IPResources` for the given
        `service` with new IPaddresses in a `cluster`.
        """
        # Sort IP's by network.
        networks = set(
            ipaddress.network_name
            for ipaddress in service.ipaddresses)
        for network in networks:
            ipaddresses = [
                ipaddress
                for ipaddress in service.ipaddresses
                if ipaddress.network_name == network]
            if ipaddresses:
                resource = cls(ipaddresses, cluster, service, model)
                if resource.ipaddresses:
                    yield resource

    @property
    def no_of_ips_per_node(self):
        """
        Returns the number of ips already defined on each node for the
        service.
        """
        ipaddresses = [
            ipaddress
            for ipaddress in self.service.ipaddresses
            if ipaddress.network_name == self.network]
        return len(ipaddresses) / int(self.service.active)

    def get_resource_name(self, counter):
        """
        Returns the resource name for a given IP position
        """
        return condense_name(self.name_template.format(
            cluster_id=self.cluster.item_id,
            service_id=self.service.item_id,
            application_id=self.application.item_id,
            network_name=self.network,
            counter=counter))

    def get_resource_names(self, start):
        """
        Return the resource names from a given position
        """
        names = []
        for i in xrange(start, self.no_of_ips_per_node + 1):
            names.append(self.get_resource_name(i))
        return names

    @property
    def resource_names(self):
        """
        Returns all the resource names for all the ips
        """
        return self.get_resource_names(start=1)

    @property
    def new_resource_names(self):
        """
        Returns the resource names for the new IP resources
        """
        return self.get_resource_names(self.resource_index + 1)

    @property
    def sorted_ips(self):
        """
        Returns a list of the ipaddresses belonging to `self.ipaddresses`
        with all ipv4 address preceeding ipv6 addresses.
        """
        ipv4 = [
            ip
            for ip in self.ipaddresses
            if is_ipv4(ip.ipaddress)]
        ipv6 = [
            ip
            for ip in self.ipaddresses
            if is_ipv6(ip.ipaddress)]
        return ipv4 + ipv6

    def create_resources(self, vcs_api):
        """
        Create the actual VCS IP resources. Delegates to `VcsCmdApi` for
        calling the actual VCS commands.
        """
        if is_clustered_service_node_count_updated(self.service):
            new_nodes_ids = added_nodes_item_ids(self.service)
            nodes = [node for node in self.service.nodes
                     if node.item_id in new_nodes_ids]
            no_of_nodes_added = len(nodes)
        else:
            nodes = self.service.nodes
            no_of_nodes_added = int(self.service.active)

        new_chunks = chunks(self.sorted_ips, no_of_nodes_added)
        for name, addresses in zip(self.new_resource_names, new_chunks):
            self.create_resource(vcs_api, name, addresses, nodes)

    def create_resource(self, vcs_api, resource_name, vips, nodes):
        """
        Create the resources for the given addresses.

        It would be 'nice to have' to split this down into separate named
        steps/methods.
        """

        ipaddresses = [address.ipaddress for address in vips]

        next_address = next(iter(ipaddresses), None)
        if next_address is None:
            return

        if is_ipv6(next_address):
            netmask = None
            prefixlen = ipv6_prefixlen(next_address)
        else:
            netmask = self.model.get_netmask(self.network)
            prefixlen = None

        group_name = service_group_name(self.cluster, self.service)

        if (self._initial_installation_failed(vips) and not
                is_clustered_service_node_count_updated(self.service)):
            vcs_api.hares_unlink_pattern(resource_name, "Res_App_.*")
            vcs_api.hares_delete(resource_name)
        vcs_api.hares_add(resource_name, IP_RESOURCE_TYPE, group_name)
        vcs_api.hares_modify(resource_name, CRITICAL, ONE)
        vcs_api.hares_local(resource_name, DEVICE)

        hostname_interfaces = self.nics_for_network(nodes)
        for hostname, interface in hostname_interfaces.items():
            vcs_api.hares_modify(
                resource_name, DEVICE, interface, hostname)

        if not self.parallel:
            if is_ipv6(next_address):
                next_address = strip_prefixlen(next_address)
            vcs_api.hares_modify(resource_name, ADDRESS, next_address)
            if is_ipv6(next_address):
                vcs_api.hares_modify(resource_name, IPOPTIONS, "nodad")
        else:
            vcs_api.hares_local(resource_name, ADDRESS)
            hostname_interfaces = sorted(hostname_interfaces.items())
            resource_ips = sorted(ipaddresses)
            for hostname, ip_addr in zip(
                    (hostname_interface[0] for hostname_interface in
                     hostname_interfaces),
                    resource_ips):
                if is_ipv6(ip_addr):
                    ip_addr = strip_prefixlen(ip_addr)
                vcs_api.hares_modify(
                    resource_name,
                    ADDRESS,
                    ip_addr,
                    hostname)

        if netmask:
            vcs_api.hares_modify(resource_name, NETMASK, netmask)
        elif prefixlen:
            vcs_api.hares_modify(resource_name, PREFIXLEN, prefixlen)

        vcs_api.hares_modify(resource_name, ENABLED, ONE)
        for hostname in dict(hostname_interfaces):
            if not self.model.model_api.is_running():
                raise PlanStoppedException(PLAN_STOPPED_MESSAGE)
            vcs_api.hares_probe(resource_name, hostname)

    def update_resource_device_new_node(self, vcs_api, node):
        """
        Updates the Device property of an IP resource with a new hostname
        when a new node has been added to the group
        """
        hostname_interfaces = self.nics_for_network([node],
                                                    include_removed=True)
        for hostname, interface in hostname_interfaces.items():
            for resource_name in self.resource_names:
                vcs_api.hares_modify(
                    resource_name, DEVICE, interface, hostname)

    @staticmethod
    def _initial_installation_failed(addresses):
        return any(address for address in addresses
                   if address.is_initial() and
                   not address.applied_properties_determinable)

    @property
    def parallel(self):
        """
        Return `True` if `self.service` is a parallel service group.
        """
        return int(self.service.standby) == 0

    def nic_proxy(self):
        """
        Returns a `NICProxy` object for the network `self.addresses`
        belong to.
        """
        return NICProxyResource(self.network, self.cluster,
                                self.service, self.model)

    def get_network(self, ipaddresses):
        """
        Returns the network `ipaddresses` belong to.
        All the ips must be in the same network
        """
        return next(iter(ipaddresses)).network_name

    @property
    def application(self):
        """
        Returns the one and only application in `self.service.applications`.
        """
        return get_service_application(self.service)


class NICProxyResource(BaseResource):
    """
    Abstraction of a NIC proxy resource for a network.
    """
    name_template = NIC_PROXY_NAME_TEMPLATE
    target_name_template = NIC_RESOURCE_NAME_TEMPLATE

    def __init__(self, network, cluster, service, model):
        self.network = network
        self.cluster = cluster
        self.service = service
        self.model = model

    def create_resources(self, vcs_api):
        """
        Creates the NIC proxy resource.

        This could also do with being split down to more bite sized chunks.
        """
        nic_proxy_name = self.name
        group_name = service_group_name(self.cluster, self.service)
        hostname_interfaces = self.nics_for_network(self.service.nodes)

        vcs_api.hares_add(self.name, PROXY, group_name)
        vcs_api.hares_modify(nic_proxy_name, CRITICAL, ONE)
        vcs_api.hares_local(nic_proxy_name, TARGET_RESOURCE)

        for hostname, interface in hostname_interfaces.items():
            target_resource_name = self.target_resource_name(interface)
            if not self.model.resource_exists(target_resource_name):
                err_msg = (
                    'The TargetResName "{0}" for the NIC Proxy '
                    '"{1}" does not exist. The NIC resource required has '
                    'not been set up.'.format(target_resource_name,
                                              nic_proxy_name))
                raise VCSRuntimeException(err_msg)

            vcs_api.hares_modify(
                nic_proxy_name,
                TARGET_RESOURCE,
                target_resource_name,
                hostname)

        vcs_api.hares_modify(nic_proxy_name, ENABLED, ONE)

    def update_target_res_new_node(self, vcs_api, node):
        """
        Updates the TargetResName property of a NIC proxy resource with a
        new hostname when a new node has been added to the group
        """
        nic_proxy_name = self.name
        hostname_interfaces = self.nics_for_network([node])

        for hostname, interface in hostname_interfaces.items():
            target_resource_name = self.target_resource_name(interface)
            if not self.model.resource_exists(target_resource_name):
                err_msg = (
                    'The TargetResName "{0}" for the NIC Proxy '
                    '"{1}" does not exist. The NIC resource required has '
                    'not been set up.'.format(target_resource_name,
                                              nic_proxy_name))
                raise VCSRuntimeException(err_msg)
            vcs_api.hares_modify(
                nic_proxy_name,
                TARGET_RESOURCE,
                target_resource_name,
                hostname)

    def link_to_ip_resource(self, ip_resource_name):
        """
        Links this NIC proxy to the ip resource with name `ip_resource_name`.
        """
        self.model.link_ip_to_proxy(ip_resource_name, self.name)

    def target_resource_name(self, interface):
        """
        Return the nic resource target for this nic proxy.
        """
        return condense_name(self.target_name_template.format(
            cluster_id=self.cluster.item_id,
            interface_name=interface))

    @property
    def name(self):
        """
        Returns the properly formatted name for this nic proxy.
        """
        return condense_name(self.name_template.format(
            cluster_id=self.cluster.item_id,
            service_id=self.service.item_id,
            network_name=self.network))


class NetworkResourceHelper(VcsBaseHelper):
    """
    The entry point for LITP to vip related functionality.
    """

    def validate_model(self, model_api):
        """
        The entry point for LITP to call the validation logic.
        """
        model = VIPModel(model_api, None)
        validators = (
            self._validate_application,
            self._validate_vips_on_llt_network,
            self._validate_well_formed_vips,
            self._validate_cluster_nics_configured,
            self._validate_networks_defined,
            self._validate_vip_subnets_defined,
            self._validate_subnet_contains_vips,
            self._validate_correct_amount_vips,
            self._validate_duplicate_vip_ipaddress,
            self._validate_num_of_new_ips_per_ip_resource,
            self._validate_vips_on_interfaces_in_initial,
            self._validate_network_subnets_ipv6_overlap,
            self._validate_duplicate_vip_on_interfaces,
            self._validate_ipv6_vips_network_consistency,
            self._validate_swapped_vips
        )

        errors = []
        for validator in validators:
            errors.extend(validator(model))
        return errors

    def _validate_vips_on_interfaces_in_initial(self, model):
        """
        Validate that each vip in an initial state on the service is
        not an interface that is in an initial state if the service
        is not being expanded. If VIPs are added during service node_list
        expansion, they are added post node lock, if VIPs are added
        to a service with stable node_list they are added pre node lock.
        """
        not_initial_services = [service for service in model.services
                                if not service.is_initial()]
        for service in not_initial_services:
            vips = model.get_vips(service=service)
            initial_vips = [vip for vip in vips if vip.is_initial()]

            expansion = is_clustered_service_node_count_increased(service)
            if expansion:
                added_nodes = self.added_node_hostnames(service)
            else:
                added_nodes = []
            for vip in initial_vips:
                for node in service.nodes:
                    if (not node.is_initial() and
                        not node.hostname in added_nodes):
                        interfaces = node.query('network-interface',
                                                network_name=vip.network_name)
                        if interfaces and interfaces[0].is_initial():
                            yield ValidationError(
                                item_path=vip.get_vpath(),
                                error_message='A "vip" cannot'
                                              ' be added to device "{0}"'
                                              ' on node "{1}"'
                                              ' as the network-interface'
                                              ' is in initial state'
                                              .format(interfaces[0]
                                                      .device_name,
                                                      node.hostname)
                                )

    def _validate_well_formed_vips(self, model):
        """
        Validate that all vips in the model contain a valid ipaddress.
        """
        for vip in model.get_vips():
            if not self.has_well_formed_ipaddress(vip):
                yield ValidationError(
                    item_path=vip.get_vpath(),
                    error_message='IP address is not well formed.')

    def _validate_application(self, model):
        """
        Validate that an application exists for each servive that contains
        vips.
        """
        for service in model.services:
            if len(service.ipaddresses) and not len(service.applications):
                yield ValidationError(
                    item_path=next(iter(service.ipaddresses)).get_vpath(),
                    error_message='An application must be defined under "%s" '
                                  'to use a vip' % service.name)

    def _validate_cluster_nics_configured(self, model):
        """
        Ensure each node in each cluster has a nic associated with the network
        for each vip.
        """
        not_conf_networks = defaultdict(set)
        for cluster in model.clusters:
            for service in cluster.services:
                if service.is_for_removal():
                    continue
                for node in service.nodes:
                    for vip in model.get_vips(service=service):
                        if not self.node_configured_for_vip(node, vip):
                            not_conf_networks[vip.network_name].add(node)
        for network, nodes in not_conf_networks.iteritems():
            for node in nodes:
                yield ValidationError(
                    item_path=node.get_vpath(),
                    error_message=(
                        'Network interface must be configured for '
                        'network "{0}" on node "{1}"'.format(network,
                                                             node.hostname)))

    def _validate_networks_defined(self, model):
        """
        Ensure that a the network attached to each vip in the LITP model
        has a correspinding network item created.
        """
        for vip in model.get_vips():
            if not self.has_network_defined(vip, model.networks):
                yield ValidationError(
                    item_path=vip.get_vpath(),
                    error_message=(
                        'A network must be defined for IP "{0}"'.format(
                            vip.network_name)))

    def _validate_vip_subnets_defined(self, model):
        """
        Ensure that each network a vip is belongs too has a subnet defined.
        """
        for vip in model.get_vips():
            network = self.network_for_vip(vip, model.networks)
            # Caught by `networks_defined`.
            if network is None:
                continue
            # Subnet only required for ipv4 addresses.
            if not self.network_has_subnet(network) and is_ipv4(vip.ipaddress):
                yield ValidationError(
                    item_path=vip.get_vpath(),
                    error_message='No subnet defined for network "{0}"'.format(
                        vip.network_name))

    def _validate_subnet_contains_vips(self, model):
        """
        Ensure that each vip is contained in the subnet of its network.
        """
        for vip in model.get_vips():
            # We don't check subnets for ipv6.
            if is_ipv6(vip.ipaddress):
                continue
            network = self.network_for_vip(vip, model.networks)
            # Will be caught by network validation.
            if network is None:
                continue
            # Will be caught be subnet validation.
            if network.subnet is None:
                continue
            if not self.vip_in_subnet(vip, network.subnet):
                yield ValidationError(
                    item_path=vip.get_vpath(),
                    error_message=(
                        'VIP "{0}" must be contained in the subnet of network'
                        ' "{1}" - "{2}".'.format(vip.ipaddress,
                                                 vip.network_name,
                                                 network.subnet)))

    def _validate_correct_amount_vips(self, model):
        """
        Validate for each service in the model the number of vips is a multiple
        of the count of the active nodes.
        """
        msg = ('The number of "{ip_type}" VIP items for network '
               '"{network_name}" must be a multiple of active property '
               'of vcs-clustered-service "{service_name}".'
               )
        for service in model.services:
            vips = list(model.get_vips(service=service))
            for network, network_vips in groupby(
                    sorted(vips, key=attrgetter('network_name')),
                    attrgetter('network_name')):
                vip_iter1, vip_iter2 = tee(network_vips)
                for ip_typ, chk_fn, vip_iter in [("IPv4", is_ipv4, vip_iter1),
                                                 ("IPv6", is_ipv6, vip_iter2)]:
                    if not self.has_correct_amount_vips(
                        vip_iter, int(service.active), chk_fn):
                        yield ValidationError(
                            item_path=service.get_vpath(),
                            error_message=(
                                msg.format(
                                network_name=network,
                                service_name=service.name,
                                ip_type=ip_typ)))

    def _validate_duplicate_vip_ipaddress(self, model):
        """
        Validate that each vip in the model contains a unique ipaddress.
        Includes legacy vips, cross validation.
        Excludes vips for services that are for deactivation or that have been
        deactiveted.
        """
        vips = list(model.get_vips()) + list(model.legacy_vips)

        for duplicate in self.get_duplicate_vips(vips):
            yield ValidationError(
                item_path=duplicate.get_vpath(),
                error_message='IP address "{0}" can only be used once in '
                              'deployment.'.format(duplicate.ipaddress))

    def _validate_vips_on_llt_network(self, model):
        """
        Validate that no vips or a member of an LLT network.
        """
        for vip in model.get_vips():
            if self.vip_on_llt_network(vip, model.llt_names):
                yield ValidationError(
                    item_path=vip.get_vpath(),
                    error_message='Can not create VIP on llt network')

    def _validate_num_of_new_ips_per_ip_resource(self, model):
        """
        Validate that if the active count changes, the number of vips
        per node for each network remains the same. If additional vips
        are added when the active count is changed, then a validation
        error occurs.
        """
        networks = model.query('network', is_removed=False)
        for service in model.services:
            active = int(service.active)
            try:
                applied_active = int(service.applied_properties["active"])
            except KeyError:
                continue
            if active == applied_active:
                continue
            for network in networks:
                vips = list(model.get_vips(service=service,
                                          network_name=network.name))
                applied_vips = [vip for vip in vips if vip.is_applied()]
                # We've had a partial run, this network applied successfully
                if (not service.applied_properties_determinable and
                        applied_vips == vips):
                    continue
                for ip_typ, chk_method in [("IPv4", is_ipv4),
                                           ("IPv6", is_ipv6)]:
                    vx_vips = [vip for vip in vips
                               if chk_method(vip.ipaddress)]
                    applied_vx_vips = [vip for vip in applied_vips
                                       if chk_method(vip.ipaddress)]
                    if (len(vx_vips) * applied_active !=
                            len(applied_vx_vips) * active):
                        yield ValidationError(item_path=service.get_vpath(),
                                        error_message=ERR_NUM_NEW_IPS.format(
                                                     network_name=network.name,
                                                     service_name=service.name,
                                                     ip_type=ip_typ,
                                                     old_active=applied_active,
                                                     new_active=active))

    def _network_from_ipv6(self, ipv6address):
        """
        Returns a netaddr.IPNetwork object instantiated from a
        network-interface model item's ipv6address property. If the prefix is
        absent from the property value, it defaults to /64
        """
        if '/' in ipv6address:
            return netaddr.IPNetwork(ipv6address)
        return netaddr.IPNetwork(ipv6address + '/' + DEFAULT_IPV6_PREFIXLEN)

    def _validate_network_subnets_ipv6_overlap(self, model):

        subnets_pre_node = defaultdict(list)
        for service in model.services:
            for node in service.nodes:
                for vip in service.ipaddresses:
                    if is_ipv6(vip.ipaddress):
                        net6 = self._network_from_ipv6(vip.ipaddress)
                        subnets_pre_node[node.hostname].append((net6, vip))
                for iface in node.network_interfaces:
                    if iface.ipv6address:
                        net6 = self._network_from_ipv6(iface.ipv6address)
                        subnets_pre_node[node.hostname].append((net6, iface))

        errors = []
        for node, ipv6addresses in subnets_pre_node.iteritems():
            errors.extend(self._compare_subnets(ipv6addresses, node))
        return errors

    def _compare_subnets(self, subnets, node):
        errors = []

        unique_error_subnet_vpaths = set()
        vpath_ipv6s_on_nodes = set()
        for i, (left_sub, left_item) in enumerate(subnets):
            for (right_sub, right_item) in subnets[i + 1:len(subnets)]:
                if left_item.network_name == right_item.network_name:
                    continue

                if left_item.get_node() and right_item.get_node():
                    vpath_ipv6s_on_nodes.add(left_item.get_vpath())
                    vpath_ipv6s_on_nodes.add(right_item.get_vpath())

                if left_sub.first <= right_sub.last \
                        and right_sub.first <= left_sub.last:
                    unique_error_subnet_vpaths.add(left_item.get_vpath())
                    unique_error_subnet_vpaths.add(right_item.get_vpath())

        msg = ('Overlapping network subnet defined on node "%s"' % node)
        for path in unique_error_subnet_vpaths:
            # Ignore overlapping error on nodes, raised by network plugin
            if path not in vpath_ipv6s_on_nodes:
                errors.append(ValidationError(item_path=path,
                                              error_message=msg))

        return errors

    def _validate_duplicate_vip_on_interfaces(self, model):
        """
        Validate that the vip in the model doesn't collide with
        the IP on node network interfaces.
        """
        for cluster in model.clusters:
            services = [service for service in cluster.services
                        if not service.is_for_removal()]
            for service in services:
                vips = model.get_vips(service=service)
                ipaddresses = [self._get_vip_properties(vip) for vip in vips]
                for node in service.nodes:
                    interfaces = node.query('network-interface',
                                            is_for_removal=False)
                    for intf in interfaces:
                        for ip in ipaddresses:
                            if ip['network_name'] != intf.network_name:
                                continue
                            if ip['ip'] in self._get_ips_from_interface(intf):
                                yield ValidationError(
                                    item_path=ip['vpath'],
                                    error_message='The IP address "{0}" '
                                                  'is already used by '
                                                  'interface "{1}" on the '
                                                  'network "{2}" on'
                                                  ' the node "{3}".'
                                                  .format(ip['vipaddress'],
                                                          intf.vpath,
                                                          intf.network_name,
                                                          node.hostname))

    def _validate_ipv6_vips_network_consistency(self, model):
        """
        Validate that all IPv6 VIPs within the same network
        have the same prefix.
        """
        def get_vips_by_network():
            netinfo_map = defaultdict(lambda: defaultdict(list))
            for cluster in get_applied_or_updated(model.clusters):
                for service in get_applied_or_updated(cluster.services):
                    for vip in service.ipaddresses:
                        if is_ipv4(vip.ipaddress):
                            continue
                        prefix = ipv6_prefixlen(vip.ipaddress)
                        netinfo_map[vip.network_name][prefix].append(
                                                            vip.get_vpath())
            return netinfo_map

        for network_name, vips_by_netinfo in get_vips_by_network().iteritems():
            if len(vips_by_netinfo) > 1:
                network = model.query('network', name=network_name)[0]
                for prefix, vips in vips_by_netinfo.iteritems():
                    yield ValidationError(
                        item_path=network.get_vpath(),
                        error_message='Network "{0}" has multiple '
                                      'IPv6 PrefixLen defined on VIPs. '
                                      'For PrefixLen "{1}" found the VIPs: '
                                      '"{2}"'.format(network_name,
                                                     prefix,
                                                     str(vips)))

    def _validate_swapped_vips(self, model):
        """
        Validate against VIPs being swapped within the same
        Service Group.
        """
        def get_vips_with_new_ipaddress(service):
            return (vip for vip in service.ipaddresses
                        if vip.is_initial() or
                           (vip.applied_properties_determinable and
                            vip.is_updated() and
                            property_updated(vip, "ipaddress")))

        def map_old_ipaddress_to_vip(service):
            return dict((vip.applied_properties["ipaddress"], vip)
                        for vip in get_applied_or_updated(service.ipaddresses)
                        if vip.applied_properties.get("ipaddress"))

        for cluster in get_applied_or_updated(model.clusters):
            for service in get_applied_or_updated(cluster.services):
                old_ipaddress_to_vip = map_old_ipaddress_to_vip(service)
                for vip in get_vips_with_new_ipaddress(service):
                    old_vip = old_ipaddress_to_vip.get(vip.ipaddress)
                    if old_vip:
                        yield ValidationError(
                            item_path=vip.get_vpath(),
                            error_message='Swap of VIP addresses '
                                          'within the same service '
                                          'is not allowed. '
                                          'VIP "{0}" ipaddress "{1}" '
                                          'was used by VIP "{2}".'
                                              .format(vip.get_vpath(),
                                                      vip.ipaddress,
                                                      old_vip.get_vpath()))

    def _get_ips_from_interface(self, interface):
        ips = []
        if interface.ipaddress:
            ips.append(netaddr.IPAddress(interface.ipaddress))
        if interface.ipv6address:
            ipaddress = strip_prefixlen(interface.ipv6address)
            ips.append(netaddr.IPAddress(ipaddress))
        return ips

    def _get_vip_properties(self, vip):
        properties = {}
        properties['ip'] = self.ip_obj_from_vip(vip)
        properties['network_name'] = vip.network_name
        properties['vipaddress'] = vip.ipaddress
        properties['vpath'] = vip.get_vpath()
        return properties

    # Business logic methods for validation.
    def has_well_formed_ipaddress(self, vip):
        """
        Return `True` if the ipaddress associated with `vip` is a valid ipv4
        or ipv6 ipaddress otherwise `False`.
        """
        try:
            return is_ipv4(vip.ipaddress) or is_ipv6(vip.ipaddress)
        except netaddr.AddrFormatError:
            return False

    def ip_obj_from_vip(self, vip):
        """
        Return a `nettaddr.IPAddress` object for the address associated with
        `vip`.
        """
        if is_ipv6(vip.ipaddress):
            address = strip_prefixlen(vip.ipaddress)
        else:
            address = vip.ipaddress
        return netaddr.IPAddress(address)

    def node_configured_for_vip(self, node, vip):
        """
        Return `True` if `node` contains and inteface configured for the same
        network as `vip` otherwise `False`.
        """
        return any(
            vip.network_name == interface.network_name
            for interface in node.network_interfaces)

    def has_network_defined(self, vip, networks):
        """
        Return `True` if a network is defined for the network of `vip`
        otherwise `False`.
        """
        return any(
            vip.network_name == network.name
            for network in networks)

    def network_for_vip(self, vip, networks):
        """
        Return the network item this `vip` is associated with or `None`
        if none exists.
        """
        return next((
            network
            for network in networks
            if vip.network_name == network.name), None)

    def network_has_subnet(self, network):
        """
        Return `True` if `network` has a subnet defined otherwise `False`.
        """
        return bool(network.subnet)

    def vip_in_subnet(self, vip, subnet):
        """
        Return `True` if `ipaddress` is in `subnet` otherwise `False`.
        """
        return self.ip_obj_from_vip(vip) in netaddr.IPNetwork(subnet)

    def has_correct_amount_vips(self, vips, active, chk_method):
        """
        Return `True` if there is a vip for each active node in `service`
        otherwise `False`.
        """
        vx_vips = [vip for vip in vips if chk_method(vip.ipaddress)]
        return len(vx_vips) % active == 0

    def vip_on_llt_network(self, vip, llt_names):
        """
        Return `True` if `vip` belongs to an llt network otherwise `False`.
        """
        return vip.network_name in llt_names

    def get_duplicate_vips(self, vips):
        """
        Return any members of `vips` which have duplicate ipaddresses.
        """
        seen = {}
        duplicates = set()
        for vip in vips:
            if (vip.ipaddress in seen and
                  not is_vip_deactivation_pair([vip, seen[vip.ipaddress]])):
                duplicates.add(vip)
                duplicates.add(seen[vip.ipaddress])
            seen[vip.ipaddress] = vip
        return duplicates

    def create_configuration(self, model_api, cluster, service):
        """
        The entry point for LITP to request tasks related to VIPS.
        """
        model = VIPModel(model_api, None)
        self.nodes = [node.hostname for node in service.nodes]
        pre_node_tasks = []
        post_node_tasks = []
        if (service.ipaddresses.has_initial_dependencies() or
            is_clustered_service_redeploy_required(service)):
            networks = set(
                ipaddress.network_name
                for ipaddress in service.ipaddresses)
            for network in networks:
                vips_for_task = [vip for vip in
                                    model.get_vips(service=service,
                                               network_name=network)
                                    if self.vip_requires_task(vip, service)]

                if not vips_for_task:
                    continue
                # Sort vips by item_id to allow for consistency
                vips_for_task.sort(key=lambda item: item.item_id)
                task = CallbackTask(
                    vips_for_task[0],
                    self.task_description(cluster, service, network),
                    self.plugin().callback_method,
                    callback_class='NetworkResourceHelper',
                    callback_func='vip_callback',
                    service_vpath=service.get_vpath(),
                    cluster_vpath=cluster.get_vpath(),
                    network_name=network)
                if (not service.is_initial() and
                        not is_clustered_service_node_count_updated(service) \
                        and not does_service_need_to_be_migrated(service)):
                    # Scenario is adding new vips to a cluster service, vips
                    # will be added before node lock. Check AT
                    # testset_story5173/
                    # test_04_p_add_vips_sg_with_lock_unlock.at
                    task.tag_name = deployment_plan_tags.PRE_NODE_CLUSTER_TAG
                    pre_node_tasks.append(task)
                else:
                    post_node_tasks.append(task)

                # Add remaining vips as dependencies
                task.model_items.update(set(vips_for_task[1:]))

        return pre_node_tasks, post_node_tasks

    def task_description(self, cluster, service, network):
        """
        Return the task description.
        """
        return (
            'Create IP resources for VCS service group "{group_name}" '
            'for network "{network}"'.format(
                group_name=service_group_name(cluster, service),
                network=network))

    def vip_requires_task(self, vip, service):
        """
        Determines if a task needs to be generated for a VIP item
        """
        return (vip.is_initial() or
            is_clustered_service_redeploy_required(service))

    def vip_callback(self, api, service_vpath, cluster_vpath, network_name):
        """
        The callback method which gets called by core.
        Delegates to the VIPDeployment class to create the
        actual resources.

        It is this method responsibility to open and close the
        VCS config file for writing.
        """
        service = self.query_by_vpath(api, service_vpath)
        cluster = self.query_by_vpath(api, cluster_vpath)
        # The fact we have to do this disturbs me, it is a recipe for bugs
        # and took me a while to figure out I had to set this attribute.
        self.nodes = select_nodes_from_service(service)
        model = VIPModel(api, self.vcs_api)

        ip_resources = next(
            ip_resources
            for ip_resources in IPResources.from_model_new(cluster, service,
                                                           model)
            if ip_resources.network == network_name)

        with self.vcs_api.readable_conf():
            ip_resources.create_resources(self.vcs_api)
            nic_proxy = ip_resources.nic_proxy()
            nic_proxy.create_resources(self.vcs_api)
            for name in ip_resources.new_resource_names:
                nic_proxy.link_to_ip_resource(name)

    def get_vip_network_item(self, model_api, vip):
        inf = model_api.query_by_vpath(NETWORKS_MODEL_PATH)
        for network in inf.query(NETWORK_ITEM_TYPE):
            if network.name == vip.network_name:
                return network

    def vip_ipaddress_requires_task(self, vip):
        return vip.is_updated() or not vip.applied_properties_determinable

    def vip_network_subnet_requires_task(self, vip, network):
        return ((vip.is_applied() and is_ipv4(vip.ipaddress)) and
                ((network.is_updated() and
                  property_updated(network, "subnet")) or
                  not network.applied_properties_determinable))

    def build_data_element(self, vip):
        old_ipaddress = strip_prefixlen(vip.applied_properties["ipaddress"])
        new_ipaddress = strip_prefixlen(vip.ipaddress)
        return (old_ipaddress, new_ipaddress)

    def update_vip_callback(self, model_api, cluster_vpath, network_vpath):
        """
        Create a Structure (dictonary) with all the parameters
        necessary to change the IP Resources.
        It is converted to JSON, so to be sent structurally to
        the API counterpart.
        """
        cluster = model_api.query_by_vpath(cluster_vpath)
        network = model_api.query_by_vpath(network_vpath)

        data = {"NetMask": get_subnet_netmask(network.subnet),
                "PrefixLen": None,
                "Data": defaultdict(lambda: {"Parallel": None,
                                             "VIPs": []})}
        num_vips = 0
        for service in get_applied_or_updated(cluster.services):
            is_parallel = not is_failover_service_group(service)
            for vip in get_applied_or_updated(service.ipaddresses):
                if (network != self.get_vip_network_item(model_api, vip) or
                    not any([
                        self.vip_network_subnet_requires_task(vip, network),
                        self.vip_ipaddress_requires_task(vip)])):
                    continue

                if  data["PrefixLen"] is None and is_ipv6(vip.ipaddress):
                    data["PrefixLen"] = ipv6_prefixlen(vip.ipaddress)

                element = self.build_data_element(vip)
                if element:
                    service_name = service.item_id
                    data["Data"][str(service_name)]["Parallel"] = is_parallel
                    data["Data"][str(service_name)]["VIPs"].append(element)
                    num_vips += 1

        if not self.nodes:
            self.nodes = select_nodes_from_cluster(cluster)

        with self.vcs_api.readable_conf():
            data_json = json.dumps(data, separators=(',', ':'))
            timeout = UPDATE_VIP_API_TIMEOUT_PER_VIP * num_vips
            retcode, _, err_msg = \
                            self.vcs_api.update_ip_resource(data_json, timeout)

        if int(retcode) > 0:
            raise CallbackExecutionException(
                            VIP_UPDATE_EXECUTION_ERROR_MSG.format(
                                                    cluster=cluster.item_id,
                                                    network=network.name,
                                                    err_msg=err_msg))

    def generate_vip_update_task(self, cluster, network, to_update):
        """
        Generate the Callback Task
        """
        title = "Update VIPs within Network '{0}'".format(network.name)
        task = CallbackTask(to_update[0],
                            title,
                            self.plugin().callback_method,
                            callback_class='NetworkResourceHelper',
                            callback_func='update_vip_callback',
                            cluster_vpath=cluster.get_vpath(),
                            network_vpath=network.get_vpath())

        task.model_items.update(to_update[1:])
        if network.is_updated():
            task.model_items.update([network])

        return task

    def get_vip_update_tasks(self, model_api, cluster):
        """
        Entry-point to be called by vcs-plugin
        """
        NetworkVIP = namedtuple('NetworkVIP', ['network', 'to_update'])

        targets = {}
        for service in get_applied_or_updated(cluster.services):
            for vip in get_applied_or_updated(service.ipaddresses):
                network = self.get_vip_network_item(model_api, vip)
                if not targets.get(network.name):
                    targets[network.name] = NetworkVIP(network, set([]))
                if (self.vip_network_subnet_requires_task(vip, network) or
                    self.vip_ipaddress_requires_task(vip)):
                    targets[network.name].to_update.add(vip)

        return [self.generate_vip_update_task(cluster, target.network,
                                                       list(target.to_update))
                        for target in targets.values() if target.to_update]


def vip_upd_standby_node(api, cmd_api, service, cluster):
    """
    Used to update the IP and NIC Proxy resources of clustered service
    when a new standby node has been added.
    """
    networks = set(ipaddress.network_name
                   for ipaddress in service.ipaddresses)
    model = VIPModel(api, cmd_api)
    applied_nodes = set(get_applied_node_list(service))
    nodes = set(service.node_list.split(','))
    new_node = nodes.difference(applied_nodes)
    node = [n for n in cluster.nodes if n.item_id in new_node][0]
    for network in networks:
        ipaddresses = [ipaddress for ipaddress in service.ipaddresses
                       if ipaddress.network_name == network and
                       ipaddress.is_applied()]
        ip_res = IPResources(ipaddresses, cluster, service,
                             model, allvips=True)
        ip_res.update_resource_device_new_node(cmd_api, node)
        nic_proxy = ip_res.nic_proxy()
        nic_proxy.update_target_res_new_node(cmd_api, node)
