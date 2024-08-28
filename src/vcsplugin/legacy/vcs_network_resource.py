##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from netaddr import IPAddress, IPNetwork, valid_ipv6, valid_ipv4
from collections import defaultdict

from litp.core.litp_logging import LitpLogger
from litp.core.execution_manager import CallbackTask
from litp.core.validators import ValidationError
from vcsplugin.vcs_exceptions import VCSRuntimeException

from vcsplugin.vcs_base_helper import VcsBaseHelper, condense_name


log = LitpLogger()

DEFAULT_IPV6_PREFIXLEN = '64'


class LegacyVcsNetworkResource(VcsBaseHelper):
    """
    Legacy class which handle `lsb-runtime` network resources.
    """

    def validate_model(self, api):
        clusters = api.query("vcs-cluster")
        errors = []
        for cluster in clusters:
            errors.extend(self._validate_ip_resources_on_nodes(api, cluster))
            errors.extend(self._validate_vip_collection(cluster,
                                                        validator=valid_ipv4))
            errors.extend(self._validate_vip_collection(cluster,
                                                        validator=valid_ipv6))
            errors.extend(self._validate_vips_not_on_heartbeat(cluster))

        return errors

    def _validate_ip_resources_on_nodes(self, api, cluster):
        errors = []

        llt_nets = cluster.llt_nets.split(",")

        for service in cluster.services:
            if service.is_for_removal():
                continue
            vips = set()
            for runtime in service.runtimes:
                for ip in [x for x in runtime.ipaddresses
                           if x.network_name not in llt_nets]:

                    adr = IPNetwork(ip.ipaddress)
                    if adr.version == 4:
                        ipv4_errors = self._validate_ipv4_resource(api, ip)
                        if ipv4_errors:
                            errors.extend(ipv4_errors)
                        else:
                            vips.add(ip)
                    elif adr.version == 6:
                        ipv6_errors = self._validate_ipv6_resource(api, ip)
                        if ipv6_errors:
                            errors.extend(ipv6_errors)
                        else:
                            vips.add(ip)

            for node in service.nodes:
                for vip in vips:
                    adr = IPNetwork(vip.ipaddress)
                    interfaces = node.network_interfaces.query(
                        'network-interface',
                        network_name=vip.network_name)
                    if not interfaces:
                        errors.append(
                                ValidationError(
                                    item_path=vip.get_vpath(),
                                    error_message="Network interface must be "
                                    "configured for network {0} on node {1}"
                                    .format(vip.network_name,
                                            node.hostname)
                                ))
                    elif not (interfaces[0].ipaddress or \
                              interfaces[0].ipv6address):
                        errors.append(
                            ValidationError(
                                item_path=vip.get_vpath(),
                                error_message="An IP for network '{0}' must "
                                "be assigned to an interface on node {1}"
                                .format(vip.network_name,
                                        node.hostname)
                            ))
        return errors

    def _validate_ipv4_resource(self, api, ip):

        errors = []
        networks = api.query("network", name=ip.network_name)
        if not networks:
            errors.append(
                ValidationError(
                    item_path=ip.get_vpath(),
                    error_message="A matching '{0}' network must "
                    "be defined in /infrastructure/networking/networks/"
                    .format(ip.network_name)
                ))
        elif not networks[0].subnet:
            errors.append(
                ValidationError(
                    item_path=ip.get_vpath(),
                    error_message="A subnet must be defined for "
                    "the network {0}".format(
                        networks[0].get_vpath())
                ))
        elif (IPAddress(ip.ipaddress) not in
              IPNetwork(networks[0].subnet)):
            errors.append(
                ValidationError(
                    item_path=ip.get_vpath(),
                    error_message="VIPs must be in the subnet "
                    "of their network defined in "
                    "infrastructure"
                ))

        return errors

    def _validate_ipv6_resource(self, api, ip):

        errors = []
        networks = api.query("network", name=ip.network_name)
        if not networks:
            errors.append(
                ValidationError(
                    item_path=ip.get_vpath(),
                    error_message="A matching '{0}' network must "
                    "be defined in /infrastructure/networking/networks/"
                    .format(ip.network_name)
                ))

        # For now that it all we can validate for I think ... ??
        # Later on we should validate for a IPv6 route for our vips but IPv6
        # routing is not delivered yet.
        return errors

    def _validate_vip_collection(self, cluster, validator=valid_ipv4):
        errors = []

        for service in cluster.services:
            if service.is_for_removal():
                continue
            num_active = service.active
            for runtime in service.runtimes:
                networks = defaultdict(list)
                for ip in runtime.ipaddresses:
                    if validator(ip.ipaddress.split('/')[0]):
                        if ip.ipaddress in networks[ip.network_name]:
                            errors.append(
                                ValidationError(
                                    item_path=runtime.get_vpath(),
                                    error_message="Duplicate IP for "
                                    "network {0}".format(ip.network_name)
                                ))
                        networks[ip.network_name].append(ip.ipaddress)

                for name, ips in networks.iteritems():
                    num_ips = len(ips)
                    if not num_ips % int(num_active) == 0:
                        errors.append(
                            ValidationError(
                                item_path=runtime.get_vpath(),
                                error_message="IPs for network {0} "
                                "not a multiple of active count "
                                "{1}".format(name, num_active)
                            ))
        return errors

    def _validate_vips_not_on_heartbeat(self, cluster):
        errors = []

        llt_nets = cluster.llt_nets.split(",")

        for ip in cluster.query('vip'):
            if ip.network_name in llt_nets:
                errors.append(
                    ValidationError(
                        item_path=ip.get_vpath(),
                        error_message="Can not create VIPs on llt networks"
                    ))
        return errors

    def create_configuration(self, api, cluster, service):
        _ = api
        pre_node_tasks = []
        post_node_tasks = []
        for runtime in service.runtimes:
            if runtime.ipaddresses.has_initial_dependencies():
                post_node_tasks.append(
                    self._generate_ip_task(runtime, service, cluster))
                return pre_node_tasks, post_node_tasks
        return pre_node_tasks, post_node_tasks

    def _generate_ip_task(self, runtime, service, cluster):
        """
        creates a CallbackTask for the given service
        :param service: clustered service
        :type  service: class
        :param model: Dictionary containing mode;
        :type  model: dict
        """

        return CallbackTask(
            service,
            'Create IPs for VCS service group "{0}"'.format(
                self.get_group_name(service.item_id, cluster.item_id)),
            self.plugin().callback_method,
            callback_class=self.__class__.__name__,
            callback_func="create_ip_callback",
            runtime_vpath=runtime.get_vpath(),
            service_vpath=service.get_vpath(),
            cluster_vpath=cluster.get_vpath()
        )

    def create_ip_callback(self, callback_api, runtime_vpath, service_vpath,
                           cluster_vpath):
        '''
        Callback function for the tasks
        :param callback_api: access to security and execution manager
        :type  callback_api: class
        :param kwargs: arguments
        :type  kwargs: dict
        '''

        runtime = self.query_by_vpath(callback_api, runtime_vpath)
        service = self.query_by_vpath(callback_api, service_vpath)
        cluster_item_id = self.query_by_vpath(callback_api,
                                              cluster_vpath).item_id

        self.nodes = [node.hostname for node in service.nodes]
        service_group_name = self.get_group_name(service.item_id,
                                                 cluster_item_id)

        log.event.info(
            "VCS Creating IP resources for {0}".format(service_group_name))

        with self.vcs_api.readable_conf():
            for runtime in service.runtimes:
                all_ips = [ip for ip in runtime.ipaddresses if ip.is_initial()]

                _create_resources(callback_api,
                                  self.vcs_api,
                                  all_ips,
                                  service,
                                  runtime,
                                  cluster_item_id,
                                  service_group_name)


def get_ip_res_names(runtime, service, cluster):
    ips_per_network = defaultdict(list)
    for ip in runtime.ipaddresses:
        if ip.is_initial():
            ips_per_network[ip.network_name].append(ip.ipaddress)

    ip_resources = []
    for network, ips in ips_per_network.iteritems():
        # For parallel VCS service groups ips are split per network into chunks
        # of size equal to the active nodes in the service group to be assigned
        # to IP Resources. This skips the chunking but generates the same
        # resource names.
        for i in xrange(1, (len(ips) / int(service.active)) + 1):
            res_name = _get_ip_resource_name(network,
                                             i,
                                             service.item_id,
                                             runtime.item_id,
                                             cluster.item_id)
            ip_resources.append(res_name)
    return ip_resources


def _create_resources(api, vcs_api, ips, service, runtime,
                      cluster_item_id, service_group_name):
    '''
    This method creates the resource for IP4 and IP6. You can define a vip
    with a ipv6 address in it that has a network_name that is also used
    by other ipv4 addresses
    '''
    ips_per_network = defaultdict(list)
    for ip in ips:
        ips_per_network[ip.network_name].append(ip.ipaddress)

    for network, ips in ips_per_network.iteritems():
        #ip4 need to be sorted together first and then ip6 together
        ips_sorted = []
        ips_4 = [ip for ip in ips if not _is_ip6(ip)]
        for ip in ips_4:
            ips_sorted.append(ip)
        ips_6 = [ip for ip in ips if _is_ip6(ip)]
        for ip in ips_6:
            ips_sorted.append(ip)

        ip_resources = []
        node_interfaces = _get_node_interface_for_network(service, network)
        # For parallel VCS service groups ips are split per network into
        # chunks of size equal to the active nodes in the service group to
        # be assigned to IP Resources. This groups the IPs naturally into
        # VCS IP resources and enumerate creates a counter for unique
        # naming of these resources.

        for i, addresses in enumerate(_split_list(ips_sorted,
                                                  int(service.active)),
                                      start=1):

            res_name = _get_ip_resource_name(network,
                                     i,
                                     service.item_id,
                                     runtime.item_id,
                                     cluster_item_id)
            ip_resources.append(res_name)

            if _is_ip6(addresses[0]):
                netmask = None
                prefixlen = _get_prefixlen(addresses)
            else:
                netmask = _get_netmask(api, network)
                prefixlen = None

            _create_ip_resource(vcs_api,
                                res_name,
                                addresses,
                                netmask,
                                node_interfaces,
                                service_group_name,
                                int(service.standby) == 0,
                                prefixlen=prefixlen)

        nic_proxy_name = _get_nic_proxy_name(cluster_item_id,
                                             service.item_id,
                                             network)

        _add_nic_proxy_resource(
            vcs_api,
            nic_proxy_name,
            node_interfaces,
            service_group_name,
            cluster_item_id)

        for ip_res in ip_resources:
            _link_ip_to_nic_proxy(vcs_api, ip_res, nic_proxy_name)


def _split_list(ips, active_count):
    '''
    This method splits the list of ips based on the active acount.
    A generator is returned
    :param ips: a list of ip objects in state initial
    :type  ips: list
    :param active_count: the active count for the clustered service
    :type  active_count: integer
    '''
    for i in xrange(0, len(ips), active_count):
        yield ips[i:i + active_count]


def _get_prefixlen(ip6addresses):
    '''
    Assumes validation has checked all ip6addresses per resource
    have the same network
    '''
    ip6 = ip6addresses[0]
    if '/' in ip6:
        return ip6.split('/')[1]
    else:
        return DEFAULT_IPV6_PREFIXLEN


def _get_netmask(api, net_name):
    netmask = None
    networks = api.query('network', name=net_name)
    if networks:
        subnet = networks[0].subnet
        # subnet is optional in network item:
        if subnet:
            netmask = str(IPNetwork(subnet).netmask)
    return netmask


def _get_node_interface_for_network(service, net_name):
    node_interfaces = []
    for node in service.nodes:
        interfaces = node.query('network-interface', network_name=net_name)
        # Network plugin validates each node has a maximum of one interface
        # onto a certain network
        if interfaces and not interfaces[0].is_for_removal():
            node_interfaces.append(
                {"hostname": node.hostname,
                 "interface": interfaces[0].device_name}
            )
    return node_interfaces


def _link_ip_to_nic_proxy(vcs_api, ip_name, nic_proxy_name):
    '''
    Command to link the IP resource to the NIC Proxy resource
    '''
    log.trace.info("VCS Linking \"{0}\" to \"{1}\"".format(ip_name,
                                                           nic_proxy_name))
    # hares -link Res_IP_cluster1_cs1_runtime1_10_10_10_151
    #     Res_Proxy_cluster1_cs1_eth0
    vcs_api.hares_link(ip_name, nic_proxy_name)


def _get_nic_proxy_name(cluster_item_id, clustered_service_item_id,
                        network):
    '''
    Returns the NIC Proxy name in the format:
    Res_NIC_Proxy_<cluster_item_id>_<clustered_service_item_id>_<network>
    For example: Res_NIC_Proxy_cluster1_cs1_mgmt
    '''
    return condense_name("Res_NIC_Proxy_{0}_{1}_{2}".format(cluster_item_id,
                                          clustered_service_item_id, network))


def _get_target_resource_name(cluster_item_id, interface_name):
    '''
    Returns the NIC Resource Name which is the Target in the format:
    Res_NIC_<cluster_item_id>_<interface_name>
    For example: Res_NIC_cluster1_eth0
    :param cluster_item_id: The id of the cluster item
    :type  cluster_item_id: string
    :param interface_name: The name of the interface
    :type  interface_name: string
    '''
    return condense_name("Res_NIC_{0}_{1}".\
                         format(cluster_item_id, interface_name))


def resource_already_exists(vcs_api, resource):
    '''
    Method to check if the resource already exists.
    The reason for this method is to avoid an MCO command failing if an attempt
    is made by MCO to create a resource which already exists.

    hares -list returns all the resources in VCS. We then check if the string
    of the proxy name is in that list.
    :param vcs_api: initialised class VcsCmdApi()
    :type  vcs_api: class
    :param resource: name of the proxy resource
    :type  resource: string
    '''
    resource_exists = False
    resources_string = vcs_api.hares_list()
    resources = []

    for resource_line in resources_string.replace(' ', '').split("\n"):
        resources.append(resource_line.split("\t\t")[0])

    if resource in resources:
        resource_exists = True

    return resource_exists


def _add_nic_proxy_resource(vcs_api, nic_proxy_name, node_interfaces,
                            service_group_name, cluster_item_id):
    '''
    VCS MCO commands to add the NIC proxy resource if it is not already there
    If the TargetResName for the NIC proxy resource does not exist, then the
    plan fails with an error message in /var/log/messages
    '''
    if not resource_already_exists(vcs_api, nic_proxy_name):
        log.trace.info("VCS Creating NIC Proxy \"{0}\"".format(nic_proxy_name))
        # hares -add Res_NIC_Proxy_cluster1_cs1_eth0 Proxy Grp_CS_cluster1_cs1
        vcs_api.hares_add(nic_proxy_name, "Proxy", service_group_name)
        # hares -modify Res_NIC_Proxy_cluster1_cs1_eth0 Critical 1
        vcs_api.hares_modify(nic_proxy_name, "Critical", "1")
        # hares -local Res_NIC_Proxy_cluster1_cs1_eth0 TargetResName
        vcs_api.hares_local(nic_proxy_name, "TargetResName")

        for node in node_interfaces:
            target_resource_name = _get_target_resource_name(cluster_item_id,
                                                             node['interface'])
            if not resource_already_exists(vcs_api, target_resource_name):
                err_msg = 'The TargetResName "{0}" for the NIC Proxy '\
                    '"{1}" does not exist. The NIC resource required has '\
                    'not been set up.'.format(target_resource_name,
                                              nic_proxy_name)
                raise VCSRuntimeException(err_msg)

            # hares -modify Res_NIC_Proxy_cluster1_cs1_eth0 TargetResName
            #     Res_NIC_cluster1_eth0 -sys mn1
            vcs_api.hares_modify(nic_proxy_name, "TargetResName",
                                 target_resource_name, node['hostname'])

        # hares -modify Res_NIC_Proxy_cluster1_cs1_eth0 Enabled 1
        vcs_api.hares_modify(nic_proxy_name, "Enabled", "1")


def _strip_prefixlen(ipaddress):
    return ipaddress.split('/', 1)[0]


def _is_ip6(ipaddress):
    '''
    Takes an ipaddress string and detects if it is a ipv6
    Takes into account that we can use CIDR
    '''
    ipaddress = _strip_prefixlen(ipaddress)
    if valid_ipv6(ipaddress):
        return True


def _get_ip_resource_name(network, counter, service, runtime, cluster_item_id):
    '''
    Return resource name with format
    Res_IP_<cluster_item_id>_<service_item_id>_<network_name>_<resource_number>
    '''
    name = "Res_IP_{0}_{1}_{2}_{3}_{4}".format(
        cluster_item_id,
        service,
        runtime,
        network,
        counter)
    return condense_name(name)


def _create_ip_resource(vcs_api, res_name, addresses, netmask,
                        interfaces, group, parallel, prefixlen=None):

    # hares -add ip_10_50_5_225 IP httpd1
    vcs_api.hares_add(res_name, "IP", group)
    # hares -modify ip_10_50_5_225 Critical 1
    vcs_api.hares_modify(res_name, "Critical", "1")
    # hares -local ip_10_50_5_225 Device
    vcs_api.hares_local(res_name, "Device")
    # hares -modify ip_10_50_5_225 Device eth0 mn1
    for node in interfaces:
        vcs_api.hares_modify(
            res_name, "Device", node['interface'], node['hostname'])

    if not parallel:
        ip_addr = addresses[0]
        # No prefixlen in the address for vcs resource
        if _is_ip6(ip_addr):
            ip_addr = _strip_prefixlen(ip_addr)
        # hares -modify ip_10_50_5_225 Address 10.50.5.225
        vcs_api.hares_modify(res_name, "Address", ip_addr)
    else:
        # hares -local ip_10_50_5_225 Address
        vcs_api.hares_local(res_name, "Address")
        res_interfaces = sorted(interfaces, key=lambda x: x['hostname'])
        res_ips = sorted(addresses)
        for node, ip_addr in zip(res_interfaces, res_ips):
            # No prefixlen in the address for vcs resource
            if _is_ip6(ip_addr):
                ip_addr = _strip_prefixlen(ip_addr)
            # hares -modify ip_10_50_5_225 Address 10.50.5.225 -sys node
            vcs_api.hares_modify(res_name,
                                 "Address",
                                 ip_addr,
                                 node['hostname'])

    if netmask:
        # hares -modify ip_10_50_5_225 NetMask 255.255.255.0
        vcs_api.hares_modify(res_name, "NetMask", netmask)
    elif prefixlen:
        # hares -modify Res_IPv6_c1_CS1_APP1_mgmt_1 PrefixLen 64
        vcs_api.hares_modify(res_name, "PrefixLen", prefixlen)

    # hares -modify ip_10_50_5_225 Enabled 1
    vcs_api.hares_modify(res_name, "Enabled", "1")
    for node in interfaces:
        # hares -probe ip_10_50_5_225 -sys node
        vcs_api.hares_probe(res_name, node['hostname'])
