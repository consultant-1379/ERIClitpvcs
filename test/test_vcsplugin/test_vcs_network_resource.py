##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

# pep8: disable=E501

import mock
import unittest

mock.patch('litp.core.litp_logging.LitpLogger').start()

from netaddr import valid_ipv6, valid_ipv4
from vcsplugin.vcs_plugin import VcsPlugin
from base_vcs_integration import VCSIntegrationBase
from vcsplugin.vcs_exceptions import VCSRuntimeException
from vcsplugin.legacy.vcs_network_resource import (
    LegacyVcsNetworkResource,
    _create_ip_resource,
    _add_nic_proxy_resource,
    _get_target_resource_name,
    _get_node_interface_for_network,
    _get_nic_proxy_name,
    _link_ip_to_nic_proxy,
    resource_already_exists,
    _get_netmask,
    _split_list)


class TestActiveStandby(VCSIntegrationBase):

    @mock.patch("vcsplugin.legacy.vcs_network_resource._add_nic_proxy_resource")
    @mock.patch("vcsplugin.legacy.vcs_network_resource._link_ip_to_nic_proxy")
    def test_ip_resource(self, link_ip_to_nic_proxy, _add_nic_proxy_resource):
        vcs_cmd_api = mock.Mock()
        vcs_cmd_api.readable_conf = mock.MagicMock()
        self.setup_model()
        ips = self._add_service_to_model(1, no_of_ips=2)
        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)
        vcs_net_helper._vcs_api = vcs_cmd_api

        post_tasks = []
        for cluster in self.context_api.query('vcs-cluster'):
            for service in cluster.services:
                service_pre_tasks, service_post_tasks = vcs_net_helper.create_configuration(
                    self.context_api, cluster, service)
                post_tasks.extend(service_post_tasks)
                task = post_tasks[0]
                vcs_net_helper.create_ip_callback(
                    self.callback_api,
                    **self._strip_kwargs(task.kwargs))

                for i, ip in enumerate(ips):

                    res_name = "Res_IP_cluster1_service1_runtime1_mgmt_{0}".format(i+1)
                    vcs_cmd_api.hares_add.assert_any_call(
                        res_name, "IP", "Grp_CS_cluster1_service1")
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "Critical", "1")
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "Enabled", "1")
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "Device", "eth0", "mn1")
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "Device", "eth0", "mn2")
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "Address", ip)
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "NetMask", "255.255.255.0")
                    vcs_cmd_api.hares_local.assert_any_call(
                        res_name, "Device")
                    vcs_cmd_api.hares_probe.assert_any_call(
                        res_name, "mn1")
                    vcs_cmd_api.hares_probe.assert_any_call(
                        res_name, "mn2")
        self.assertEqual(link_ip_to_nic_proxy.call_count, 2)
        self.assertEqual(link_ip_to_nic_proxy.call_args_list, [
            mock.call(vcs_cmd_api, 'Res_IP_cluster1_service1_runtime1_mgmt_1',
                      'Res_NIC_Proxy_cluster1_service1_mgmt'),
            mock.call(vcs_cmd_api, 'Res_IP_cluster1_service1_runtime1_mgmt_2',
                      'Res_NIC_Proxy_cluster1_service1_mgmt'),
            ])
        self.assertEqual(_add_nic_proxy_resource.call_args_list, [
            mock.call(vcs_cmd_api, 'Res_NIC_Proxy_cluster1_service1_mgmt',
                     [{'interface': 'eth0', 'hostname': 'mn1'},
                      {'interface': 'eth0', 'hostname': 'mn2'}],
                     'Grp_CS_cluster1_service1', 'cluster1')
            ])

    @mock.patch("vcsplugin.legacy.vcs_network_resource._add_nic_proxy_resource")
    def test_ip_resource_parallel(self, _add_nic_proxy_resource):
        vcs_cmd_api = mock.MagicMock()
        self.setup_model(num_of_nodes=3)
        ips = self._add_service_to_model(1,
                                         active=3,
                                         standby=0,
                                         no_of_ips=3,
                                         no_of_nodes=3)
        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)
        vcs_net_helper._vcs_api = vcs_cmd_api

        post_tasks = []
        for cluster in self.context_api.query('vcs-cluster'):
            for service in cluster.services:
                service_pre_tasks, service_post_tasks = vcs_net_helper.create_configuration(
                    self.context_api, cluster, service)
                post_tasks.extend(service_post_tasks)

                task = post_tasks[0]
                vcs_net_helper.create_ip_callback(
                    self.callback_api,
                    **self._strip_kwargs(task.kwargs))

                ips.sort()
                for i, addresses in enumerate(_split_list(ips, 3)):
                    res_name = "Res_IP_cluster1_service1_runtime1_mgmt_{0}".format(i+1)

                    vcs_cmd_api.hares_add.assert_any_call(
                        res_name, "IP", "Grp_CS_cluster1_service1")
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "Critical", "1")
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "Enabled", "1")
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "Device", "eth0", "mn1")
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "Device", "eth0", "mn2")
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "Device", "eth0", "mn3")
                    vcs_cmd_api.hares_local.assert_any_call(
                        res_name, "Address")
                    for ip, node in zip(addresses, ["mn1", "mn2", "mn3"]):
                        vcs_cmd_api.hares_modify.assert_any_call(
                            res_name, "Address", ip, node)
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "NetMask", "255.255.255.0")
                    vcs_cmd_api.hares_local.assert_any_call(
                        res_name, "Device")
                    vcs_cmd_api.hares_probe.assert_any_call(
                        res_name, "mn1")
                    vcs_cmd_api.hares_probe.assert_any_call(
                        res_name, "mn2")
        self.assertEqual(_add_nic_proxy_resource.call_args_list, [
            mock.call(vcs_cmd_api, 'Res_NIC_Proxy_cluster1_service1_mgmt',
                     [{'interface': 'eth0', 'hostname': 'mn1'},
                      {'interface': 'eth0', 'hostname': 'mn2'},
                      {'interface': 'eth0', 'hostname': 'mn3'}],
                     'Grp_CS_cluster1_service1', 'cluster1')
            ])

    @mock.patch("vcsplugin.legacy.vcs_network_resource._create_ip_resource")
    def test_no_ip_resource(self, _create_ip_resource):
        self.setup_model()
        self._add_service_to_model(1, no_of_ips=0)
        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        pre_tasks = []
        post_tasks = []
        for cluster in self.context_api.query('vcs-cluster'):
            for service in cluster.services:
                service_pre_tasks, service_post_tasks = vcs_net_helper.create_configuration(
                    self.context_api, cluster, service)
                post_tasks.extend(service_post_tasks)

        self.assertEqual(len(post_tasks), 0)

    @mock.patch("vcsplugin.legacy.vcs_network_resource._link_ip_to_nic_proxy")
    @mock.patch("vcsplugin.legacy.vcs_network_resource._add_nic_proxy_resource")
    @mock.patch("vcsplugin.legacy.vcs_network_resource._create_ip_resource")
    def test_multiple_ip_resource(self, create_ip_resource,
                                  add_nic_proxy_resource,
                                  link_ip_to_nic_proxy):
        self.setup_model()
        self._add_service_to_model(1, no_of_ips=10)
        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        api = mock.Mock()
        api.haconf = mock.Mock()
        api.readable_conf = mock.MagicMock()
        vcs_net_helper._vcs_api = api

        post_tasks = []
        for cluster in self.context_api.query('vcs-cluster'):
            for service in cluster.services:
                service_pre_tasks, service_post_tasks = vcs_net_helper.create_configuration(
                    self.context_api, cluster, service)
                post_tasks.extend(service_post_tasks)

        for task in post_tasks:
            vcs_net_helper.create_ip_callback(
                self.callback_api,
                **self._strip_kwargs(task.kwargs))
        self.assertEqual(create_ip_resource.call_count, 10)
        self.assertEqual(add_nic_proxy_resource.call_count, 1)
        self.assertEqual(link_ip_to_nic_proxy.call_count, 10)

    @mock.patch("vcsplugin.legacy.vcs_network_resource._add_nic_proxy_resource")
    def test_ip_resource_other_range(self, _add_nic_proxy_resource):
        vcs_cmd_api = mock.Mock()
        self.setup_model()
        ips = self._add_service_to_model(1, no_of_ips=0)
        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)
        vcs_net_helper._vcs_api = vcs_cmd_api
        vcs_net_helper._vcs_api.readable_conf = mock.MagicMock()

        self._add_item_to_model(
            'network',
            '/infrastructure/networking/networks/range_1',
            name='traffic',
            subnet='10.10.11.0/24')

        ips.append(self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip",
            network_name='traffic',
            ipaddress="10.10.11.20").ipaddress)

        for i in range(1, 3):
            self._add_item_to_model(
                'eth',
                "/deployments/test/clusters/cluster1/nodes/node%s/network_interfaces/ip_1" % i,
                network_name='traffic',
                ipaddress='10.10.11.%d' % i,
                macaddress='aa:aa:aa:aa:aa:aa',
                device_name='eth1')

        post_tasks = []
        for cluster in self.context_api.query('vcs-cluster'):
            for service in cluster.services:
                service_pre_task, service_post_task = vcs_net_helper.create_configuration(
                    self.context_api, cluster, service)
                post_tasks.extend(service_post_task)
                task = post_tasks[0]
                vcs_net_helper.create_ip_callback(
                    self.callback_api,
                    **self._strip_kwargs(task.kwargs))
                for i, ip in enumerate(ips, start=1):
                    res_name = "Res_IP_cluster1_service1_runtime1_traffic_{0}".format(i)
                    vcs_cmd_api.hares_add.assert_any_call(
                        res_name, "IP", "Grp_CS_cluster1_service1")
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "Critical", "1")
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "Enabled", "1")
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "Device", "eth1", "mn1")
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "Device", "eth1", "mn2")
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "Address", ip)
                    vcs_cmd_api.hares_modify.assert_any_call(
                        res_name, "NetMask", "255.255.255.0")
                    vcs_cmd_api.hares_local.assert_any_call(
                        res_name, "Device")
                    vcs_cmd_api.hares_probe.assert_any_call(
                        res_name, "mn1")
                    vcs_cmd_api.hares_probe.assert_any_call(
                        res_name, "mn2")
        self.assertEqual(_add_nic_proxy_resource.call_args_list, [
            mock.call(vcs_cmd_api, 'Res_NIC_Proxy_cluster1_service1_traffic',
                     [{'interface': 'eth1', 'hostname': 'mn1'},
                      {'interface': 'eth1', 'hostname': 'mn2'}],
                     'Grp_CS_cluster1_service1', 'cluster1')
            ])

    def test_get_target_resource_name(self):
        cluster_item_id = 'cluster1'
        interface_name = 'eth0'

        expected_target_resource_name = 'Res_NIC_cluster1_eth0'
        target_resource_name = _get_target_resource_name(cluster_item_id,
                                                         interface_name)

        self.assertEqual(target_resource_name, expected_target_resource_name)

    def test_get_nic_proxy_name(self):
        cluster_item_id = 'cluster1'
        clustered_service_item_id = 'cs1'
        network = 'mgmt'

        expected_nic_proxy_name = 'Res_NIC_Proxy_cluster1_cs1_mgmt'
        nic_proxy_name = _get_nic_proxy_name(cluster_item_id,
                                             clustered_service_item_id,
                                             network)

        self.assertEqual(nic_proxy_name, expected_nic_proxy_name)

    @mock.patch('vcsplugin.legacy.vcs_network_resource.log')
    def test_link_ip_to_nic_proxy(self, log):
        vcs_api = mock.Mock(['hares_link'])
        ip_name = 'IP_cluster1_cs1_runtime1_10_10_10_151'
        nic_proxy_name = 'Res_NIC_Proxy_cluster1_cs1_eth0'

        _link_ip_to_nic_proxy(vcs_api, ip_name, nic_proxy_name)

        self.assertEqual(vcs_api.hares_link.call_args_list, [
            mock.call('IP_cluster1_cs1_runtime1_10_10_10_151',
                      'Res_NIC_Proxy_cluster1_cs1_eth0')
            ])
        self.assertEqual(log.trace.info.call_args_list, [
            mock.call('VCS Linking \"IP_cluster1_cs1_runtime1_10_10_10_151\" '
                      'to \"Res_NIC_Proxy_cluster1_cs1_eth0\"'),
            ])


class TestValidation(VCSIntegrationBase):

    def test_validation_vip_v4(self):
        self.setup_model()
        self._add_service_to_model(1, active="2", standby="0", no_of_ips=2)

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip",
            network_name='traffic',
            ipaddress='10.10.11.20')

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip1",
            network_name='traffic',
            ipaddress='10.10.11.21')

        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        errors = []
        for cluster in self.context_api.query("vcs-cluster"):
            errors += vcs_net_helper._validate_vip_collection(
                cluster)

        self.assertEqual(len(errors), 0)

    def test_validation_vip_missing_ipv6_prefix(self):
        self.setup_model()
        self._add_service_to_model(1, active="2", standby="0", no_of_ips=0)

        # Fixme: This test should FAIL as we didn't specify prefix for IPv6
        # self.assertRaises(RuntimeError, self._add_item_to_model,
        #           'vip',
        #           "/deployments/test/clusters/cluster1/services/service1"
        #           "/runtimes/runtime1/ipaddresses/vcs_ip1",
        #           network_name='traffic',
        #           ipaddress='2001:aa::1:11')

    def test_validation_vip_incorrect_ipv6_address(self):
        self.setup_model()
        self._add_service_to_model(1, active="2", standby="0", no_of_ips=0)

        self.assertRaises(RuntimeError, self._add_item_to_model,
                          'vip',
                          "/deployments/test/clusters/cluster1/services/service1"
                          "/runtimes/runtime1/ipaddresses/vcs_ip1",
                          network_name='traffic',
                          ipaddress='2001:az::1:11/64')

    def test_validation_vip_v6(self):
        self.setup_model()
        self._add_service_to_model(1, active="2", standby="0", no_of_ips=2)

        self._add_item_to_model(
         'vip',
         "/deployments/test/clusters/cluster1/services/service1"
         "/runtimes/runtime1/ipaddresses/vcs_ip1",
         network_name='traffic',
         ipaddress='2001:aa::1:11/64')

        self._add_item_to_model(
         'vip',
         "/deployments/test/clusters/cluster1/services/service1"
         "/runtimes/runtime1/ipaddresses/vcs_ip2",
         network_name='traffic',
         ipaddress='2001:aa::1:12/64')

        self._add_item_to_model(
         'vip',
         "/deployments/test/clusters/cluster1/services/service1"
         "/runtimes/runtime1/ipaddresses/vcs_ip3",
         network_name='traffic',
         ipaddress='2001:aa::1:13/64')

        self._add_item_to_model(
        'vip',
        "/deployments/test/clusters/cluster1/services/service1"
        "/runtimes/runtime1/ipaddresses/vcs_ip4",
        network_name='traffic',
        ipaddress='2001:aa::1:14/64')

        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        errors = []
        for cluster in self.context_api.query("vcs-cluster"):
            errors += vcs_net_helper._validate_vip_collection(
                cluster, validator=valid_ipv4)
            errors += vcs_net_helper._validate_vip_collection(
                cluster, validator=valid_ipv6)
        self.assertEqual(len(errors), 0)

    def test_validation_number_of_vips_vs_number_of_active_nodes_v4(self):
        self.setup_model()
        self._add_service_to_model(1, active="2", standby="0", no_of_ips=2)

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip",
            network_name='traffic',
            ipaddress='10.10.11.20')

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip1",
            network_name='traffic',
            ipaddress='10.10.11.21')

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip2",
            network_name='traffic',
            ipaddress='10.10.11.22')

        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        errors = []
        for cluster in self.context_api.query("vcs-cluster"):
            errors += vcs_net_helper._validate_vip_collection(
                cluster)

        self.assertEqual(len(errors), 1)
        expected = sorted(["</deployments/test/clusters/cluster1/services/service1/runtimes/runtime1 - ValidationError - IPs for network traffic not a multiple of active count 2>"])

        self.assertEqual(self.string_and_sort(errors), expected)

    def test_validation_number_of_vips_vs_number_of_active_nodes_v6(self):
        self.setup_model()
        self._add_service_to_model(1, active="2", standby="0", no_of_ips=0)

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip",
            network_name='traffic',
            ipaddress='2001:aa::1:11/64')

        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        errors = []
        for cluster in self.context_api.query("vcs-cluster"):
            errors += vcs_net_helper._validate_vip_collection(
                cluster, validator=valid_ipv6)

        self.assertEqual(len(errors), 1)
        expected = sorted(["</deployments/test/clusters/cluster1/services/service1/runtimes/runtime1 - ValidationError - IPs for network traffic not a multiple of active count 2>"])

        self.assertEqual(self.string_and_sort(errors), expected)

    def test_validation_vip_duplicate_address_v4(self):
        self.setup_model()
        self._add_service_to_model(1, active="2", standby="0", no_of_ips=2)

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip",
            network_name='traffic',
            ipaddress='10.10.11.20')

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip1",
            network_name='traffic',
            ipaddress='10.10.11.20')

        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        errors = []
        for cluster in self.context_api.query("vcs-cluster"):
            errors += vcs_net_helper._validate_vip_collection(
                cluster)

        self.assertEqual(len(errors), 1)
        expected = sorted(["</deployments/test/clusters/cluster1/services/service1/runtimes/runtime1 - ValidationError - Duplicate IP for network traffic>"])

        self.assertEqual(self.string_and_sort(errors), expected)

    def test_validation_vip_duplicate_address_v6(self):
        self.setup_model()
        self._add_service_to_model(1, active="2", standby="0", no_of_ips=2)

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip1",
            network_name='traffic',
            ipaddress='2001:aa::1:11/64')

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip2",
            network_name='traffic',
            ipaddress='2001:aa::1:11/64')

        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        errors = []
        for cluster in self.context_api.query("vcs-cluster"):
            errors += vcs_net_helper._validate_vip_collection(
                cluster, validator=valid_ipv6)

        self.assertEqual(len(errors), 1)
        expected = sorted(["</deployments/test/clusters/cluster1/services/service1/runtimes/runtime1 - ValidationError - Duplicate IP for network traffic>"])

        self.assertEqual(self.string_and_sort(errors), expected)

    def test_validation_vcs_address_not_present_on_interface_v6(self):
        self.setup_model()
        self._add_service_to_model(1, active="1", standby="1", no_of_ips=0)

        self._add_item_to_model(
            'network',
            '/infrastructure/networking/networks/v6traffic',
            name='v6traffic')

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip",
            network_name='v6traffic',
            ipaddress='2001:aa::1:11/64')

        self._add_item_to_model(
            'eth',
            "/deployments/test/clusters/cluster1"
            "/nodes/node1/network_interfaces/if3",
            macaddress="08:00:27:5B:C1:41",
            network_name="v6traffic",
            ipv6address='2001:aa:1::12/64',
            device_name="eth3",)

        self._add_item_to_model(
            'eth',
            "/deployments/test/clusters/cluster1"
            "/nodes/node2/network_interfaces/if3",
            macaddress="08:00:27:5B:C1:42",
            network_name="v6traffic",
            ipv6address='2001:aa:1::13/64',
            device_name="eth3",)

        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        errors = []
        errors += vcs_net_helper.validate_model(
            self.context_api)

        self.assertEqual(len(errors), 0)

    def test_validation_vips_on_diff_net_vs_number_of_active_nodes(self):
        self.setup_model()
        self._add_service_to_model(1, active="2", standby="0", no_of_ips=2)

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip",
            network_name='traffic',
            ipaddress='10.10.11.20')

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip1",
            network_name='mgmt',
            ipaddress='10.10.10.53')

        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        errors = []
        for cluster in self.context_api.query("vcs-cluster"):
            errors += vcs_net_helper._validate_vip_collection(
                cluster)

        self.assertEqual(len(errors), 2)
        expected = sorted(["</deployments/test/clusters/cluster1/services/service1/runtimes/runtime1 - ValidationError - IPs for network traffic not a multiple of active count 2>", "</deployments/test/clusters/cluster1/services/service1/runtimes/runtime1 - ValidationError - IPs for network mgmt not a multiple of active count 2>"])

        self.assertEqual(self.string_and_sort(errors), expected)

    def test_validation_vcs_ip_network_not_created_in_infrastructure(self):
        self.setup_model()
        self._add_service_to_model(1, no_of_ips=1)

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip",
            network_name='traffic',
            ipaddress='10.10.11.20')

        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        errors = []
        errors += vcs_net_helper.validate_model(
            self.context_api)

        expected = sorted(["</deployments/test/clusters/cluster1/services/service1/runtimes/runtime1/ipaddresses/vcs_ip - ValidationError - A matching 'traffic' network must be defined in /infrastructure/networking/networks/>"])
        self.assertEqual(len(errors), 1)
        self.assertEqual(self.string_and_sort(errors), expected)

    def test_validation_vcs_ip_network_doesnt_have_subnet_defined(self):
        self.setup_model()
        self._add_service_to_model(1, no_of_ips=1)

        self._add_item_to_model(
            'network',
            "/infrastructure/networking/networks/traffic2",
            name='traffic2')

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip",
            network_name='traffic2',
            ipaddress='10.10.12.20')

        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        errors = []
        errors += vcs_net_helper.validate_model(
            self.context_api)

        expected = sorted(["</deployments/test/clusters/cluster1/services/service1/runtimes/runtime1/ipaddresses/vcs_ip - ValidationError - A subnet must be defined for the network /infrastructure/networking/networks/traffic2>"])
        self.assertEqual(len(errors), 1)
        self.assertEqual(self.string_and_sort(errors), expected)

    def test_validation_vcs_ip_must_not_be_assigned_to_hearbeat_networks(self):
        self.setup_model()
        self._add_service_to_model(1, no_of_ips=1)
        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip",
            network_name='heartbeat1',
            ipaddress='10.10.11.20')

        errors = []
        errors += vcs_net_helper.validate_model(
            self.context_api)

        expected = sorted(['</deployments/test/clusters/cluster1/services/service1/runtimes/runtime1/ipaddresses/vcs_ip - ValidationError - Can not create VIPs on llt networks>'])

        self.assertEqual(self.string_and_sort(errors), expected)

    def test_validation_vcs_ip_network_not_assigned_on_nodes(self):
        self.setup_model()
        self._add_service_to_model(1, no_of_ips=1)

        self._add_item_to_model(
            'network',
            '/infrastructure/networking/networks/range_1',
            name='traffic',
            subnet='10.10.11.0/24')

        self._add_item_to_model(
            'eth',
            "/deployments/test/clusters/cluster1"
            "/nodes/node1/network_interfaces/if3",
            macaddress="08:00:27:5B:C1:42",
            network_name="traffic",
            #ipaddress='10.10.10.252',
            device_name="eth3",)

        self._add_item_to_model(
            'eth',
            "/deployments/test/clusters/cluster1"
            "/nodes/node2/network_interfaces/if3",
            macaddress="08:00:27:5B:C1:42",
            network_name="traffic",
            #ipaddress='10.10.10.252',
            device_name="eth3",)


        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip",
            network_name='traffic',
            ipaddress='10.10.11.20')

        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        errors = []
        errors += vcs_net_helper.validate_model(
            self.context_api)

        expected = sorted(["</deployments/test/clusters/cluster1/services/service1/runtimes/runtime1/ipaddresses/vcs_ip - ValidationError - An IP for network 'traffic' must be assigned to an interface on node mn1>",
                           "</deployments/test/clusters/cluster1/services/service1/runtimes/runtime1/ipaddresses/vcs_ip - ValidationError - An IP for network 'traffic' must be assigned to an interface on node mn2>"])

        self.assertEqual(len(errors), 2)
        self.assertEqual(self.string_and_sort(errors), expected)

    def test_VIPs_must_lie_in_subnet_of_network(self):
        self.setup_model()
        self._add_service_to_model(1, no_of_ips=1)

        self._add_item_to_model(
            'network',
            '/infrastructure/networking/networks/range_1',
            name='traffic',
            subnet='10.10.11.0/24')

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip",
            network_name='traffic',
            ipaddress='10.10.12.20')

        for i in range(1, 3):
            self._add_item_to_model(
                'eth',
                "/deployments/test/clusters/cluster1/nodes/node%s/network_interfaces/ip_1" % i,
                network_name='traffic',
                device_name='eth1',
                macaddress='aa:aa:aa:aa:aa:aa',
                ipaddress='10.10.11.%d' % i)

        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        errors = []
        errors += vcs_net_helper.validate_model(
            self.context_api)

        expected = sorted(["</deployments/test/clusters/cluster1/services/service1/runtimes/runtime1/ipaddresses/vcs_ip - ValidationError - VIPs must be in the subnet of their network defined in infrastructure>"])

        self.assertEqual(len(errors), 1)
        self.assertEqual(self.string_and_sort(errors), expected)

    def test_all_nodes_have_base_ip_for_vcs_network(self):
        self.setup_model()
        self._add_service_to_model(1, no_of_ips=1)

        self._add_item_to_model(
            'network',
            '/infrastructure/networking/networks/range_1',
            name='traffic',
            subnet='10.10.11.0/24')

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip",
            network_name='traffic',
            ipaddress='10.10.11.20')

        for i in range(1, 3):
            self._add_item_to_model(
                'eth',
                "/deployments/test/clusters/cluster1/nodes/node%s/network_interfaces/ip_1" % i,
                network_name="traffic",
                macaddress='aa:aa:aa:aa:aa:aa',
                device_name='eth1')

        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        errors = []
        errors += vcs_net_helper.validate_model(
            self.context_api)

        expected = sorted(["</deployments/test/clusters/cluster1/services/service1/runtimes/runtime1/ipaddresses/vcs_ip - ValidationError - An IP for network 'traffic' must be assigned to an interface on node mn1>",
                           "</deployments/test/clusters/cluster1/services/service1/runtimes/runtime1/ipaddresses/vcs_ip - ValidationError - An IP for network 'traffic' must be assigned to an interface on node mn2>"])

        self.assertEqual(len(errors), 2)
        self.assertEqual(self.string_and_sort(errors), expected)

    def test_validation(self):
        self.setup_model()
        self._add_service_to_model(1, no_of_ips=1)

        self._add_item_to_model(
            'network',
            '/infrastructure/networking/networks/range_1',
            name='traffic',
            subnet='10.10.11.0/24')

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip",
            network_name='traffic',
            ipaddress='10.10.11.20')

        for i in range(1, 3):
            self._add_item_to_model(
                'eth',
                "/deployments/test/clusters/cluster1/nodes/node%s/network_interfaces/ip_1" % i,
                network_name='traffic',
                device_name='eth1',
                macaddress='aa:aa:aa:aa:aa:aa',
                ipaddress='10.10.11.%d' % i)

        vcs_net_helper = LegacyVcsNetworkResource(VcsPlugin)

        errors = []
        errors += vcs_net_helper.validate_model(
            self.context_api)

        self.assertEqual(len(errors), 0)


class TestGetNetmask(unittest.TestCase):

    def test_success(self):
        api = mock.Mock(['query'])

        MockNetwork = mock.Mock(['subnet'])
        MockNetwork.subnet = '255.255.255.0/24'

        api.query.return_value = [MockNetwork]
        net_name = 'mgmt'
        expected_netmask = '255.255.255.0'
        self.assertEqual(_get_netmask(api, net_name), expected_netmask)


class TestSplitList(unittest.TestCase):
    '''
    Yield is a keyword that is used like return, except the function will
    return a generator. The return of this method is a generator
    '''
    def setUp(self):
        self.MockIP = mock.Mock(['network_name', 'ipaddress'])
        self.MockIP.network_name = 'traffic'
        self.MockIP.ipaddress = '10.10.10.151'

        self.MockIP2 = mock.Mock(['network_name', 'ipaddress'])
        self.MockIP2.network_name = 'traffic'
        self.MockIP2.ipaddress = '10.10.10.152'

    def test_success_n_is_1(self):
        l = [self.MockIP, self.MockIP2]
        n = 1

        index = 0
        for address in _split_list(l, n):
            expected_return = [l[index]]
            self.assertEqual(address, expected_return)
            index += 1

    def test_success_n_is_2(self):
        l = [self.MockIP, self.MockIP2]
        n = 2

        for address in _split_list(l, n):
            expected_return = l
            self.assertEqual(address, expected_return)

    def test_success_n_is_3(self):
        l = [self.MockIP, self.MockIP2]
        n = 3

        for address in _split_list(l, n):
            expected_return = l
            self.assertEqual(address, expected_return)

    def test_success_n_is_4(self):
        l = [self.MockIP, self.MockIP2]
        n = 4

        for address in _split_list(l, n):
            expected_return = l
            self.assertEqual(address, expected_return)


class TestResourceExists(VCSIntegrationBase):

    def test_false_empty_string(self):
        vcs_api = mock.Mock(['hares_list'])
        vcs_api.hares_list.return_value = ''

        nic_proxy_name = 'Res_NIC_Proxy_cluster1_cs1_eth0'
        self.assertEqual(resource_already_exists(vcs_api, nic_proxy_name),
                         False)

    def test_false_no_exists(self):
        vcs_api = mock.Mock(['hares_list'])
        vcs_api.hares_list.return_value = \
            'Res_App_cluster1_cs1_runtime1            \t\tmn1\n'\
            'Res_App_cluster1_cs1_runtime1            \t\tmn2\n'\
            'Res_IP_cluster1_cs1_runtime1_10_10_10_151\t\tmn1\n'\
            'Res_IP_cluster1_cs1_runtime1_10_10_10_151\t\tmn2\n'\
            'Res_NIC_cluster1_eth0                    \t\tmn1\n'\
            'Res_NIC_cluster1_eth0                    \t\tmn2\n'\
            'Res_Phantom_NIC_cluster1_eth0            \t\tmn1\n'\
            'Res_Phantom_NIC_cluster1_eth0            \t\tmn2'

        nic_proxy_name = 'Res_NIC_Proxy_cluster1_cs1_eth0'
        self.assertEqual(resource_already_exists(vcs_api, nic_proxy_name),
                         False)

    def test_false_not_exact_string(self):
        vcs_api = mock.Mock(['hares_list'])
        vcs_api.hares_list.return_value = \
            'Res_NIC_Proxy_cluster1_cs1_eth         \t\tmn1\n'\
            'Res_NIC_Proxy_cluster1_cs1_eth0m         \t\tmn2\n'\
            'Res_App_cluster1_cs1_runtime1            \t\tmn1\n'\
            'Res_App_cluster1_cs1_runtime1            \t\tmn2\n'\
            'Res_IP_cluster1_cs1_runtime1_10_10_10_151\t\tmn1\n'\
            'Res_IP_cluster1_cs1_runtime1_10_10_10_151\t\tmn2\n'\
            'Res_NIC_cluster1_eth0                    \t\tmn1\n'\
            'Res_NIC_cluster1_eth0                    \t\tmn2\n'\
            'Res_Phantom_NIC_cluster1_eth0            \t\tmn1\n'\
            'Res_Phantom_NIC_cluster1_eth0            \t\tmn2'

        nic_proxy_name = 'Res_NIC_Proxy_cluster1_cs1_eth0'
        self.assertEqual(resource_already_exists(vcs_api, nic_proxy_name),
                         False)

    def test_true(self):
        vcs_api = mock.Mock(['hares_list'])
        vcs_api.hares_list.return_value = \
            'Res_App_cluster1_cs1_runtime1            \t\tmn1\n'\
            'Res_App_cluster1_cs1_runtime1            \t\tmn2\n'\
            'Res_IP_cluster1_cs1_runtime1_10_10_10_151\t\tmn1\n'\
            'Res_IP_cluster1_cs1_runtime1_10_10_10_151\t\tmn2\n'\
            'Res_NIC_cluster1_eth0                    \t\tmn1\n'\
            'Res_NIC_cluster1_eth0                    \t\tmn2\n'\
            'Res_Phantom_NIC_cluster1_eth0            \t\tmn1\n'\
            'Res_Phantom_NIC_cluster1_eth0            \t\tmn2\n'\
            'Res_NIC_Proxy_cluster1_cs1_eth0          \t\tmn1\n'\
            'Res_NIC_Proxy_cluster1_cs1_eth0          \t\tmn2'

        nic_proxy_name = 'Res_NIC_Proxy_cluster1_cs1_eth0'
        self.assertEqual(resource_already_exists(vcs_api, nic_proxy_name),
                         True)


class TestAddNICProxy(VCSIntegrationBase):

    @mock.patch('vcsplugin.legacy.vcs_network_resource.resource_already_exists')
    @mock.patch('vcsplugin.legacy.vcs_network_resource.log')
    def test_success(self, log, _resource_already_exists):
        vcs_api = mock.Mock(['hares_add', 'hares_modify', 'hares_local'])
        service_group_name = 'NicGrp_eth0'
        cluster_item_id = 'cluster1'
        nic_proxy_name = "Res_NIC_Proxy_cluster1_cs1_traffic"
        node_interfaces = [{'hostname': 'mn1', 'interface': 'eth0'},
                           {'hostname': 'mn2', 'interface': 'eth0'}]

        resource_exists = [False, True, True]
        def mock_resource_already_exists(*args, **kwargs):
            return resource_exists.pop(0)

        _resource_already_exists.side_effect = mock_resource_already_exists
        _add_nic_proxy_resource(vcs_api, nic_proxy_name, node_interfaces,
                                service_group_name, cluster_item_id)

        self.assertEqual(vcs_api.hares_add.call_count, 1)
        self.assertEqual(vcs_api.hares_modify.call_count, 4)
        self.assertEqual(vcs_api.hares_add.call_args_list, [
            mock.call('Res_NIC_Proxy_cluster1_cs1_traffic', 'Proxy',
                      'NicGrp_eth0')
            ])
        self.assertEqual(vcs_api.hares_modify.call_args_list, [
            mock.call('Res_NIC_Proxy_cluster1_cs1_traffic', 'Critical', '1'),
            mock.call('Res_NIC_Proxy_cluster1_cs1_traffic', 'TargetResName',
                      'Res_NIC_cluster1_eth0', 'mn1'),
            mock.call('Res_NIC_Proxy_cluster1_cs1_traffic', 'TargetResName',
                      'Res_NIC_cluster1_eth0', 'mn2'),
            mock.call('Res_NIC_Proxy_cluster1_cs1_traffic', 'Enabled', '1')
            ])
        self.assertEqual(vcs_api.hares_local.call_args_list, [
            mock.call('Res_NIC_Proxy_cluster1_cs1_traffic', 'TargetResName')
            ])
        self.assertEqual(log.trace.info.call_args_list, [
            mock.call('VCS Creating NIC Proxy '
                      '"Res_NIC_Proxy_cluster1_cs1_traffic"')])

    @mock.patch('vcsplugin.legacy.vcs_network_resource.resource_already_exists')
    @mock.patch('vcsplugin.legacy.vcs_network_resource.log')
    def test_success_interfaces(self, log, _resource_already_exists):
        vcs_api = mock.Mock(['hares_add', 'hares_modify', 'hares_local'])
        service_group_name = 'NicGrp_eth0'
        cluster_item_id = 'cluster1'
        nic_proxy_name = "Res_NIC_Proxy_cluster1_cs1_mgmt"
        node_interfaces = [{'hostname': 'mn1', 'interface': 'eth0'},
                           {'hostname': 'mn2', 'interface': 'eth1'}]

        resource_exists = [False, True, True]
        def mock_resource_already_exists(*args, **kwargs):
            return resource_exists.pop(0)

        _resource_already_exists.side_effect = mock_resource_already_exists
        _add_nic_proxy_resource(vcs_api, nic_proxy_name, node_interfaces,
                                service_group_name, cluster_item_id)

        self.assertEqual(vcs_api.hares_add.call_count, 1)
        self.assertEqual(vcs_api.hares_modify.call_count, 4)
        self.assertEqual(vcs_api.hares_add.call_args_list, [
            mock.call('Res_NIC_Proxy_cluster1_cs1_mgmt', 'Proxy',
                      'NicGrp_eth0')
            ])
        self.assertEqual(vcs_api.hares_modify.call_args_list, [
            mock.call('Res_NIC_Proxy_cluster1_cs1_mgmt', 'Critical', '1'),
            mock.call('Res_NIC_Proxy_cluster1_cs1_mgmt', 'TargetResName',
                      'Res_NIC_cluster1_eth0', 'mn1'),
            mock.call('Res_NIC_Proxy_cluster1_cs1_mgmt', 'TargetResName',
                      'Res_NIC_cluster1_eth1', 'mn2'),
            mock.call('Res_NIC_Proxy_cluster1_cs1_mgmt', 'Enabled', '1')
            ])
        self.assertEqual(vcs_api.hares_local.call_args_list, [
            mock.call('Res_NIC_Proxy_cluster1_cs1_mgmt', 'TargetResName')
            ])
        self.assertEqual(log.trace.info.call_args_list, [
            mock.call('VCS Creating NIC Proxy '
                      '"Res_NIC_Proxy_cluster1_cs1_mgmt"')])

    @mock.patch('vcsplugin.legacy.vcs_network_resource.resource_already_exists')
    @mock.patch('vcsplugin.legacy.vcs_network_resource.log')
    def test_proxy_already_created(self, log, _resource_already_exists):
        vcs_api = mock.Mock(['hares_add', 'hares_modify'])
        service_group_name = 'NicGrp_eth0'
        cluster_item_id = 'cluster1'
        resource_name = "Res_NIC_Proxy_cluster1_cs1_eth0"
        node_interfaces = [{'hostname': 'mn1', 'interface': 'eth0'},
                           {'hostname': 'mn2', 'interface': 'eth0'}]

        resource_exists = [True]
        def mock_resource_already_exists(*args, **kwargs):
            return resource_exists.pop(0)

        _resource_already_exists.side_effect = mock_resource_already_exists
        _add_nic_proxy_resource(vcs_api, resource_name, node_interfaces,
                                service_group_name, cluster_item_id)

        self.assertEqual(vcs_api.hares_add.call_count, 0)
        self.assertEqual(vcs_api.hares_modify.call_count, 0)

    @mock.patch('vcsplugin.legacy.vcs_network_resource.resource_already_exists')
    @mock.patch('vcsplugin.legacy.vcs_network_resource.log')
    def test_target_resource_not_available(self, log, _resource_already_exists):
        vcs_api = mock.Mock(['hares_add', 'hares_modify', 'hares_local'])
        service_group_name = 'NicGrp_eth0'
        cluster_item_id = 'cluster1'
        resource_name = "Res_NIC_Proxy_cluster1_cs1_mgmt"
        node_interfaces = [{'hostname': 'mn1', 'interface': 'eth0'},
                           {'hostname': 'mn2', 'interface': 'eth0'}]

        resource_exists = [False, False, True]
        def mock_resource_already_exists(*args, **kwargs):
            return resource_exists.pop(0)

        _resource_already_exists.side_effect = mock_resource_already_exists

        try:
            _add_nic_proxy_resource(vcs_api, resource_name, node_interfaces,
                service_group_name, cluster_item_id)
        except VCSRuntimeException, e:
            pass

        self.assertEqual(vcs_api.hares_add.call_count, 1)
        self.assertEqual(vcs_api.hares_modify.call_count, 1)
        self.assertEqual(vcs_api.hares_add.call_args_list, [
            mock.call('Res_NIC_Proxy_cluster1_cs1_mgmt', 'Proxy',
                      'NicGrp_eth0')
            ])
        self.assertEqual(vcs_api.hares_modify.call_args_list, [
            mock.call('Res_NIC_Proxy_cluster1_cs1_mgmt', 'Critical', '1')
            ])
        self.assertEqual(vcs_api.hares_local.call_args_list, [
            mock.call('Res_NIC_Proxy_cluster1_cs1_mgmt', 'TargetResName')
            ])
        self.assertEqual(log.trace.info.call_args_list, [
            mock.call('VCS Creating NIC Proxy '
                      '"Res_NIC_Proxy_cluster1_cs1_mgmt"')])
        self.assertEqual(e.args, ('The TargetResName "Res_NIC_cluster1_eth0"'
            ' for the NIC Proxy "Res_NIC_Proxy_cluster1_cs1_mgmt" does not '
            'exist. The NIC resource required has not been set up.',))

    def test_get_node_interface_for_network_ipv6(self):

        self.setup_model()
        self._add_service_to_model(1, no_of_ips=1)

        self._add_item_to_model(
            'network',
            '/infrastructure/networking/networks/traffic',
            name='traffic')

        self._add_item_to_model(
            'vip',
            "/deployments/test/clusters/cluster1/services/service1"
            "/runtimes/runtime1/ipaddresses/vcs_ip",
            network_name='traffic',
            ipaddress='fdde:4d7e:d471::835:140:219/64')

        for i in range(1, 3):
            self._add_item_to_model(
                'eth',
                "/deployments/test/clusters/cluster1/nodes/node%s/network_interfaces/ip_1" % i,
                network_name='traffic',
                device_name='eth3',
                macaddress='aa:aa:aa:aa:aa:aa',
                ipv6address='fdde:4d7e:d471::835:140:10%d/64' % i)

        service = self.context_api.query('vcs-clustered-service', name='cs1')

        node_interfaces = _get_node_interface_for_network(service[0], 'traffic')
        self.assertEqual(len(node_interfaces), 2)
        self.assertEqual(node_interfaces, [
            {'interface': 'eth3', 'hostname': 'mn1'},
            {'interface': 'eth3', 'hostname': 'mn2'}
        ])


class TestCreateIPResources(unittest.TestCase):

    def test_success_parallel(self):
        vcs_api = mock.Mock(['hares_add', 'hares_modify', 'hares_local', 'hares_probe'])
        res_name = 'Res_IP_cluster1_cs1_runtime1_mgmt_1'
        addresses = ['10.10.10.155', '10.10.10.156']
        netmask = '255.255.255.0'
        interfaces = [{'hostname': 'mn1', 'interface': 'eth0'},
                      {'hostname': 'mn2', 'interface': 'eth0'}]
        group = 'Grp_CS_cluster1_cs1'
        parallel = True

        _create_ip_resource(vcs_api, res_name, addresses, netmask, interfaces,
            group, parallel)

        self.assertEqual(vcs_api.hares_add.call_args_list, [
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'IP', 'Grp_CS_cluster1_cs1'),
            ])
        self.assertEqual(vcs_api.hares_modify.call_args_list, [
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'Critical', '1'),
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'Device', 'eth0', 'mn1'),
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'Device', 'eth0', 'mn2'),
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'Address', '10.10.10.155', 'mn1'),
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'Address', '10.10.10.156', 'mn2'),
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'NetMask', '255.255.255.0'),
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'Enabled', '1'),
            ])
        self.assertEqual(vcs_api.hares_local.call_args_list, [
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'Device'),
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'Address'),
            ])
        self.assertEqual(vcs_api.hares_probe.call_args_list, [
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'mn1'),
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'mn2'),
            ])

    def test_success_failover(self):
        vcs_api = mock.Mock(['hares_add', 'hares_modify', 'hares_local', 'hares_probe'])
        res_name = 'Res_IP_cluster1_cs1_runtime1_mgmt_1'
        addresses = ['10.10.10.155']
        netmask = '255.255.255.0'
        interfaces = [{'hostname': 'mn1', 'interface': 'eth0'},
                      {'hostname': 'mn2', 'interface': 'eth1'}]
        group = 'Grp_CS_cluster1_cs1'
        parallel = False

        _create_ip_resource(vcs_api, res_name, addresses, netmask, interfaces,
            group, parallel)

        self.assertEqual(vcs_api.hares_add.call_args_list, [
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'IP', 'Grp_CS_cluster1_cs1'),
            ])
        self.assertEqual(vcs_api.hares_modify.call_args_list, [
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'Critical', '1'),
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'Device', 'eth0', 'mn1'),
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'Device', 'eth1', 'mn2'),
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'Address', '10.10.10.155'),
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'NetMask', '255.255.255.0'),
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'Enabled', '1'),
            ])
        self.assertEqual(vcs_api.hares_local.call_args_list, [
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'Device'),
            ])
        self.assertEqual(vcs_api.hares_probe.call_args_list, [
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'mn1'),
            mock.call('Res_IP_cluster1_cs1_runtime1_mgmt_1', 'mn2'),
            ])

