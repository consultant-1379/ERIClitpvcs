"""
Unit tests for network_resource.py.
"""

import unittest

import netaddr
import mock

from vcsplugin import network_resource
from vcsplugin.vcs_exceptions import VCSRuntimeException
from base_vcs_integration import VCSIntegrationBase
from test_vcs_utils import MockVip


def test_chunks():
    assert (list(network_resource.chunks(range(6), 2))
            == [[0, 1], [2, 3], [4, 5]]), 'Wrong chunks returned.'


def test_ipv6_prefixlen():
    assert '123' == network_resource.ipv6_prefixlen('123234/123')


def test_strip_prefixlen():
    assert '123' == network_resource.strip_prefixlen('123/4556')


@mock.patch('vcsplugin.network_resource.VcsBaseHelper')
def test_service_group_name(mock_base):
    network_resource.service_group_name(
        mock.Mock(item_id='foo'),
        mock.Mock(item_id='bar'))
    mock_base.get_group_name.assert_called_with('bar', 'foo')


class MockPlugin(object):
    def callback_method(self):
        pass


class TestVIPModel(unittest.TestCase):
    def setUp(self):
        self.model_api = mock.Mock()
        self.vcs_api = mock.Mock()
        self.model = network_resource.VIPModel(self.model_api, self.vcs_api)

    def test_networks(self):
        _ = self.model.networks
        self.model_api.query.assert_called_with('network')

    def test_services(self):
        self.model_api = mock.MagicMock()
        self.model = network_resource.VIPModel(self.model_api, self.vcs_api)
        _ = self.model.services
        self.model_api.query.assert_called_with('vcs-clustered-service')

    def test_clusters(self):
        _ = self.model.clusters
        self.model_api.query.assert_called_with('vcs-cluster')

    def test_existing_resources(self):
        hares_list = mock.Mock()
        hares_list.return_value = """foo bar\nbang        billy\nsilly\t\tlad
        """
        self.model.vcs_api.hares_list = hares_list
        self.assertEquals(
            ['foo', 'bang', 'silly'],
            self.model.existing_resources)

    def test_resource_exists(self):
        hares_list = mock.Mock()
        hares_list.return_value = """foo bar\nbang        billy\nsilly\t\tlad"""
        self.model.vcs_api.hares_list = hares_list
        self.assertTrue(self.model.resource_exists('foo'))
        self.assertTrue(self.model.resource_exists('bang'))
        self.assertTrue(self.model.resource_exists('silly'))
        self.assertFalse(self.model.resource_exists('si123lly'))
        self.assertFalse(self.model.resource_exists(''))

    def test_link_ip_to_proxy(self):
        self.model.link_ip_to_proxy(1, 2)
        self.vcs_api.hares_link.assert_called_with(1, 2)

    def test_get_netmask(self):
        self.model_api.query.return_value = [
            mock.Mock(subnet='10.10.10.10/24')
        ]
        self.assertEquals(
            '255.255.255.0',
            self.model.get_netmask('foo'))
        self.model_api.query.return_value = [
            mock.Mock(subnet=None, network_name='bar')
        ]
        try:
            self.model.get_netmask('foo')
            self.assertTrue(False)
        except ValueError:
            self.assertTrue(True)

    def test_llt_names(self):
        self.model_api.query.return_value = [
            mock.Mock(llt_nets='foo,bar'),
            mock.Mock(llt_nets='baz')
        ]
        self.assertEqual(
            ('foo', 'bar', 'baz'),
            self.model.llt_names)

    def test_legacy_vips(self):
        self.model_api.query.return_value = [mock.Mock(ipaddresses=[1, 2, 3])]
        self.assertEqual(
            [1, 2, 3],
            list(self.model.legacy_vips))

    def test_get_vips(self):
        service = mock.Mock(ipaddresses=[1, 2, 3])
        service.is_for_removal.return_value = False
        self.assertEqual([1, 2, 3], list(self.model.get_vips(service=service)))
        cluster = mock.Mock(services=[service, service])
        self.assertEqual(
            [1, 2, 3, 1, 2, 3],
            list(self.model.get_vips(cluster=cluster)))

        self.model.query.return_value = [service]
        self.assertEqual(
            [1, 2, 3],
            list(self.model.get_vips()))

class TestVIPDeploymentValidator(unittest.TestCase):
    def setUp(self):
        self.model = mock.Mock()
        self.model.get_vips = mock.MagicMock()
        self.model.get_vips.return_value = [
            mock.Mock(ipaddress='2001:cdba:0000:0000:0000:0000:3257:9652'),
            mock.Mock(ipaddress='127.0.0.1')
        ]
        self.validator = network_resource.NetworkResourceHelper(mock.MagicMock())
        self.validator._model = self.model

    def test_validation_vips_not_allowed_on_initial_interfaces(self):
        self.model.get_vips.return_value = [
            get_mock_vip('1', 'mgmt', False, True),
            get_mock_vip('2', 'mgmt', False, True),
            get_mock_vip('3', 'traffic1', False, True),
            get_mock_vip('4', 'traffic1', False, True),
        ]

        applied_interface = mock.Mock(network_name='mgmt',
                                      is_initial=lambda: False)
        initial_interface = mock.Mock(network_name='traffic1',
                                      is_initial=lambda: True)
        interfaces = dict()
        interfaces['network-interface'] = {'mgmt': applied_interface,
                                           'traffic1': initial_interface}
        node = mock.Mock(hostname='mn1')
        node.query = (lambda item_type, network_name:
                      [interfaces[item_type][network_name]])
        node.is_initial.return_value = False

        self.model.services = [mock.Mock(
            applied_properties={"node_list": "node_1"},
            active=1,
            node_list="node_1",
            nodes=[node],
            is_initial=lambda: False,
            is_for_removal=lambda: False)]

        errors = list(self.validator
                      ._validate_vips_on_interfaces_in_initial(self.model))

        self.assertEqual(2, len(errors))

    def test_validate_vips_on_interfaces_in_initial_no_vips(self):
        self.model.get_vips.return_value = [
            get_mock_vip('1', 'mgmt', True, False),
            get_mock_vip('2', 'mgmt', False, True),
            get_mock_vip('3', 'traffic1', True, False),
            get_mock_vip('4', 'traffic1', False, True),
        ]

        applied_interface = mock.Mock(network_name='mgmt',
                                      is_initial=lambda: False)
        initial_interface = mock.Mock(network_name='traffic1',
                                      is_initial=lambda: True)
        interfaces = dict()
        interfaces['network-interface'] = {'mgmt': applied_interface,
                                           'traffic1': initial_interface}
        node = mock.Mock(hostname='mn1')
        node.query.return_value = []
        node.is_initial.return_value = False

        self.model.services = [mock.Mock(
            applied_properties={"node_list": "node_1"},
            active=1,
            node_list="node_1",
            nodes=[node],
            is_initial=lambda: False,
            is_for_removal=lambda: False)]

        errors = list(self.validator
                      ._validate_vips_on_interfaces_in_initial(self.model))

        self.assertEqual(0, len(errors))

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def test_validate_vips_on_interfaces_in_initial_expansion(self, mock_os_reinstall):
        self.model.get_vips.return_value = [
            get_mock_vip('1', 'mgmt', False, True),
            get_mock_vip('2', 'mgmt', False, True),
            get_mock_vip('3', 'traffic1', False, True),
            get_mock_vip('4', 'traffic1', False, True),
        ]

        applied_interface1 = mock.Mock(network_name='mgmt',
                                       is_initial=lambda: False)
        applied_interface2 = mock.Mock(network_name='traffic1',
                                       is_initial=lambda: False)
        initial_interface1 = mock.Mock(network_name='mgmt',
                                       is_initial=lambda: True)
        initial_interface2 = mock.Mock(network_name='traffic1',
                                       is_initial=lambda: True)
        n1interfaces = dict()
        n1interfaces['network-interface'] = {'mgmt': applied_interface1,
                                             'traffic1': applied_interface2}
        node1 = mock.Mock(hostname='mn1',
                          item_id="node_1")
        node1.query.return_value = []
        node1.query = (lambda item_type, network_name:
                           [n1interfaces[item_type][network_name]])
        node1.is_initial.return_value = False
        n2interfaces = dict()
        n2interfaces['network-interface'] = {'mgmt': initial_interface1,
                                             'traffic1': initial_interface2}
        node2 = mock.Mock(hostname='mn1',
                          item_id="node_2")
        node2.query.return_value = []
        node2.query = (lambda item_type, network_name:
                           [n2interfaces[item_type][network_name]])
        node2.is_initial.return_value = False

        self.model.services = [mock.Mock(
            applied_properties={"node_list": "node_1",
                                "active": "1",
                                "standby": "0"},
            active=2,
            standby=0,
            node_list="node_1,node_2",
            nodes=[node1, node2],
            is_initial=lambda: False,
            is_for_removal=lambda: False)]

        errors = list(self.validator
                      ._validate_vips_on_interfaces_in_initial(self.model))
        print errors

        self.assertEqual(0, len(errors))

    def test_well_formed_vip(self):
        self.assertEqual([], list(self.validator._validate_well_formed_vips(self.model)))
        self.model.get_vips.assert_called_once_with()
        self.assertEqual(
            ['2001:cdba:0000:0000:0000:0000:3257:9652', '127.0.0.1'],
            [ip.ipaddress for ip in self.model.get_vips()]
        )

    def test_validate_application_exists(self):
        self.model.services = [
            mock.Mock(ipaddresses=[mock.Mock()], applications=[])]
        self.assertEqual(1, len(list(self.validator._validate_application(self.model))))
        self.model.services = [
            mock.Mock(ipaddresses=[mock.Mock()], applications=[mock.Mock()])]
        self.assertEqual(0, len(list(self.validator._validate_application(self.model))))

    @mock.patch('vcsplugin.network_resource.is_vip_deactivation_pair')
    def test_get_duplicate_vips(self, patch_deactivation):
        patch_deactivation.return_value = False
        vip1 = MockVip(1)
        vip2 = MockVip(2)
        vips = map(MockVip, range(3,10))
        vips.append(vip1)
        vips.append(vip2)
        self.assertEquals(set(), self.validator.get_duplicate_vips(vips))
        self.assertEquals(set(), self.validator.get_duplicate_vips([]))
        dupe_1 = MockVip(1)
        vips.append(dupe_1)
        self.assertEquals(set([dupe_1, vip1]),
                          self.validator.get_duplicate_vips(vips))
        dupe_2 = MockVip(2)
        vips.append(dupe_2)
        self.assertEquals(set([dupe_1, vip1, dupe_2, vip2]),
                          self.validator.get_duplicate_vips(vips))

    def test_vip_on_llt_network(self):
        llt_names = ('llt1', 'llt2')
        vip = MockVip(network_name='llt1')
        self.assertTrue(self.validator.vip_on_llt_network(vip, llt_names))
        vip = MockVip()
        self.assertFalse(self.validator.vip_on_llt_network(vip, llt_names))

    def test_has_correct_amount_vips(self):
        v1 = MockVip('192.168.0.1')
        v2 = MockVip('192.168.0.2')
        v3 = MockVip('192.168.0.3')
        v4 = MockVip('192.168.0.4')
        v5 = MockVip('2001:abcd:ef::1/64')
        v6 = MockVip('2001:abcd:ef::2/64')
        service = mock.Mock(active=1)
        self.assertTrue(
            self.validator.has_correct_amount_vips([],
                                                   1,
                                                   network_resource.is_ipv4))
        self.assertTrue(self.validator.has_correct_amount_vips(
            [v1, v2], 1, network_resource.is_ipv4))
        self.assertTrue(self.validator.has_correct_amount_vips(
            [v1], 1, network_resource.is_ipv4))
        self.assertTrue(self.validator.has_correct_amount_vips(
            [v1, v5], 1, network_resource.is_ipv4))
        service = mock.Mock(active=2)
        self.assertTrue(self.validator.has_correct_amount_vips(
            [v1, v2], 2, network_resource.is_ipv4))
        self.assertTrue(self.validator.has_correct_amount_vips(
            [v1, v2, v3, v4], 2, network_resource.is_ipv4))
        self.assertTrue(self.validator.has_correct_amount_vips(
            [v1, v2, v3, v4, v5, v6], 2, network_resource.is_ipv4))
        self.assertFalse(self.validator.has_correct_amount_vips(
            [v1, v2, v3], 2, network_resource.is_ipv4))
        self.assertFalse(self.validator.has_correct_amount_vips(
            [v1, v2, v3, v5], 2, network_resource.is_ipv4))

    def test_vip_on_subnet(self):
        vip = MockVip('192.168.1.1')
        subnet = '192.168.1.0/24'
        self.assertTrue(self.validator.vip_in_subnet(vip, subnet))
        subnet = '10.10.10.0/24'
        self.assertFalse(self.validator.vip_in_subnet(vip, subnet))

    def test_network_has_subnet(self):
        network = mock.Mock(subnet=None)
        self.assertFalse(self.validator.network_has_subnet(network))
        network = mock.Mock(subnet='192.168.1.0/24')
        self.assertTrue(self.validator.network_has_subnet(network))

    def test_network_for_vip(self):
        net1 = mock.Mock()
        net1.name = 'net1'
        net2 = mock.Mock()
        net2.name = 'net2'
        networks = [net1, net2]

        vip = MockVip(network_name='foo')
        self.assertEquals(None, self.validator.network_for_vip(vip, networks))
        vip = MockVip(network_name='net1')
        self.assertTrue(
            'net1' == self.validator.network_for_vip(
                vip, networks).name)

    def test_has_network_defined(self):
        net1 = mock.Mock()
        net1.name = 'net1'
        net2 = mock.Mock()
        net2.name = 'net2'
        networks = [net1, net2]
        vip = MockVip(network_name='foo')
        self.assertFalse(self.validator.has_network_defined(vip, networks))
        vip = MockVip(network_name='net1')
        self.assertTrue(self.validator.has_network_defined(vip, networks))
        vip = MockVip(network_name='net2')
        self.assertTrue(self.validator.has_network_defined(vip, networks))

    def test_node_configured_for_vip(self):
        node = mock.Mock(network_interfaces=[
            mock.Mock(network_name='foo'),
            mock.Mock(network_name='bar')])
        vip = MockVip(network_name='baz')
        self.assertFalse(self.validator.node_configured_for_vip(node, vip))
        vip = MockVip(network_name='foo')
        self.assertTrue(self.validator.node_configured_for_vip(node, vip))

    def test_ip_obj_from_vip(self):
        vip = MockVip('10.10.10.10')
        self.assertTrue(
            isinstance(self.validator.ip_obj_from_vip(vip), netaddr.IPAddress))
        vip = MockVip('FE80:0000:0000:0000:0202:B3FF:FE1E:8329')
        self.assertTrue(
            isinstance(self.validator.ip_obj_from_vip(vip), netaddr.IPAddress))

    def test_has_well_formed_ipaddress(self):
        vip = MockVip('10.0.0.0')
        self.assertTrue(self.validator.has_well_formed_ipaddress(vip))
        vip = MockVip('FE80:0000:0000:0000:0202:B3FF:FE1E:8329')
        self.assertTrue(self.validator.has_well_formed_ipaddress(vip))
        vip = MockVip('FE80::0202:B3FF:FE1E:8329')
        self.assertTrue(self.validator.has_well_formed_ipaddress(vip))
        vip = MockVip('fwef23rf324')
        self.assertFalse(self.validator.has_well_formed_ipaddress(vip))
        vip = MockVip('')
        self.assertFalse(self.validator.has_well_formed_ipaddress(vip))

    def test_ipv6(self):
        ip = 'FE80:0000:0000:0000:0202:B3FF:FE1E:8329'
        self.assertTrue(network_resource.is_ipv6(ip))
        ip = 'FE80::0202:B3FF:FE1E:8329'
        self.assertTrue(network_resource.is_ipv6(ip))
        self.assertFalse(network_resource.is_ipv6('fwfew'))
        try:
            self.assertFalse(network_resource.is_ipv6(''))
            self.assertTrue(False)
        except netaddr.AddrFormatError:
            self.assertTrue(True)

    def test_ipv4(self):
        ip = '10.10.10.10'
        self.assertTrue(network_resource.is_ipv4(ip))
        ip = '001.001.001.001'
        self.assertTrue(network_resource.is_ipv4(ip))
        self.assertFalse(network_resource.is_ipv4(None))
        self.assertFalse(network_resource.is_ipv4('fwfew'))
        try:
            self.assertFalse(network_resource.is_ipv4(''))
            self.assertTrue(False)
        except netaddr.AddrFormatError:
            self.assertTrue(True)

    def test_well_formed_vips(self):
        self.model.get_vips.return_value = [
            MockVip('invalid address', 'dwfwe')
        ]
        self.assertTrue(1, len(list(self.validator._validate_well_formed_vips(self.model))))

    def test_vips_on_llt(self):
        self.model.get_vips.return_value = [
            MockVip('invalid address', 'llt1')
        ]
        self.model.llt_names = ['llt1', 'llt2']
        self.assertEqual(1, len(list(self.validator._validate_vips_on_llt_network(self.model))))
        self.model.get_vips.return_value = [
            MockVip('invalid address', 'mgmt')
        ]
        self.assertEqual(0, len(list(self.validator._validate_vips_on_llt_network(self.model))))

    @mock.patch('vcsplugin.network_resource.is_vip_deactivation_pair')
    def test_duplicate_vip_ipaddress(self, patch_deactivation):
        patch_deactivation.return_value = False
        self.model.get_vips.return_value = [
            MockVip('invalid address', 'llt1')
        ]
        self.model.legacy_vips = []
        self.assertEqual(0, len(list(self.validator._validate_duplicate_vip_ipaddress(self.model))))
        vip = MockVip('10.10.10.10', 'llt1')
        # Core has implemented comparison methods on types.
        self.model.get_vips.return_value = [
            vip, vip
        ]
        self.model.legacy_vips = []
        self.assertEqual(1, len(list(self.validator._validate_duplicate_vip_ipaddress(self.model))))
        self.model.get_vips.return_value = [vip]
        self.model.legacy_vips = [vip]
        self.assertEqual(1, len(list(self.validator._validate_duplicate_vip_ipaddress(self.model))))

    def test_networks_defined(self):
        self.model.get_vips.return_value = [
            MockVip('10.10.10.10', 'mgmt')
        ]
        network = mock.Mock()
        network.name = 'mgmt'
        self.model.networks = [network]
        self.assertEqual(0, len(list(self.validator._validate_networks_defined(self.model))))
        network.name = 'foobar'
        self.model.networks = [network]
        self.assertEqual(1, len(list(self.validator._validate_networks_defined(self.model))))

    def test_vip_subnets_defined(self):
        self.model.get_vips.return_value = [
            MockVip('10.10.10.10', 'mgmt')
        ]
        network = mock.Mock(subnet=None)
        network.name = 'mgmt'
        self.model.networks = [network]
        self.assertEqual(1, len(list(self.validator._validate_vip_subnets_defined(self.model))))

        self.model.get_vips.return_value = [
            MockVip('10.10.10.10', 'mgmt')
        ]
        network = mock.Mock(subnet='10.10.10.0/24')
        network.name = 'mgmt'
        self.model.networks = [network]
        self.assertEqual(0, len(list(self.validator._validate_vip_subnets_defined(self.model))))

        self.model.get_vips.return_value = [
            MockVip('FE80:0000:0000:0000:0202:B3FF:FE1E:8329', 'mgmt')
        ]
        network = mock.Mock(subnet=None)
        network.name = 'mgmt'
        self.model.networks = [network]
        self.assertEqual(0, len(list(self.validator._validate_vip_subnets_defined(self.model))))

    def test_correct_amount_vips(self):
        self.model.services = [mock.Mock(active=1, is_for_removal=lambda: False)]
        self.model.get_vips.return_value = [
            MockVip('1', '1'),
            MockVip('2', '2'),
            MockVip('3', '3')]
        self.assertEqual(0, len(list(self.validator._validate_correct_amount_vips(self.model))))

        self.model.services = [mock.Mock(active=2, is_for_removal=lambda: False)]
        self.assertEqual(3, len(list(self.validator._validate_correct_amount_vips(self.model))))

        self.model.services = [mock.Mock(active=1)]
        self.assertEqual(0, len(list(self.validator._validate_correct_amount_vips(self.model))))

    def test_num_of_new_ips_per_ip_resource_errors_all_is_initial(self):
        net1 = mock.Mock()
        net1.name = '1'
        net2 = mock.Mock()
        net2.name = '2'
        net3 = mock.Mock()
        net3.name = '3'
        self.model.networks = [net1, net2, net3]
        self.model.services = [mock.Mock(active=2,
                                         applied_properties={"active": "1"},
                                         is_for_removal=lambda: False)]
        self.model.get_vips.return_value = [
            get_mock_vip('1', '1', False, True),
            get_mock_vip('2', '2', False, True),
            get_mock_vip('3', '3', False, True)]

        self.model.query.return_value = [net1, net2, net3]

        errs = len(list(self.validator._validate_num_of_new_ips_per_ip_resource(self.model)))
        self.assertEqual(3, errs)

    def test_num_of_new_ips_per_ip_resource_no_errors_half_is_initial(self):
        net1 = mock.Mock()
        net1.name = '1'
        net2 = mock.Mock()
        net2.name = '2'
        net3 = mock.Mock()
        net3.name = '3'
        self.model.networks = [net1, net2, net3]
        self.model.services = [mock.Mock(active=2,
                                         applied_properties={"active": "1"},
                                         is_for_removal=lambda: False)]

        self.model.query.return_value = [net1, net2, net3]
        self.model.get_vips.return_value = [
            get_mock_vip('1', '1', True, False),
            get_mock_vip('2', '2', True, False),
            get_mock_vip('3', '1', False, True),
            get_mock_vip('4', '2', False, True)]
        errs = len(list(self.validator._validate_num_of_new_ips_per_ip_resource(self.model)))
        self.assertEqual(0, errs)

    def test_num_of_new_ips_per_ip_resource_no_errors_active_count_same(self):
        net1 = mock.Mock()
        net1.name = '1'
        net2 = mock.Mock()
        net2.name = '2'
        net3 = mock.Mock()
        net3.name = '3'
        self.model.networks = [net1, net2, net3]
        self.model.services = [mock.Mock(active=1,
                                         applied_properties={"active": "1"},
                                         is_for_removal=lambda: False)]

        self.model.query.return_value = [net1, net2, net3]
        errs = len(list(self.validator._validate_num_of_new_ips_per_ip_resource(self.model)))
        self.assertEqual(0, errs)

    def test_num_of_new_ips_per_ip_resource_error_same_network(self):
        net1 = mock.Mock()
        net1.name = '1'
        net2 = mock.Mock()
        net2.name = '2'
        net3 = mock.Mock()
        net3.name = '3'
        self.model.networks = [net1, net2, net3]
        self.model.services = [mock.Mock(active=2,
                                         applied_properties={"active": "1"},
                                         is_for_removal=lambda: False)]

        self.model.get_vips.return_value = [
            get_mock_vip('1', '1', True, False),
            get_mock_vip('2', '2', True, False),
            get_mock_vip('3', '3', False, True)]

        self.model.query.return_value = [net1, net2, net3]

        errs = len(list(self.validator._validate_num_of_new_ips_per_ip_resource(self.model)))
        self.assertEqual(3, errs)

    def test_num_of_new_ips_per_ip_resource_error_not_same_network(self):
        net1 = mock.Mock()
        net1.name = '1'
        net2 = mock.Mock()
        net2.name = '2'
        net3 = mock.Mock()
        net3.name = '3'
        self.model.networks = [net1, net2, net3]
        self.model.services = [mock.Mock(active=2,
                                         applied_properties={"active": "1"},
                                         is_for_removal=lambda: False)]

        self.model.get_vips.return_value = [
            get_mock_vip('1', '1', True, False),
            get_mock_vip('2', '2', True, False),
            get_mock_vip('3', '1', False, True)]

        self.model.query.return_value = [net1, net2, net3]
        errs = len(list(self.validator._validate_num_of_new_ips_per_ip_resource(self.model)))
        self.assertEqual(3, errs)

    def test_num_of_new_v6_ips_per_ip_resource_error_same_network(self):
        net1 = mock.Mock()
        net1.name = '1'
        net2 = mock.Mock()
        net2.name = '2'
        net3 = mock.Mock()
        net3.name = '3'
        self.model.networks = [net1, net2, net3]
        self.model.services = [mock.Mock(active=2,
                                         applied_properties={"active": "1"},
                                         is_for_removal=lambda: False)]

        self.model.get_vips.return_value = [
            get_mock_vip('1', '1', True, False),
            get_mock_vip('2', '1', True, False),
            get_mock_vip('1::1', '1', True, False),
            get_mock_vip('2::2', '1', True, False),
            get_mock_vip('3', '1', False, True),
            get_mock_vip('3::3', '1', False, True),
            get_mock_vip('4::4', '1', False, True),
            get_mock_vip('5::5', '1', False, True)]

        self.model.query.return_value = [net1]
        errs = len(list(self.validator._validate_num_of_new_ips_per_ip_resource(self.model)))
        self.assertEqual(2, errs)

    def test_num_of_new_ips_per_ip_resource_after_removal(self):
        net1 = mock.Mock()
        net1.name = 'net1'
        self.model.networks = [net1]
        self.model.services = [mock.Mock(active=2,
                                         applied_properties={"active": "2"},
                                         is_for_removal=lambda: True)]
        self.model.get_vips.return_value = [
            get_mock_vip('1', 'net1', False, False, True),
            get_mock_vip('2', 'net1', False, False, True),
            get_mock_vip('3', 'net1', False, False, True),
            get_mock_vip('4', 'net1', False, False, True),
            get_mock_vip('1::1', 'net1', False, False, True),
            get_mock_vip('2::2', 'net1', False, False, True),
            get_mock_vip('3::3', 'net1', False, False, True),
            get_mock_vip('4::4', 'net1', False, False, True)]

        self.model.query.return_value = [net1]
        errs = list(self.validator._validate_num_of_new_ips_per_ip_resource(self.model))
        self.assertEqual(0, len(errs))

    def test_validate(self):
        api = mock.MagicMock()
        self.assertTrue(isinstance(self.validator.validate_model(api), list))


class TestBaseResource(unittest.TestCase):
    def setUp(self):
        self.resource = network_resource.BaseResource()

    def test_create_resources(self):
        try:
            self.resource.create_resources(mock.Mock())
            self.assertTrue(False)
        except NotImplementedError:
            self.assertTrue(True)

    def test_nic_for_network(self):
        node = mock.Mock()
        interface = mock.Mock(device_name='foonic')
        interface.is_for_removal.return_value = False
        node.query.return_value = [interface]
        self.assertEqual('foonic', self.resource.nic_for_network(node, 'foo'))

    def test_nics_for_network(self):
        nodes=[
            mock.Mock(hostname='foo'), mock.Mock(hostname='bar')]
        self.resource.service = mock.Mock(nodes)
        self.resource.network = 'foo'
        self.resource.nic_for_network = mock.Mock(return_value='bill')
        self.assertEqual(
            {'foo': 'bill', 'bar': 'bill'},
            self.resource.nics_for_network(nodes))


class TestIPResources(unittest.TestCase):
    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def setUp(self, mock_os_reinstall):
        mock_os_reinstall = mock.Mock(return_value=False)
        self.ip1 = mock.Mock(ipaddress='10.10.10.10', network_name='mgmt')
        self.ip2 = mock.Mock(ipaddress='2001:cdba:0000:0000:0000:0000:3257:9652',
                             network_name='mgmt')
        self.ip3 = mock.Mock(ipaddress='10.10.10.11', network_name='mgmt')
        self.ip4 = mock.Mock(ipaddress='2001:cdba:0:0:0:0:3257:9653',
                             network_name='mgmt')
        self.ip5 = mock.Mock(ipaddress='10.10.10.12', network_name='mgmt')
        self.ip6 = mock.Mock(ipaddress='10.10.10.13', network_name='mgmt')
        self.ipaddresses = [self.ip1, self.ip2]
        self.cluster = mock.Mock(item_id="cluster",
                                 is_initial=lambda: False,
                                 services=[])
        intf1 = mock.Mock(device_name="eth0",
                          is_for_removal=lambda: False)
        self.node1 = mock.Mock(item_id="mn1",
                               hostname="node1",
                               query=lambda x,network_name: [intf1])
        self.node2 = mock.Mock(item_id="mn2",
                               hostname="node2",
                               query=lambda x,network_name: [intf1])
        self.service = mock.Mock(active="1", standby="1",
                                 applications=[mock.Mock(item_id="application")],
                                 applied_properties={'node_list': "mn1,mn2",
                                                     'active': "1",
                                                     'standby': "1"},
                                 node_list="mn1,mn2",
                                 nodes=[self.node1, self.node2],
                                 ipaddresses=self.ipaddresses,
                                 is_updated=lambda: False,
                                 item_id="service",
                                 is_for_removal=lambda: False,
                                 get_cluster= lambda: self.cluster)
        self.model = mock.Mock(get_netmask=lambda x: "netmask")
        self.resource = network_resource.IPResources(
            self.ipaddresses,
            self.cluster,
            self.service,
            self.model)

    def _get_node_list(self, active, standby):
        return ",".join(["mn{0}".format(i+1)
                         for i in xrange(int(active)+int(standby))])

    def _get_nodes(self, active, standby):
        return [mock.Mock(item_id="mn{0}".format(i+1))
                for i in xrange(int(active)+int(standby))]

    def prepare_ipresource(self, active, standby,
                           ipaddresses = None,
                           update_applied_properties = False):
        self.service.is_updated = lambda: True
        self.service.active = active
        self.service.standby = standby
        self.service.node_list = self._get_node_list(active, standby)
        self.service.nodes = self._get_nodes(active, standby)

        if update_applied_properties:
            self.service.applied_properties['active'] = active
            self.service.applied_properties['standby'] = standby
            self.service.applied_properties['node_list'] = self.service.node_list

        if ipaddresses:
            self.ipaddresses = ipaddresses
            self.service.ipaddresses = ipaddresses

        self.resource = network_resource.IPResources(
            self.ipaddresses,
            self.cluster,
            self.service,
            self.model)

    def test_sorted_ips(self):
        self.assertEqual([self.ip1, self.ip2],
                         self.resource.sorted_ips)

    def test_parallel(self):
        self.service.standby = 1
        self.assertFalse(self.resource.parallel)
        self.service.standby = 0
        self.assertTrue(self.resource.parallel)

    def test_nic_proxy(self):
        self.assertTrue(
            isinstance(
                self.resource.nic_proxy(),
                network_resource.NICProxyResource))

    def test_application(self):
        self.service.applications = [1, 2, 3, 4]
        self.assertEquals(self.resource.application, 1)

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def test_resource_names_addition(self, mock_os_reinstall):
        self.ip1.is_initial = lambda: False
        ipaddresses = [self.ip1, self.ip2, self.ip3]
        mock_os_reinstall.return_value = False
        self.prepare_ipresource("1", "1", ipaddresses)
        names = list(self.resource.resource_names)
        self.assertEqual(['Res_IP_cluster_service_application_mgmt_1',
                          'Res_IP_cluster_service_application_mgmt_2',
                          'Res_IP_cluster_service_application_mgmt_3'], names)

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def test_new_resource_names_addition(self, mock_os_reinstall):
        self.ip1.is_initial = lambda: False
        ipaddresses = [self.ip1, self.ip2, self.ip3]
        mock_os_reinstall.return_value = False
        self.prepare_ipresource("1", "1", ipaddresses)
        names = list(self.resource.new_resource_names)
        self.assertEqual(['Res_IP_cluster_service_application_mgmt_2',
                          'Res_IP_cluster_service_application_mgmt_3'], names)

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def test_resource_names_failover_to_parallel(self, mock_os_reinstall):
        ipaddresses = [self.ip1, self.ip2, self.ip3, self.ip4]
        mock_os_reinstall.return_value = False
        self.prepare_ipresource("2", "0", ipaddresses)
        names = list(self.resource.resource_names)
        self.assertEqual(['Res_IP_cluster_service_application_mgmt_1',
                          'Res_IP_cluster_service_application_mgmt_2'], names)

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    @mock.patch('vcsplugin.network_resource.IPResources.create_resource')
    def test_create_resources_failover_to_parallel(self, mock_create_resource,
                                                   mock_os_reinstall):
        self.ip1.is_initial = lambda: False
        self.ip2.is_initial = lambda: False
        ipaddresses = [self.ip1, self.ip2, self.ip3, self.ip4]
        self.prepare_ipresource("2", "0", ipaddresses)
        mock_os_reinstall.return_value = False

        mock_vcs_api = mock.Mock()
        self.resource.create_resources(mock_vcs_api)
        calls = [mock.call(mock_vcs_api,
                           'Res_IP_cluster_service_application_mgmt_1',
                           [self.ip1, self.ip3],
                           self.service.nodes),
                 mock.call(mock_vcs_api,
                           'Res_IP_cluster_service_application_mgmt_2',
                           [self.ip2, self.ip4],
                           self.service.nodes)]
        mock_create_resource.assert_has_calls(calls)

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    @mock.patch('vcsplugin.network_resource.IPResources.create_resource')
    def test_create_resources_expansion(self, mock_create_resource,
                                        mock_os_reinstall):
        self.ip1.is_initial = lambda: False
        self.ip3.is_initial = lambda: False
        ipaddresses = [self.ip1, self.ip3, self.ip5, self.ip6]
        self.prepare_ipresource("1", "0", ipaddresses, True)
        self.prepare_ipresource("2", "0", ipaddresses)
        mock_os_reinstall.return_value = False

        mock_vcs_api = mock.Mock()
        self.resource.create_resources(mock_vcs_api)
        calls = [mock.call(mock_vcs_api,
                           'Res_IP_cluster_service_application_mgmt_1',
                           [self.ip5],
                           [self.service.nodes[1]]),
                 mock.call(mock_vcs_api,
                           'Res_IP_cluster_service_application_mgmt_2',
                           [self.ip6],
                           [self.service.nodes[1]])]
        mock_create_resource.assert_has_calls(calls)

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    @mock.patch('vcsplugin.network_resource.IPResources.create_resource')
    def test_create_resources_additional_vips_failover_active_one(self,
                                                                  mock_create_resource,
                                                                  mock_os_reinstall):
        self.ip1.is_initial = lambda: False
        self.ip2.is_initial = lambda: False
        ipaddresses = [self.ip1, self.ip2, self.ip3, self.ip4]
        self.prepare_ipresource("1", "1", ipaddresses)
        mock_os_reinstall.return_value = False

        mock_vcs_api = mock.Mock()
        self.resource.create_resources(mock_vcs_api)
        calls = [mock.call(mock_vcs_api,
                           'Res_IP_cluster_service_application_mgmt_3',
                           [self.ip3],
                           self.service.nodes),
                 mock.call(mock_vcs_api,
                           'Res_IP_cluster_service_application_mgmt_4',
                           [self.ip4],
                           self.service.nodes)]
        mock_create_resource.assert_has_calls(calls)

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    @mock.patch('vcsplugin.network_resource.IPResources.create_resource')
    def test_create_resources_additional_vips_parallel(self,
                                                       mock_create_resource,
                                                       mock_os_reinstall):
        self.ip1.is_initial = lambda: False
        self.ip2.is_initial = lambda: False
        ipaddresses = [self.ip1, self.ip2, self.ip3, self.ip4, self.ip5, self.ip6]
        self.prepare_ipresource("2", "0", ipaddresses, True)
        mock_os_reinstall.return_value = False

        mock_vcs_api = mock.Mock()
        self.resource.create_resources(mock_vcs_api)
        calls = [mock.call(mock_vcs_api,
                           'Res_IP_cluster_service_application_mgmt_2',
                           [self.ip3, self.ip5],
                           self.service.nodes),
                 mock.call(mock_vcs_api,
                           'Res_IP_cluster_service_application_mgmt_3',
                           [self.ip6, self.ip4],
                           self.service.nodes)]
        mock_create_resource.assert_has_calls(calls)

    def test_create_resource(self):
        mock_vcs_api = mock.MagicMock()
        resource_name = "Res_IP_cluster_service_application_mgmt_1"
        self.resource.nics_for_network = lambda x: {"mgmt": "eth1"}
        self.resource.create_resource(mock_vcs_api,
                                      resource_name,
                                      self.ipaddresses,
                                      self.service.nodes)
        hares_add_calls = [
            mock.call(resource_name, 'IP', 'Grp_CS_cluster_service')
        ]
        hares_local_calls = [
            mock.call(resource_name, 'Device')
        ]
        hares_modify_calls = [
            mock.call(resource_name, 'Critical', '1'),
            mock.call(resource_name, 'Device', 'eth1', 'mgmt'),
            mock.call(resource_name, 'Address', self.ip1.ipaddress),
            mock.call(resource_name, 'NetMask', 'netmask'),
            mock.call(resource_name, 'Enabled', '1')
        ]
        hares_probe_calls = [
            mock.call(resource_name, 'mgmt')
        ]
        mock_vcs_api.hares_add.assert_has_calls(hares_add_calls)
        mock_vcs_api.hares_local.assert_has_calls(hares_local_calls)
        mock_vcs_api.hares_modify.assert_has_calls(hares_modify_calls)
        mock_vcs_api.hares_probe.assert_has_calls(hares_probe_calls)

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def test_from_model_new(self, mock_os_reinstall):
        ipaddresses = [
                mock.Mock(item_id='vip1',
                          network_name='net1',
                          is_initial=lambda: True),
                mock.Mock(item_id='vip2',
                          network_name='net1',
                          is_initial=lambda: True),
                mock.Mock(item_id='vip3',
                          network_name='net1',
                          is_initial=lambda: True),
                mock.Mock(item_id='vip4',
                          network_name='net1',
                          is_initial=lambda: True),
                mock.Mock(item_id='vip5',
                          network_name='net2',
                          is_initial=lambda: True),
                mock.Mock(item_id='vip6',
                          network_name='net2',
                          is_initial=lambda: True)
                ]
        service = mock.Mock(item_id='cs1',
                            is_updated=lambda: False,
                            ipaddresses=ipaddresses,
                            applications=[mock.Mock()],
                            active=1,
                            node_list="n1",
                            applied_properties={'node_list':'n1'},
                            nodes=[mock.Mock()])
        mock_os_reinstall.return_value = False
        res = [item for item
                in network_resource.IPResources.from_model_new(
                    mock.Mock(),
                    service,
                    mock.Mock())]
        self.assertEquals(2, len(res))
        self.assertEquals(2, len(res[0].ipaddresses))
        self.assertEquals('net2', res[0].ipaddresses[0].network_name)
        self.assertEquals('vip5', res[0].ipaddresses[0].item_id)
        self.assertEquals('net2', res[0].ipaddresses[1].network_name)
        self.assertEquals('vip6', res[0].ipaddresses[1].item_id)
        self.assertEquals(4, len(res[1].ipaddresses))
        self.assertEquals('net1', res[1].ipaddresses[0].network_name)
        self.assertEquals('vip1', res[1].ipaddresses[0].item_id)
        self.assertEquals('net1', res[1].ipaddresses[1].network_name)
        self.assertEquals('vip2', res[1].ipaddresses[1].item_id)
        self.assertEquals('net1', res[1].ipaddresses[2].network_name)
        self.assertEquals('vip3', res[1].ipaddresses[2].item_id)
        self.assertEquals('net1', res[1].ipaddresses[3].network_name)
        self.assertEquals('vip4', res[1].ipaddresses[3].item_id)

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def test_from_model_new_skips_applied_vips(self, mock_os_reinstall):
        ipaddresses = [
                mock.Mock(item_id='vip1',
                          network_name='net1',
                          is_initial=lambda: False),
                mock.Mock(item_id='vip2',
                          network_name='net2',
                          is_initial=lambda: False),
                mock.Mock(item_id='vip3',
                          network_name='net2',
                          is_initial=lambda: True)
                ]
        service = mock.Mock(item_id='cs1',
                            is_updated=lambda: False,
                            ipaddresses=ipaddresses,
                            node_list="n1",
                            applied_properties={'node_list':'n1'},
                            applications=[mock.Mock()],
                            active=1,
                            nodes=[mock.Mock()])
        mock_os_reinstall.return_value = False
        res = [item for item
                in network_resource.IPResources.from_model_new(
                    mock.Mock(),
                    service,
                    mock.Mock())]
        self.assertEquals(1, len(res))
        self.assertEquals(1, len(res[0].ipaddresses))
        self.assertEquals('net2', res[0].ipaddresses[0].network_name)
        self.assertEquals('vip3', res[0].ipaddresses[0].item_id)

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def test_from_model_new_skips_all_applied_vips(self, mock_os_reinstall):
        ipaddresses = [
                mock.Mock(item_id='vip1',
                          network_name='net1',
                          is_initial=lambda: False),
                mock.Mock(item_id='vip2',
                          network_name='net1',
                          is_initial=lambda: False),
                mock.Mock(item_id='vip3',
                          network_name='net2',
                          is_initial=lambda: False)
                ]
        service = mock.Mock(item_id='cs1',
                            is_updated=lambda: False,
                            ipaddresses=ipaddresses,
                            node_list="n1",
                            applied_properties={'node_list':'n1'},
                            applications=[mock.Mock()],
                            active=1,
                            nodes=[mock.Mock()])
        mock_os_reinstall.return_value = False
        res = [item for item
                in network_resource.IPResources.from_model_new(
                    mock.Mock(),
                    service,
                    mock.Mock())]
        self.assertEquals([], res)

    def test_update_resource_device_new_node(self):
        hostname_intf = self.resource.nics_for_network(
            [self.node1])
        vcs_api = mock.MagicMock()
        self.resource.update_resource_device_new_node(vcs_api, self.node1)
        vcs_api.hares_modify.assert_has_calls(
            [mock.call('Res_IP_cluster_service_application_mgmt_1',
                       'Device', 'eth0', 'node1'),
             mock.call('Res_IP_cluster_service_application_mgmt_2',
                       'Device', 'eth0', 'node1')])


class TestIPResourceCallbacks(VCSIntegrationBase):

    def setUp(self):
        super(TestIPResourceCallbacks, self).setUp()
        self.helper = network_resource.NetworkResourceHelper(mock.Mock())
        self.helper._vcs_api = mock.MagicMock()

    def test_vip_callback_ip_addition_fo(self):
        self.setup_model()

        self._add_service_to_model("1", "s1", "cs1", no_of_ips=2, runtime=False)

        cluster = self.context_api.query('vcs-cluster')[0]
        service = next(iter(cluster.services))

        self.model.set_all_applied()

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip3',
                                network_name='mgmt',
                                ipaddress='10.10.10.100')

        # We simulate the Res NIC creation
        self.helper._vcs_api.hares_list.return_value = "Res_NIC_cluster1_eth0"
        self.helper.vip_callback(self.callback_api, service.vpath,
                                 cluster.vpath, 'mgmt')

        self.assertEqual(0, self.helper.vcs_api.hares_delete.call_count)

        create_resource = mock.call('Res_IP_cluster1_service1_app1_mgmt_3',
                                    'IP', 'Grp_CS_cluster1_service1')
        create_proxy = mock.call('Res_NIC_Proxy_cluster1_service1_mgmt',
                                 'Proxy', 'Grp_CS_cluster1_service1')
        self.helper.vcs_api.hares_add.assert_has_calls([create_resource,
                                                       create_proxy])
        add_device_n1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_3',
                                  'Device', 'eth0', 'mn1')
        add_device_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_3',
                                  'Device', 'eth0', 'mn2')
        add_network = mock.call('Res_IP_cluster1_service1_app1_mgmt_3',
                                'Address', '10.10.10.100')

        self.helper._vcs_api.hares_modify.assert_has_calls([add_device_n1,
                                                            add_device_n2,
                                                            add_network])

    def test_vip_callback_ip_addition_fo_failed(self):
        self.setup_model()

        self._add_service_to_model("1", "s1", "cs1", no_of_ips=2, runtime=False)

        cluster = self.context_api.query('vcs-cluster')[0]
        service = next(iter(cluster.services))

        self.model.set_all_applied()

        vip = self._add_item_to_model('vip',
                                      service.vpath + '/ipaddresses/ip3',
                                      network_name='mgmt',
                                      ipaddress='10.10.10.100')
        vip.applied_properties_determinable = False

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip4',
                                network_name='mgmt',
                                ipaddress='10.10.10.101')

        # We simulate the Res NIC creation
        self.helper._vcs_api.hares_list.return_value = "Res_NIC_cluster1_eth0"
        self.helper.vip_callback(self.callback_api, service.vpath,
                                 cluster.vpath, 'mgmt')

        self.helper.vcs_api.hares_delete.assert_called_once_with(
            'Res_IP_cluster1_service1_app1_mgmt_3')

        create_resource1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_3',
                                     'IP', 'Grp_CS_cluster1_service1')
        create_resource2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_4',
                                     'IP', 'Grp_CS_cluster1_service1')
        create_proxy = mock.call('Res_NIC_Proxy_cluster1_service1_mgmt',
                                 'Proxy', 'Grp_CS_cluster1_service1')
        self.helper.vcs_api.hares_add.assert_has_calls([create_resource1,
                                                        create_resource2,
                                                        create_proxy])
        add_device_n1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_3',
                                  'Device', 'eth0', 'mn1')
        add_device_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_3',
                                  'Device', 'eth0', 'mn2')
        add_network = mock.call('Res_IP_cluster1_service1_app1_mgmt_3',
                                'Address', '10.10.10.100')

        self.helper._vcs_api.hares_modify.assert_has_calls([add_device_n1,
                                                            add_device_n2,
                                                            add_network])

    def test_vip_callback_2_ip_addition_fo(self):
        self.setup_model()

        self._add_service_to_model("1", "s1", "cs1", no_of_ips=2, runtime=False)

        cluster = self.context_api.query('vcs-cluster')[0]
        service = next(iter(cluster.services))

        self.model.set_all_applied()

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip3',
                                network_name='mgmt',
                                ipaddress='10.10.10.100')

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip4',
                                network_name='mgmt',
                                ipaddress='10.10.10.101')

        # We simulate the Res NIC creation
        self.helper._vcs_api.hares_list.return_value = "Res_NIC_cluster1_eth0"
        self.helper.vip_callback(self.callback_api, service.vpath,
                                 cluster.vpath, 'mgmt')

        self.assertEqual(0, self.helper.vcs_api.hares_delete.call_count)

        create_resource1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_3',
                                     'IP', 'Grp_CS_cluster1_service1')
        create_resource2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_4',
                                     'IP', 'Grp_CS_cluster1_service1')
        create_proxy = mock.call('Res_NIC_Proxy_cluster1_service1_mgmt',
                                 'Proxy', 'Grp_CS_cluster1_service1')
        self.helper.vcs_api.hares_add.assert_has_calls([create_resource1,
                                                       create_resource2,
                                                       create_proxy])
        add_device1_n1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_3',
                                   'Device', 'eth0', 'mn1')
        add_device1_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_3',
                                   'Device', 'eth0', 'mn2')
        add_network1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_3',
                                 'Address', '10.10.10.100')

        add_device2_n1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_4',
                                   'Device', 'eth0', 'mn1')
        add_device2_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_4',
                                   'Device', 'eth0', 'mn2')
        add_network2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_4',
                                 'Address', '10.10.10.101')

        self.helper._vcs_api.hares_modify.assert_has_calls([add_device1_n1,
                                                            add_device1_n2,
                                                            add_network1])

        self.helper._vcs_api.hares_modify.assert_has_calls([add_device2_n1,
                                                            add_device2_n2,
                                                            add_network2])

    def test_vip_callback_2_ip_addition_pl(self):
        self.setup_model()

        self._add_service_to_model("1", "s1", "cs1", no_of_ips=2, runtime=False,
                                   active='2', standby='0')

        cluster = self.context_api.query('vcs-cluster')[0]
        service = next(iter(cluster.services))

        self.model.set_all_applied()

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip3',
                                network_name='mgmt',
                                ipaddress='10.10.10.100')

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip4',
                                network_name='mgmt',
                                ipaddress='10.10.10.101')

        # We simulate the Res NIC creation
        self.helper._vcs_api.hares_list.return_value = "Res_NIC_cluster1_eth0"
        self.helper.vip_callback(self.callback_api, service.vpath,
                                 cluster.vpath, 'mgmt')

        self.assertEqual(0, self.helper.vcs_api.hares_delete.call_count)

        create_resource1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_2',
                                     'IP', 'Grp_CS_cluster1_service1')
        create_proxy = mock.call('Res_NIC_Proxy_cluster1_service1_mgmt',
                                 'Proxy', 'Grp_CS_cluster1_service1')
        self.helper.vcs_api.hares_add.assert_has_calls([create_resource1,
                                                       create_proxy])
        add_device1_n1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_2',
                                   'Device', 'eth0', 'mn1')
        add_device1_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_2',
                                   'Device', 'eth0', 'mn2')
        add_network1_n1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_2',
                                    'Address', '10.10.10.100', 'mn1')
        add_network1_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_2',
                                    'Address', '10.10.10.101', 'mn2')

        self.helper._vcs_api.hares_modify.assert_has_calls([add_device1_n1,
                                                            add_device1_n2,
                                                            add_network1_n1,
                                                            add_network1_n2])

    def test_vip_callback_2_ip_addition_pl_new_network(self):
        self.setup_model()

        self._add_service_to_model("1", "s1", "cs1", no_of_ips=2, runtime=False,
                                   active='2', standby='0')

        cluster = self.context_api.query('vcs-cluster')[0]
        service = next(iter(cluster.services))

        self._add_item_to_model(
            'network',
            '/infrastructure/networking/networks/new_net',
            name='new_net',
            subnet='10.10.11.0/24',
            litp_management='false')

        self._add_item_to_model(
            'eth',
            cluster.vpath + "/nodes/node1/network_interfaces/if3",
            macaddress="08:00:27:5B:C1:35",
            network_name="new_net",
            device_name="eth3")

        self._add_item_to_model(
            'eth',
            cluster.vpath + "/nodes/node2/network_interfaces/if3",
            macaddress="08:00:27:5B:C1:36",
            network_name="new_net",
            device_name="eth3")

        self.model.set_all_applied()

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip3',
                                network_name='new_net',
                                ipaddress='10.10.11.100')

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip4',
                                network_name='new_net',
                                ipaddress='10.10.11.101')

        # We simulate the Res NIC creation
        self.helper._vcs_api.hares_list.return_value = "Res_NIC_cluster1_eth3"
        self.helper.vip_callback(self.callback_api, service.vpath,
                                 cluster.vpath, 'new_net')

        self.assertEqual(0, self.helper.vcs_api.hares_delete.call_count)

        create_resource1 = mock.call('Res_IP_cluster1_service1_app1_new_net_1',
                                     'IP', 'Grp_CS_cluster1_service1')
        create_proxy = mock.call('Res_NIC_Proxy_cluster1_service1_new_net',
                                 'Proxy', 'Grp_CS_cluster1_service1')
        self.helper.vcs_api.hares_add.assert_has_calls([create_resource1,
                                                       create_proxy])
        add_device1_n1 = mock.call('Res_IP_cluster1_service1_app1_new_net_1',
                                   'Device', 'eth3', 'mn1')
        add_device1_n2 = mock.call('Res_IP_cluster1_service1_app1_new_net_1',
                                   'Device', 'eth3', 'mn2')
        add_network1_n1 = mock.call('Res_IP_cluster1_service1_app1_new_net_1',
                                    'Address', '10.10.11.100', 'mn1')
        add_network1_n2 = mock.call('Res_IP_cluster1_service1_app1_new_net_1',
                                    'Address', '10.10.11.101', 'mn2')

        self.helper._vcs_api.hares_modify.assert_has_calls([add_device1_n1,
                                                            add_device1_n2,
                                                            add_network1_n1,
                                                            add_network1_n2])

    def test_vip_callback_2_ip_addition_pl_new_network_ipv6(self):
        self.setup_model()

        self._add_service_to_model("1", "s1", "cs1", no_of_ips=2, runtime=False,
                                   active='2', standby='0')

        cluster = self.context_api.query('vcs-cluster')[0]
        service = next(iter(cluster.services))

        self._add_item_to_model(
            'network',
            '/infrastructure/networking/networks/new_net',
            name='new_net',
            subnet='10.10.11.0/24',
            litp_management='false')

        self._add_item_to_model(
            'eth',
            cluster.vpath + "/nodes/node1/network_interfaces/if3",
            macaddress="08:00:27:5B:C1:35",
            network_name="new_net",
            device_name="eth3")

        self._add_item_to_model(
            'eth',
            cluster.vpath + "/nodes/node2/network_interfaces/if3",
            macaddress="08:00:27:5B:C1:36",
            network_name="new_net",
            device_name="eth3")

        self.model.set_all_applied()

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip3',
                                network_name='new_net',
                                ipaddress='2001:cdba:0:0:0:0:3257:9652/64')

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip4',
                                network_name='new_net',
                                ipaddress='10.10.11.101')

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip5',
                                network_name='new_net',
                                ipaddress='2001:cdba:0:0:0:0:3258:9652/64')

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip6',
                                network_name='new_net',
                                ipaddress='10.10.11.102')

        # We simulate the Res NIC creation
        self.helper._vcs_api.hares_list.return_value = "Res_NIC_cluster1_eth3"

        self.helper.vip_callback(self.callback_api, service.vpath,
                                 cluster.vpath, 'new_net')

        self.assertEqual(0, self.helper.vcs_api.hares_delete.call_count)

        # Check proxy resource
        create_resource1 = mock.call('Res_IP_cluster1_service1_app1_new_net_1',
                                     'IP', 'Grp_CS_cluster1_service1')
        create_resource2 = mock.call('Res_IP_cluster1_service1_app1_new_net_2',
                                     'IP', 'Grp_CS_cluster1_service1')
        create_proxy = mock.call('Res_NIC_Proxy_cluster1_service1_new_net',
                                 'Proxy', 'Grp_CS_cluster1_service1')
        self.helper.vcs_api.hares_add.assert_has_calls([create_resource1,
                                                        create_resource2,
                                                        create_proxy])

        # Verify IPv4 resource
        add_device1_n1 = mock.call('Res_IP_cluster1_service1_app1_new_net_1',
                                   'Device', 'eth3', 'mn1')
        add_device1_n2 = mock.call('Res_IP_cluster1_service1_app1_new_net_1',
                                   'Device', 'eth3', 'mn2')
        add_network1_n1 = mock.call('Res_IP_cluster1_service1_app1_new_net_1',
                                    'Address', '10.10.11.101', 'mn1')
        add_network1_n2 = mock.call('Res_IP_cluster1_service1_app1_new_net_1',
                                    'Address', '10.10.11.102', 'mn2')

        self.helper._vcs_api.hares_modify.assert_has_calls([add_device1_n1,
                                                            add_device1_n2,
                                                            add_network1_n1,
                                                            add_network1_n2])

        # Check IPv6 resource
        add_device2_n1 = mock.call('Res_IP_cluster1_service1_app1_new_net_2',
                                   'Device', 'eth3', 'mn1')
        add_device2_n2 = mock.call('Res_IP_cluster1_service1_app1_new_net_2',
                                   'Device', 'eth3', 'mn2')
        add_network2_n1 = mock.call('Res_IP_cluster1_service1_app1_new_net_2',
                                    'Address', '2001:cdba:0:0:0:0:3257:9652',
                                    'mn1')
        add_network2_n2 = mock.call('Res_IP_cluster1_service1_app1_new_net_2',
                                    'Address', '2001:cdba:0:0:0:0:3258:9652',
                                    'mn2')
        self.helper._vcs_api.hares_modify.assert_has_calls([add_device2_n1,
                                                            add_device2_n2,
                                                            add_network2_n1,
                                                            add_network2_n2])

    def test_vip_callback_expansion(self):
        self.setup_model()

        self._add_service_to_model("1", "s1", "cs1", no_of_ips=2, runtime=False,
                                   active='1', standby='0', no_of_nodes=1)

        cluster = self.context_api.query('vcs-cluster')[0]

        service = next(iter(cluster.services))

        self.model.set_all_applied()

        self._update_item_in_model(service.vpath, active='2', standby='0',
                                   node_list='node1,node2')

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip5',
                                network_name='mgmt',
                                ipaddress='10.10.10.100')

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip6',
                                network_name='mgmt',
                                ipaddress='10.10.10.101')

        # We simulate the Res NIC creation
        self.helper._vcs_api.hares_list.return_value = "Res_NIC_cluster1_eth0"
        self.helper.vip_callback(self.callback_api, service.vpath,
                                 cluster.vpath, 'mgmt')

        self.assertEqual(0, self.helper.vcs_api.hares_delete.call_count)

        create_resource1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_1',
                                     'IP', 'Grp_CS_cluster1_service1')
        create_resource2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_2',
                                     'IP', 'Grp_CS_cluster1_service1')

        create_proxy = mock.call('Res_NIC_Proxy_cluster1_service1_mgmt',
                                 'Proxy', 'Grp_CS_cluster1_service1')
        self.helper.vcs_api.hares_add.assert_has_calls([create_resource1,
                                                        create_resource2,
                                                       create_proxy])
        add_device1_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_1',
                                   'Device', 'eth0', 'mn2')
        add_network1_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_1',
                                    'Address', '10.10.10.101', 'mn2')

        self.helper._vcs_api.hares_modify.assert_has_calls([add_device1_n2,
                                                            add_network1_n2])

        add_device2_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_2',
                                   'Device', 'eth0', 'mn2')
        add_network2_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_2',
                                    'Address', '10.10.10.100', 'mn2')

        self.helper._vcs_api.hares_modify.assert_has_calls([add_device2_n2,
                                                            add_network2_n2])

    def test_vip_callback_expansion_failed(self):
        self.setup_model()

        self._add_service_to_model("1", "s1", "cs1", no_of_ips=2, runtime=False,
                                   active='1', standby='0', no_of_nodes=1)

        cluster = self.context_api.query('vcs-cluster')[0]

        service = next(iter(cluster.services))

        self.model.set_all_applied()

        self._update_item_in_model(service.vpath, active='2', standby='0',
                                   node_list='node1,node2')

        vip = self._add_item_to_model('vip',
                                      service.vpath + '/ipaddresses/ip5',
                                      network_name='mgmt',
                                      ipaddress='10.10.10.100')

        vip.applied_properties_determinable = False

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip6',
                                network_name='mgmt',
                                ipaddress='10.10.10.101')

        # We simulate the Res NIC creation
        self.helper._vcs_api.hares_list.return_value = "Res_NIC_cluster1_eth0"
        self.helper.vip_callback(self.callback_api, service.vpath,
                                 cluster.vpath, 'mgmt')

        self.assertEqual(0, self.helper.vcs_api.hares_delete.call_count)

        create_resource1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_1',
                                     'IP', 'Grp_CS_cluster1_service1')
        create_resource2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_2',
                                     'IP', 'Grp_CS_cluster1_service1')

        create_proxy = mock.call('Res_NIC_Proxy_cluster1_service1_mgmt',
                                 'Proxy', 'Grp_CS_cluster1_service1')
        self.helper.vcs_api.hares_add.assert_has_calls([create_resource1,
                                                        create_resource2,
                                                       create_proxy])
        add_device1_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_1',
                                   'Device', 'eth0', 'mn2')
        add_network1_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_1',
                                    'Address', '10.10.10.101', 'mn2')

        self.helper._vcs_api.hares_modify.assert_has_calls([add_device1_n2,
                                                            add_network1_n2])

        add_device2_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_2',
                                   'Device', 'eth0', 'mn2')
        add_network2_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_2',
                                    'Address', '10.10.10.100', 'mn2')

        self.helper._vcs_api.hares_modify.assert_has_calls([add_device2_n2,
                                                            add_network2_n2])

    def test_vip_callback_fo_to_pl(self):
        self.setup_model()

        self._add_service_to_model("1", "s1", "cs1", no_of_ips=2, runtime=False,
                                   active='1', standby='1', no_of_nodes=2)

        cluster = self.context_api.query('vcs-cluster')[0]

        service = next(iter(cluster.services))

        self.model.set_all_applied()

        self._update_item_in_model(service.vpath, active='2', standby='0')

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip5',
                                network_name='mgmt',
                                ipaddress='10.10.10.100')

        self._add_item_to_model('vip',
                                service.vpath + '/ipaddresses/ip6',
                                network_name='mgmt',
                                ipaddress='10.10.10.101')

        # We simulate the Res NIC creation
        self.helper._vcs_api.hares_list.return_value = "Res_NIC_cluster1_eth0"
        self.helper.vip_callback(self.callback_api, service.vpath,
                                 cluster.vpath, 'mgmt')

        self.assertEqual(0, self.helper.vcs_api.hares_delete.call_count)

        create_resource1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_1',
                                     'IP', 'Grp_CS_cluster1_service1')
        create_resource2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_2',
                                     'IP', 'Grp_CS_cluster1_service1')

        create_proxy = mock.call('Res_NIC_Proxy_cluster1_service1_mgmt',
                                 'Proxy', 'Grp_CS_cluster1_service1')
        self.helper.vcs_api.hares_add.assert_has_calls([create_resource1,
                                                        create_resource2,
                                                       create_proxy])
        add_device1_n1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_1',
                                   'Device', 'eth0', 'mn1')
        add_device1_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_1',
                                   'Device', 'eth0', 'mn2')
        add_network1_n1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_1',
                                    'Address', '10.10.10.51', 'mn1')
        add_network1_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_1',
                                    'Address', '10.10.10.52', 'mn2')

        self.helper._vcs_api.hares_modify.assert_has_calls([add_device1_n1,
                                                            add_device1_n2,
                                                            add_network1_n1,
                                                            add_network1_n2])

        add_device2_n1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_2',
                                   'Device', 'eth0', 'mn1')
        add_device2_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_2',
                                   'Device', 'eth0', 'mn2')
        add_network2_n1 = mock.call('Res_IP_cluster1_service1_app1_mgmt_2',
                                    'Address', '10.10.10.100', 'mn1')
        add_network2_n2 = mock.call('Res_IP_cluster1_service1_app1_mgmt_2',
                                    'Address', '10.10.10.101', 'mn2')

        self.helper._vcs_api.hares_modify.assert_has_calls([add_device2_n1,
                                                            add_device2_n2,
                                                            add_network2_n1,
                                                            add_network2_n2])

    def test_get_vip_update_tasks(self):
        self.setup_model()

        self._add_service_to_model("1", "s1", "cs1", no_of_ips=2, runtime=False)

        cluster = self.context_api.query('vcs-cluster')[0]
        network = self.context_api.query('network')[0]
        vip0 = '/deployments/test/clusters/cluster1/services/service1/ipaddresses/ip0'
        vip1 = '/deployments/test/clusters/cluster1/services/service1/ipaddresses/ip1'

        self.model.set_all_applied()
        self._update_item_in_model(network.vpath, subnet='10.11.11.0/23')
        self._update_item_in_model(vip0, ipaddress='10.11.11.51')
        self._update_item_in_model(vip1, ipaddress='1001::1/77')

        self.helper._vcs_api.update_ip_resource.return_value = (0, None, "")
        self.helper.update_vip_callback(self.callback_api,
                                        cluster.vpath, network.vpath)
        data_json = ('{"PrefixLen":"77","NetMask":"255.255.254.0","Data":'
                     '{"service1":{"VIPs":'
                     '[["10.10.10.51","10.11.11.51"],["10.10.10.52",'
                     '"1001::1"]],"Parallel":false}}}')
        self.helper._vcs_api.update_ip_resource.assert_called_once_with(
                                                     data_json, 20)


class TestNICProxyResource(unittest.TestCase):
    def setUp(self):
        self.network = "mgmt"
        self.cluster = mock.Mock(item_id='foobar')
        self.service = mock.Mock(item_id="s1")
        self.model = mock.Mock()
        self.nic_proxy = network_resource.NICProxyResource(
            self.network,
            self.cluster,
            self.service,
            self.model)

    def test_link_to_ip_resource(self):
        self.nic_proxy.link_to_ip_resource('foobar')
        self.model.link_ip_to_proxy.assert_called_with(
            'foobar',
            self.nic_proxy.name)

    def test_target_resource_name(self):
        self.assertEqual(
            'Res_NIC_foobar_barfoo',
            self.nic_proxy.target_resource_name('barfoo'))

    def test_create_resources(self):
        mock_vcs_api = mock.Mock()
        self.nic_proxy.nics_for_network = mock.Mock(
            return_value={'mgmt': ['eth0', 'eth1']})
        self.model.resource_exists = mock.Mock(side_effect=[True])
        self.nic_proxy.create_resources(mock_vcs_api)
        self.model.resource_exists = mock.Mock(side_effect=[False])
        try:
            self.nic_proxy.create_resources(mock_vcs_api)
            self.assertTrue(False)
        except VCSRuntimeException:
            self.assertTrue(True)

    def test_update_target_res_new_node(self):
        self.nic_proxy.nics_for_network = mock.Mock(
            return_value={'node1': 'eth0'})
        vcs_api = mock.MagicMock()
        node = mock.Mock(item_id="mn1")
        self.nic_proxy.update_target_res_new_node(vcs_api, node)
        vcs_api.hares_modify.assert_has_calls(
            [mock.call('Res_NIC_Proxy_foobar_s1_mgmt',
                       'TargetResName',
                       'Res_NIC_foobar_eth0',
                       'node1')])


class TestNetworkResourceHelper(unittest.TestCase):
    def setUp(self):
        self.helper = network_resource.NetworkResourceHelper(MockPlugin)
        self.helper._model = network_resource.VIPModel(mock.MagicMock(), None)
        self.helper.nodes = ['foo', 'bar']

    def test_validate_model(self):
        self.assertEqual([], self.helper.validate_model(mock.MagicMock()))

    @mock.patch('vcsplugin.network_resource.service_group_name')
    def test_task_description(self, mock_sgn):
        mock_sgn.return_value = 'foo'
        description = self.helper.task_description(
            'cluster', 'service', 'network')
        self.assertTrue(isinstance(description, basestring))

    def test_vip_requires_task_initial(self):
        vip = mock.Mock(
            is_initial = lambda: True,
        )
        service = mock.Mock(active=1, standby=1,
                            applications=[mock.Mock(item_id="application")],
                            applied_properties={},
                            node_list="mn1,mn2",
                            nodes=[mock.Mock(item_id="mn1"),
                                   mock.Mock(item_id="mn2")],
                            is_initial=lambda: True,
                            is_updated=lambda: False,
                            item_id="service")
        self.assertTrue(self.helper.vip_requires_task(vip, service))

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def test_vip_requires_task_no_initial(self, mock_os_reinstall):
        vip = mock.Mock(
            is_initial = lambda: False,
        )
        service = mock.Mock(active=1, standby=1,
                            applications=[mock.Mock(item_id="application")],
                            applied_properties={'standby': 1},
                            node_list="mn1,mn2",
                            nodes=[mock.Mock(item_id="mn1"),
                                   mock.Mock(item_id="mn2")],
                            is_initial=lambda: False,
                            is_updated=lambda: True,
                            item_id="service")
        mock_os_reinstall.return_value = False
        self.assertFalse(self.helper.vip_requires_task(vip, service))

    def test_create_configuration_initial_service(self):
        ip1 = mock.Mock(ipaddress='10.10.10.10', network_name='mgmt')
        ip2 = mock.Mock(ipaddress='2001:cdba:0:0:0:0:3257:9652',
                             network_name='mgmt')
        mgmt_network = mock.Mock(litp_management=True,
                                 subnet="10.10.10.0/24",
                                 is_updated=lambda: False)
        mgmt_network.name = "mgmt"
        ipaddresses = mock.Mock(__iter__ = lambda x: iter([ip1, ip2]),
                                has_initial_dependencies = lambda: True)
        cluster = mock.Mock(item_id="cluster")
        service = mock.Mock(active=1, standby=1,
                            applications=[mock.Mock(item_id="application")],
                            applied_properties={},
                            node_list="mn1,mn2",
                            nodes=[mock.Mock(item_id="mn1"),
                                   mock.Mock(item_id="mn2")],
                            ipaddresses=ipaddresses,
                            is_initial=lambda: True,
                            is_updated=lambda: False,
                            item_id="service")
        infrastructure_item = mock.Mock(query=lambda x: [mgmt_network])
        model = mock.Mock(get_netmask=lambda x: "netmask",
                          query_by_vpath=lambda x: infrastructure_item)
        pre_node_tasks, post_node_tasks = self.helper.create_configuration(
                                            model, cluster, service)
        self.assertEqual(0, len(pre_node_tasks))
        self.assertEqual(1, len(post_node_tasks))

    def test_create_configuration_expansion(self):
        ip1 = mock.Mock(ipaddress='10.10.10.10', network_name='mgmt')
        ip2 = mock.Mock(ipaddress='2001:cdba:0:0:0:0:3257:9652',
                             network_name='mgmt')
        mgmt_network = mock.Mock(litp_management=True,
                                 subnet="10.10.10.0/24",
                                 is_updated=lambda: False)
        mgmt_network.name = "mgmt"
        ipaddresses = mock.Mock(__iter__ = lambda x: iter([ip1, ip2]),
                                has_initial_dependencies = lambda: True)
        cluster = mock.Mock(item_id="cluster")
        service = mock.Mock(active=1, standby=1,
                            applications=[mock.Mock(item_id="application")],
                            applied_properties={'node_list': "",
                                                "standby": 1},
                            node_list="mn1,mn2",
                            nodes=[mock.Mock(item_id="mn1"),
                                   mock.Mock(item_id="mn2")],
                            ipaddresses=ipaddresses,
                            is_updated=lambda: True,
                            item_id="service")
        infrastructure_item = mock.Mock(query=lambda x: [mgmt_network])
        model = mock.Mock(get_netmask=lambda x: "netmask",
                          query_by_vpath=lambda x: infrastructure_item)
        pre_node_tasks, post_node_tasks = self.helper.create_configuration(
                                            model, cluster, service)
        self.assertEqual(0, len(pre_node_tasks))
        self.assertEqual(1, len(post_node_tasks))

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def test_create_configuration_addition(self, mock_os_reinstall):
        ip1 = mock.Mock(ipaddress='10.10.10.10',
                        network_name='mgmt',
                        is_initial=lambda: False)
        ip2 = mock.Mock(ipaddress='2001:cdba:0:0:0:0:3257:9652',
                        network_name='mgmt',
                        is_initial=lambda: False)
        ip3 = mock.Mock(ipaddress='10.10.10.11',
                        network_name='mgmt',
                        is_initial=lambda: True)
        ip4 = mock.Mock(ipaddress='2001:cdba:0:0:0:0:3257:9653',
                        network_name='mgmt',
                        is_initial=lambda: True)
        mgmt_network = mock.Mock(litp_management=True,
                                 subnet="10.10.10.0/24",
                                 is_updated=lambda: False)
        mgmt_network.name = 'mgmt'
        ipaddresses = mock.Mock(__iter__ = lambda x: iter([ip1, ip2, ip3, ip4]),
                                has_initial_dependencies = lambda: True)
        cluster = mock.Mock(item_id="cluster")
        service = mock.Mock(active=1, standby=1,
                            applications=[mock.Mock(item_id="application")],
                            applied_properties={'node_list': "mn1,mn2",
                                                'active': '1',
                                                'standby': '1'},
                            node_list="mn1,mn2",
                            nodes=[mock.Mock(item_id="mn1"),
                                   mock.Mock(item_id="mn2")],
                            ipaddresses=ipaddresses,
                            is_updated=lambda: False,
                            is_initial=lambda: False,
                            is_applied=lambda: True,
                            item_id="service")
        infrastructure_item = mock.Mock(query=lambda x: [mgmt_network])
        model = mock.Mock(get_netmask=lambda x: "netmask",
                          query_by_vpath=lambda x: infrastructure_item)
        mock_os_reinstall.return_value = False
        pre_node_tasks, post_node_tasks = self.helper.create_configuration(
                                            model, cluster, service)
        self.assertEqual(1, len(pre_node_tasks))
        self.assertEqual(0, len(post_node_tasks))

        task = pre_node_tasks[0]
        self.assertEqual('NetworkResourceHelper', task.kwargs['callback_class'])
        self.assertEqual('vip_callback', task.kwargs['callback_func'])
        self.assertEqual(service.get_vpath(), task.kwargs['service_vpath'])
        self.assertEqual(cluster.get_vpath(), task.kwargs['cluster_vpath'])
        self.assertEqual('mgmt', task.kwargs['network_name'])

    def test_get_callback_update_vip(self):
        ip1 = mock.Mock(ipaddress='10.10.10.10',
                        network_name='mgmt',
                        is_initial=lambda: False)
        ip2 = mock.Mock(ipaddress='2001:cdba:0:0:0:0:3257:9652',
                        network_name='mgmt',
                        is_initial=lambda: False)
        ip3 = mock.Mock(ipaddress='10.10.10.11',
                        network_name='mgmt',
                        is_initial=lambda: True)
        ip4 = mock.Mock(ipaddress='2001:cdba:0:0:0:0:3257:9653',
                        network_name='mgmt',
                        is_initial=lambda: True)
        mgmt_network = mock.Mock(litp_management=True,
                                 subnet="10.10.10.0/24",
                                 applied_properties={'subnet':'10.10.10.0/25'},
                                 is_updated=lambda: True)
        mgmt_network.name = 'mgmt'
        ipaddresses = mock.Mock(__iter__ = lambda x: iter([ip1, ip2, ip3, ip4]),
                                has_initial_dependencies = lambda: True)
        service = mock.Mock(ipaddresses=ipaddresses,
                            applications=[mock.Mock(item_id="application")])
        cluster = mock.Mock(services=[service],
                            get_vpath=lambda: "cluster_path")
        infrastructure_item = mock.Mock(query=lambda x: [mgmt_network])
        context = mock.Mock(get_netmask=lambda x: "netmask",
                            query=lambda x, name: [mgmt_network],
                            query_by_vpath=lambda x: infrastructure_item)
        tasks = self.helper.get_vip_update_tasks(context, cluster)
        self.assertEqual(1, len(tasks))

        task = tasks[0]
        self.assertEqual('NetworkResourceHelper', task.kwargs['callback_class'])
        self.assertEqual('update_vip_callback', task.kwargs['callback_func'])
        self.assertEqual(cluster.get_vpath(), task.kwargs['cluster_vpath'])
        self.assertEqual(mgmt_network.get_vpath(), task.kwargs['network_vpath'])

    def test_network_from_ipv6(self):
        ipv6 = '2001:abcd:ef::10/38'
        result = self.helper._network_from_ipv6(ipv6)
        self.assertEqual(netaddr.IPNetwork('2001:abcd:ef::13/38'), result)

    def test_network_from_ipv6_no_mask(self):
        ipv6 = '2001:abcd:ef::10'
        result = self.helper._network_from_ipv6(ipv6)
        self.assertEqual(netaddr.IPNetwork('2001:abcd:ef::13/64'), result)

    def test_compare_subnets_no_overlaping(self):
        node1 = mock.Mock(hostaname='mn1')
        vip1 = mock.Mock()
        vip1.get_vpath.return_value = "vpath_vip1"
        vip1.get_node.return_value = node1
        subnet_vip1 = netaddr.IPNetwork('2001:abcd:ef::13/64')

        vip2 = mock.Mock()
        vip2.get_vpath.return_value = "vpath_vip2"
        vip2.get_node.return_value = None
        subnet_vip2 = netaddr.IPNetwork('2001:abcb:ef::13/64')

        subnets = [(subnet_vip1, vip1),
                   (subnet_vip2, vip2)]

        errors = self.helper._compare_subnets(subnets, node1.hostname)
        self.assertEquals([], errors)

    def test_compare_subnets_overlaping_with_node(self):
        node1 = mock.Mock(hostaname='mn1')
        nic1 = mock.Mock()
        nic1.get_vpath.return_value = "vpath_nic_0"
        nic1.get_node.return_value = node1
        subnet_nic1 = netaddr.IPNetwork('2001:abcd:ef::13/64')

        vip2 = mock.Mock()
        vip2.get_vpath.return_value = "vpath_vip2"
        vip2.get_node.return_value = None
        subnet_vip2 = netaddr.IPNetwork('2001:abcd:ef::10/64')

        subnets = [(subnet_nic1, nic1),
                   (subnet_vip2, vip2)]

        errors = self.helper._compare_subnets(subnets, node1.hostname)
        self.assertEquals(2, len(errors))

    def test_compare_subnets_overlaping_with_service(self):
        node1 = mock.Mock(hostaname='mn1')
        vip1 = mock.Mock()
        vip1.get_vpath.return_value = "vpath_vip1"
        vip1.get_node.return_value = None
        subnet_vip1 = netaddr.IPNetwork('2001:abcd:ef::13/64')

        vip2 = mock.Mock()
        vip2.get_vpath.return_value = "vpath_vip2"
        vip2.get_node.return_value = None
        subnet_vip2 = netaddr.IPNetwork('2001:abcd:ef::10/64')

        subnets = [(subnet_vip1, vip1),
                   (subnet_vip2, vip2)]

        errors = self.helper._compare_subnets(subnets, node1.hostname)
        self.assertEquals(2, len(errors))

    def test_validate_network_subnets_ipv6_no_overlap(self):
        vip1 = mock.Mock(ipaddress='3021:54a:a::10/64', network_name='traffic2')
        vip1.get_node.return_value = None
        vip2 = mock.Mock(ipaddress='3023:54a:a::20', network_name='traffic1')
        vip2.get_node.return_value = None
        node1 = mock.Mock(hostname='mn1', network_interfaces=[])
        service1 = mock.Mock(ipaddresses=[vip1, vip2], nodes=[node1])
        model = mock.Mock(services=[service1])

        errors = self.helper._validate_network_subnets_ipv6_overlap(model)
        self.assertEqual(0, len(errors))

    def test_validate_network_subnets_ipv6_overlap(self):
        vip1 = mock.Mock(ipaddress='3021:54a:a::10/64', network_name='traffic2')
        vip1.get_node.return_value = None
        vip2 = mock.Mock(ipaddress='3021:54a:a::20', network_name='traffic1')
        vip2.get_node.return_value = None
        node1 = mock.Mock(hostname='mn1', network_interfaces=[])
        service1 = mock.Mock(ipaddresses=[vip1, vip2], nodes=[node1])
        model = mock.Mock(services=[service1])

        errors = self.helper._validate_network_subnets_ipv6_overlap(model)
        self.assertEqual(2, len(errors))

    @mock.patch('vcsplugin.network_resource.IPResources')
    @mock.patch('vcsplugin.network_resource.VIPModel')
    def test_vip_upd_standby_node(self, mock_model_class,
                                  mock_ip_res_class):
        mock_upd_res_dev = mock.Mock()
        mock_upd_target_res = mock.Mock()
        mock_nic_proxy = mock.Mock(
            update_target_res_new_node=mock_upd_target_res)
        mock_ip_res = mock.Mock(
            update_resource_device_new_node=mock_upd_res_dev,
            nic_proxy=mock.Mock(return_value=mock_nic_proxy))
        mock_ip_res_class.return_value = mock_ip_res
        mock_model_class.return_value = mock.Mock()
        context = mock.Mock()
        vcs_api = mock.MagicMock()
        n3 = mock.Mock(item_id="n3")
        cluster = mock.Mock(nodes=[n3])
        service = mock.Mock(node_list="n1,n3",
                            applied_properties={"node_list": "n1,n2"},
                            ipaddresses=[mock.Mock(network_name="mgmt",
                                                   is_applied=lambda: True)])
        network_resource.vip_upd_standby_node(context, vcs_api, service,
                                              cluster)
        mock_upd_res_dev.assert_has_calls([mock.call(vcs_api, n3)])
        mock_upd_target_res.assert_has_calls([mock.call(vcs_api, n3)])


def get_mock_vip(ipaddr, net_name, applied, initial, for_removal=False):
    vip = mock.Mock(name=ipaddr,
                    ipaddress=ipaddr, network_name=net_name,
                    is_applied=mock.Mock(return_value=applied),
                    is_initial=mock.Mock(return_value=initial),
                    is_for_removal=mock.Mock(return_value=for_removal))
    return vip
