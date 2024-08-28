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
import unittest

import mock

from vcsplugin.vcs_model import VCSModel, State
from mocks import mock_model_item, State as MockState


class AttrDefaultDict(defaultdict):
    def __init__(self, *args, **kwargs):
        super(AttrDefaultDict, self).__init__(*args, **kwargs)
        self.__dict__ = self
    def __iter__(self):
        return iter(self.values())
tree = lambda: AttrDefaultDict(tree)


class TestNicServiceGroups(unittest.TestCase):
    def setUp(self):
        mock_context_api = mock.Mock()
        self.vcs_model = VCSModel(mock_context_api)

    @mock.patch('vcsplugin.vcs_model.VCSModel._hb_networks_info_for_node')
    def test_not_includes_hb_network(self, patch_1):
        hb_macs = {
            'eth1': '00:00:00:00:00:00',
            'eth2': '00:00:00:00:00:00',
        }
        patch_1.return_value = (hb_macs, {})

        cluster = tree()
        cluster['nodes']['node1']['hostname'] = 'node1'
        cluster['nodes']['node2']['hostname'] = 'node2'
        cluster['nodes']['node1']['is_for_removal'] = lambda: False
        cluster['nodes']['node2']['is_for_removal'] = lambda: False
        cluster['nodes']['node1']['network_interfaces']['interface0']['device_name'] = 'eth0'
        cluster['nodes']['node1']['network_interfaces']['interface0']['is_initial'] = lambda: True
        cluster['nodes']['node1']['network_interfaces']['interface0']['is_for_removal'] = lambda: False
        cluster['nodes']['node1']['network_interfaces']['interface1']['device_name'] = 'eth1'
        cluster['nodes']['node1']['network_interfaces']['interface1']['is_initial'] = lambda: True
        cluster['nodes']['node1']['network_interfaces']['interface1']['is_for_removal'] = lambda: False
        cluster['nodes']['node1']['network_interfaces']['interface2']['device_name'] = 'eth2'
        cluster['nodes']['node1']['network_interfaces']['interface2']['is_initial'] = lambda: True
        cluster['nodes']['node1']['network_interfaces']['interface2']['is_for_removal'] = lambda: False
        cluster['nodes']['node2']['network_interfaces']['interface0']['device_name'] = 'eth0'
        cluster['nodes']['node2']['network_interfaces']['interface0']['is_initial'] = lambda: True
        cluster['nodes']['node2']['network_interfaces']['interface0']['is_for_removal'] = lambda: False
        cluster['nodes']['node2']['network_interfaces']['interface1']['device_name'] = 'eth1'
        cluster['nodes']['node2']['network_interfaces']['interface1']['is_initial'] = lambda: True
        cluster['nodes']['node2']['network_interfaces']['interface1']['is_for_removal'] = lambda: False
        cluster['nodes']['node2']['network_interfaces']['interface2']['device_name'] = 'eth2'
        cluster['nodes']['node2']['network_interfaces']['interface2']['is_initial'] = lambda: True
        cluster['nodes']['node2']['network_interfaces']['interface2']['is_for_removal'] = lambda: False
        cluster['network_hosts'] = []

        nic_groups = self.vcs_model.get_nic_groups(cluster)
        self.assertTrue('eth1' not in nic_groups.keys())
        self.assertTrue('eth2' not in nic_groups.keys())

    @mock.patch('vcsplugin.vcs_model.VCSModel._hb_networks_info_for_node')
    def test_add_new_nic_to_cluster(self, patch_1):
        hb_macs = {
            'eth1': '00:00:00:00:00:00'
        }
        patch_1.return_value = (hb_macs, {})

        nic_groups_expected = {'eth2': {'node1': None,
                                        'node2': None}}
        cluster = tree()
        cluster['is_initial'] = lambda: False
        cluster['nodes']['node1']['hostname'] = 'node1'
        cluster['nodes']['node2']['hostname'] = 'node2'
        cluster['nodes']['node1']['is_for_removal'] = lambda: False
        cluster['nodes']['node2']['is_for_removal'] = lambda: False
        cluster['nodes']['node1']['network_interfaces']['interface0']['device_name'] = 'eth0'
        cluster['nodes']['node1']['network_interfaces']['interface0']['is_initial'] = lambda: False
        cluster['nodes']['node1']['network_interfaces']['interface0']['is_for_removal'] = lambda: False
        cluster['nodes']['node1']['network_interfaces']['interface1']['device_name'] = 'eth1'
        cluster['nodes']['node1']['network_interfaces']['interface1']['is_initial'] = lambda: False
        cluster['nodes']['node1']['network_interfaces']['interface1']['is_for_removal'] = lambda: False
        cluster['nodes']['node1']['network_interfaces']['interface2']['device_name'] = 'eth2'
        cluster['nodes']['node1']['network_interfaces']['interface2']['is_initial'] = lambda: True
        cluster['nodes']['node1']['network_interfaces']['interface2']['is_for_removal'] = lambda: False
        cluster['nodes']['node2']['network_interfaces']['interface0']['device_name'] = 'eth0'
        cluster['nodes']['node2']['network_interfaces']['interface0']['is_initial'] = lambda: False
        cluster['nodes']['node2']['network_interfaces']['interface0']['is_for_removal'] = lambda: False
        cluster['nodes']['node2']['network_interfaces']['interface1']['device_name'] = 'eth1'
        cluster['nodes']['node2']['network_interfaces']['interface1']['is_initial'] = lambda: False
        cluster['nodes']['node2']['network_interfaces']['interface1']['is_for_removal'] = lambda: False
        cluster['nodes']['node2']['network_interfaces']['interface2']['device_name'] = 'eth2'
        cluster['nodes']['node2']['network_interfaces']['interface2']['is_initial'] = lambda: True
        cluster['nodes']['node2']['network_interfaces']['interface2']['is_for_removal'] = lambda: False
        cluster['network_hosts'] = []

        nic_groups = self.vcs_model.get_nic_groups(cluster)
        self.assertEqual(len(nic_groups), 1)
        self.assertEqual(nic_groups_expected, nic_groups)

    @mock.patch('vcsplugin.vcs_model.VCSModel._hb_networks_info_for_node')
    def test_heterogeneous_network_nic_groups(self, patch_1):
        hb_macs = {
            'eth1': '00:00:00:00:00:00',
            'eth2': '00:00:00:00:00:00',
        }
        patch_1.return_value = (hb_macs, {})

        cluster = tree()
        cluster['nodes']['node1']['hostname'] = 'node1'
        cluster['nodes']['node2']['hostname'] = 'node2'
        cluster['nodes']['node1']['is_for_removal'] = lambda: False
        cluster['nodes']['node2']['is_for_removal'] = lambda: False
        cluster['nodes']['node1']['network_interfaces']['interface0']['device_name'] = 'eth0'
        cluster['nodes']['node1']['network_interfaces']['interface0']['is_initial'] = lambda: True
        cluster['nodes']['node1']['network_interfaces']['interface0']['is_for_removal'] = lambda: False
        cluster['nodes']['node1']['network_interfaces']['interface1']['device_name'] = 'eth1'
        cluster['nodes']['node1']['network_interfaces']['interface1']['is_initial'] = lambda: True
        cluster['nodes']['node1']['network_interfaces']['interface1']['is_for_removal'] = lambda: False
        cluster['nodes']['node1']['network_interfaces']['interface2']['device_name'] = 'eth2'
        cluster['nodes']['node1']['network_interfaces']['interface2']['is_initial'] = lambda: True
        cluster['nodes']['node1']['network_interfaces']['interface2']['is_for_removal'] = lambda: False
        cluster['nodes']['node2']['network_interfaces']['interface0']['device_name'] = 'eth0'
        cluster['nodes']['node2']['network_interfaces']['interface0']['is_initial'] = lambda: True
        cluster['nodes']['node2']['network_interfaces']['interface0']['is_for_removal'] = lambda: False
        cluster['nodes']['node2']['network_interfaces']['interface1']['device_name'] = 'eth1'
        cluster['nodes']['node2']['network_interfaces']['interface1']['is_initial'] = lambda: True
        cluster['nodes']['node2']['network_interfaces']['interface1']['is_for_removal'] = lambda: False
        cluster['nodes']['node2']['network_interfaces']['interface2']['device_name'] = 'eth2'
        cluster['nodes']['node2']['network_interfaces']['interface2']['is_initial'] = lambda: True
        cluster['nodes']['node2']['network_interfaces']['interface2']['is_for_removal'] = lambda: False
        cluster['nodes']['node2']['network_interfaces']['interface3']['device_name'] = 'eth3'
        cluster['nodes']['node2']['network_interfaces']['interface3']['is_initial'] = lambda: True
        cluster['nodes']['node2']['network_interfaces']['interface3']['is_for_removal'] = lambda: False
        cluster['network_hosts'] = []

        nic_groups = self.vcs_model.get_nic_groups(cluster)
        self.assertEquals(
            sorted((
                ('eth0', {'node1': None,
                          'node2': None}),
                ('eth3', {'node2': None}))
            ),
            sorted(nic_groups.items()))

    def test_get_nic_groups(self):
        hb_networks = [{'eth2': '08:00:27:F3:7C:C3', 'eth3': '08:00:27:F3:7D:C4'},
                       {'eth0': '08:00:27:F3:7C:C5', 'eth1': '08:00:27:F3:7D:C6'}]
        def mock_hb_networks_info_for_node(*args, **kwargs):
            return hb_networks.pop(0), {}

        interface1_mn1 = mock.Mock(device_name = 'eth0', bridge="", master="")
        interface1_mn1.is_for_removal = lambda: False
        interface2_mn1 = mock.Mock(device_name = 'eth1', bridge="", master="")
        interface2_mn1.is_for_removal = lambda: False
        interface3_mn1 = mock.Mock(device_name = 'eth2', bridge="", master="")
        interface3_mn1.is_for_removal = lambda: False
        interface4_mn1 = mock.Mock(device_name = 'eth3', bridge="", master="")
        interface4_mn1.is_for_removal = lambda: False
        interface1_mn2 = mock.Mock(device_name = 'eth0', bridge="", master="")
        interface1_mn2.is_for_removal = lambda: False
        interface2_mn2 = mock.Mock(device_name = 'eth1', bridge="", master="")
        interface2_mn2.is_for_removal = lambda: False
        interface3_mn2 = mock.Mock(device_name = 'eth2', bridge="", master="")
        interface3_mn2.is_for_removal = lambda: False
        interface4_mn2 = mock.Mock(device_name = 'eth3', bridge="", master="")
        interface4_mn2.is_for_removal = lambda: False

        node1 = mock.Mock(hostname = 'mn1', state='Initial')
        node1.network_interfaces = [interface1_mn1, interface2_mn1, interface3_mn1, interface4_mn1]
        node2 = mock.Mock(hostname = 'mn2', state='Initial')
        node2.network_interfaces = [interface1_mn2, interface2_mn2, interface3_mn2, interface4_mn2]
        node1.is_for_removal = lambda: False
        node2.is_for_removal = lambda: False
        cluster = mock.Mock(nodes=[node1, node2], network_hosts=[])
        vcs_model = VCSModel(None)

        vcs_model._hb_networks_info_for_node = mock.Mock(
            side_effect=mock_hb_networks_info_for_node)

        expected_return = defaultdict(dict)
        expected_return['eth0']['mn1'] = None
        expected_return['eth1']['mn1'] = None
        expected_return['eth2']['mn2'] = None
        expected_return['eth3']['mn2'] = None

        self.assertEqual(vcs_model.get_nic_groups(cluster), expected_return)
        self.assertEqual(vcs_model._hb_networks_info_for_node.call_count, 2)

    def test_get_nic_groups_with_bonds_for_removal(self):

        hb_networks = [{'eth2': '08:00:27:F3:7C:C3', 'eth3': '08:00:27:F3:7D:C4'},
                       {'eth2': '08:00:27:F3:7C:C5', 'eth3': '08:00:27:F3:7D:C6'}]
        def mock_hb_networks_info_for_node(*args, **kwargs):
            return hb_networks.pop(0), {}

        interface1_mn1 = mock_model_item(state=MockState.APPLIED,
                                         device_name='eth0',
                                         bridge="", master="")
        interface2_mn1 = mock_model_item(state=MockState.FOR_REMOVAL,
                                         device_name='eth1',
                                         bridge="", master="bond0")
        interface3_mn1 = mock_model_item(state=MockState.APPLIED,
                                         device_name='eth2',
                                         bridge="", master="")
        interface4_mn1 = mock_model_item(state=MockState.APPLIED,
                                         device_name='eth3',
                                         bridge="", master="")
        interface5_mn1 = mock_model_item(state=MockState.FOR_REMOVAL,
                                         device_name='bond0',
                                         bridge="", master="")
        interface1_mn2 = mock_model_item(state=MockState.APPLIED,
                                         device_name='eth0',
                                         bridge="", master="")
        interface2_mn2 = mock_model_item(state=MockState.FOR_REMOVAL,
                                         device_name='eth1',
                                         bridge="", master="bond0")
        interface3_mn2 = mock_model_item(state=MockState.APPLIED,
                                         device_name='eth2',
                                         bridge="", master="")
        interface4_mn2 = mock_model_item(state=MockState.APPLIED,
                                         device_name='eth3',
                                         bridge="", master="")
        interface5_mn2 = mock_model_item(state=MockState.FOR_REMOVAL,
                                         device_name='bond0',
                                         bridge="", master="")


        interface1_mn1.is_for_removal = lambda: False
        interface2_mn1.is_for_removal = lambda: True
        interface3_mn1.is_for_removal = lambda: False
        interface4_mn1.is_for_removal = lambda: False
        interface5_mn1.is_for_removal = lambda: True
        interface1_mn2.is_for_removal = lambda: False
        interface2_mn2.is_for_removal = lambda: True
        interface3_mn2.is_for_removal = lambda: False
        interface4_mn2.is_for_removal = lambda: False
        interface5_mn2.is_for_removal = lambda: True

        node1 = mock_model_item(state=MockState.APPLIED, hostname='mn1')
        node1.network_interfaces = [interface1_mn1, interface2_mn1,
                                    interface3_mn1, interface4_mn1, interface5_mn1]
        node2 = mock_model_item(state=MockState.APPLIED, hostname='mn2')
        node2.network_interfaces = [interface1_mn2, interface2_mn2,
                                    interface3_mn2, interface4_mn2,
                                    interface5_mn2]
        cluster = mock_model_item(state=MockState.APPLIED,
                                  nodes=[node1, node2])
        vcs_model = VCSModel(None)

        vcs_model._hb_networks_info_for_node = mock.Mock(
            side_effect=mock_hb_networks_info_for_node)

        expected_return = defaultdict(dict)
        expected_return['bond0']['mn1'] = None
        expected_return['bond0']['mn2'] = None

        self.assertEqual(vcs_model.get_nic_groups(cluster,
                                                  state=State.REMOVAL()),
                         expected_return)
        self.assertEqual(vcs_model._hb_networks_info_for_node.call_count, 2)

    def test_get_nic_groups_with_bridges(self):

        hb_networks = [{'eth2': '08:00:27:F3:7C:C3', 'eth3': '08:00:27:F3:7D:C4'},
                       {'eth2': '08:00:27:F3:7C:C5', 'eth3': '08:00:27:F3:7D:C6'}]
        def mock_hb_networks_info_for_node(*args, **kwargs):
            return hb_networks.pop(0), {}

        interface1_mn1 = mock_model_item(state=MockState.APPLIED, autospec=False,
                                         device_name='eth0', bridge="")
        interface2_mn1 = mock_model_item(state=MockState.FOR_REMOVAL, autospec=False,
                                         device_name='eth1', bridge="br0")
        interface3_mn1 = mock_model_item(state=MockState.APPLIED, autospec=False,
                                         device_name='eth2', bridge="")
        interface4_mn1 = mock_model_item(state=MockState.APPLIED, autospec=False,
                                         device_name='eth3', bridge="")
        interface5_mn1 = mock_model_item(state=MockState.FOR_REMOVAL, autospec=False,
                                         device_name='br0', bridge="")
        interface1_mn2 = mock_model_item(state=MockState.APPLIED, autospec=False,
                                         device_name='eth0', bridge="")
        interface2_mn2 = mock_model_item(state=MockState.FOR_REMOVAL, autospec=False,
                                         device_name='eth1', bridge="br0")
        interface3_mn2 = mock_model_item(state=MockState.APPLIED, autospec=False,
                                         device_name='eth2', bridge="")
        interface4_mn2 = mock_model_item(state=MockState.APPLIED, autospec=False,
                                         device_name='eth3', bridge="")
        interface5_mn2 = mock_model_item(state=MockState.FOR_REMOVAL, autospec=False,
                                         device_name='br0', bridge="")

        interface1_mn1.is_for_removal = lambda: False
        interface2_mn1.is_for_removal = lambda: True
        interface3_mn1.is_for_removal = lambda: False
        interface4_mn1.is_for_removal = lambda: False
        interface5_mn1.is_for_removal = lambda: True
        interface1_mn2.is_for_removal = lambda: False
        interface2_mn2.is_for_removal = lambda: True
        interface3_mn2.is_for_removal = lambda: False
        interface4_mn2.is_for_removal = lambda: False
        interface5_mn2.is_for_removal = lambda: True

        node1 = mock_model_item(state=MockState.APPLIED, hostname='mn1')
        node1.network_interfaces = [interface1_mn1, interface2_mn1,
                                    interface3_mn1, interface4_mn1, interface5_mn1]
        node2 = mock_model_item(state=MockState.APPLIED, hostname='mn2')
        node2.network_interfaces = [interface1_mn2, interface2_mn2,
                                    interface3_mn2, interface4_mn2,
                                    interface5_mn2]
        cluster = mock_model_item(state=MockState.APPLIED,
                                  nodes=[node1, node2])
        vcs_model = VCSModel(None)

        vcs_model._hb_networks_info_for_node = mock.Mock(
            side_effect=mock_hb_networks_info_for_node)

        expected_return = defaultdict(dict)
        expected_return['br0']['mn1'] = None
        expected_return['br0']['mn2'] = None

        self.assertEqual(vcs_model.get_nic_groups(cluster,
                                                  state=State.REMOVAL()),
                         expected_return)
        self.assertEqual(vcs_model._hb_networks_info_for_node.call_count, 2)

    def test_get_nic_groups_with_bond_initial(self):

        hb_networks = [{'eth2': {'mac': '08:00:27:F3:7C:C3', 'sap': ''},
                        'eth3': {'mac': '08:00:27:F3:7D:C4', 'sap': ''}},
                       {'eth2': {'mac': '08:00:27:F3:7C:C5', 'sap': ''},
                        'eth3': {'mac': '08:00:27:F3:7D:C6', 'sap': ''}}]
        def mock_hb_networks_info_for_node(*args, **kwargs):
            return hb_networks.pop(0), {}

        interface1_mn1 = mock_model_item(device_name='eth0',
                                         bridge="", master="")
        interface1_mn1.is_for_removal = lambda: False

        interface2_mn1 = mock_model_item(device_name='eth1',
                                         bridge="", master="bond0")

        interface2_mn1.is_for_removal = lambda: False
        interface3_mn1 = mock_model_item(device_name='eth2',
                                         bridge="", master="")
        interface3_mn1.is_for_removal = lambda: False
        interface4_mn1 = mock_model_item(device_name='eth3',
                                         bridge="", master="")
        interface4_mn1.is_for_removal = lambda: False
        interface5_mn1 = mock_model_item(device_name='bond0',
                                         bridge="", master="")
        interface5_mn1.is_for_removal = lambda: False
        interface1_mn2 = mock_model_item(device_name='eth0',
                                         bridge="", master="")
        interface1_mn2.is_for_removal = lambda: False
        interface2_mn2 = mock_model_item(device_name='eth1',
                                         bridge="", master="bond0")
        interface2_mn2.is_for_removal = lambda: False
        interface3_mn2 = mock_model_item(device_name='eth2',
                                         bridge="", master="")
        interface3_mn2.is_for_removal = lambda: False
        interface4_mn2 = mock_model_item(device_name='eth3',
                                         bridge="", master="")
        interface4_mn2.is_for_removal = lambda: False
        interface5_mn2 = mock_model_item(device_name='bond0',
                                         bridge="", master="")
        interface5_mn2.is_for_removal = lambda: False

        node1 = mock_model_item(hostname='mn1')
        node1.network_interfaces = [interface1_mn1, interface2_mn1,
                                    interface3_mn1, interface4_mn1, interface5_mn1]
        node2 = mock_model_item(hostname='mn2')
        node2.network_interfaces = [interface1_mn2, interface2_mn2,
                                    interface3_mn2, interface4_mn2,
                                    interface5_mn2]
        cluster = mock_model_item(nodes=[node1, node2])
        vcs_model = VCSModel(None)

        vcs_model._hb_networks_info_for_node = mock.Mock(
            side_effect=mock_hb_networks_info_for_node)

        expected_return = defaultdict(dict)
        expected_return['bond0']['mn1'] = None
        expected_return['bond0']['mn2'] = None
        expected_return['eth0']['mn1'] = None
        expected_return['eth0']['mn2'] = None

        self.assertEqual(vcs_model.get_nic_groups(cluster),
                         expected_return)
        self.assertEqual(vcs_model._hb_networks_info_for_node.call_count, 2)
