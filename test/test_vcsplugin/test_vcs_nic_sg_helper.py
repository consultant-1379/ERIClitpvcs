##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import mock
import unittest

from litp.plan_types.deployment_plan import deployment_plan_tags

from vcsplugin.vcs_base_helper import VcsBaseHelper
import vcsplugin.vcs_nic_sg_helper
from vcsplugin.vcs_nic_sg_helper import (VcsNICServiceGroupHelper,
                                         VCSNICServiceGroupUpdateHelper,
                                         _get_nic_phantom_resource_name,
                                         _get_nic_resource_name,
                                         _add_nic_sg_resources,
                                         create_nic_resources,
                                         get_applied_nic_groups,
                                         _get_nics_for_removal,
                                         _get_nic_groups_for_removal,
                                         get_nic_items_for_device,)

from base_vcs_integration import VCSIntegrationBase
from mocks import mock_model_item, DummyPlugin, State
from test_vcs_model import tree


mock.patch('litp.core.litp_logging.LitpLogger').start()


class DummyPluginForTest(object):
    def callback_method(self):
        pass


class TestVCSNICServiceGroupUpdateHelper(unittest.TestCase):
    """
    Test cases for `VCSNICServiceGroupUpdateHelper`.
    """
    def setUp(self):
        self.helper = VCSNICServiceGroupUpdateHelper(DummyPluginForTest)
        clusters = tree()
        cluster = clusters['cluster1']
        cluster['is_for_removal'] = lambda: False
        cluster['network_hosts'] = []
        cluster['item_id'] = 'cluster_id'
        cluster['get_vpath'] = lambda: 'cluster_vpath'
        cluster['nodes']['n1']['hostname'] = 'n1'
        cluster['nodes']['n1']['is_initial'] = lambda: False
        cluster['nodes']['n1']['get_vpath'] = lambda: 'n1_vpath'
        cluster['nodes']['n2']['hostname'] = 'n2'
        cluster['nodes']['n2']['is_initial'] = lambda: False
        cluster['nodes']['n2']['get_vpath'] = lambda: 'n2_vpath'

        cluster['nodes']['n1']['network_interfaces']['eth0'] = \
                mock_model_item(state=State.UPDATED, device_name="eth0",
                ipaddress='1.1.1.1',
                master=True,
                applied_properties_determinable=True,
                applied_properties={'device_name': 'eth0', 'master': 'bond0', u'macaddress': u'08:00:27:5E:BE:AC'},
                network_name="mgmt", autospec=False)
        cluster['nodes']['n1']['network_interfaces']['eth0'].set_updated()


        cluster['nodes']['n2']['network_interfaces']['eth0'] = \
                mock_model_item(state=State.APPLIED, device_name="eth0",
                ipaddress='1.1.1.1',
                master=True,
                applied_properties_determinable=True,
                applied_properties={'device_name': 'eth0', 'master': 'bond0', u'macaddress': u'08:00:27:5E:BE:AD'},
                network_name="mgmt", autospec=False)
        cluster['nodes']['n2']['network_interfaces']['eth0'].set_updated()

        cluster['nodes']['n1']['network_interfaces']['eth1'] = \
                mock_model_item(state=State.APPLIED, device_name="eth1",
                ipaddress='1.1.1.1',
                master=True,
                applied_properties_determinable=True,
                applied_properties={'device_name': 'eth1'},
                network_name="traffic1", autospec=False)
        cluster['nodes']['n1']['network_interfaces']['eth1'].set_applied()

        cluster['default_nic_monitor'] = 'netstat'
        cluster['applied_properties']['default_nic_monitor'] = 'netstat'
        self.cluster = cluster

    @mock.patch('vcsplugin.vcs_nic_sg_helper.VCSModel')
    def test_get_network_host_update_tasks_does_not_trigger_initial_cluster(self, mock_model):
        mock_model.get_nic_groups.return_value = {
            'eth0': {
                'n1': ['1.1.1.1'],
                'n2': ['1.1.1.1'],
            }
        }
        self.cluster['nodes']['n1']['is_initial'] = lambda: True
        self.cluster['nodes']['n2']['is_initial'] = lambda: True
        self.cluster['network_hosts']=tree()
        self.cluster['network_hosts']['nwhost1']['is_initial'] = lambda: True
        self.cluster['network_hosts']['nwhost1']['is_for_removal'] = lambda: False
        self.cluster['network_hosts']['nwhost1']['network_name'] = 'mgmt'
        tasks = self.helper.get_network_host_update_tasks(mock.Mock(),
                self.cluster)
        self.assertEqual([], tasks)

    @mock.patch('vcsplugin.vcs_nic_sg_helper.VCSModel')
    def test_get_network_host_update_tasks_does_not_trigger_all_applied(self, mock_model):
        mock_model.get_nic_groups.return_value = {
            'eth0': {
                'n1': ['1.1.1.1'],
                'n2': ['1.1.1.1'],
            }
        }
        self.cluster['network_hosts']=tree()
        self.cluster['network_hosts']['nwhost1']['is_initial'] = lambda: False
        self.cluster['network_hosts']['nwhost1']['is_for_removal'] = lambda: False
        self.cluster['network_hosts']['nwhost1']['is_applied'] = lambda: False
        self.cluster['network_hosts']['nwhost1']['network_name'] = 'mgmt'
        tasks = self.helper.get_network_host_update_tasks(mock.Mock(),
                self.cluster)
        self.assertEqual([], tasks)

    @mock.patch('vcsplugin.vcs_nic_sg_helper.CallbackTask')
    @mock.patch('vcsplugin.vcs_nic_sg_helper.VCSModel')
    def test_get_network_host_update_tasks_gens_nwhost(
            self, mock_model, MockCallbackTask):
        mock_model.return_value.get_nic_groups.return_value = {
            'eth0': {
                'n1': ['1.1.1.1'],
                'n2': ['1.1.1.1'],
            },
            'eth1': {
                'n1': ['2.2.2.2'],
            }
        }
        self.cluster['network_hosts']=mock.MagicMock()
        nwhost1 = mock.Mock(is_initial=mock.Mock(return_value=True),
                            is_for_removal=mock.Mock(return_value=False),
                            network_name='traffic1',
                            ip="2.2.2.2")
        self.cluster['network_hosts'].query.side_effect = (lambda id,
                network_name: [nwhost for nwhost in [nwhost1]
                        if nwhost.network_name == network_name])
        self.cluster['network_hosts'].__iter__.return_value = [nwhost1]

        tasks = self.helper.get_network_host_update_tasks(mock.Mock(),
                self.cluster)
        self.assertEqual(1, len(tasks))
        self.assertEqual(['2.2.2.2'], MockCallbackTask.call_args[1]['addresses'])
        self.assertEqual('n1', MockCallbackTask.call_args[1]['sys'])

    @mock.patch('vcsplugin.vcs_nic_sg_helper.CallbackTask')
    @mock.patch('vcsplugin.vcs_nic_sg_helper.VCSModel')
    def test_get_network_host_update_tasks_gens_nwhost_update_no_def_route(
        self, mock_model, MockCallbackTask):
        mock_model.return_value.get_nic_groups.return_value = {
            'eth0': {
                'n1': ['1.1.1.1'],
                'n2': ['1.1.1.1'],
            },
            'eth1': {
                'n1': None,
            }
        }
        self.cluster['network_hosts']=mock.MagicMock()
        nwhost1 = mock.Mock(is_initial=mock.Mock(return_value=False),
                            is_for_removal=mock.Mock(return_value=True),
                            network_name='traffic1',
                            ip='1.2.3.4')
        self.cluster['network_hosts'].query.side_effect = (lambda id,
                network_name: [nwhost for nwhost in [nwhost1]
                        if nwhost.network_name == network_name])
        self.cluster['network_hosts'].__iter__.return_value = [nwhost1]

        tasks = self.helper.get_network_host_update_tasks(mock.Mock(),
                self.cluster)
        self.assertEqual(1, len(tasks))
        self.assertEqual([], MockCallbackTask.call_args[1]['addresses'])
        self.assertEqual('n1', MockCallbackTask.call_args[1]['sys'])

    def test_instantation(self):
        self.assertTrue(
            isinstance(self.helper, VCSNICServiceGroupUpdateHelper))

    def test_get_update_slave_nics(self):
        updated_nics = self.helper.get_updated_slave_nics(self.cluster)
        n1_eth0 = self.cluster['nodes']['n1']['network_interfaces']['eth0']
        n2_eth0 = self.cluster['nodes']['n2']['network_interfaces']['eth0']
        expected_list = [(n1_eth0, self.cluster['nodes']['n1']),
                         (n2_eth0, self.cluster['nodes']['n2'])]
        self.assertEquals(updated_nics, expected_list)

    def test_nic_is_updated_to_slave(self):
        nic = mock.Mock(is_updated=lambda:True, master="bond1",
            applied_properties = {u'macaddress': u'08:00:27:5E:BE:AC',
            u'master': u'bond0', u'device_name': u'eth1'})
        self.assertTrue(self.helper.nic_is_updated_to_slave([nic], nic))
        nic = mock.Mock(is_updated=lambda:False, master=True)
        self.assertFalse(self.helper.nic_is_updated_to_slave([nic], nic))
        nic = mock.Mock(is_updated=lambda:True, master=False)
        self.assertFalse(self.helper.nic_is_updated_to_slave([nic], nic))
        nic = mock.Mock(is_updated=lambda:True, master="bond1",
            applied_properties = {u'macaddress': u'08:00:27:5E:BE:AC',
            u'network_name': u'mgmt', u'ipaddress': u'10.10.10.101'})
        self.assertTrue(self.helper.nic_is_updated_to_slave([nic], nic))

    @mock.patch('vcsplugin.vcs_nic_sg_helper.CallbackTask')
    @mock.patch('vcsplugin.vcs_nic_sg_helper.get_nic_items_for_device')
    @mock.patch('vcsplugin.vcs_nic_sg_helper.VCSModel')
    def test_create_configuration(
            self, patched_model, get_nic_items, MockCallbackTask):
        MockCallbackTask.side_effect = lambda *args, **kwargs: mock.MagicMock()
        mock_model = mock.Mock()
        mock_model.get_nic_groups.return_value = {
            'eth0':  {
                'n1': '1.1.1.1',
                'n2': '1.1.1.1',
            },
            'eth1':  {
                'n1': '1.1.1.1',
                'n2': '1.1.1.1',
            }
        }
        patched_model.return_value = mock_model
        get_nic_items.return_value = [mock.Mock()]
        tasks = self.helper.create_configuration(mock.Mock(), self.cluster)
        self.assertEqual(3, len(tasks))
        mock_model.get_nic_groups.return_value = {
            'eth0':  {
                'n1': '1.1.1.1',
                'n2': '1.1.1.1',
                'n3': '1.1.1.1',
            },
            'eth1':  {
                'n1': '1.1.1.1',
                'n2': '1.1.1.1',
            }
        }
        tasks = self.helper.create_configuration(mock.Mock(), self.cluster)
        self.assertEqual(2, len(tasks))

    def test_create_configuration_cluster_removal(self):
        plugin = mock.Mock()
        plugin_inst = mock.Mock()
        plugin.return_value = plugin_inst
        helper = VCSNICServiceGroupUpdateHelper(plugin)
        cluster = mock.MagicMock()
        node1 = mock.MagicMock()
        node1.hostname = "mn1"
        eth0 = mock_model_item(state=State.UPDATED, device_name="eth0",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth0'},
                               master="bond0", network_name="", autospec=False)
        bond0 = mock_model_item(state=State.APPLIED, device_name="bond0",
                                applied_properties_determinable=True,
                                applied_properties={'device_name': 'bond0'},
                                network_name="", autospec=False)
        node1.network_interfaces = [eth0, bond0]
        cluster.nodes = [node1]
        cluster.is_for_removal.return_value = True
        tasks = helper.create_configuration(plugin_inst, cluster)
        self.assertEqual(0, len(tasks))


    def _add_vpaths_to_cluster(self):

        self.cluster['nodes']['n1']['network_interfaces']['eth0'].get_vpath = \
                lambda: 'n1_eth0_vpath'
        self.cluster['nodes']['n1']['network_interfaces']['eth1'].get_vpath = \
                lambda: 'n1_eth1_vpath'
        self.cluster['nodes']['n2']['network_interfaces']['eth0'].get_vpath = \
                lambda: 'n2_eth0_vpath'

    def test_get_nic_items_for_device_returns_empty_list_for_bad_hostnames(self):
        self.assertEquals([], get_nic_items_for_device(self.cluster,
                                                       'eth0', ['n3', 'n4']))

    def test_get_nic_items_for_device_returns_empty_list_for_bad_nics(self):
        self.assertEquals([], get_nic_items_for_device(self.cluster,
                                                       'eth2', ['n1', 'n2']))

    def test_get_nic_items_for_device_returns_empty_list_for_bad_nics(self):
        self.assertEquals([], get_nic_items_for_device(self.cluster,
                                                       'eth2', ['n1', 'n2']))

    def test_get_nic_items_for_device_pos_01(self):
        self._add_vpaths_to_cluster()
        res = get_nic_items_for_device(self.cluster, 'eth0', ['n1', 'n2'])
        self.assertEquals(2, len(res))
        self.assertEquals('n1_eth0_vpath', res[0].get_vpath())
        self.assertEquals('n2_eth0_vpath', res[1].get_vpath())

    def test_get_nic_items_for_device_pos_02(self):
        self._add_vpaths_to_cluster()
        res = get_nic_items_for_device(self.cluster, 'eth1', ['n1', 'n2'])
        self.assertEquals(1, len(res))
        self.assertEquals('n1_eth1_vpath', res[0].get_vpath())

    def test_update_network_hosts(self):
        mii = '0'
        self.helper.nodes = ['n3']
        n1 = mock.Mock(hostname='n1')
        self.helper._vcs_api = mock.MagicMock()
        self.helper.update_network_hosts(mock.Mock(), "resource",
                                ['nwhost1', 'nwhost2'], '0', 'n1')
        self.assertEqual(['n1'], self.helper.nodes)
        calls = [mock.call('resource', 'NetworkHosts', 'nwhost1 nwhost2', sys='n1'),
                 mock.call('resource', 'Mii', '0', sys='n1')]

        self.helper._vcs_api.hares_modify.assert_has_calls(calls)

    def test_update_network_hosts_empty_list(self):
        self.helper.nodes = ['n3']
        self.helper._vcs_api = mock.MagicMock()
        self.helper.update_network_hosts(mock.Mock(), "resource",
                                [],'vpath', 'n1')
        self.helper._vcs_api.hares_modify.assert_any_call(
                "resource", "NetworkHosts", "-keys", delete=True, sys='n1')

    def test_get_nic_for_network(self):
        node = mock.Mock(query=lambda *args, **kwargs: [])
        self.assertEqual(
            None,
            self.helper._get_nic_for_network(node, 'fooo'))
        node = mock.Mock(query=lambda *args, **kwargs: ['foo'])
        self.assertEqual(
            'foo',
            self.helper._get_nic_for_network(node, 'foo'))

    @mock.patch('vcsplugin.vcs_nic_sg_helper.CallbackTask')
    @mock.patch('vcsplugin.vcs_nic_sg_helper.VCSModel')
    def test_update_doesnt_create_task_for_ifaces_with_no_ip(
            self, mock_model, MockCallbackTask):

        # TORF-186827
        # There should not be any reconfigure task for eth2, with no IP and
        # not previous IP
        self.cluster['nodes']['n1']['network_interfaces']['eth2'] = \
                mock_model_item(state=State.APPLIED, device_name="eth2",
                ipaddress='',
                applied_properties_determinable=True,
                applied_properties={'device_name': 'eth2',
                                    'macaddress': 'AA:AA:AA:AA:AA:AA'},
                network_name="dummy", autospec=False)

        mock_model.return_value.get_nic_groups.return_value = {
            'eth0': {
                'n1': ['1.1.1.1'],
                'n2': ['1.1.1.1'],
            },
            'eth1': {
                'n1': ['2.2.2.2'],
            },
            'eth2': {
                'n1': [''],
            }
        }
        self.cluster['network_hosts']=mock.MagicMock()
        nwhost1 = mock.Mock(is_initial=mock.Mock(return_value=True),
                            is_for_removal=mock.Mock(return_value=False),
                            network_name='traffic1',
                            ip="2.2.2.2"
                            )
        self.cluster['network_hosts'].query.side_effect = (lambda id,
                network_name: [nwhost for nwhost in [nwhost1]
                        if nwhost.network_name == network_name])
        self.cluster['network_hosts'].__iter__.return_value = [nwhost1]

        tasks = self.helper.get_network_host_update_tasks(mock.Mock(),
                                                          self.cluster)
        self.assertEqual(1, len(tasks))

class TestRemovalOfNic(VCSIntegrationBase):

    def setUp(self):
        super(TestRemovalOfNic, self).setUp()
        self.helper = VcsNICServiceGroupHelper(self.plugin.__class__)

    def test_validate_nic_to_be_removed_is_in_use(self):
        self.setup_model()
        self._add_service_to_model(1)
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
            ipaddress="10.10.11.20")

        for i in range(1, 3):
            self._add_item_to_model(
                'eth',
                "/deployments/test/clusters/cluster1/nodes/node%s/network_interfaces/ip_1" % i,
           #     network_name='traffic',
           #     ipaddress='10.10.11.%d' % i,
                macaddress='aa:aa:aa:aa:aa:aa',
                device_name='eth1',
                bridge="br0")


        for i in range(1, 3):
            self._add_item_to_model(
                "bridge",
                "/deployments/test/clusters/cluster1/nodes/node%s/network_interfaces/br_1" % i,
                network_name="traffic",
                device_name="br0")

        self._set_model_applied()
        self._remove_item_from_model("/deployments/test/clusters/cluster1/nodes/node1/network_interfaces/br_1")

        errors = self.helper.validate_model(self.context_api)

        expected = sorted(["</deployments/test/clusters/cluster1/nodes/node1/network_interfaces/br_1 - ValidationError - This interface is in use by /deployments/test/clusters/cluster1/services/service1/runtimes/runtime1/ipaddresses/vcs_ip>"])

        self.assertEqual(self.string_and_sort(errors), expected)

    def test_validate_nic_to_be_removed_is_not_in_use(self):
        self.setup_model()
        self._add_item_to_model(
            'network',
            '/infrastructure/networking/networks/range_1',
            name='traffic',
            subnet='10.10.11.0/24')

        for i in range(1, 3):
            self._add_item_to_model(
                'eth',
                "/deployments/test/clusters/cluster1/nodes/node%s/network_interfaces/ip_1" % i,
                network_name='traffic',
                ipaddress='10.10.11.%d' % i,
                macaddress='aa:aa:aa:aa:aa:aa',
                device_name='eth1')

        self._set_model_applied()
        self._remove_item_from_model("/deployments/test/clusters/cluster1/nodes/node1/network_interfaces/ip_1")
        errors = self.helper.validate_model(self.context_api)

        self.assertEqual(errors, [])

    def test_tasks_nic_to_be_removed_is_not_in_use(self):
        self.setup_model()
        self._add_item_to_model(
            'network',
            '/infrastructure/networking/networks/range_1',
            name='traffic',
            subnet='10.10.11.0/24')

        for i in range(1, 3):
            self._add_item_to_model(
                'eth',
                "/deployments/test/clusters/cluster1/nodes/node%s/network_interfaces/ip_1" % i,
                network_name='traffic',
                ipaddress='10.10.11.%d' % i,
                macaddress='aa:aa:aa:aa:aa:aa',
                device_name='eth1')

        self._set_model_applied()
        self._remove_item_from_model("/deployments/test/clusters/cluster1/nodes/node1/network_interfaces/ip_1")

        tasks = []
        for cluster in self.context_api.query("vcs-cluster"):
            tasks.extend(self.helper.create_configuration(self.context_api,
                                                          cluster))

        self._print_task_descriptions(tasks)
#        self.assertEqual(tasks, [])

class TestNicRemoval(unittest.TestCase):

    def test_validate_interfaces_for_removal(self):
        cluster = mock.MagicMock()
        ip1 = mock.MagicMock()
        ip1.network_name = "network"
        ip1.get_vpath.return_value = "ip"
        ip1.is_for_removal.return_value = False
        ip2 = mock.MagicMock()
        ip2.network_name = "network"
        ip2.get_vpath.return_value = "ip2"
        ip2.is_for_removal.return_value = False
        ip3 = mock.MagicMock()
        ip3.network_name = "network2"
        ip3.get_vpath.return_value = "ip3"
        ip3.is_for_removal.return_value = False
        interface1 = mock.MagicMock()
        interface1.network_name = "network"
        interface1.get_vpath.return_value = "eth0"
        interface2 = mock.MagicMock()
        interface2.network_name = "network"
        interface2.get_vpath.return_value = "eth0"
        cluster.services.query.return_value = [ip1, ip2, ip3]

        helper = VcsNICServiceGroupHelper(mock.Mock())
        helper._get_sr_grps_nics_for_removal = mock.Mock()
        helper._get_sr_grps_nics_for_removal.return_value = [interface1,
                                                             interface2]
        errors = helper._validate_interfaces_for_removal(cluster)
        expected = sorted(["<eth0 - ValidationError - This interface is in use by ip, ip2>",
                           "<eth0 - ValidationError - This interface is in use by ip, ip2>"])

        self.assertEqual(VCSIntegrationBase.string_and_sort(errors),
                         expected)

    def test_remove_nodes_from_nicgrp_callback(self):
        cluster = mock.MagicMock()
        cluster.item_id = "cluster1"
        vcs_api = mock.MagicMock()

        helper = VcsNICServiceGroupHelper(mock.Mock())
        helper.query_by_vpath = mock.MagicMock()
        helper.query_by_vpath.return_value = cluster
        helper.nodes = ["n1"]
        helper._vcs_api = vcs_api
        helper._remove_node_from_nicgrp_callback(mock.Mock(),
                                                 "eth3",
                                                 ["mn1", "mn2"],
                                                 "/cluster")

        vcs_api.hagrp_offline.assert_any_call("Grp_NIC_cluster1_eth3",
                                              "mn1", forced=False)
        vcs_api.hagrp_delete_in_system_list.assert_any_call("Grp_NIC_cluster1_eth3",
                                              'mn1')
        vcs_api.hagrp_offline.assert_any_call("Grp_NIC_cluster1_eth3",
                                              "mn2", forced=False)
        vcs_api.hagrp_delete_in_system_list.assert_any_call("Grp_NIC_cluster1_eth3",
                                              'mn2')
        self.assertEqual(vcs_api.hagrp_offline.call_count, 2)
        self.assertEqual(vcs_api.hagrp_modify.call_count, 0)

    def test_remove_node_from_nicgrp_callback(self):
        cluster = mock.MagicMock()
        cluster.item_id = "cluster1"
        vcs_api = mock.MagicMock()

        helper = VcsNICServiceGroupHelper(mock.Mock())
        helper.query_by_vpath = mock.MagicMock()
        helper.query_by_vpath.return_value = cluster
        helper._vcs_api = mock.MagicMock()
        helper.hagrp_delete_in_system_list = mock.Mock()
        helper.nodes = ["n1"]
        helper._vcs_api = vcs_api
        helper._remove_node_from_nicgrp_callback(mock.Mock(),
                                                 "eth3",
                                                 ["mn1"],
                                                 "/cluster")

        vcs_api.hagrp_offline.assert_called_once_with("Grp_NIC_cluster1_eth3",
                                                      "mn1", forced=False)
        vcs_api.hagrp_delete_in_system_list.assert_called_once_with("Grp_NIC_cluster1_eth3",
                                                      'mn1')

    def test_remove_nicgrp_callback(self):
        cluster = mock.MagicMock()
        cluster.item_id = "cluster1"
        vcs_api = mock.MagicMock()

        helper = VcsNICServiceGroupHelper(mock.Mock())
        helper.query_by_vpath = mock.MagicMock()
        helper.query_by_vpath.return_value = cluster
        helper.nodes = ["n1"]
        helper._vcs_api = mock.MagicMock()
        helper._vcs_api = vcs_api
        helper._remove_nicgrp_callback(mock.Mock(),
                                       "eth3",
                                       "/cluster")

        vcs_api.hagrp_offline.assert_called_once_with("Grp_NIC_cluster1_eth3")
        vcs_api.hagrp_remove.assert_called_once_with("Grp_NIC_cluster1_eth3")

    def test_get_nics_for_removal(self):
        cluster = mock.MagicMock()
        cluster.item_id = "cluster1"
        cluster.llt_nets = "hb1"
        node1 = mock.MagicMock()
        node1.hostname = "mn1"
        eth0 = mock_model_item(state=State.APPLIED, device_name="eth0",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth0'},
                               network_name="", autospec=False)
        eth1 = mock_model_item(state=State.FOR_REMOVAL, device_name="eth1",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth1'},
                               network_name="", autospec=False)
        eth2 = mock_model_item(state=State.APPLIED, device_name="eth2",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth2'},
                               network_name="hb1", autospec=False)
        eth3 = mock_model_item(state=State.FOR_REMOVAL, device_name="eth3",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth3'},
                               network_name="", autospec=False)
        node1.network_interfaces = [eth0, eth1, eth2, eth3]

        node2 = mock_model_item()
        node2.hostname = "mn2"
        eth0 = mock_model_item(state=State.APPLIED, device_name="eth0",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth0'},
                               network_name="", autospec=False)
        eth1 = mock_model_item(state=State.FOR_REMOVAL, device_name="eth1",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth1'},
                               network_name="", autospec=False)
        eth2 = mock_model_item(state=State.APPLIED, device_name="eth2",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth2'},
                               network_name="hb1", autospec=False)
        eth3 = mock_model_item(state=State.APPLIED, device_name="eth3",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth3'},
                               network_name="", autospec=False)

        node2.network_interfaces = [eth0, eth1, eth2, eth3]
        cluster.nodes = [node1, node2]

        nics_for_removal = _get_nics_for_removal(cluster)
        nic_groups_for_removal = _get_nic_groups_for_removal(cluster)
        self.assertEqual(nics_for_removal,
                         {"eth3": ["mn1"]})

        self.assertEqual(nic_groups_for_removal,
                         ["eth1"])

    def test_get_nics_for_removal_incomplete_state(self):
        cluster = mock.MagicMock()
        cluster.item_id = "cluster1"
        cluster.llt_nets = "hb1"
        node1 = mock.MagicMock()
        node1.hostname = "mn1"
        eth0 = mock_model_item(state=State.INITIAL, device_name="eth0",
                               applied_properties_determinable=False,
                               applied_properties={},
                               network_name="", autospec=False)
        node1.network_interfaces = [eth0]

        node2 = mock_model_item()
        node2.hostname = "mn2"
        eth0 = mock_model_item(state=State.INITIAL, device_name="eth0",
                               applied_properties_determinable=False,
                               applied_properties={},
                               network_name="", autospec=False)

        node2.network_interfaces = [eth0]
        cluster.nodes = [node1, node2]

        nic_groups_for_removal = _get_nic_groups_for_removal(cluster)
        self.assertEqual(nic_groups_for_removal,
                         [])

    def test_get_nics_for_removal_not_applied(self):
        cluster = mock.MagicMock()
        cluster.item_id = "cluster1"
        cluster.llt_nets = "hb1"
        node1 = mock.MagicMock()
        node1.hostname = "mn1"
        eth0 = mock_model_item(state=State.INITIAL, device_name="eth0",
                               applied_properties_determinable=True,
                               applied_properties={},
                               network_name="", autospec=False)
        node1.network_interfaces = [eth0]

        node2 = mock_model_item()
        node2.hostname = "mn2"
        eth0 = mock_model_item(state=State.INITIAL, device_name="eth0",
                               applied_properties_determinable=True,
                               applied_properties={},
                               network_name="", autospec=False)

        node2.network_interfaces = [eth0]
        cluster.nodes = [node1, node2]

        nic_groups_for_removal = _get_nic_groups_for_removal(cluster)
        self.assertEqual(nic_groups_for_removal,
                         [])

    def test_get_nics_for_removal_with_bridges(self):
        cluster = mock.MagicMock()
        cluster.item_id = "cluster1"
        cluster.llt_nets = "hb1"
        node1 = mock.MagicMock()
        node1.hostname = "mn1"
        eth0 = mock_model_item(state=State.APPLIED, device_name="eth0",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth0'},
                               network_name="", autospec=False)
        eth1 = mock_model_item(state=State.FOR_REMOVAL, device_name="eth1",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth1'},
                               bridge="br0", network_name="", autospec=False)
        eth2 = mock_model_item(state=State.APPLIED, device_name="eth2",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth2'},
                               network_name="hb1", autospec=False)
        eth3 = mock_model_item(state=State.APPLIED, device_name="eth3",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth3'},
                               bridge="br1", network_name="", autospec=False)
        br0 = mock_model_item(state=State.FOR_REMOVAL, device_name="br0",
                              applied_properties_determinable=True,
                              applied_properties={'device_name': 'br0'},
                              network_name="", autospec=False)
        br1 = mock_model_item(state=State.FOR_REMOVAL, device_name="br1",
                              applied_properties_determinable=True,
                              applied_properties={'device_name': 'br1'},
                              network_name="", autospec=False)
        node1.network_interfaces = [eth0, eth1, eth2, eth3, br0, br1]

        node2 = mock_model_item()
        node2.hostname = "mn2"
        eth0 = mock_model_item(state=State.APPLIED, device_name="eth0",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth0'},
                               network_name="", autospec=False)
        eth1 = mock_model_item(state=State.APPLIED, device_name="eth1",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth1'},
                               network_name="", autospec=False)
        eth2 = mock_model_item(state=State.APPLIED, device_name="eth2",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth2'},
                               network_name="hb1", autospec=False)
        eth3 = mock_model_item(state=State.APPLIED, device_name="eth3",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth3'},
                               bridge="br1", network_name="", autospec=False)
        br1 = mock_model_item(state=State.APPLIED, device_name="br1",
                              applied_properties_determinable=True,
                              applied_properties={'device_name': 'br1'},
                              network_name="", autospec=False)

        node2.network_interfaces = [eth0, eth1, eth2, eth3, br1]
        cluster.nodes = [node1, node2]

        nics_for_removal = _get_nics_for_removal(cluster)
        nic_groups_for_removal = _get_nic_groups_for_removal(cluster)
        self.assertEqual(nics_for_removal,
                         {"br1": ["mn1"]})

        self.assertEqual(nic_groups_for_removal,
                         ["br0"])

    def test_get_nics_for_removal_with_bonds(self):
        cluster = mock.MagicMock()
        cluster.item_id = "cluster1"
        cluster.llt_nets = "hb1"
        node1 = mock.MagicMock()
        node1.hostname = "mn1"
        eth0 = mock_model_item(state=State.APPLIED, device_name="eth0",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth0'},
                               network_name="", autospec=False)
        eth1 = mock_model_item(state=State.FOR_REMOVAL, device_name="eth1",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth1'},
                               master="bond0", network_name="", autospec=False)
        eth2 = mock_model_item(state=State.APPLIED, device_name="eth2",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth2'},
                               network_name="hb1", autospec=False)
        eth3 = mock_model_item(state=State.APPLIED, device_name="eth3",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth3'},
                               master="bond1", network_name="", autospec=False)
        bond0 = mock_model_item(state=State.FOR_REMOVAL, device_name="bond0",
                                applied_properties_determinable=True,
                                applied_properties={'device_name': 'bond0'},
                                network_name="", autospec=False)
        bond1 = mock_model_item(state=State.FOR_REMOVAL, device_name="bond1",
                                applied_properties_determinable=True,
                                applied_properties={'device_name': 'bond1'},
                                network_name="", autospec=False)
        node1.network_interfaces = [eth0, eth1, eth2, eth3, bond0, bond1]

        node2 = mock_model_item()
        node2.hostname = "mn2"
        eth0 = mock_model_item(state=State.APPLIED, device_name="eth0",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth0'},
                               network_name="", autospec=False)
        eth1 = mock_model_item(state=State.APPLIED, device_name="eth1",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth1'},
                               network_name="", autospec=False)
        eth2 = mock_model_item(state=State.APPLIED, device_name="eth2",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth2'},
                               network_name="hb1",
                               autospec=False)
        eth3 = mock_model_item(state=State.APPLIED, device_name="eth3",
                               applied_properties_determinable=True,
                               applied_properties={'device_name': 'eth3'},
                               master="bond1", network_name="", autospec=False)
        bond1 = mock_model_item(state=State.APPLIED, device_name="bond1",
                                applied_properties_determinable=True,
                                applied_properties={'device_name': 'bond1'},
                                network_name="", autospec=False)

        node2.network_interfaces = [eth0, eth1, eth2, eth3, bond1]
        cluster.nodes = [node1, node2]

        nics_for_removal = _get_nics_for_removal(cluster)
        nic_groups_for_removal = _get_nic_groups_for_removal(cluster)
        self.assertEqual(nics_for_removal,
                         {"bond1": ["mn1"]})

        self.assertEqual(nic_groups_for_removal,
                         ["bond0"])

    def test_get_applied_nics_groups(self):
        cluster = mock.MagicMock()
        cluster.item_id = "cluster1"
        cluster.llt_nets = "hb1"
        node1 = mock.MagicMock()
        node1.hostname = "mn1"
        node1.is_for_removal.return_value = False
        eth0= mock.MagicMock(device_name="eth0")
        eth1= mock.MagicMock(device_name="eth1")
        eth2= mock.MagicMock(device_name="eth2", network_name="hb1")
        eth3= mock.MagicMock(device_name="eth3")
        eth0.is_applied.return_value = False
        eth1.is_applied.return_value = True
        eth2.is_applied.return_value = True
        eth3.is_applied.return_value = True
        node1.network_interfaces = [eth0, eth1, eth2, eth3]

        node2 = mock.MagicMock()
        node2.hostname = "mn2"
        node2.is_for_removal.return_value = False
        eth0= mock.MagicMock(device_name="eth0")
        eth1= mock.MagicMock(device_name="eth1")
        eth2= mock.MagicMock(device_name="eth2", network_name="hb1")
        eth3= mock.MagicMock(device_name="eth3")
        eth0.is_applied.return_value = False
        eth1.is_applied.return_value = True
        eth2.is_applied.return_value = False
        eth3.is_applied.return_value = False

        node2.network_interfaces = [eth0, eth1, eth2, eth3]
        cluster.nodes = [node1, node2]

        applied_nic_groups = get_applied_nic_groups(cluster)
        self.assertEqual(applied_nic_groups,
                         ['Grp_NIC_cluster1_eth3', 'Grp_NIC_cluster1_eth2',
                          'Grp_NIC_cluster1_eth1'])

    @mock.patch("vcsplugin.vcs_nic_sg_helper.get_nic_items_for_device")
    @mock.patch("vcsplugin.vcs_nic_sg_helper.CallbackTask")
    def test_create_remove_nic_task(self, MockCallbackTask, get_nic_items):
        pluginClass = mock.MagicMock()
        plugin = mock.MagicMock()
        pluginClass.return_value = plugin
        plugin.callback_method = mock.Mock()
        helper = VcsNICServiceGroupHelper(pluginClass)

        cluster = mock.MagicMock()
        cluster.item_id = "cluster1"
        cluster.get_vpath.return_value = "/cluster1"

        nic_model_item = mock.Mock()
        get_nic_items.return_value = [nic_model_item]

        tasks = helper._create_remove_nic_task(
            cluster,
            "Grp_NIC_cluster1_eth1",
            ["mn1"])

        MockCallbackTask.assert_called_once_with(
            cluster,
            'Remove nodes "mn1" from service group for NIC "Grp_NIC_cluster1_eth1"',
            plugin.callback_method,
            nodes=['mn1'],
            callback_func='_remove_node_from_nicgrp_callback',
            callback_class='VcsNICServiceGroupHelper',
            nic_group='Grp_NIC_cluster1_eth1',
            cluster_vpath="/cluster1",
            expect_faulted=False,
            tag_name='DEPLOYMENT_PRE_NODE_CLUSTER_TAG'
        )

    @mock.patch("vcsplugin.vcs_nic_sg_helper.get_nic_items_for_device")
    @mock.patch("vcsplugin.vcs_nic_sg_helper.CallbackTask")
    def test_create_remove_nic_group_task(self, MockCallbackTask, get_nic_items):
        MockCallbackTask
        pluginClass = mock.MagicMock()
        plugin = mock.MagicMock()
        pluginClass.return_value = plugin
        plugin.callback_method = mock.Mock()
        helper = VcsNICServiceGroupHelper(pluginClass)
        nic_model_item = mock.Mock()
        get_nic_items.return_value = [nic_model_item]

        cluster = mock.MagicMock()
        cluster.item_id = "cluster1"
        cluster.get_vpath.return_value = "/cluster1"
        cluster.is_for_removal.return_value = False
        tasks = helper._create_remove_nic_group_task(
            cluster,
            "Grp_NIC_cluster1_eth1")

        MockCallbackTask.assert_called_once_with(
            cluster,
            'Remove VCS service group for NIC "Grp_NIC_cluster1_eth1"',
            plugin.callback_method,
            callback_func='_remove_nicgrp_callback',
            callback_class='VcsNICServiceGroupHelper',
            nic_group='Grp_NIC_cluster1_eth1',
            cluster_vpath=cluster.get_vpath(),
            offline=True,
            tag_name='DEPLOYMENT_PRE_NODE_CLUSTER_TAG')

    @mock.patch("vcsplugin.vcs_nic_sg_helper.get_nic_items_for_device")
    @mock.patch("vcsplugin.vcs_nic_sg_helper.CallbackTask")
    def test_create_remove_nic_group_task_cluster_removal(self, MockCallbackTask, get_nic_items):
        MockCallbackTask
        pluginClass = mock.MagicMock()
        plugin = mock.MagicMock()
        pluginClass.return_value = plugin
        plugin.callback_method = mock.Mock()
        helper = VcsNICServiceGroupHelper(pluginClass)
        nic_model_item = mock.Mock()
        get_nic_items.return_value = [nic_model_item]

        cluster = mock.MagicMock()
        cluster.item_id = "cluster1"
        cluster.get_vpath.return_value = "/cluster1"
        cluster.is_for_removal.return_value = True
        tasks = helper._create_remove_nic_group_task(
            cluster,
            "Grp_NIC_cluster1_eth1")
        self.assertEqual(0, len(tasks))

    @mock.patch("vcsplugin.vcs_nic_sg_helper.VCSModel")
    @mock.patch("vcsplugin.vcs_nic_sg_helper._get_nics_for_removal")
    def test_create_configuration(self, _get_nics_for_removal, MockVCSModel):
        vcs_model = mock.MagicMock()
        vcs_model.get_nic_groups.side_effect = [False, True]
        MockVCSModel.return_value = vcs_model
        plugin = mock.MagicMock()
        helper = VcsNICServiceGroupHelper(plugin)

        _get_nics_for_removal.return_value = {"eth0": ["node1"]}

        create_remove_nic_task = mock.MagicMock()
        create_remove_nic_task.return_value = "task"
        helper._create_remove_nic_task = create_remove_nic_task
        api = mock.MagicMock()

        cluster = mock.MagicMock()
        cluster.item_id = "cluster1"
        cluster.is_initial.return_value = False
        cluster.is_for_removal.return_value = False
        pre_node_tasks, post_node_tasks = helper.create_configuration(api,
                                                                      cluster)
        self.assertEqual(["task"], pre_node_tasks)
        self.assertEqual([], post_node_tasks)
        create_remove_nic_task.assert_called_once_with(cluster,
                                                       "eth0",
                                                       ["node1"])


class TestVcsNICServiceGroupHelper(unittest.TestCase):
    def test_get_nic_service_group_name(self):
        cluster_item_id = '1234'
        nic_key = 'eth0'

        expected_service_group_name = 'Grp_NIC_1234_eth0'
        service_group_name = VcsBaseHelper.get_nic_service_group_name(
                                           cluster_item_id,
                                           nic_key)

        self.assertEqual(service_group_name, expected_service_group_name)

    @mock.patch('vcsplugin.vcs_nic_sg_helper.get_nic_items_for_device')
    def test_nicgroup_task(self, get_nic_items):
        plugin = DummyPluginForTest
        plugin_callback_method_mock = mock.Mock()
        plugin.callback_method = plugin_callback_method_mock

        cluster = mock.Mock(['item_id', 'services', 'get_vpath', 'query'])
        cluster.item_id = 1234
        cluster.services = 'service'
        cluster.nodes = [mock.Mock(hostname="mn1"), mock.Mock(hostname="mn2")]
        network_host1 = mock.Mock(ip='10.10.10.150', network_name='mgmt')
        cluster.query.return_value = [network_host1]
        groups = {'eth0': {'mn1': ['10.10.10.150']}}

        nic_0 = mock.Mock(device_name='eth0', network_name='mgmt',
                          ipaddress='192.168.1.1')
        nic_1 = mock.Mock(device_name='eth0', network_name='mgmt',
                          ipaddress='192.168.1.2')
        get_nic_items.return_value = [nic_0, nic_1]

        expected_task_description = 'Callback task for NIC Group'

        with mock.patch('vcsplugin.vcs_nic_sg_helper.CallbackTask') \
                as callback_task_mock:
            callback_task_mock.return_value = mock.Mock(
                    description='Callback task for NIC Group',
                    model_items=set())
            tasks = VcsNICServiceGroupHelper(plugin). \
                _generate_nicgrp_task(cluster, groups)

        self.assertEquals(1, len(tasks))
        self.assertEquals(expected_task_description, tasks[0].description)
        self.assertEquals(set([nic_0, nic_1, network_host1]),
                          tasks[0].model_items)

        self.assertEqual(callback_task_mock.call_count, 1)
        callback_task_mock.assert_called_with(
            cluster,
            'Create VCS service group for NIC "eth0"',
            plugin_callback_method_mock,
            callback_class='VcsNICServiceGroupHelper',
            callback_func="add_nicgrp_callback",
            nic_name='eth0',
            node_gateways={'mn1': ['10.10.10.150']},
            mii="0",
            cluster_item_id=1234)

    @mock.patch('vcsplugin.vcs_nic_sg_helper.get_nic_items_for_device')
    def test_nicgroup_force_mii(self, get_nic_items):
        plugin = DummyPluginForTest
        plugin_callback_method_mock = mock.Mock()
        plugin.callback_method = plugin_callback_method_mock

        cluster = mock.Mock(['item_id', 'services', 'get_vpath', 'query'])
        cluster.item_id = 1234
        cluster.services = 'service'
        cluster.nodes = [mock.Mock(hostname="mn1"), mock.Mock(hostname="mn2")]
        network_host1 = mock.Mock(ip='10.10.10.150', network_name='mgmt')
        cluster.query.return_value = [network_host1]
        groups = {'eth0': {'mn1': ['10.10.10.150']}}

        nic_0 = mock.Mock(device_name='eth0', ipaddress='')
        nic_1 = mock.Mock(device_name='eth0', ipaddress='')
        get_nic_items.return_value = [nic_0, nic_1]

        expected_task_description = 'Callback task for NIC Group'

        with mock.patch('vcsplugin.vcs_nic_sg_helper.CallbackTask') \
                as callback_task_mock:
            callback_task_mock.return_value = mock.Mock(
                    description='Callback task for NIC Group',
                    model_items=set())
            tasks = VcsNICServiceGroupHelper(plugin). \
                _generate_nicgrp_task(cluster, groups)

        self.assertEquals(1, len(tasks))
        self.assertEquals(expected_task_description, tasks[0].description)
        self.assertEquals(set([nic_0, nic_1, network_host1]),
                          tasks[0].model_items)

        self.assertEqual(callback_task_mock.call_count, 1)
        callback_task_mock.assert_called_with(
            cluster,
            'Create VCS service group for NIC "eth0"',
            plugin_callback_method_mock,
            callback_class='VcsNICServiceGroupHelper',
            callback_func="add_nicgrp_callback",
            nic_name='eth0',
            node_gateways={'mn1': ['10.10.10.150']},
            mii="1",
            cluster_item_id=1234)

    @mock.patch('vcsplugin.vcs_nic_sg_helper.create_nic_resources')
    @mock.patch('vcsplugin.vcs_nic_sg_helper.log')
    def test_nic_callback(self, log, create_nic_resources):
        plugin = DummyPluginForTest
        callback_api = mock.MagicMock()
        mock_cluster = mock.MagicMock()
        mock_cluster.default_nic_monitor = "netstat"

        vcs_api = mock.MagicMock()
        vcs_api.readable_conf = mock.MagicMock()

        vcs_sg_helper = VcsNICServiceGroupHelper(plugin)
        vcs_sg_helper.query_by_vpath = mock.Mock(return_value=mock_cluster)
        vcs_sg_helper._clustered_service_group_add = mock.Mock()
        vcs_sg_helper._clustered_service_set_parallel = mock.Mock()
        vcs_sg_helper._clustered_service_set_syslist = mock.Mock()
        vcs_sg_helper._vcs_api = vcs_api
        vcs_sg_helper.nodes = [mock.Mock()]

        vcs_sg_helper.add_nicgrp_callback(
            callback_api,
            nic_name='eth0',
            node_gateways={'mn1': ['10.10.10.150'],
                           'mn2': ['10.10.11.150']},
            mii='0',
            cluster_item_id='1234')

        self.assertEqual(vcs_api.readable_conf.call_count, 1)
        vcs_api._clustered_service_set_attributes.assert_called_once_with(
            'Grp_NIC_1234_eth0', ((0, 'mn1'), (1, 'mn2')), True)

        self.assertEqual(log.event.info.call_args_list, [
            mock.call('VCS Creating NIC service group Grp_NIC_1234_eth0'),
        ])
        create_nic_resources.assert_called_with(
            vcs_api,
            'Grp_NIC_1234_eth0',
            'eth0',
            {'mn1': ['10.10.10.150'], 'mn2': ['10.10.11.150']},
            "0",
            '1234')

class TestCreateConfiguration(unittest.TestCase):
    def test_cluster_is_not_initial(self):
        plugin = DummyPluginForTest
        vcs_sg_helper = VcsNICServiceGroupHelper(plugin)
        plugin_api_context_mock = mock.Mock()

        cluster = mock.Mock(['is_initial', 'has_initial_dependencies', 'is_for_removal'],
                            nodes=[])
        cluster.is_initial.return_value = False
        cluster.has_initial_dependencies.return_value = False
        cluster.is_for_removal.return_value = False
        vcs_sg_helper._generate_nicgrp_task = mock.Mock()
        vcs_model_return = mock.Mock(['get_nic_groups'])
        vcs_model_return.get_nic_groups.return_value = []

        with mock.patch('vcsplugin.vcs_nic_sg_helper.VCSModel') \
                as vcs_model_mock:
            vcs_model_mock.return_value = vcs_model_return
            tasks = vcs_sg_helper.create_configuration(plugin_api_context_mock, cluster)

        self.assertEqual(([],[]), tasks)
        self.assertEqual(0, vcs_sg_helper._generate_nicgrp_task.call_count)
        self.assertEqual(1, vcs_model_mock.call_count)
        self.assertEqual(2, vcs_model_return.get_nic_groups.call_count)

    def test_cluster_is_initial_nics_not_initial(self):
        helper = VcsNICServiceGroupHelper(DummyPlugin)
        api = mock.MagicMock()
        cluster = mock_model_item("/cluster", "cluster")
        node = mock_model_item("/node", "node")
        interface = mock_model_item("/eth0", "eth0", device_name="eth0",
                                    bridge="", master="")
        interface.set_applied()
        interface1 = mock_model_item("/eth1", "eth1", device_name="eth1",
                                     bridge="", master="")
        interface1.set_for_removal()

        api.query.return_value = [cluster]
        cluster.nodes = [node]
        node.network_interfaces = [interface, interface1]

        pre_node_tasks, post_node_tasks = helper.create_configuration(api,
                                                                      cluster)
        self.assertEqual(1, len(post_node_tasks))
        self.assertEqual(0, len(pre_node_tasks))
        for task in post_node_tasks:
            self.assertEqual(task.description,
                             'Create VCS service group for NIC "eth0"')

    def test_cluster_have_initial_dependencies(self):
        plugin = DummyPluginForTest
        task = mock.Mock(name='task')

        vcs_sg_helper = VcsNICServiceGroupHelper(plugin)
        vcs_sg_helper._generate_nicgrp_task = mock.Mock(return_value=[task])
        plugin_api_context_mock = mock.Mock(name='api_context')
        plugin_api_context_mock.query = mock.Mock(return_value=None)

        cluster = mock.Mock(['is_initial', 'has_initial_dependencies'])
        cluster.is_initial.return_value = True
        cluster.has_initial_dependencies.return_value = True

        cluster.nodes = [mock.Mock(hostname="node1"),
                         mock.Mock(hostname="node2")]

        vcs_model_return = mock.Mock(['get_nic_groups'])
        vcs_model_return.get_nic_groups.return_value = []

        with mock.patch('vcsplugin.vcs_nic_sg_helper.VCSModel') \
                as vcs_model_mock:
            vcs_model_mock.return_value = vcs_model_return

            pre_node_tasks, post_node_tasks = vcs_sg_helper.create_configuration(
                plugin_api_context_mock, cluster)
        self.assertEqual([task], post_node_tasks)
        self.assertEqual([], pre_node_tasks)
        self.assertEqual(1, vcs_sg_helper._generate_nicgrp_task.call_count)
        self.assertEqual(2, len(vcs_sg_helper._generate_nicgrp_task.call_args))
        self.assertEqual(1, vcs_model_return.get_nic_groups.call_count)

    def test_cluster_no_nic_grp_tasks(self):
        plugin = DummyPluginForTest
        vcs_sg_helper = VcsNICServiceGroupHelper(plugin)
        plugin_api_context_mock = mock.Mock()
        cluster = mock.Mock(['is_initial'])
        cluster.is_initial.return_value = True

        vcs_sg_helper._generate_nicgrp_task = mock.Mock()
        vcs_sg_helper._generate_nicgrp_task.return_value = []
        vcs_model_return = mock.Mock(['get_nic_groups'])

        with mock.patch('vcsplugin.vcs_nic_sg_helper.VCSModel') \
                as vcs_model_mock:
            vcs_model_mock.return_value = vcs_model_return
            tasks = vcs_sg_helper.create_configuration(
                plugin_api_context_mock, cluster)

        self.assertEqual(([], []), tasks)
        self.assertEqual(1, vcs_sg_helper._generate_nicgrp_task.call_count)
        self.assertEqual(1, vcs_model_mock.call_count)
        self.assertEqual(1, vcs_model_return.get_nic_groups.call_count)

    def test_success(self):
        plugin = DummyPluginForTest
        vcs_sg_helper = VcsNICServiceGroupHelper(plugin)
        plugin_api_context_mock = mock.Mock()
        cluster = mock.Mock(['is_initial'])
        cluster.is_initial.return_value = True

        task = mock.Mock()
        vcs_sg_helper._generate_nicgrp_task = mock.Mock()
        vcs_sg_helper._generate_nicgrp_task.return_value = [task]
        vcs_model_return = mock.Mock(['get_nic_groups'])

        with mock.patch('vcsplugin.vcs_nic_sg_helper.VCSModel') \
                as vcs_model_mock:
            vcs_model_mock.return_value = vcs_model_return
            pre_node_tasks, post_node_tasks = \
                vcs_sg_helper.create_configuration(plugin_api_context_mock,
                                                   cluster)

        self.assertEqual([task], post_node_tasks)
        self.assertEqual([], pre_node_tasks)
        self.assertEqual(1, vcs_sg_helper._generate_nicgrp_task.call_count)
        self.assertEqual(1, vcs_model_mock.call_count)
        self.assertEqual(1, vcs_model_return.get_nic_groups.call_count)


class TestCreateNICResources(unittest.TestCase):
    def test_get_nic_phantom_resource_name(self):
        cluster_item_id = '1234'
        nic_key = 'eth0'

        expected_resource_name = 'Res_Phantom_NIC_1234_eth0'
        resource_name = _get_nic_phantom_resource_name(cluster_item_id, nic_key)

        self.assertEqual(resource_name, expected_resource_name)

    def test_get_nic_resource_name(self):
        cluster_item_id = '1234'
        nic_key = 'eth0'

        expected_resource_name = 'Res_NIC_1234_eth0'
        resource_name = _get_nic_resource_name(cluster_item_id, nic_key)

        self.assertEqual(resource_name, expected_resource_name)

    def test_add_nic_sg_resources(self):
        vcs_api = mock.Mock(['hares_add', 'hares_modify', 'hares_local'])
        nic_service_group_name = 'NicGrp_eth0'
        nic_key = 'eth0'
        node_gateways = {'mn1': ['10.10.10.150']}
        cluster_item_id = '1234'
        mii = "0"

        with mock.patch('vcsplugin.vcs_nic_sg_helper._get_nic_resource_name') \
                as _get_nic_resource_name_mock:
            with mock.patch('vcsplugin.vcs_nic_sg_helper.' +
                    '_get_nic_phantom_resource_name') \
                    as _get_nic_phantom_resource_name_mock:
                _get_nic_resource_name_mock.return_value = 'Res_NIC_1234_eth0'
                _get_nic_phantom_resource_name_mock.return_value = \
                    'Res_Phantom_NIC_1234_eth0'
                _add_nic_sg_resources(vcs_api, nic_service_group_name, nic_key,
                                      node_gateways, mii, cluster_item_id)

        self.assertEqual(vcs_api.hares_add.call_count, 2)
        self.assertEqual(vcs_api.hares_modify.call_count, 7)
        self.assertEqual(_get_nic_resource_name_mock.call_count, 1)
        self.assertEqual(_get_nic_phantom_resource_name_mock.call_count, 1)
        self.assertEqual(vcs_api.hares_add.call_args_list, [
            mock.call('Res_NIC_1234_eth0', 'NIC', 'NicGrp_eth0'),
            mock.call('Res_Phantom_NIC_1234_eth0', 'Phantom', 'NicGrp_eth0')
        ])
        self.assertEqual(vcs_api.hares_modify.call_args_list, [
            mock.call('Res_NIC_1234_eth0', 'Critical', '1'),
            mock.call('Res_NIC_1234_eth0', 'Device', 'eth0'),
            mock.call('Res_NIC_1234_eth0', 'Mii', '0', sys='mn1'),
            mock.call('Res_NIC_1234_eth0', 'NetworkHosts', '10.10.10.150', sys='mn1'),
            mock.call('Res_Phantom_NIC_1234_eth0', 'Critical', '1'),
            mock.call('Res_NIC_1234_eth0', 'Enabled', '1'),
            mock.call('Res_Phantom_NIC_1234_eth0', 'Enabled', '1'),
        ])

    def test_add_nic_sg_resources_multi_gateway(self):
        vcs_api = mock.Mock(['hares_add', 'hares_modify', 'hares_local'])
        nic_service_group_name = 'NicGrp_eth0'
        nic_key = 'eth0'
        node_gateways = {'mn1': ['10.10.10.150', '10.10.10.151']}
        cluster_item_id = '1234'
        mii = "0"

        with mock.patch('vcsplugin.vcs_nic_sg_helper._get_nic_resource_name') \
                as _get_nic_resource_name_mock:
            with mock.patch('vcsplugin.vcs_nic_sg_helper.' +
                    '_get_nic_phantom_resource_name') \
                    as _get_nic_phantom_resource_name_mock:
                _get_nic_resource_name_mock.return_value = 'Res_NIC_1234_eth0'
                _get_nic_phantom_resource_name_mock.return_value = \
                    'Res_Phantom_NIC_1234_eth0'
                _add_nic_sg_resources(vcs_api, nic_service_group_name, nic_key,
                                      node_gateways, mii, cluster_item_id)

        self.assertEqual(vcs_api.hares_add.call_count, 2)
        self.assertEqual(vcs_api.hares_modify.call_count, 7)
        self.assertEqual(_get_nic_resource_name_mock.call_count, 1)
        self.assertEqual(_get_nic_phantom_resource_name_mock.call_count, 1)
        self.assertEqual(vcs_api.hares_add.call_args_list, [
            mock.call('Res_NIC_1234_eth0', 'NIC', 'NicGrp_eth0'),
            mock.call('Res_Phantom_NIC_1234_eth0', 'Phantom', 'NicGrp_eth0')
        ])
        self.assertEqual(vcs_api.hares_modify.call_args_list, [
            mock.call('Res_NIC_1234_eth0', 'Critical', '1'),
            mock.call('Res_NIC_1234_eth0', 'Device', 'eth0'),
            mock.call('Res_NIC_1234_eth0', 'Mii', '0', sys='mn1'),
            mock.call('Res_NIC_1234_eth0', 'NetworkHosts', '10.10.10.150 10.10.10.151', sys='mn1'),
            mock.call('Res_Phantom_NIC_1234_eth0', 'Critical', '1'),
            mock.call('Res_NIC_1234_eth0', 'Enabled', '1'),
            mock.call('Res_Phantom_NIC_1234_eth0', 'Enabled', '1'),
        ])

    def test_add_nic_sg_resources_no_gateway(self):
        vcs_api = mock.Mock(['hares_add', 'hares_modify', 'hares_local'])
        nic_service_group_name = 'NicGrp_eth0'
        nic_key = 'eth0'
        nic_value = {'mn1': None}
        cluster_item_id = '1234'
        mii = "0"

        with mock.patch('vcsplugin.vcs_nic_sg_helper._get_nic_resource_name') \
                as _get_nic_resource_name_mock:
            with mock.patch('vcsplugin.vcs_nic_sg_helper.' +
                    '_get_nic_phantom_resource_name') \
                    as _get_nic_phantom_resource_name_mock:
                _get_nic_resource_name_mock.return_value = 'Res_NIC_1234_eth0'
                _get_nic_phantom_resource_name_mock.return_value = \
                    'Res_Phantom_NIC_1234_eth0'
                _add_nic_sg_resources(vcs_api, nic_service_group_name, nic_key,
                                      nic_value, mii, cluster_item_id)

        self.assertEqual(vcs_api.hares_add.call_count, 2)
        self.assertEqual(vcs_api.hares_modify.call_count, 6)
        self.assertEqual(_get_nic_resource_name_mock.call_count, 1)
        self.assertEqual(_get_nic_phantom_resource_name_mock.call_count, 1)
        self.assertEqual(vcs_api.hares_add.call_args_list, [
            mock.call('Res_NIC_1234_eth0', 'NIC', 'NicGrp_eth0'),
            mock.call('Res_Phantom_NIC_1234_eth0', 'Phantom', 'NicGrp_eth0')
        ])
        self.assertEqual(vcs_api.hares_modify.call_args_list, [
            mock.call('Res_NIC_1234_eth0', 'Critical', '1'),
            mock.call('Res_NIC_1234_eth0', 'Device', 'eth0'),
            mock.call('Res_NIC_1234_eth0', 'Mii', '0', sys='mn1'),
            mock.call('Res_Phantom_NIC_1234_eth0', 'Critical', '1'),
            mock.call('Res_NIC_1234_eth0', 'Enabled', '1'),
            mock.call('Res_Phantom_NIC_1234_eth0', 'Enabled', '1'),
        ])

    def test_add_nic_sg_resources_no_gateway_mii(self):
        vcs_api = mock.Mock(['hares_add', 'hares_modify', 'hares_local'])
        nic_service_group_name = 'NicGrp_eth0'
        nic_key = 'eth0'
        nic_value = {'mn1':None}
        cluster_item_id = '1234'
        mii = "1"

        with mock.patch('vcsplugin.vcs_nic_sg_helper._get_nic_resource_name') \
                as _get_nic_resource_name_mock:
            with mock.patch('vcsplugin.vcs_nic_sg_helper.' +
                    '_get_nic_phantom_resource_name') \
                    as _get_nic_phantom_resource_name_mock:
                _get_nic_resource_name_mock.return_value = 'Res_NIC_1234_eth0'
                _get_nic_phantom_resource_name_mock.return_value = \
                    'Res_Phantom_NIC_1234_eth0'
                _add_nic_sg_resources(vcs_api, nic_service_group_name, nic_key,
                                      nic_value, mii, cluster_item_id)

        self.assertEqual(vcs_api.hares_add.call_count, 2)
        self.assertEqual(vcs_api.hares_modify.call_count, 6)
        self.assertEqual(_get_nic_resource_name_mock.call_count, 1)
        self.assertEqual(_get_nic_phantom_resource_name_mock.call_count, 1)
        self.assertEqual(vcs_api.hares_add.call_args_list, [
            mock.call('Res_NIC_1234_eth0', 'NIC', 'NicGrp_eth0'),
            mock.call('Res_Phantom_NIC_1234_eth0', 'Phantom', 'NicGrp_eth0')
        ])
        self.assertEqual(vcs_api.hares_modify.call_args_list, [
            mock.call('Res_NIC_1234_eth0', 'Critical', '1'),
            mock.call('Res_NIC_1234_eth0', 'Device', 'eth0'),
            mock.call('Res_NIC_1234_eth0', 'Mii', '1', sys='mn1'),
            mock.call('Res_Phantom_NIC_1234_eth0', 'Critical', '1'),
            mock.call('Res_NIC_1234_eth0', 'Enabled', '1'),
            mock.call('Res_Phantom_NIC_1234_eth0', 'Enabled', '1'),
        ])

    def test_create_nic_resources(self):
        vcs_api = mock.Mock()
        nic_service_group_name = mock.Mock()
        nic_name = mock.Mock()
        node_gateways = mock.Mock()
        cluster_item_id = mock.Mock()
        nic_monitor = "netstat"

        with mock.patch('vcsplugin.vcs_nic_sg_helper._add_nic_sg_resources') \
                as _add_nic_sg_resources_mock:
            create_nic_resources(vcs_api, nic_service_group_name, nic_name,
                                 node_gateways, cluster_item_id,
                                 nic_monitor)

        _add_nic_sg_resources_mock.assert_called_with(
            vcs_api,
            nic_service_group_name, nic_name, node_gateways, cluster_item_id,
            nic_monitor)

    def test_validate_net_host_on_llt(self):
        cluster = mock.Mock()
        cluster.llt_nets = "net1,net2"
        mock_net = mock.Mock()
        mock_net.network_name = "net1"
        mock_net.ip = "10.10.10.1"
        cluster.network_hosts = [mock_net]
        plugin = mock.MagicMock()
        nic_helper = vcsplugin.vcs_nic_sg_helper.VcsNICServiceGroupHelper(plugin)
        ret = nic_helper._validate_net_host_on_llt(cluster)
        self.assertEqual(ret[0].error_message, 'Can not add a "vcs-network-host" to a network that belongs to a VCS LLT network')

    def test_validate_net_host_not_duplicate(self):
        cluster = mock.Mock()
        mock_net = mock.Mock()
        mock_net.network_name = "net1"
        mock_net.ip = "10.10.10.1"
        mock_net.get_vpath.return_value = "mock net vpath"
        mock_net.is_for_removal.return_value = False
        mock_net2 = mock.Mock()
        mock_net2.network_name = "net1"
        mock_net2.ip = "10.10.10.1"
        mock_net2.get_vpath.return_value = "mock net 2 vpath"
        mock_net2.is_for_removal.return_value = False
        cluster.network_hosts = [mock_net, mock_net2]
        plugin = mock.MagicMock()
        nic_helper = vcsplugin.vcs_nic_sg_helper.VcsNICServiceGroupHelper(plugin)
        ret = nic_helper._validate_net_host_not_duplicate(cluster)
        self.assertEqual(ret[0].error_message, 'The network_name "net1" and ip "10.10.10.1" have already been defined in: "mock net vpath"')

    def test_validate_net_host_not_duplicate_when_for_removal(self):
        cluster = mock.Mock()
        mock_net = mock.Mock()
        mock_net.network_name = "net1"
        mock_net.ip = "10.10.10.1"
        mock_net.get_vpath.return_value = "mock net vpath"
        mock_net.is_for_removal.return_value = False
        mock_net2 = mock.Mock()
        mock_net2.network_name = "net1"
        mock_net2.ip = "10.10.10.1"
        mock_net2.get_vpath.return_value = "mock net 2 vpath"
        mock_net2.is_for_removal.return_value = True
        cluster.network_hosts = [mock_net, mock_net2]
        plugin = mock.MagicMock()
        nic_helper = vcsplugin.vcs_nic_sg_helper.VcsNICServiceGroupHelper(plugin)
        ret = nic_helper._validate_net_host_not_duplicate(cluster)
        self.assertEqual(len(ret), 0)

    def test_validate_net_host_in_network(self):
        cluster = mock.Mock()
        node = mock.Mock()
        node.network_interfaces = [mock.Mock()]
        node.network_interfaces[0].network_name = "net99"
        cluster.nodes = [node]
        mock_net = mock.Mock()
        mock_net.network_name = "net1"
        mock_net.ip = "10.10.10.1"
        cluster.network_hosts = [mock_net]
        plugin = mock.MagicMock()
        nic_helper = vcsplugin.vcs_nic_sg_helper.VcsNICServiceGroupHelper(plugin)
        ret = nic_helper._validate_net_host_in_network(cluster)
        self.assertEqual(ret[0].error_message, "The network name for vcs-network-host "
                                      "is not present on cluster")

    def test_validate_network_hosts_for_removal(self):
        cluster = mock.Mock()
        node = mock.Mock()
        node.is_for_removal.return_value = False
        cluster.nodes = [node]
        node.network_interfaces = [mock.Mock()]

        mock_nh = mock.Mock()
        mock_nh.network_name = "traffic"
        mock_nh.ip = "10.10.10.1"
        mock_nh.get_vpath.return_value = "network host vpath"
        mock_nh.is_for_removal.return_value = False
        cluster.network_hosts = [mock_nh]

        plugin = mock.MagicMock()
        nic_helper = VcsNICServiceGroupHelper(plugin)

        for_removal_nic = mock.Mock(network_name='traffic')
        for_removal_nic.get_vpath.return_value = "for removal nic vpath"
        nic_helper._get_all_node_nics_in_use_marked_for_removal = mock.Mock(return_value = [for_removal_nic])

        ret = nic_helper._validate_network_hosts_for_removal(cluster)
        self.assertEqual(ret[0].error_message, "The network in this interface is being used by: network host vpath")

    def test_validate_maximum_network_hosts_ignores_nwhosts_for_removal(self):
        cluster = mock.Mock()
        node = mock.Mock()
        cluster.nodes = [node]
        node.network_interfaces = [mock.Mock()]

        nw_hosts = []
        # Add 20 network hosts, 10 not for removal, 10 for removal
        for i in range(20):
            nw_host = mock.Mock(
                    network_name="traffic",
                    ip="10.10.10.{0}".format(i),
                    get_vpath=mock.Mock(return_value="vpath{0}".format(i)),
                    is_for_removal=mock.Mock(return_value=(i>9)))
            nw_hosts.append(nw_host)
        cluster.network_hosts = nw_hosts
        nic_helper = VcsNICServiceGroupHelper(mock.Mock())
        ret = nic_helper._validate_maximum_network_hosts(cluster)
        self.assertEqual(ret, [])


class TestValidation(VCSIntegrationBase):

    def setUp(self):
        super(TestValidation, self).setUp()
        self.helper = VcsNICServiceGroupHelper(self.plugin.__class__)

    def test_max_number_network_hosts(self):
        self.setup_model()
        # Add 11 vcs-network_host items to the model
        for i in range(0, 11):
            self._add_item_to_model(
                "vcs-network-host",
                "/deployments/test/clusters/cluster1/network_hosts/nh_%s" % i,
                network_name="mgmt",
                ip="10.10.10.1%s" %i)

        errors = self.helper.validate_model(self.context_api)
        expected = sorted(['</deployments/test/clusters/cluster1/network_hosts/nh_0 - ValidationError - The number of network hosts using the network_name "mgmt" has exceeded the maximum number allowed "10">'])
        self.assertEqual(self.string_and_sort(errors), expected)
