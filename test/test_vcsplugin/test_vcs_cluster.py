##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################
import mock
from litp.core.exceptions import RpcExecutionException
from litp.core.execution_manager import CallbackExecutionException
mock.patch('litp.core.litp_logging.LitpLogger').start()
from litp.plan_types.deployment_plan import deployment_plan_tags
from vcsplugin.vcs_plugin import VcsPlugin
from vcsplugin.vcs_cluster import (VcsCluster,
                                   ERROR_VCS_SEED_THRESHOLD_EXCEED_NODE_COUNT)
from vcsplugin.vcs_exceptions import VCSConfigException
from base_vcs_integration import VCSIntegrationBase
from vcsplugin.vcs_config import VCSConfig
from mocks import mock_model_item
from vcsplugin.vcs_cmd_api import VcsCmdApi
from collections import defaultdict
from vcsplugin.vcs_exceptions import VcsCmdApiException

class DummyPluginForTest(object):
    pass


class TestVcsCluster(VCSIntegrationBase):

    def setUp(self):
        super(TestVcsCluster, self).setUp()
        self.vcs_cluster = VcsCluster(VcsPlugin)

    def query(self, item_type=None, **kwargs):
        # Use ModelManager.query to find items in the model
        # properties to match desired item are passed as kwargs.
        # The use of this method is not required, but helps
        # plugin developer mimic the run-time environment
        # where plugin sees QueryItem-s.
        return self.model.query(item_type, **kwargs)

    def test_cluster_with_mngt_interface_not_in_network_interfaces(self):
        # If the mngt network interface is not in the
        # network interfaces of both nodes... validate_model() appends an error
        # for each
        self.setup_model(num_of_nodes=2)
        self.model.remove_item("/deployments/test/clusters/cluster1/nodes/node1/network_interfaces/if0")
        self.model.remove_item(
            "/deployments/test/clusters/cluster1/nodes/node2/network_interfaces/if0")
        #self.model.create_item("network", "/infrastructure/networking/network_profiles/nodes/networks/mgmt", interface='test_nic', network_name='mgmt')
        errors = self.vcs_cluster.validate_model(self)
        self.assertEqual(2, len(errors))

    def test_two_clusters_one_id(self):
        # Two clusters with the same cluster ID in model should give
        # validation error
        self.setup_model(num_of_nodes=2)
        self.add_cluster(2, cluster_name="cluste2", cluster_id='1231')
        #self.setup_model(2, cluster_name='cluster2')
        # self.create_second_cluster()
        errors = self.vcs_cluster.validate_model(self)

        expected = sorted([
            "</deployments/test/clusters/cluste2 - "
            "ValidationError - Cluster IDs must be unique.>",
            "</deployments/test/clusters/cluster1 - "
            "ValidationError - Cluster IDs must be unique.>"])

        self.assertEqual(expected,
                         self.string_and_sort(errors))

    def test_validation_ip_on_low_piority_llt_network(self):
        self.setup_model(num_of_nodes=2)
        self._update_item_in_model(
            "/deployments/test/clusters/cluster1/nodes/node1/network_interfaces/if0",
            ipaddress="10.10.10.49"
        )
        errors = self.vcs_cluster.validate_model(self.context_api)
        self.assertEqual(errors, [])

    def test_validation_ip_on_llt_network(self):
        self.setup_model(num_of_nodes=2)
        self._update_item_in_model(
            "/deployments/test/clusters/cluster1/nodes/node1/network_interfaces/if1",
            ipaddress="10.10.10.49"
        )
        errors = self.vcs_cluster.validate_model(self.context_api)

        expected = sorted(["</deployments/test/clusters/cluster1/nodes/node1/network_interfaces/if1 - ValidationError - Interface is used for VCS llt. It should not have an IP address>"])
        self.assertEqual(self.string_and_sort(errors), expected)

#    @mock.patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper")
#    def test_validate_model(self):
#        self.setup_model(num_of_nodes=2)
#        #Invoke plugin's methods to run test cases
#        # and assert expected output.
#        errors = self.vcs_cluster.validate_model(self)
#        self.assertEqual(0, len(errors))

    def test_create_configuration_id(self):
        # In our case there should be 2 config tasks
        # as we have two nodes in vcs cluster, and no ID needs to be generated
        self.setup_model(num_of_nodes=2)
        # Invoke plugin's methods to run test cases
        # and assert expected output.
        tasks = []
        for cluster in self.context_api.query('vcs-cluster'):
            tasks += self.vcs_cluster.create_configuration(self, cluster)
        self.assertEqual(4, len(tasks))
        self.assertEqual(0, len(tasks[0]))
        self.assertEqual(4, len(tasks[1]))
        self.assertEqual(1, len(tasks[2]))
        self.assertEqual(0, len(tasks[3]))

    @mock.patch("vcsplugin.vcs_cluster.VCSConfig", autospec=True)
    @mock.patch("vcsplugin.vcs_cluster.ConfigTask")
    @mock.patch("vcsplugin.vcs_cluster.CallbackTask")
    def test_create_configuration(self, CallbackTask, ConfigTask, VCSConfig):
        self.setup_model(vcs_seed_threshold="2", app_agent_num_threads=10)

        vcs_config = mock.Mock()
        vcs_config.read_plugin_config.return_value = ""
        VCSConfig.return_value = vcs_config

        plugin = mock.Mock()
        plugin_inst = mock.Mock()
        plugin.return_value = plugin_inst
        helper = VcsCluster(plugin)

        cluster = self.context_api.query('vcs-cluster')[0]
        node1 = self.context_api.query('node')[0]
        node2 = self.context_api.query('node')[1]

        tasks = helper.create_configuration(self.context_api, cluster)

        self.assertEqual(4, len(tasks))
        self.assertEqual(0, len(tasks[0]))
        self.assertEqual(4, len(tasks[1]))
        self.assertEqual(2, len(tasks[2]))
        self.assertEqual(0, len(tasks[3]))
        vcs_poll_task = CallbackTask(
            cluster,
            'Check VCS engine is running on cluster "cluster"',
            plugin_inst.callback_method,
            callback_class="VcsCluster",
            callback_func="vcs_poll_callback",
            nodes=['mn1', 'mn2'])

        CallbackTask.assert_has_calls(
            [mock.call(cluster,
                       'Check VCS engine is running on cluster "cluster1"',
                       plugin_inst.callback_method,
                       callback_func='vcs_poll_callback',
                       callback_class='VcsCluster',
                       nodes=['mn1', 'mn2'],),
             mock.call(cluster,
                       'Update "app_agent_num_threads" property on cluster '
                       '"cluster1"',
                       plugin_inst.callback_method,
                       callback_class='VcsCluster',
                       callback_func="vcs_app_agent_num_threads_callback",
                       nodes=['mn1', 'mn2'],
                       app_agent_num_threads=10),
             mock.call().__nonzero__(),  # In the 'if' statement
             mock.call().requires.add(vcs_poll_task)
             ])
        ConfigTask.assert_has_calls(
            [mock.call(node1, node1,
                       'Configure "sfha" software on node "mn1"',
                       call_type='vcs::configure', number_of_nodes='2',
                       heartbeats_MACs={'eth2': '08:00:27:5B:C1:31', 'eth1': '08:00:27:5B:C1:31'},
                       hostname='mn1', clust_type='sfha',
                       call_id='cluster1', cluster_name='cluster1',
                       fencing_dg_name=None, cluster_ID='1231',
                       cluster_UUID='ac258320-3d09-3747-af35-ebb29d498753',
                       managment_MAC={'eth0': '08:00:27:5B:C1:31'}, license_key='ENTERPRISE',
                       hostnames={'1': 'mn2', '0': 'mn1'}, rpm_list='',
                       manage_vxfencing=False, base_os=node1.os.version,
                       heartbeats_SAPs={}, management_SAP={},
                       boot_mode='bios'),
             mock.call().requires.add(node1.storage_profile),
             mock.call(node2, node2,
                       'Configure "sfha" software on node "mn2"',
                       call_type='vcs::configure', number_of_nodes='2',
                       heartbeats_MACs={'eth2': '08:00:27:5B:C1:32', 'eth1': '08:00:27:5B:C1:32'},
                       hostname='mn2', clust_type='sfha',
                       call_id='cluster1', cluster_name='cluster1',
                       fencing_dg_name=None, cluster_ID='1231',
                       cluster_UUID='ac258320-3d09-3747-af35-ebb29d498753',
                       managment_MAC={'eth0': '08:00:27:5B:C1:32'}, license_key='ENTERPRISE',
                       hostnames={'1': 'mn2', '0': 'mn1'}, rpm_list='',
                       manage_vxfencing=False, base_os=node2.os.version,
                       heartbeats_SAPs={}, management_SAP={},
                       boot_mode='bios')],
            mock.call().requires.add(node2.storage_profile),
        )

    @mock.patch("vcsplugin.vcs_cluster.CallbackTask")
    def test_create_configuration_cluster_removal(self, CallbackTask):
        plugin = mock.Mock()
        plugin_inst = mock.Mock()
        plugin.return_value = plugin_inst
        helper = VcsCluster(plugin)

        cluster = mock_model_item(cluster_type="vcs", is_for_removal=lambda: True)
        cluster.item_id = "cluster1"
        cluster.get_vpath.return_value = "/cluster1"

        node1 = mock_model_item("/node1", "node1", hostname="node1", is_for_removal=lambda: True)
        node2 = mock_model_item("/node2", "node2", hostname="node2", is_for_removal=lambda: True)
        cluster.nodes = [node1, node2]

        tasks = helper.create_configuration(self.context_api, cluster)

        CallbackTask.assert_has_calls(
            [mock.call(cluster,
                       'Remove node "{0}" from cluster "{1}"'.format(node1.item_id, cluster.item_id),
                       plugin_inst.callback_method,
                       callback_class='VcsCluster',
                       callback_func='remove_node_from_cluster_cb',
                       cluster_vpath=cluster.get_vpath(),
                       node=node1.hostname,
                       cluster_removal=cluster.is_for_removal(),
                       tag_name='DEPLOYMENT_PRE_NODE_CLUSTER_TAG',),
             mock.call(cluster,
                       'Remove node "{0}" from cluster "{1}"'.format(node2.item_id, cluster.item_id),
                       plugin_inst.callback_method,
                       callback_class='VcsCluster',
                       callback_func='remove_node_from_cluster_cb',
                       cluster_vpath=cluster.get_vpath(),
                       node=node2.hostname,
                       cluster_removal=cluster.is_for_removal(),
                       tag_name='DEPLOYMENT_PRE_NODE_CLUSTER_TAG',),
             ])

        nodes, node_ids = helper._get_nodes(cluster)
        self.assertEqual(node_ids, {})

    def test_create_configuration_no_ha_manager(self):
        # 3 tasks as Callback task appended to generate ID and write
        # it back to the model
        self.setup_model(num_of_nodes=2, ha_manager="")
        # Invoke plugin's methods to run test cases
        # and assert expected output.
        tasks = []
        for cluster in self.context_api.query('vcs-cluster'):
            tasks += self.vcs_cluster.create_configuration(self, cluster)
        self.assertEquals(4, len(tasks))
        self.assertEquals(0, len(tasks[0]))
        self.assertEquals(4, len(tasks[1]))
        self.assertEquals(1, len(tasks[1][0]))
        self.assertEquals(1, len(tasks[1][1]))
        self.assertEquals(1, len(tasks[2]))
        self.assertEquals(0, len(tasks[3]))

    #LITPCDS-4467 OrderedTaskList should not be created if not tasks:
    @mock.patch('vcsplugin.vcs_plugin.is_ha_manager_only_on_nodes')
    @mock.patch('vcsplugin.vcs_plugin.log')
    @mock.patch('vcsplugin.vcs_plugin.VIP_UPDATE_HELPER_CLASSES')
    @mock.patch('vcsplugin.vcs_plugin.INSTALL_HELPER_CLASSES')
    @mock.patch('vcsplugin.vcs_plugin.UPGRADE_HELPER_CLASSES')
    @mock.patch('vcsplugin.vcs_plugin.CLUSTER_HELPER_CLASSES')
    @mock.patch('vcsplugin.vcs_plugin.SERVICE_GROUP_HELPER_CLASSES')
    def test_no_tasks_generated_returns_empty(self, service_group_mock, cluster_helper_mock,
                                              upgrade_helper_mock, install_helper_mock, subnet_update_mock,
                                              log_patch, mock_is_ha_manager_only):
        install_helper_mock = []
        cluster_helper_mock = []
        service_group_mock = []
        upgrade_helper_mock = []
        subnet_update_mock = []
        mock_is_ha_manager_only.return_value = False

        vcs_plug = VcsPlugin()

        api_mock = mock.Mock()
        cluster_mock = mock.Mock()
        cluster_mock.services = []
        clusters_mock = [cluster_mock]
        api_mock.query = mock.Mock(return_value=clusters_mock)

        tasks = vcs_plug.create_configuration(api_mock)
        self.assertEqual(0, len(tasks))
        self.assertEqual(log_patch.event.debug.call_args_list, [
            mock.call('Create Service Groups in the order: []'),
            mock.call('Remove Service Groups in the order: []')])


    def test_create_configuration_exception_wrong_cluster_passed(self):
        #Checking that the read_plugin_config() method raises
        # an exception if wrong data is passed in
        plugin = DummyPluginForTest
        cluster = mock.MagicMock()
        cluster.cluster_type.return_value = "other"
        self.assertRaises(VCSConfigException,
            lambda: VcsCluster(plugin).create_configuration(self.context_api,
                                                            cluster))

    @mock.patch('vcsplugin.vcs_cluster.property_updated')
    @mock.patch("vcsplugin.vcs_cluster.VCSConfig", autospec=True)
    @mock.patch("vcsplugin.vcs_cluster.ConfigTask")
    @mock.patch("vcsplugin.vcs_cluster.CallbackTask")
    @mock.patch("vcsplugin.vcs_cluster.is_os_reinstall_on_peer_nodes")
    @mock.patch("vcsplugin.vcs_cluster.VcsCluster.is_uplift_plan")
    def test_create_configuration_vxfencing_os_reinstall(self, mock_is_uplift_plan, mock_is_os_reinstall_mock, mock_CallbackTask,
                                                         mock_ConfigTask, mock_VCSConfig, mock_property_updated):
        self.setup_model(vcs_seed_threshold="2")
        vcs_config = mock.Mock()
        vcs_config.read_plugin_config.return_value = ""
        mock_VCSConfig.return_value = vcs_config

        mock_is_uplift_plan.return_value = False
        mock_is_os_reinstall_mock.return_value = True
        mock_property_updated.return_value = False

        plugin = mock.Mock()
        plugin_inst = mock.Mock()
        plugin.return_value = plugin_inst
        helper = VcsCluster(plugin)

        fencing_disk1 = mock.Mock(uuid='30000000fc85c926')
        fencing_disk2 = mock.Mock(uuid='30000000fc85c927')
        fencing_disk3 = mock.Mock(uuid='30000000fc85c928')

        cluster = mock_model_item("/cluster", "cluster", cluster_type="sfha",
                                  cluster_id="1234", app_agent_num_threads=10,
                                  vcs_seed_threshold="2",
                                  applied_properties_determinable=True)

        node1 = mock_model_item("/node1", "node1", hostname="node1",
                                is_for_removal=mock.Mock(return_value=False))
        node2 = mock_model_item("/node2", "node2", hostname="node2",
                                is_for_removal=mock.Mock(return_value=False))

        fen1 = mock_model_item("/fen1", "fen1", fencing_disk1)
        fen2 = mock_model_item("/fen2", "fen2", fencing_disk2)
        fen3 = mock_model_item("/fen3", "fen3", fencing_disk3)

        configs = mock.Mock()
        network_interfaces = []

        cluster.nodes = [node1, node2]
        cluster.fencing_disks = [fen1, fen2, fen3]
        cluster.is_initial.return_value = True
        storage_profile = mock.Mock()
        for node in cluster.nodes:
            node.configs = configs
            node.network_interfaces = network_interfaces
            node.storage_profile = storage_profile

        tasks = helper.create_configuration(self.context_api, cluster)

        self.assertEqual(4, len(tasks))
        self.assertEqual(0, len(tasks[0]))
        self.assertEqual(6, len(tasks[1]))
        self.assertEqual(2, len(tasks[2]))
        self.assertEqual(0, len(tasks[3]))
        vcs_poll_task = mock_CallbackTask(
            cluster,
            'Check VCS engine is running on cluster "cluster"',
            plugin_inst.callback_method,
            callback_class="VcsCluster",
            callback_func="vcs_poll_callback",
            nodes=['node1', 'node2'])

        mock_CallbackTask.assert_has_calls(
            [mock.call(node1,
                      'Start VCS on VX Fencing on node "node1"',
                      plugin_inst.callback_method,
                      callback_func='start_vx_io_fencing',
                      callback_class='VcsCluster',
                      hostname='node1',
                      tag_name=deployment_plan_tags.NODE_TAG),
             mock.call().requires.add(tasks[1][0][0]), # Configure "sfha" software on node "node1"
             mock.call(node1,
                      'Remove unused debug files on node "node1"',
                      plugin_inst.callback_method,
                      callback_func='remove_unused_debug_files_cb',
                      callback_class='VcsCluster',
                      hostname='node1'),
             mock.call().requires.add(tasks[1][0][0]),
             mock.call(node2,
                       'Start VCS on VX Fencing on node "node2"',
                       plugin_inst.callback_method,
                       callback_func='start_vx_io_fencing',
                       callback_class='VcsCluster',
                       hostname='node2',
                       tag_name=deployment_plan_tags.NODE_TAG),
             mock.call().requires.add(tasks[1][3][0]), # Configure "sfha" software on node "node2"
             mock.call(node2,
                       'Remove unused debug files on node "node2"',
                       plugin_inst.callback_method,
                       callback_func='remove_unused_debug_files_cb',
                       callback_class='VcsCluster',
                       hostname='node2'),
             mock.call().requires.add(tasks[1][3][0]),
             mock.call(cluster,
                       'Check VCS engine is running on cluster "cluster"',
                       plugin_inst.callback_method,
                       callback_func='vcs_poll_callback',
                       callback_class='VcsCluster',
                       nodes=['node1', 'node2'],),
             mock.call(cluster,
                       'Update "app_agent_num_threads" property on cluster '
                       '"cluster"',
                       plugin_inst.callback_method,
                       callback_class='VcsCluster',
                       callback_func="vcs_app_agent_num_threads_callback",
                       nodes=['node1', 'node2'],
                       app_agent_num_threads=10),
             mock.call().__nonzero__(),  # In the 'if' statement
             mock.call().requires.add(vcs_poll_task)])

        mock_ConfigTask.assert_has_calls(
            [mock.call(node1, node1,
                       'Configure "sfha" software on node "node1"',
                       call_type='vcs::configure', number_of_nodes='2',
                       heartbeats_MACs={}, hostname='node1', clust_type='sfha',
                       call_id='cluster', cluster_name='cluster',
                       fencing_dg_name='vxfencoorddg_1234', cluster_ID='1234',
                       cluster_UUID='d90e07cd-e2d4-3e5e-adf9-5133a6e5fb04',
                       managment_MAC={}, license_key='ENTERPRISE',
                       hostnames={'1': 'node2', '0': 'node1'}, rpm_list='',
                       manage_vxfencing=False, base_os=node1.os.version,
                       heartbeats_SAPs={}, management_SAP={}, boot_mode='bios'),
             mock.call().requires.add(storage_profile),
             mock.call().model_items.add(cluster),
             mock.call(node2, node2,
                       'Configure "sfha" software on node "node2"',
                       call_type='vcs::configure', number_of_nodes='2',
                       heartbeats_MACs={}, hostname='node2', clust_type='sfha',
                       call_id='cluster', cluster_name='cluster',
                       fencing_dg_name='vxfencoorddg_1234', cluster_ID='1234',
                       cluster_UUID='d90e07cd-e2d4-3e5e-adf9-5133a6e5fb04',
                       managment_MAC={}, license_key='ENTERPRISE',
                       hostnames={'1': 'node2', '0': 'node1'}, rpm_list='',
                       manage_vxfencing=False, base_os=node2.os.version,
                       heartbeats_SAPs={}, management_SAP={},
                       boot_mode='bios'),
             mock.call().requires.add(storage_profile),
             mock.call().model_items.add(cluster)]
        )

    @mock.patch('vcsplugin.vcs_cluster.VcsCluster.vcs_api')
    @mock.patch('vcsplugin.vcs_cluster.log')
    def test_start_vx_io_fencing(self, mock_log, mock_vcs_api):
        hostname = 'foo'
        self.vcs_cluster.start_vx_io_fencing("bar", hostname)

        self.assertEqual(self.vcs_cluster.nodes, hostname)
        self.assertEqual(mock_log.event.info.call_args_list, [
            mock.call('Starting Vx Fencing on node "{0}"'.format(hostname))])
        mock_vcs_api.set_node.assert_called_once_with(hostname)
        mock_vcs_api.start_vx_fencing.assert_called_once()

    @mock.patch('vcsplugin.vcs_cluster.VcsExtension')
    @mock.patch('vcsplugin.vcs_cluster.log')
    def test_remove_unused_debug_files_cb(self, m_log, m_ext):
        vxvm_debug_list = ['foo1.debug', 'foo2.debug', 'foo3.debug']
        aslapm_debug_list = ['bar4.debug', 'bar5.debug']
        m_ext.get_package_file_info.side_effect = [vxvm_debug_list, aslapm_debug_list]
        m_ext.remove_unused_vrts_debug_files.return_value = []
        self.vcs_cluster.remove_unused_debug_files_cb("foo", "bar")

        m_log.trace.debug.assert_has_calls([
            mock.call('Node bar. Check for debug files'),
            mock.call("Node bar: Retrieved the following debug files from "
                      "package VRTSvxvm - {0}".format(vxvm_debug_list)),
            mock.call("Node bar: Retrieved the following debug files from package "
                      "VRTSaslapm - {0}".format(aslapm_debug_list))])

        m_ext.get_package_file_info.assert_has_calls(
            [mock.call('foo', 'bar', 'VRTSvxvm', ['/opt', '.debug']),
             mock.call('foo', 'bar', 'VRTSaslapm', ['/opt', '.debug'])])

        m_ext.remove_unused_vrts_debug_files.assert_has_calls(
            [mock.call('foo', 'bar', vxvm_debug_list),
             mock.call('foo', 'bar', aslapm_debug_list)])

    def test_read_plugin_config_exception(self):
         #Checking that the read_plugin_config() method raises
         # an exception if wrong data is passed in
        self.assertRaises(VCSConfigException,
                          lambda: VCSConfig().read_plugin_config("other", "rpms"))

    def test_get_licence_vcs(self):
        #Test that correct licence is returned for vcs type
        self.assertEqual("AVAILABILITY", VcsCluster(None)._get_license("vcs"))

    def test_get_licence_sfha(self):
        #Test that correct licence is returned for sfha type
        self.assertEqual("ENTERPRISE", VcsCluster(None)._get_license("sfha"))

    def test_uuid(self):
        expected_uuid = '48bd4c87-8704-36fc-a32f-1b4b9953d29f'
        uuid_number = self.vcs_cluster._gen_uuid('c1', '1234')
        self.assertEquals(str(uuid_number), expected_uuid)

    def test_get_priority_networks_for_cluster(self):
        helper = VcsCluster(None)
        llt_nets = 'heartbeat1,heartbeat2'
        low_prio_net = 'mgmt'
        expected_networks = ['heartbeat1', 'heartbeat2', 'mgmt']
        cluster = mock.Mock(llt_nets=llt_nets, low_prio_net=low_prio_net)

        # with low priority
        networks_names = helper.\
            get_hb_networks_for_cluster(cluster, inc_low_priority=True)
        self.assertEqual(networks_names, expected_networks)
        # without low_priority
        networks_names = helper.\
            get_hb_networks_for_cluster(cluster, inc_low_priority=False)
        self.assertEqual(networks_names, llt_nets.split(','))

    def test_get_nics_per_node_for_networks(self):
        nets_names = ['heartbeat1', 'heartbeat2', 'mgmt']
        nic_0 = mock.Mock(network_name='mgmt')
        nic_1 = mock.Mock(network_name='heartbeat1')
        nic_2 = mock.Mock(network_name='traffic2')
        nic_3 = mock.Mock(network_name='traffic1')
        nic_4 = mock.Mock(network_name='heartbeat2')
        network_interfaces = [nic_0, nic_1, nic_2, nic_3, nic_4]
        node = mock.Mock(network_interfaces=network_interfaces)

        expected = [nic_0, nic_1, nic_4]
        actual = self.vcs_cluster.get_nics_per_node_for_networks(node,
                                                                 nets_names)
        self.assertEqual(actual, expected)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi.get_etc_llthosts')
    def test_create_configuration_expansion(self, mock_get_etc_llthosts):
        mock_get_etc_llthosts.return_value = (0, "0 mn1\n1 mn2", '')
        # Setup two node cluster, then put all items to applied
        # after that add new node to the cluster
        self.setup_model(num_of_nodes=2, ha_manager="vcs")
        self.model.set_all_applied()
        self.add_node("/deployments/test/clusters/cluster1", node_id=3)
        # Invoke plugin methods to run test cases
        # we should have 3 config tasks for all nodes in the cluster
        # and 2 CallbackTasks to start vcs and check VCS state
        tasks = []
        for cluster in self.context_api.query('vcs-cluster'):
            tasks += self.vcs_cluster.create_configuration(self, cluster)
        # Make sure we have 3 config tasks to configure to nodes and 3
        # callback tasks to remove unused debug files.
        self.assertEqual(6, len(tasks[1]))
        # Make sure we have 1 CallbackTasks for cluster
        self.assertEqual(1, len(tasks[2]))

    @mock.patch('vcsplugin.vcs_cluster.property_updated')
    def test_get_nodes_expansion(self, mock_property_updated):
        mock_property_updated.return_value = False
        node1 = mock.Mock(hostname='node1', is_applied=lambda: True,
                          is_initial=lambda: False,is_updated=lambda: False,
                          network_interfaces=[])
        node2 = mock.Mock(hostname='node2', is_applied=lambda: False,
                          is_initial=lambda: False, is_updated=lambda: True,
                          network_interfaces=[])
        node3 = mock.Mock(hostname='node3', is_applied=lambda: False,
                          is_initial=lambda: True, is_updated=lambda: False,
                          network_interfaces=[])
        node4 = mock.Mock(hostname='node4', is_applied=lambda: False,
                          is_initial=lambda: True, is_updated=lambda: False,
                          network_interfaces=[])
        cluster = mock.Mock(nodes=[node1, node2, node3, node4],
                            is_initial=lambda: False,
                            llt_nets="")

        mock_existing_node_ids = {'1': 'node1', '0': 'node2'}
        self.vcs_cluster._get_vcs_node_ids = mock.Mock(
            return_value=mock_existing_node_ids)

        nodes, node_ids = self.vcs_cluster._get_nodes(cluster)

        self.assertEqual(4, len(nodes))
        expected_node_ids = {'1': 'node1', '0': 'node2',
                             '2': 'node3', '3': 'node4'}
        self.assertEqual(node_ids, expected_node_ids)

    @mock.patch('vcsplugin.vcs_cluster.property_updated')
    def test_get_nodes_contraction(self, mock_property_updated):
        mock_property_updated.return_value = False
        node1 = mock.Mock(hostname='node1', is_applied=lambda: False,
                          is_initial=lambda: False,is_updated=lambda: False,
                          is_for_removal=lambda: True,
                          network_interfaces=[])
        node2 = mock.Mock(hostname='node2', is_applied=lambda: True,
                          is_initial=lambda: False, is_updated=lambda: False,
                          is_for_removal=lambda: False,
                          network_interfaces=[])
        node3 = mock.Mock(hostname='node3', is_applied=lambda: False,
                          is_initial=lambda: False, is_updated=lambda: False,
                          is_for_removal=lambda: True,
                          network_interfaces=[])
        node4 = mock.Mock(hostname='node4', is_applied=lambda: True,
                          is_initial=lambda: False, is_updated=lambda: False,
                          is_for_removal=lambda: False,
                          network_interfaces=[])
        cluster = mock.Mock(nodes=[node1, node2, node3, node4],
                            is_initial=lambda: False,
                            llt_nets="")

        mock_existing_node_ids = {'1': 'node1', '0': 'node2',
                                  '2': 'node3', '3': 'node4'}
        self.vcs_cluster._get_vcs_node_ids = mock.Mock(
            return_value=mock_existing_node_ids)

        nodes, node_ids = self.vcs_cluster._get_nodes(cluster)

        self.assertEqual(2, len(nodes))
        expected_node_ids = {'0': 'node2',
                             '3': 'node4'}
        self.assertEqual(node_ids, expected_node_ids)

    @mock.patch('vcsplugin.vcs_cluster.property_updated')
    def test_get_nodes_replace1(self, mock_property_updated):
        mock_property_updated.return_value = False
        node1 = mock.Mock(hostname='node1', is_applied=lambda: False,
                          is_initial=lambda: False,is_updated=lambda: False,
                          is_for_removal=lambda: True,
                          network_interfaces=[])
        node2 = mock.Mock(hostname='node2', is_applied=lambda: True,
                          is_initial=lambda: False, is_updated=lambda: False,
                          is_for_removal=lambda: False,
                          network_interfaces=[])
        node3 = mock.Mock(hostname='node3', is_applied=lambda: False,
                          is_initial=lambda: False, is_updated=lambda: False,
                          is_for_removal=lambda: True,
                          network_interfaces=[])
        node4 = mock.Mock(hostname='node4', is_applied=lambda: True,
                          is_initial=lambda: False, is_updated=lambda: False,
                          is_for_removal=lambda: False,
                          network_interfaces=[])
        node5 = mock.Mock(hostname='node5', is_applied=lambda: False,
                          is_initial=lambda: True, is_updated=lambda: False,
                          is_for_removal=lambda: False,
                          network_interfaces=[])
        cluster = mock.Mock(nodes=[node1, node2, node3, node4, node5],
                            is_initial=lambda: False,
                            llt_nets="")

        mock_existing_node_ids = {'1': 'node1', '0': 'node2',
                                  '2': 'node3', '3': 'node4'}
        self.vcs_cluster._get_vcs_node_ids = mock.Mock(
            return_value=mock_existing_node_ids)

        nodes, node_ids = self.vcs_cluster._get_nodes(cluster)

        self.assertEqual(3, len(nodes))
        expected_node_ids = {'0': 'node2', '4': 'node5',
                             '3': 'node4'}
        self.assertEqual(node_ids, expected_node_ids)

    @mock.patch('vcsplugin.vcs_cluster.property_updated')
    def test_get_nodes_replace2(self, mock_property_updated):
        mock_property_updated.return_value = False
        node1 = mock.Mock(hostname='node1', is_applied=lambda: False,
                          is_initial=lambda: True,is_updated=lambda: False,
                          is_for_removal=lambda: False,
                          network_interfaces=[])
        node2 = mock.Mock(hostname='node2', is_applied=lambda: True,
                          is_initial=lambda: False, is_updated=lambda: False,
                          is_for_removal=lambda: False,
                          network_interfaces=[])
        node3 = mock.Mock(hostname='node3', is_applied=lambda: False,
                          is_initial=lambda: True, is_updated=lambda: False,
                          is_for_removal=lambda: False,
                          network_interfaces=[])
        node4 = mock.Mock(hostname='node4', is_applied=lambda: True,
                          is_initial=lambda: False, is_updated=lambda: False,
                          is_for_removal=lambda: False,
                          network_interfaces=[])
        node5 = mock.Mock(hostname='node5', is_applied=lambda: True,
                          is_initial=lambda: False, is_updated=lambda: False,
                          is_for_removal=lambda: False,
                          network_interfaces=[])
        node6 = mock.Mock(hostname='node6', is_applied=lambda: False,
                          is_initial=lambda: True, is_updated=lambda: False,
                          is_for_removal=lambda: False,
                          network_interfaces=[])
        cluster = mock.Mock(nodes=[node1, node2, node3, node4, node5, node6],
                            is_initial=lambda: False,
                            llt_nets="")

        mock_existing_node_ids = {'0': 'node2', '4': 'node5',
                                  '3': 'node4'}
        self.vcs_cluster._get_vcs_node_ids = mock.Mock(
            return_value=mock_existing_node_ids)

        nodes, node_ids = self.vcs_cluster._get_nodes(cluster)

        self.assertEqual(6, len(nodes))
        expected_node_ids = {'0': 'node2', '1': 'node1', '2': 'node3',
                             '3': 'node4', '4': 'node5', '5': 'node6'}
        self.assertEqual(node_ids, expected_node_ids)

    def test_get_nodes_installation(self):
        node1 = mock.Mock(hostname='node1', is_applied=lambda: False,
                          is_initial=lambda: True, is_updated=lambda: False,
                          is_for_removal=lambda: False)
        node2 = mock.Mock(hostname='node2', is_applied=lambda: False,
                          is_initial=lambda: True, is_updated=lambda: False,
                          is_for_removal=lambda: False)
        node3 = mock.Mock(hostname='node3', is_applied=lambda: False,
                          is_initial=lambda: True, is_updated=lambda: False,
                          is_for_removal=lambda: False)
        cluster = mock.Mock(nodes=[node1, node2, node3])

        nodes, node_ids = self.vcs_cluster._get_nodes(cluster)

        self.assertEqual(3, len(nodes))
        expected_node_ids = {'0': 'node1', '1': 'node2', '2': 'node3'}
        self.assertEqual(node_ids, expected_node_ids)

    @mock.patch('vcsplugin.vcs_cluster.property_updated')
    def test_get_nodes_cluster_removal(self, mock_property_updated):
        mock_property_updated.return_value = False
        node1 = mock.Mock(hostname='node1', is_applied=lambda: True,
                          is_initial=lambda: False,is_updated=lambda: False,
                          is_for_removal=lambda: False,
                          network_interfaces=[])
        node2 = mock.Mock(hostname='node2', is_applied=lambda: True,
                          is_initial=lambda: False, is_updated=lambda: False,
                          is_for_removal=lambda: False,
                          network_interfaces=[])
        node3 = mock.Mock(hostname='node3', is_applied=lambda: True,
                          is_initial=lambda: False, is_updated=lambda: False,
                          is_for_removal=lambda: False,
                          network_interfaces=[])
        node4 = mock.Mock(hostname='node4', is_applied=lambda: True,
                          is_initial=lambda: False, is_updated=lambda: False,
                          is_for_removal=lambda: False,
                          network_interfaces=[])
        node5 = mock.Mock(hostname='node5', is_applied=lambda: True,
                          is_initial=lambda: False, is_updated=lambda: False,
                          is_for_removal=lambda: False,
                          network_interfaces=[])
        cluster = mock.Mock(nodes=[node1, node2, node3, node4, node5],
                            is_initial=lambda: False,
                            is_for_removal=lambda: True,
                            llt_nets="")

        mock_existing_node_ids = {'1': 'node1', '0': 'node2',
                                  '2': 'node3', '3': 'node4'}
        self.vcs_cluster._get_vcs_node_ids = mock.Mock(
            return_value=mock_existing_node_ids)

        nodes, node_ids = self.vcs_cluster._get_nodes(cluster)

        self.assertEqual(0, len(nodes))
        expected_node_ids = {}
        self.assertEqual(node_ids, expected_node_ids)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi.get_etc_llthosts')
    def test_get_vcs_node_ids_success(self, mock_get_etc_llthosts):
        mock_get_etc_llthosts.return_value = (0, "0 node1\n1 node2\n2 node3", '')
        node = mock.Mock(hostname='node1')
        expected_output = {'1': 'node2', '0': 'node1', '2': 'node3'}
        output = self.vcs_cluster._get_vcs_node_ids(node)
        self.assertEqual(output, expected_output)

    @mock.patch('vcsplugin.vcs_cluster.log')
    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi.get_etc_llthosts')
    def test_get_vcs_node_ids_no_llthost_fact(self, mock_get_etc_llthosts, mock_log):
        mock_get_etc_llthosts.return_value = (0, "Nothing\nNada\nZilch", '')
        node = mock.Mock(hostname='node1')
        self.assertRaises(VCSConfigException,
                          self.vcs_cluster._get_vcs_node_ids,
                          node)
        expected_msg = ('Invalid output from /etc/llthosts retrieval: need more than 1 value to unpack')
        mock_log.event.error.assert_called_with(expected_msg)

    @mock.patch('vcsplugin.vcs_cluster.log')
    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi.get_etc_llthosts')
    def test_get_vcs_node_ids_command_error(self, mock_get_etc_llthosts, mock_log):
        mock_get_etc_llthosts.return_value = (1, "", '')
        node = mock.Mock(hostname='node1')

        self.assertRaises(VCSConfigException,
                          self.vcs_cluster._get_vcs_node_ids,
                          node)
        expected_msg = ('Failed to retrieve /etc/llthosts from node "node1"')
        mock_log.event.error.assert_called_with(expected_msg)

    def test_aa_validate_interfaces_for_removal(self):
        """
        Validate that removing nics used by LLt & HBs on any of the nodes
        - throws a validation error per nic
        """
        llt_nets = 'hb1,hb2'
        low_prio_net = 'mgmt'
        # mock node1
        nic_0 = mock.Mock(network_name='mgmt', device_name='eth0',
                          is_for_removal=lambda: True)
        nic_1 = mock.Mock(network_name='hb1', device_name='eth1',
                          is_for_removal=lambda: True)
        nic_2 = mock.Mock(network_name='traffic2', device_name='eth2',
                          is_for_removal=lambda: False)
        nic_3 = mock.Mock(network_name='traffic1', device_name='eth3',
                          is_for_removal=lambda: False)
        nic_4 = mock.Mock(network_name='hb2', device_name='eth4',
                          is_for_removal=lambda: True)
        network_interfaces = [nic_0, nic_1, nic_2, nic_3, nic_4]
        node1 = mock.Mock(network_interfaces=network_interfaces,
                          hostname='node_1',
                          is_for_removal=lambda: False)
        # mock node2
        nic_0 = mock.Mock(network_name='hb1', device_name='eth0',
                          is_for_removal=lambda: True)
        nic_1 = mock.Mock(network_name='mgmt',  device_name='eth1',
                          is_for_removal=lambda: True)
        nic_2 = mock.Mock(network_name='traffic3', device_name='eth2',
                          is_for_removal=lambda: False)
        nic_3 = mock.Mock(network_name='hb2', device_name='eth3',
                          is_for_removal=lambda: True)
        nic_4 = mock.Mock(network_name='traffic1', device_name='eth4',
                          is_for_removal=lambda: False)
        network_interfaces = [nic_0, nic_1, nic_2, nic_3, nic_4]
        node2 = mock.Mock(network_interfaces=network_interfaces,
                          hostname='node_2',
                          is_for_removal=lambda: False)

        nodes = [node1, node2]
        cluster = mock.Mock(llt_nets=llt_nets, low_prio_net=low_prio_net,
                            nodes=nodes, services=[])
        actual = self.vcs_cluster._validate_interfaces_for_removal(cluster)
        self.assertEqual(len(actual), 6)
        error_partial = [
            "Device_name: 'eth0' on node: 'node_1' - cannot be removed",
            "Device_name: 'eth1' on node: 'node_1' - cannot be removed",
            "Device_name: 'eth4' on node: 'node_1' - cannot be removed",
            "Device_name: 'eth0' on node: 'node_2' - cannot be removed",
            "Device_name: 'eth1' on node: 'node_2' - cannot be removed",
            "Device_name: 'eth3' on node: 'node_2' - cannot be removed"]
        error_messages = [error.error_message for error in actual]
        for message in error_partial:
            self.assertTrue(message in ' '.join(error_messages))

    def test_create_vcs_app_agent_num_threads_task(self):
        node1 = mock.Mock(hostname='mn1')
        node1.is_for_removal.return_value = False
        node2 = mock.Mock(hostname='mn2')
        node2.is_for_removal.return_value = False
        cluster = mock.Mock(nodes=[node1, node2], item_id='c1')
        cluster.is_initial.return_value = True
        vcs_poll_task = mock.Mock()

        task = self.vcs_cluster.create_vcs_app_agent_num_threads_task(cluster, 16, vcs_poll_task)
        self.assertEqual('Update "app_agent_num_threads" property on cluster "c1"',
                          task.description)
        self.assertEqual(['mn1', 'mn2'], task.kwargs['nodes'])
        self.assertEqual(16, task.kwargs['app_agent_num_threads'])

    def test_vcs_app_agent_num_threads_callback(self):
        api = mock.Mock()
        nodes = ['mn1', 'mn2']
        success = {'retcode': 0, 'out': '', 'err': ''}
        with mock.patch.object(VcsCmdApi, '_call_mco', return_value=success) as mco_call:
            self.vcs_cluster.vcs_app_agent_num_threads_callback(api, nodes, 20)

        calls = [mock.call('haconf', {'read_only': 'False', 'haaction': 'makerw'}, expected_errors=[]),
                 mock.call('cluster_app_agent_num_threads', {'app_agent_num_threads': 20}),
                 mock.call('haconf', {'read_only': 'True', 'haaction': 'dump'}, expected_errors=[])]
        mco_call.assert_has_calls(calls)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi.get_etc_llthosts')
    def test_update_llttab_mac_address(self, mock_get_etc_llthosts):

        self.setup_model(num_of_nodes=2, ha_manager="vcs")
        self.model.set_all_applied()
        cluster = self.context_api.query('vcs-cluster')[0]

        mock_get_etc_llthosts.return_value = (0, "0 mn1\n1 mn2", '')

        # No changes
        nodes, node_ids = self.vcs_cluster._get_nodes(cluster)
        self.assertEqual(0, len(nodes))

        node1 = self.context_api.query('node', hostname='mn1')[0]

        self._update_item_in_model(
            "/deployments/test/clusters/cluster1/nodes/"
            "node1/network_interfaces/if0",
            macaddress="aa:bb:cc:dd:ee:ff")

        expected_node_ids = {'0': 'mn1', '1': 'mn2'}
        nodes, node_ids = self.vcs_cluster._get_nodes(cluster)

        self.assertEqual([node1], nodes)
        self.assertEqual(expected_node_ids, node_ids)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi.get_etc_llthosts')
    def test_plan_recreated_during_node_installation(self, mock_get_etc_llthosts):
        # install node in the cluster and stop plan just after the node was
        # set to applied. llthosts fact won't be available yet and likely any
        # bridged interface will still be in Initial state. See torf-209699
        self.setup_model(num_of_nodes=2, ha_manager="vcs")
        cluster = self.context_api.query('vcs-cluster')[0]
        self._update_item_in_model(
            cluster.get_vpath(),
            llt_nets=cluster.llt_nets + ',heartbeat3'
        )
        self.model.set_all_applied()

        mock_get_etc_llthosts.return_value = (0, "0 mn1\n1 mn2", '')

        common_path = '/deployments/test/clusters/cluster1/nodes'
        self._add_item_to_model(
            'bridge',
            common_path + "/node1/network_interfaces/if3",
            network_name="heartbeat3",
            device_name="br0")
        self._add_item_to_model(
            'bridge',
            common_path + "/node2/network_interfaces/if3",
            network_name="heartbeat3",
            device_name="br0")

        expected_node_ids = {}
        nodes, node_ids = self.vcs_cluster._get_nodes(cluster)

        self.assertEqual([], nodes)
        self.assertEqual(expected_node_ids, node_ids)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi.get_etc_llthosts')
    def test_update_interface_not_in_llt_network(self, mock_get_etc_llthosts):

        self.setup_model(num_of_nodes=2, ha_manager="vcs")

        self._add_item_to_model('eth',
                                "/deployments/test/clusters/cluster1/nodes/"
                                "node1/network_interfaces/if90",
                                device_name='eth11',
                                macaddress="aa:aa:cc:aa:aa:aa")

        self.model.set_all_applied()
        cluster = self.context_api.query('vcs-cluster')[0]

        mock_get_etc_llthosts.return_value = (0, "0 mn1\n1 mn2", '')

        self._update_item_in_model("/deployments/test/clusters/cluster1/nodes/node1/network_interfaces/if90",
                                   macaddress="aa:cc:dd:cc:bb:aa")

        nodes, node_ids = self.vcs_cluster._get_nodes(cluster)

        self.assertEqual([], nodes)
        self.assertEqual({}, node_ids)

    @mock.patch('vcsplugin.vcs_cluster.is_clustered_service_redeploy_required')
    @mock.patch('vcsplugin.vcs_cluster.VcsCluster._get_ip6_info')
    @mock.patch('vcsplugin.vcs_cluster.CallbackTask')
    @mock.patch('vcsplugin.vcs_cluster.ConfigTask')
    @mock.patch('vcsplugin.vcs_utils.VcsUtils.get_parent_with_type')
    def test_get_trigger_tasks_1(self, get_parent_mock, MockConfigTask, MockCallbackTask, MockIpv6, redeploy_required_mock):
        get_parent_mock.return_value = None
        redeploy_required_mock.return_value = False
        cluster = mock.Mock(item_id='c1',
                            get_vpath=lambda: 'cluster',
                            nodes=[mock.Mock(item_id='n1'),
                                   mock.Mock(item_id='n2')])
        nodes = [mock.Mock(hostname="host1")]
        s1 = mock.Mock(item_id='ser1')
        s1.nodes = nodes
        s1.node_list = "n1,n2"
        s1.applied_properties = {"node_list": ""}
        s1.is_for_removal = lambda: False
        s1.applications = [mock.Mock()]
        s1.get_cluster = lambda: cluster
        s1.triggers = [mock.Mock(item_type=mock.Mock(item_type_id='trigger'),
                                 item_id='t1',
                                 trigger_type='nofailover',
                                 is_for_removal=lambda: False,
                                 is_initial=lambda: True,
                                 service_argument=None)]
        cluster.services = [s1]
        cluster.nodes = [mock.Mock(item_id='n1',
                                   item_type=mock.Mock(item_type_id='node'),
                                   hostname='node2'),
                         mock.Mock(item_id='n2',
                                   item_type=mock.Mock(item_type_id='node'),
                                   hostname='node2')]
        node_tasks, cluster_tasks = \
            self.vcs_cluster._get_trigger_tasks(cluster, [])
        self.assertEqual(2, len(node_tasks))
        self.assertEqual(1, len(cluster_tasks))
        MockIpv6.return_value = defaultdict(list)

        # VcsCluster._create_trigger_task() appears to deliberately create
        # a new VcsPlugin instance. So can't .assert_called_with() here, can't
        # get the correct bound callback method object of the plugin instance
        # to compare.
        self.assertEqual(s1.triggers[0], MockCallbackTask.call_args[0][0])
        self.assertEqual(
            'Enable nofailover trigger for VCS service group "Grp_CS_c1_ser1"',
            MockCallbackTask.call_args[0][1])
        self.assertEqual('VcsCluster',
            MockCallbackTask.call_args[1]['callback_class'])
        self.assertEqual('enable_or_disable_trigger_cb',
            MockCallbackTask.call_args[1]['callback_func'])
        self.assertEqual('Grp_CS_c1_ser1',
            MockCallbackTask.call_args[1]['group_name'])
        self.assertEqual('cluster',
            MockCallbackTask.call_args[1]['cluster_vpath'])
        self.assertEqual('nofailover',
            MockCallbackTask.call_args[1]['trigger_type'])
        self.assertEqual("False",
            MockCallbackTask.call_args[1]['delete'])


        # node2 in both descriptions (cf. hostname in nodes)
        MockConfigTask.assert_any_call(
            cluster.nodes[0],
            cluster.nodes[0],
            'Configure nofailover trigger on node "node2"',
            trigger_map=[['Grp_CS_c1_ser1', None]],
            call_type='vcs::configure_nofailover_trigger',
            call_id='c1')

        MockConfigTask.assert_any_call(
            cluster.nodes[1],
            cluster.nodes[1],
            'Configure nofailover trigger on node "node2"',
            trigger_map=[['Grp_CS_c1_ser1', None]],
            call_type='vcs::configure_nofailover_trigger',
            call_id='c1')


    @mock.patch('vcsplugin.vcs_cluster.select_nodes_from_cluster')
    @mock.patch('vcsplugin.vcs_base_helper.VcsCmdApi')
    def test_enable_trigger_nofailover_cb(self, vcs_api_mock, select_nodes):
        group_name = "Grp1"
        cluster = "C1"
        select_nodes.return_value = ['node1']
        callback_api = mock.Mock(query_by_vpath=lambda x: 'cluster')

        self.vcs_cluster.enable_or_disable_trigger_cb(callback_api, group_name,
                                                      cluster, 'nofailover',
                                                      False)
        self.vcs_cluster._vcs_api.hagrp_add_in_triggers_enabled.\
            assert_called_once_with('Grp1', 'NOFAILOVER')

    @mock.patch('vcsplugin.vcs_cluster.select_nodes_from_cluster')
    @mock.patch('vcsplugin.vcs_base_helper.VcsCmdApi')
    def test_disable_trigger_nofailover_cb(self, vcs_api_mock, select_nodes):
        group_name = "Grp1"
        cluster = "C1"
        select_nodes.return_value = ['node1']
        callback_api = mock.Mock(query_by_vpath=lambda x: 'cluster')

        self.vcs_cluster.enable_or_disable_trigger_cb(callback_api, group_name,
                                                      cluster, 'nofailover',
                                                      "True")
        self.vcs_cluster._vcs_api.hagrp_delete_in_triggers_enabled.\
            assert_called_once_with('Grp1', 'NOFAILOVER')

    def test_validate_vcs_seed_threshold(self):
        def _test_vcs_seed_threshold_ok(threshold):
            cluster.vcs_seed_threshold = threshold
            errors = self.vcs_cluster._validate_vcs_seed_threshold(cluster)
            self.assertEqual(0, len(errors))

        def _test_vcs_seed_threshold_nok(threshold):
            cluster.vcs_seed_threshold = threshold
            node_count = len([node for node in cluster.nodes
                            if not node.is_for_removal()])
            expected = sorted(
                    ['<path_cluster1 - ValidationError - {0}>'.format(
                        ERROR_VCS_SEED_THRESHOLD_EXCEED_NODE_COUNT.format(node_count))])
            errors = self.vcs_cluster._validate_vcs_seed_threshold(cluster)
            self.assertEqual(expected, self.string_and_sort(errors))

        #Mock two node cluster
        cluster = mock.MagicMock()
        cluster.get_vpath.return_value = 'path_cluster1'
        cluster.nodes = [mock.Mock(item_id='n1',
                                   is_for_removal=lambda: False),
                         mock.Mock(item_id='n2',
                                   is_for_removal=lambda: False),
                         mock.Mock(item_id='n3',
                                   is_for_removal=lambda: True)]

        _test_vcs_seed_threshold_nok("0")
        _test_vcs_seed_threshold_ok("1")
        _test_vcs_seed_threshold_ok("2")
        _test_vcs_seed_threshold_nok("3")

    def test_get_vcs_seed_threshold(self):
        cluster = mock.MagicMock()
        node = mock.MagicMock(is_for_removal=mock.Mock(return_value=False))
        node_for_removal = mock.MagicMock(is_for_removal=mock.Mock(return_value=True))

        cluster.nodes = [node]
        self.assertEqual(1, self.vcs_cluster._get_vcs_seed_threshold(cluster))

        cluster.nodes = [node, node]
        self.assertEqual(1, self.vcs_cluster._get_vcs_seed_threshold(cluster))

        cluster.nodes = [node, node, node]
        self.assertEqual(2, self.vcs_cluster._get_vcs_seed_threshold(cluster))

        cluster.nodes = [node, node, node, node_for_removal]
        self.assertEqual(2, self.vcs_cluster._get_vcs_seed_threshold(cluster))

    def test_unset_vcs_seed_threshold_property_upon_create_configuration(self):
        self.setup_model(num_of_nodes=2)
        cluster = self.context_api.query('vcs-cluster')[0]

        with mock.patch.object(self.vcs_cluster, '_get_vcs_seed_threshold',
               autospec=True, wraps=self.vcs_cluster._get_vcs_seed_threshold) as \
                                                 mock_get_vcs_seed_threshold:
            self.assertEqual(None, cluster.vcs_seed_threshold)
            self.vcs_cluster.create_configuration(self, cluster)
            self.assertEqual(None, cluster.vcs_seed_threshold)
            self.assertEqual(1, mock_get_vcs_seed_threshold.call_count)
            mock_get_vcs_seed_threshold.assert_called_with(cluster)

    @mock.patch("vcsplugin.vcs_cluster.VCSConfig", autospec=True)
    @mock.patch("vcsplugin.vcs_cluster.ConfigTask")
    def test_create_configuration_rack_node(self, mock_ConfigTask,
                                            mock_VCSConfig):
        self.setup_model(is_rack_deployment=True)

        cluster = self.context_api.query('vcs-cluster')[0]
        node1 = self.context_api.query('node')[0]
        node2 = self.context_api.query('node')[1]

        vcs_config = mock.Mock()
        vcs_config.read_plugin_config.return_value = ""
        mock_VCSConfig.return_value = vcs_config

        plugin = mock.Mock()
        plugin_inst = mock.Mock()
        plugin.return_value = plugin_inst
        helper = VcsCluster(plugin)


        tasks = helper.create_configuration(self.context_api, cluster)

        self.assertEqual(4, len(tasks[1]))

        calls = [mock.call(node1, node1,
                       'Configure "sfha" software on node "mn1"',
                       call_type='vcs::configure', number_of_nodes='1',
                       heartbeats_MACs={}, hostname='mn1', clust_type='sfha',
                       call_id='cluster1', cluster_name='cluster1',
                       fencing_dg_name=None, cluster_ID='1231',
                       cluster_UUID='ac258320-3d09-3747-af35-ebb29d498753',
                       managment_MAC={}, license_key='ENTERPRISE',
                       hostnames={'1': 'mn2', '0': 'mn1'}, rpm_list='',
                       manage_vxfencing=False, base_os=node1.os.version,
                       heartbeats_SAPs={'bond0.91': '0xcafd', 'bond0.17': '0xcafc'},
                       management_SAP={'br0': '0xcafe'}, boot_mode='uefi'),
                 mock.call(node2, node2,
                       'Configure "sfha" software on node "mn2"',
                       call_type='vcs::configure', number_of_nodes='1',
                       heartbeats_MACs={}, hostname='mn2', clust_type='sfha',
                       call_id='cluster1', cluster_name='cluster1',
                       fencing_dg_name=None, cluster_ID='1231',
                       cluster_UUID='ac258320-3d09-3747-af35-ebb29d498753',
                       managment_MAC={}, license_key='ENTERPRISE',
                       hostnames={'1': 'mn2', '0': 'mn1'}, rpm_list='',
                       manage_vxfencing=False, base_os=node1.os.version,
                       heartbeats_SAPs={'bond0.91': '0xcafd', 'bond0.17': '0xcafc'},
                       management_SAP={'br0': '0xcafe'}, boot_mode='uefi')]
        mock_ConfigTask.assert_has_calls(calls, any_order=True)

    def test_user_set_vcs_seed_threshold_property_upon_create_configuration(self):
        self.setup_model(num_of_nodes=2, vcs_seed_threshold=2)
        cluster = self.context_api.query('vcs-cluster')[0]

        with mock.patch.object(self.vcs_cluster, '_get_vcs_seed_threshold',
               autospec=True, wraps=self.vcs_cluster._get_vcs_seed_threshold) as \
                                                 mock_get_vcs_seed_threshold:
            self.assertEqual(2, cluster.vcs_seed_threshold)
            self.vcs_cluster.create_configuration(self, cluster)
            self.assertEqual(2, cluster.vcs_seed_threshold)
            self.assertEqual(0, mock_get_vcs_seed_threshold.call_count)

    def test_vcs_seed_threshold_is_not_plugin_updatable(self):
        self.setup_model(num_of_nodes=2)
        cluster = self.context_api.query('vcs-cluster')[0]
        try:
            cluster.vcs_seed_threshold = 1

            # Stop if no exceptions
            self.assertTrue(False)

        except AttributeError as e:
            error_msg = 'Field "vcs_seed_threshold" in <ModelItem ' \
                        '/deployments/test/clusters/cluster1 ' \
                        'type=vcs-cluster state=Initial> is not ' \
                        'updatable by plugins'
            self.assertEqual(error_msg, str(e))

        # To catch any other unexpected exception
        except:
            self.assertTrue(False)

    def test_validate_no_node_removal_on_cluster_without_fencing_disks(self):
        self.setup_model(num_of_nodes=4, fencing_num=0)
        self.model.set_all_applied()

        cluster = self.context_api.query('vcs-cluster')[0]
        errors = self.vcs_cluster.\
            _validate_no_node_removal_on_cluster_with_fencing_disks(cluster)

        self.assertEqual([], self.string_and_sort(errors))

    def test_validate_no_node_removal_on_cluster_with_fencing_disks(self):
        self.setup_model(num_of_nodes=4, fencing_num=3)
        self.model.set_all_applied()
        self.model.remove_item("/deployments/test/clusters/cluster1/nodes/node2")
        self.model.remove_item("/deployments/test/clusters/cluster1/nodes/node3")

        cluster = self.context_api.query('vcs-cluster')[0]
        errors = self.vcs_cluster.\
            _validate_no_node_removal_on_cluster_with_fencing_disks(cluster)

        expected = sorted(
                    ['</deployments/test/clusters/cluster1/nodes/node2 - '
                        'ValidationError - Removal of node "mn2" from '
                        'cluster "cluster1" is not supported because this '
                        'cluster has fencing disks.>',
                     '</deployments/test/clusters/cluster1/nodes/node3 - '
                        'ValidationError - Removal of node "mn3" from '
                        'cluster "cluster1" is not supported because this '
                        'cluster has fencing disks.>'])

        self.assertEqual(expected, self.string_and_sort(errors))

    @mock.patch.object(VcsCluster,
            '_validate_no_node_removal_on_cluster_with_fencing_disks',
            autospec=True)
    def test_if_validate_model_do_not_call_validate_no_node_removal_on_cluster_with_fencing_disks(self, validate_mock):
        self.setup_model(num_of_nodes=4, fencing_num=0)
        self.model.set_all_applied()
        cluster = self.context_api.query('vcs-cluster')[0]

        self.vcs_cluster.validate_model(self.context_api)
        self.assertEqual(0, validate_mock.call_count)

    def test_remove_cluster_seed_threshold_validation_ok(self):
        self.setup_model(num_of_nodes=4, num_of_clusters=2, vcs_seed_threshold="1")
        self.model.set_all_applied()
        self.model.remove_item("/deployments/test/clusters/cluster2")
        errors = self.vcs_cluster.validate_model(self.context_api)
        self.assertEqual([], errors)

    @mock.patch.object(VcsCluster,
            '_validate_no_node_removal_on_cluster_with_fencing_disks',
            autospec=True)
    def test_if_validate_model_calls_validate_no_node_removal_on_cluster_with_fencing_disks(self, validate_mock):
        self.setup_model(num_of_nodes=4, fencing_num=3)
        self.model.set_all_applied()
        cluster = self.context_api.query('vcs-cluster')[0]

        self.vcs_cluster.validate_model(self.context_api)
        validate_mock.assert_called_once_with(self.vcs_cluster, cluster)

    @mock.patch('vcsplugin.vcs_cluster.VcsCluster.vcs_api')
    @mock.patch('vcsplugin.vcs_plugin.VcsUtils.wait_on_state')
    def test_stop_vcs_on_cluster_cb(self, wait_on_state, vcs_api):
        self.setup_model(num_of_nodes=4, num_of_clusters=2)
        self.model.set_all_applied()
        self.model.remove_item("/deployments/test/clusters/cluster1/node1")
        wait_on_state.return_value = False

        self.assertRaises(CallbackExecutionException,
                          self.vcs_cluster.stop_vcs_on_node,
                          self.context_api, '/deployments/test/clusters/cluster1',
                          'node1')

        self.assertEqual(vcs_api.haconf.call_args_list, [mock.call("dump", read_only="True")])
        self.assertEqual(vcs_api.stop_vcs.call_args_list, [mock.call(ignore_vcs_stop_err=True, sys='node1')])

    def test_stop_service_cb(self):
        plugin_inst = mock.Mock()
        self.vcs_cluster.stop_service_cb(plugin_inst.callback_method, 'n1', 'puppet')
        plugin_inst.callback_method.rpc_application.assert_called_once_with(
        ['n1'],
        ['service', 'puppet', 'stop', '-y'])

    @mock.patch('vcsplugin.vcs_cluster.VcsRPC')
    @mock.patch('vcsplugin.vcs_cluster.log')
    def test_check_stopped_cluster_return_code_one(self, log, vcs_rpc_patch):
        vcsrpc_mock = mock.Mock()
        vcs_rpc_patch.return_value = vcsrpc_mock
        vcsrpc_mock.cluster_stopped.return_value = (1, "", "error msg")

        vcs_cluster = VcsCluster(None)
        node = "mn2"
        stopped = vcs_cluster._check_vcs_stopped_on_node(node)

        self.assertEqual(stopped, False)
        self.assertEqual(log.event.debug.call_args_list, [
            mock.call('VCS is not stopped on node "mn2", error: "error msg", output: ""')])

    @mock.patch('vcsplugin.vcs_cluster.VcsRPC')
    @mock.patch('vcsplugin.vcs_cluster.log')
    def test_check_stopped_cluster_vcscmd_exception(self, log, vcs_rpc_patch):
        vcsrpc_mock = mock.Mock()
        vcs_rpc_patch.return_value = vcsrpc_mock
        vcsrpc_mock.cluster_stopped.side_effect = VcsCmdApiException

        vcs_cluster = VcsCluster(None)
        node = "mn1"
        stopped = vcs_cluster._check_vcs_stopped_on_node(node)

        self.assertEqual(stopped, False)
        self.assertEqual(log.event.debug.call_args_list, [
            mock.call('VCS is not stopped on node "mn1", error: ""')])

    @mock.patch('vcsplugin.vcs_cluster.VcsCluster.is_node_reachable')
    @mock.patch('vcsplugin.vcs_cluster.RpcCommandProcessorBase')
    def test_remove_node_from_cluster_cb_cluster_removal_disable_services(
            self, rcpb, mock_is_node_reachable):
        self.setup_model(num_of_nodes=2, ha_manager="vcs")
        cluster = self.context_api.query('vcs-cluster')[0]
        mock_is_node_reachable.return_value = True

        rcpb().execute_rpc_and_process_result.side_effect = [
            RpcExecutionException('err'), (None, {'n2': ['stuff broke']})]
        self.assertRaises(CallbackExecutionException,
                          self.vcs_cluster.remove_node_from_cluster_cb,
                          self.callback_api, cluster.get_vpath(), 'n1', True)
        self.assertRaises(CallbackExecutionException,
                          self.vcs_cluster.remove_node_from_cluster_cb,
                          self.callback_api, cluster.get_vpath(), 'n2', True)

    @mock.patch('vcsplugin.vcs_cluster.VcsCluster.stop_service_cb')
    @mock.patch('vcsplugin.vcs_cluster.VcsCluster.stop_vcs_on_node')
    @mock.patch('vcsplugin.vcs_cluster.VcsCluster.is_node_reachable')
    @mock.patch('vcsplugin.vcs_cluster.RpcCommandProcessorBase')
    def test_remove_node_from_cluster_cb_cluster_removal_stop_services(
            self, rcpb, mock_is_node_reachable, mock_stop_vcs, mock_stop_service):
        self.setup_model(num_of_nodes=2, ha_manager="vcs")
        cluster = self.context_api.query('vcs-cluster')[0]
        mock_is_node_reachable.return_value = True
        rcpb().execute_rpc_and_process_result.side_effect = ([None, []],
                                                             [None, []],
                                                             [None, []])

        self.vcs_cluster.remove_node_from_cluster_cb(self.callback_api, cluster.get_vpath(), 'n1', True)
        mock_stop_vcs.assert_has_calls([mock.call(self.callback_api, cluster.get_vpath(), 'n1')])
        self.assertEqual(mock_stop_vcs.call_count, 1)
        mock_stop_service.assert_has_calls([mock.call(self.callback_api, 'n1', 'puppet'),
                                            mock.call(self.callback_api, 'n1', 'mcollective')
                                            ])

    @mock.patch('vcsplugin.vcs_cluster.VcsCluster.is_node_reachable')
    def test_remove_node_from_cluster_cb_unreachable_node_cluster_removal(
            self, mock_is_node_reachable):
        self.setup_model(num_of_nodes=2, ha_manager="vcs")
        cluster = self.context_api.query('vcs-cluster')[0]
        mock_is_node_reachable.return_value = False

        ret = self.vcs_cluster.remove_node_from_cluster_cb(self.callback_api, cluster.get_vpath(), 'n1', True)

        self.assertEqual(ret, None)

    @mock.patch('vcsplugin.vcs_base_helper.VcsCmdApi')
    @mock.patch('vcsplugin.vcs_cluster.select_nodes_from_cluster')
    @mock.patch('vcsplugin.vcs_cluster.VcsCluster.is_node_reachable')
    def test_remove_node_from_cluster_cb_node_removal(self, mock_is_node_reachable, mock_select_nodes, mock_vcs_cmd_api):
        self.setup_model(num_of_nodes=2, ha_manager="vcs")
        cluster = self.context_api.query('vcs-cluster')[0]
        mock_is_node_reachable.return_value = False
        mock_select_nodes.return_value = ['n1']

        self.vcs_cluster.remove_node_from_cluster_cb(self.callback_api, cluster.get_vpath(), 'n1', False)
        self.vcs_cluster._vcs_api.hasys_delete.assert_called_once_with('n1')

    @mock.patch('vcsplugin.vcs_cluster.VcsRPC')
    def test_check_stopped_cluster_success(self, vcs_rpc_patch):
        vcsrpc_mock = mock.Mock()
        vcs_rpc_patch.return_value = vcsrpc_mock
        vcsrpc_mock.cluster_stopped.return_value = (0, "", "")

        vcs_cluster = VcsCluster(None)
        node = "mn2"
        stopped = vcs_cluster._check_vcs_stopped_on_node(node)

        self.assertEqual(stopped, True)
        self.assertEqual(vcsrpc_mock.cluster_stopped.call_count, 1)

    def test_is_node_reachable_no_errors(self):
        callback_api = mock.Mock(
            rpc_command=lambda n, agent, action, timeout: {"n1": {'out': "Timestamp: 1677235165",
                                                                  "errors": []
                                                                  }})
        self.assertEqual(True, self.vcs_cluster.is_node_reachable(callback_api, 'n1'))

    def test_is_node_reachable_errors(self):
        callback_api = mock.Mock(
            rpc_command=lambda n, agent, action, timeout: {"n1": {'out': "",
                                                                  "errors": ["No response from: node 'n1'"]
                                                                  }})
        self.assertEqual(False, self.vcs_cluster.is_node_reachable(callback_api, 'n1'))

    @mock.patch('vcsplugin.vcs_cluster.log')
    def test_is_node_reachable_key_error(self, mock_log):
        node = 'n1'
        callback_api = mock.Mock(
            rpc_command=lambda n, agent, action, timeout: {"nX": {'out': "",
                                                                  "errors": ["No response from: node 'n1'"]
                                                                  }})
        result = self.vcs_cluster.is_node_reachable(callback_api, node)
        self.assertEqual(False, result)
        self.assertEqual(mock_log.trace.warning.call_args_list, [
            mock.call("No {0} in command output. '{0}'".format(node))])

    def test_is_uplift_plan(self):
        upgrade = mock.Mock(os_reinstall='true')

        def mock_node_query(itemtype):
            if 'upgrade' == itemtype:
                return [upgrade]

        nodes = [mock.Mock(hostname=host)
                 for host in ('db-1', 'db-2', 'db-3', 'db-4')]
        for node in nodes:
            node.query = mock_node_query
            node.upgrade = upgrade

        kluster = mock.Mock(cluster_type='sfha', nodes=nodes)

        vcs_cluster = VcsCluster(None)
        self.assertTrue(vcs_cluster.is_uplift_plan(kluster))

        # ----
        upgrade.os_reinstall = 'false'
        self.assertFalse(vcs_cluster.is_uplift_plan(kluster))

        # ----

        for node in nodes:
            node.upgrade = None
        self.assertFalse(vcs_cluster.is_uplift_plan(kluster))

        # ----
        kluster.nodes = []
        self.assertFalse(vcs_cluster.is_uplift_plan(kluster))

        # ----
        kluster = None
        self.assertFalse(vcs_cluster.is_uplift_plan(kluster))

    def test_get_node_ids_for_uplift(self):
        vcs_cluster = VcsCluster(None)

        mnode1 = mock.Mock(hostname='db-1', is_applied=lambda: True)
        mnode2 = mock.Mock(hostname='db-2', is_applied=lambda: True)
        mnode3 = mock.Mock(hostname='db-3', is_applied=lambda: True)
        mnode4 = mock.Mock(hostname='db-4', is_applied=lambda: True)

        mnodes = [mnode1, mnode2, mnode3, mnode4]
        mkluster = mock.Mock(cluster_type='sfha', nodes=mnodes)

        nodes, node_ids = vcs_cluster._get_node_ids_for_uplift(mkluster)
        self.assertEqual([], nodes)
        self.assertEqual({}, node_ids)

        # ----

        mnode1 = mock.Mock(hostname='db-1', is_applied=lambda: False)
        mnode2 = mock.Mock(hostname='db-2', is_applied=lambda: False)
        mnode3 = mock.Mock(hostname='db-3', is_applied=lambda: False)
        mnode4 = mock.Mock(hostname='db-4', is_applied=lambda: False)

        mnodes = [mnode1, mnode2, mnode3, mnode4]
        mkluster = mock.Mock(cluster_type='sfha', nodes=mnodes)

        # ----

        etc_llthosts_data = {'0': 'db-1',
                             '1': 'db-2',
                             '2': 'db-3',
                             '3': 'db-4'}

        vcs_cluster._get_vcs_node_ids = mock.Mock(return_value=etc_llthosts_data)

        nodes, node_ids = vcs_cluster._get_node_ids_for_uplift(mkluster)

        expected_nodes = mnodes
        expected_node_ids = etc_llthosts_data
        self.assertEqual(expected_nodes, nodes)
        self.assertEqual(expected_node_ids, node_ids)

        #----

        etc_llthosts_data = {'0': 'db-1',
                             '1': 'db-3',
                             '2': 'db-2',
                             '3': 'db-4'}

        vcs_cluster._get_vcs_node_ids = mock.Mock(return_value=etc_llthosts_data)

        nodes, node_ids = vcs_cluster._get_node_ids_for_uplift(mkluster)

        expected_nodes = [mnode1, mnode3, mnode2, mnode4]
        expected_node_ids = etc_llthosts_data

        self.assertEqual(expected_nodes, nodes)
        self.assertEqual(expected_node_ids, node_ids)
