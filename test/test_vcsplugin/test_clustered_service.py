##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################
from vcsplugin.vcs_sg_helper import (VcsServiceGroupHelper,
                                     ERR_INVALID_NODE_LIST,
                                     ERR_NO_SG_CONTRACTION_WITH_VIPS)
from vcsplugin.vcs_exceptions import VCSRuntimeException
from litp.core.execution_manager import CallbackTask

import unittest
import mock
from mock import patch


def create_node(name):
    node = mock.Mock()
    node.hostname = name
    node.is_for_removal.return_value = False
    return node

def create_service(name, nodes = None, runtimes = None, dependency_list='',
                   initial_online_dependency_list=''):
    service = mock.Mock()
    service.item_id = name
    service.name = name
    service.nodes = nodes
    service.runtimes = runtimes
    service.active = "1"
    service.standby = "1"
    service.is_initial.return_value = True
    service.is_for_removal.return_value = False
    service.dependency_list = dependency_list
    service.initial_online_dependency_list = initial_online_dependency_list
    service.applied_properties = {'dependency_list': '',
                                  'initial_online_dependency_list': ''}
    if nodes:
        service.node_list = ','.join(n.hostname for n in nodes)
        service.applied_properties['node_list'] = service.node_list
    service.deactivates = None
    return service

def create_cluster(nodes, services=None):
    cluster = mock.Mock()
    cluster.nodes = nodes
    cluster.services = services
    return cluster

def setup_nodes(n_nodes=2):
    nodes = list()
    for n in range(1, n_nodes+1):
        nodes.append(create_node("mn"+str(n)))
    return nodes

def setup_services():
    services = list()
    services.append(create_service("ser1"))
    services.append(create_service("ser2"))
    return services

def create_runtime(name):
    runtime  = mock.Mock()
    runtime.start_command = "start command"
    runtime.stop_command = "stop command"
    runtime.status_command = "status command"
    runtime.cleanup_command = "cleanup command"
    return runtime


class TestClusteredService(unittest.TestCase):

    def setUp(self):
        plugin = mock.Mock()
        plugin.callback.return_value = True
        self.csh = VcsServiceGroupHelper(plugin)

        self.api_context = mock.Mock(
            'litp.core.plugin_context_api.PluginApiContext', autospec=True)()
        # pylint complains about **kwargs
        # pylint: disable=unused-argument
        def query(*args, **kwargs):
            if args[0] == "vcs-cluster":
                return self.clusters
        self.api_context.query.side_effect = query

    def test_vcs_api_exception(self):
        self.assertRaises(VCSRuntimeException,
                          lambda: self.csh.vcs_api())

    def test_vcs_api(self):
        self.csh.nodes = ("mn1", "mn2")
        api = self.csh.vcs_api
        self.assertTrue(api is not None)
        self.assertTrue(api.node == "mn1")

    def test_validate_nodes_in_cluster_node_for_removal(self):
        nodes = setup_nodes()
        nodes[0].is_for_removal.return_value = True
        cluster = create_cluster(nodes)
        service = create_service("s1", nodes)
        errs = self.csh._validate_nodes_in_cluster(cluster, service)
        self.assertTrue(len(errs) == 1)

    def test_validate_nodes_in_cluster_ok(self):
        nodes = setup_nodes()
        cluster = create_cluster(nodes)
        service = create_service("s1", nodes)
        errs = self.csh._validate_nodes_in_cluster(cluster, service)
        self.assertTrue(len(errs) == 0)

    #test disabled as now handle in ats, file vcs_services_validation.at
    def valid_num_runtime_in_cluster_service(self):
        runtime = list()
        runtime.append(create_runtime("rt1"))
        service = create_service("ser1")
        service.runtimes = runtime
        errs = self.csh._validate_number_of_runtime(service)
        self.assertTrue(len(errs) == 0)

    #test disabled as now handle in ats, file vcs_services_validation.at
    def invalid_num_runtime_in_cluster_service(self):
        runtime = list()
        runtime.append(create_runtime("rt1"))
        runtime.append(create_runtime("rt2"))
        service = create_service("ser1")
        service.runtimes = runtime
        errs = self.csh._validate_number_of_runtime(service)
        self.assertTrue(len(errs) != 0)

    def test_validate_unique_service_name_fail(self):
        services = list()
        services.append(create_service("ser1"))
        services.append(create_service("ser1"))
        services.append(create_service("ser2"))
        cluster = create_cluster(None, services)
        cluster.get_vpath = mock.Mock()

        service = create_service("ser1")
        errs = self.csh._validate_unique_service_name(cluster, service)
        self.assertTrue(len(errs) == 1)

    def test_validate_unique_service_name_ok(self):
        services = list()
        services.append(create_service("ser1"))
        services.append(create_service("ser2"))
        cluster = create_cluster(None, services)

        service = create_service("ser1")
        errs = self.csh._validate_unique_service_name(cluster, service)
        self.assertTrue(len(errs) == 0)

    @patch("vcsplugin.vcs_base_helper.VcsBaseHelper.removed_node_hostnames")
    @patch("vcsplugin.vcs_base_helper.is_node_intersection")
    def test_validate_against_contraction_with_vips(self, patch_node_intersection,
                                                    patch_removed_nodes):
        patch_removed_nodes.return_value = []
        patch_node_intersection.return_value = False
        cs = create_service('cs1')
        cs.active = "2"
        cs.standby = "0"
        cs.is_updated.return_value = True
        vip = mock.Mock()
        cs.ipaddresses = [vip]
        errs = self.csh._validate_against_contraction_with_vips(cs)
        self.assertEqual(0, len(errs))

        #part 2,  Enusre an intersection
        patch_node_intersection.return_value = True
        errs = self.csh._validate_against_contraction_with_vips(cs)
        self.assertEqual(0, len(errs))

    @patch("vcsplugin.vcs_base_helper.VcsBaseHelper.removed_node_hostnames")
    @patch("vcsplugin.vcs_base_helper.is_node_intersection")
    def test_validate_against_contraction_with_vips_error(self,
                                 patch_node_intersection, patch_removed_nodes):
        patch_removed_nodes.return_value = ['mn2']
        patch_node_intersection.return_value = True

        nodes = setup_nodes()
        cs = create_service('cs1', nodes)
        cs.active = "2"
        cs.standby = "0"
        cs.is_updated.return_value = True
        cs.applied_properties = {'standby': '0'}
        cs.get_vpath = mock.Mock(return_value="cs1_vpath")
        vip = mock.Mock()
        cs.ipaddresses = [vip]
        errs = self.csh._validate_against_contraction_with_vips(cs)
        self.assertEqual(1, len(errs))
        expected = {'message': ERR_NO_SG_CONTRACTION_WITH_VIPS,
                    'uri': 'cs1_vpath',
                    'error': 'ValidationError'}
        self.assertEqual(expected, errs[0].to_dict())

    def test_validate_clustered_service_fail1(self):
        self.csh._validate_unique_service_name = mock.Mock(return_value=[])
        self.csh._validate_cluster_service_id_no_dash_underscore = mock.Mock(return_value=[])
        self.csh._validate_fs_item_id_no_dash_underscore = mock.Mock(return_value=[])
        self.csh._validate_network_name_no_dash_underscore = mock.Mock(return_value=[])
        self.csh._validate_nodes_in_cluster = mock.Mock(return_value=[])
        self.csh._validate_number_of_runtime = mock.Mock(return_value=[])

        nodes = setup_nodes()
        clustered_service = create_service("ser1", nodes)
        clustered_service.active = 2
        cluster = create_cluster(nodes, [clustered_service])
        cluster.get_vpath = mock.Mock()
        self.csh._get_app_list = mock.Mock(return_value=[])
        errs = self.csh._validate_clustered_service(cluster,
                                                    clustered_service)
        self.assertTrue(len(errs) == 2)

    def test_validate_can_have_update_exist_lsbruntimes(self):
        cluster = mock.Mock()
        cluster.is_updated = mock.Mock(return_value=True)
        self.csh._get_app_list = mock.Mock(return_value=['one'])

        errs = self.csh. _validate_can_have_update(cluster)
        self.assertEqual(1, len(errs))

    def test_validate_can_have_update_noexist_lsbruntimes(self):
        cluster = mock.Mock()
        cluster.is_updated = mock.Mock(return_value=True)
        self.csh._get_app_list = mock.Mock(return_value=[])

        errs = self.csh._validate_can_have_update(cluster)
        self.assertEqual(0, len(errs))

    def test_validate_clustered_service_fail2(self):
        self.csh._validate_unique_service_name = mock.Mock(return_value=[])
        self.csh._validate_cluster_service_id_no_dash_underscore = mock.Mock(return_value=[])
        self.csh._validate_fs_item_id_no_dash_underscore = mock.Mock(return_value=[])
        self.csh._validate_network_name_no_dash_underscore = mock.Mock(return_value=[])
        self.csh._validate_nodes_in_cluster = mock.Mock(return_value=[])
        self.csh._validate_number_of_runtime = mock.Mock(return_value=[])

        nodes = setup_nodes()
        clustered_service = create_service("ser1", nodes)
        clustered_service.standby = 2
        cluster = create_cluster(None, [clustered_service])
        cluster.get_vpath = mock.Mock()
        self.csh._get_app_list = mock.Mock(return_value=[])
        errs = self.csh._validate_clustered_service(cluster,
                                                    clustered_service)
        self.assertTrue(len(errs) == 2)

    def test_validate_clustered_service_ok(self):
        self.csh._validate_unique_service_name = mock.Mock(return_value=[])
        self.csh._validate_nodes_in_cluster = mock.Mock(return_value=[])
        self.csh._validate_fs_item_id_no_dash_underscore = mock.Mock(return_value=[])
        self.csh._validate_network_name_no_dash_underscore = mock.Mock(return_value=[])
        self.csh._validate_number_of_runtime = mock.Mock(return_value=[])

        nodes = setup_nodes()
        clustered_service = create_service("ser1", nodes)
        cluster = create_cluster(nodes, [clustered_service])
        self.csh._get_app_list = mock.Mock(return_value=[])
        errs = self.csh._validate_clustered_service(cluster,
                                                    clustered_service)
        self.assertTrue(len(errs) == 0)

    def test_validate_clustered_service_one_node_error(self):
        self.csh._validate_active_standby = mock.Mock(return_value=[])
        self.csh._validate_number_of_nodes = mock.Mock(return_value=[])
        self.csh._validate_unique_service_name = mock.Mock(return_value=[])
        self.csh._validate_cluster_service_id_no_dash_underscore = mock.Mock(return_value=[])
        self.csh._validate_fs_item_id_no_dash_underscore = mock.Mock(return_value=[])
        self.csh._validate_network_name_no_dash_underscore = mock.Mock(return_value=[])
        self.csh._validate_nodes_in_cluster = mock.Mock(return_value=[])
        self.csh._validate_node_list_order = mock.Mock(return_value=[])
        self.csh._validate_number_of_runtime = mock.Mock(return_value=[])
        self.csh._validate_dependency_not_one_node = mock.Mock(return_value=['error'])
        self.csh._validate_dependencies_node_list = mock.Mock(return_value=[])
        self.csh._validate_same_service_in_dep_list_and_initial_list = mock.Mock(return_value=[])
        self.csh._validate_node_list = mock.Mock(return_value=[])
        self.csh._validate_against_contraction_with_vips = mock.Mock(return_value=[])
        self.csh._validate_deactivates = mock.Mock(return_value=[])

        cluster = mock.Mock()
        clustered_service = mock.Mock()
        clustered_service.is_for_removal.return_value=False
        self.csh._get_app_list = mock.Mock(return_value=[])
        errs = self.csh._validate_clustered_service(cluster, clustered_service)
        self.assertTrue(len(errs) == 1)
        self.assertEqual(self.csh._validate_dependency_not_one_node.call_count, 1)
        self.assertEqual(self.csh._validate_dependencies_node_list.call_count, 0)

    def test_validate_model_fail(self):
        self.csh._validate_clustered_service =\
             mock.Mock(return_value=["err_cs"])
        services = setup_services()
        self.clusters = [create_cluster(None, services)]
        self.csh._get_app_list = mock.Mock(return_value=[])
        errs = self.csh.validate_model(self.api_context)
        self.assertTrue(len(errs) == 2)

    def test_validate_model_fail2(self):
        self.csh._validate_number_of_runtime = mock.Mock(return_value=[])
        self.csh._validate_fs_item_id_no_dash_underscore = mock.Mock(return_value=[])
        self.csh._validate_network_name_no_dash_underscore = mock.Mock(return_value=[])
        nodes = setup_nodes()
        s1 = [create_service("s1", nodes), create_service("s2", nodes)]
        s2 = [create_service("s3", nodes), create_service("s4", nodes)]
        s2[0].active = 0
        self.clusters = [create_cluster(nodes, s1), create_cluster(nodes, s2)]
        self.csh._get_app_list = mock.Mock(return_value=[])
        errs = self.csh.validate_model(self.api_context)
        self.assertTrue(len(errs) == 2)

    def test_validate_model_fail3(self):
        self.csh._validate_number_of_runtime = mock.Mock(return_value=[])
        self.csh._validate_fs_item_id_no_dash_underscore = mock.Mock(return_value=[])
        self.csh._validate_network_name_no_dash_underscore = mock.Mock(return_value=[])
        nodes = setup_nodes()
        s1 = [create_service("s1", nodes), create_service("s2", nodes)]
        s2 = [create_service("s3", nodes), create_service("s4", nodes)]
        s2[1].standby = 2
        self.clusters = [create_cluster(nodes, s1), create_cluster(nodes, s2)]
        self.csh._get_app_list = mock.Mock(return_value=[])
        errs = self.csh.validate_model(self.api_context)
        self.assertTrue(len(errs) == 2)

    def test_validate_model_ok(self):
        self.csh._validate_clustered_service = mock.Mock(return_value=[])
        self.csh_validate_number_of_runtime = mock.Mock(return_value=[])
        services = setup_services()
        self.clusters = [create_cluster(None, services)]
        errs = self.csh.validate_model(self.api_context)
        """
        Add checks for number of times validate is called
        """
        self.assertTrue(self.csh._validate_clustered_service.call_count == 2)
        self.assertTrue(len(errs) == 0)

    def test_validate_model_ok2(self):
        self.csh._validate_fs_item_id_no_dash_underscore = mock.Mock(return_value=[])
        self.csh._validate_network_name_no_dash_underscore = mock.Mock(return_value=[])
        self.csh._validate_number_of_runtime = mock.Mock(return_value=[])
        nodes = setup_nodes()
        s1 = [create_service("s1", nodes), create_service("s2", nodes)]
        s2 = [create_service("s3", nodes), create_service("s4", nodes)]
        self.clusters = [create_cluster(nodes, s1), create_cluster(nodes, s2)]
        self.csh._get_app_list = mock.Mock(return_value=[])
        errs = self.csh.validate_model(self.api_context)
        self.assertTrue(len(errs) == 0)

    def test_generate_install_task_ok(self):
        nodes = setup_nodes()
        cluster = mock.Mock()
        cluster_vpath = cluster.get_vpath.return_value = 'cluster vpath'
        service = create_service("ser1")
        service.nodes = nodes
        self.csh.plugin = mock.Mock()
        service.query = mock.Mock(return_value='vip1')
        task = self.csh._generate_install_task(service, 1234, cluster_vpath)
        self.assertTrue(task is not None)

    #==========================================================================
    # @mock.patch("litp.core.execution_manager.CallbackTask")
    # def test_generate_task(self, cb):
    #     cb.side_effect = [mock.Mock(spec=CallbackTask)]
    #     nodes = setup_nodes()
    #     s1 = [create_service("s1", nodes), create_service("s2", nodes)]
    #     s2 = [create_service("s3", nodes), create_service("s4", nodes)]
    #     with mock.patch('vcsplugin.vcs_model.VCSModel.fromApi') as mock_model:
    #         mock_model.return_value = {}
    #         self.clusters = [create_cluster(nodes, s1),
    #                          create_cluster(nodes, s2)]
    #         tasks = self.csh.generate_task(self.api_context)
    #         self.assertTrue(len(tasks) == 2)
    #==========================================================================
#==============================================================================
#
#     @mock.patch("litp.core.execution_manager.CallbackTask")
#     def test_generate_task2(self, cb):
#         cb.side_effect = [mock.Mock(spec=CallbackTask)]
#         nodes = setup_nodes()
#         s1 = [create_service("s1", nodes), create_service("s2", nodes)]
#         s1[0].is_initial.return_value = False
#         s2 = [create_service("s3", nodes), create_service("s4", nodes)]
#         s2[1].is_initial.return_value = False
#         with mock.patch('vcsplugin.vcs_model.VCSModel.fromApi') as mock_model:
#             mock_model.return_value = {}
#             self.clusters = [create_cluster(nodes, s1),
#                              create_cluster(nodes, s2)]
#             tasks = self.csh.generate_task(self.api_context)
#             self.assertTrue(len(tasks) == 2)
#==============================================================================

    def test_install_callback_apd(self):
        self.csh.get_group_name = mock.Mock(return_value="cs1")
        self.csh._vcs_api = mock.Mock()
        self.csh._vcs_api.readable_conf = mock.MagicMock()
        self.csh._remove_if_service_group_exist_in_cluster = mock.Mock(return_value=None)

        cluster = mock.Mock()
        cluster_vpath = cluster.get_vpath.return_value = 'cluster vpath'
        service = mock.MagicMock()
        service.standby = "0"
        service.applied_properties_determinable = False
        self.csh.query_by_vpath = mock.Mock(return_value=service)
        operation_instance = mock.MagicMock()
        try:
            self.csh.install_callback(None, service_vpath="",
                                    cluster_item_id="cluster1",
                                    cluster_vpath = cluster_vpath)
        except Exception as ex:
            raise AssertionError
        self.assertEqual(self.csh._vcs_api.readable_conf.call_count, 1)
        self.assertEqual(self.csh._remove_if_service_group_exist_in_cluster.call_count, 1)

    def test_install_callback(self):
        self.csh.get_group_name = mock.Mock(return_value="cs1")
        self.csh._vcs_api = mock.Mock()
        self.csh._vcs_api.readable_conf = mock.MagicMock()
        self.csh._remove_if_service_group_exist_in_cluster = mock.Mock(return_value=None)

        cluster = mock.Mock()
        cluster_vpath = cluster.get_vpath.return_value = 'cluster vpath'
        service = mock.MagicMock()
        service.standby = "0"
        self.csh.query_by_vpath = mock.Mock(return_value=service)
        operation_instance = mock.MagicMock()
        try:
            self.csh.install_callback(None, service_vpath="",
                                    cluster_item_id="cluster1",
                                    cluster_vpath=cluster_vpath)
        except Exception as ex:
            raise AssertionError
        self.assertEqual(self.csh._vcs_api.readable_conf.call_count, 1)
        self.assertEqual(self.csh._remove_if_service_group_exist_in_cluster.call_count, 0)

    @patch("vcsplugin.vcs_sg_helper.is_os_reinstall_on_peer_nodes")
    def test_install_callback_os_reinstall(self, is_os_reinstall_mock):
        self.csh.get_group_name = mock.Mock(return_value="cs1")
        self.csh._vcs_api = mock.Mock()
        self.csh._vcs_api.readable_conf = mock.MagicMock()
        self.csh._remove_if_service_group_exist_in_cluster = mock.Mock(return_value=None)

        cluster = mock.Mock()
        cluster_vpath = cluster.get_vpath.return_value = 'cluster vpath'
        service = mock.MagicMock()
        service.standby = "0"
        service.applied_properties_determinable = False
        self.csh.query_by_vpath = mock.Mock(return_value=service)
        # Test os_reinstall is true
        is_os_reinstall_mock.return_value = True
        try:
            self.csh.install_callback(None, service_vpath="",
                                    cluster_item_id="cluster1",
                                    cluster_vpath = cluster_vpath)
        except Exception as ex:
            raise AssertionError
        self.assertEqual(self.csh._remove_if_service_group_exist_in_cluster.call_count, 1)

        # Test os_reinstall is False
        is_os_reinstall_mock.return_value = False
        try:
            self.csh.install_callback(None, service_vpath="",
                                    cluster_item_id="cluster1",
                                    cluster_vpath = cluster_vpath)
        except Exception as ex:
            raise AssertionError
        self.assertEqual(self.csh._remove_if_service_group_exist_in_cluster.call_count, 2)

    def test_update_callback(self):
        self.csh.get_group_name = mock.Mock(return_value="cs1")
        self.csh._vcs_api = mock.Mock()
        self.csh._vcs_api.readable_conf = mock.MagicMock()

        service = mock.MagicMock()
        service.standby = "0"
        service.nodes = setup_nodes()

        self.csh.query_by_vpath = mock.Mock(return_value=service)
        try:
            self.csh.update_callback(None, service_vpath="",
                                    cluster_item_id="cluster1")
        except Exception as ex:
            raise AssertionError
        self.assertEqual(1, self.csh._vcs_api.readable_conf.call_count)

    def test_validate_dependency_list_no_errors(self):
        cluster = mock.Mock()
        cs1 = mock.Mock(dependency_list='')
        cs2 = mock.Mock(dependency_list='')
        cs1.applied_properties = {'dependency_list': ''}
        cs2.applied_properties = {'dependency_list': ''}
        cluster.services = [cs1, cs2]
        errors = self.csh._validate_dependency_list(cluster)
        self.assertEqual(errors, [])

    def test_validate_dependency_list_circular(self):
        cluster = mock.Mock()
        cluster.get_vpath.return_value = 'cluster vpath'
        cs1 = mock.Mock(item_id='cs1', dependency_list='cs2')
        cs2 = mock.Mock(item_id='cs2', dependency_list='cs1')
        cluster.services = [cs1, cs2]
        errors = self.csh._validate_dependency_list(cluster)

        expected_errors = '[<cluster vpath - ValidationError - A circular dependency has been detected between the following clustered-services: "cs1" and "cs2". Check the "dependency_list" property of each clustered-service item to resolve the issue.>]'
        self.assertEqual(expected_errors, str(errors))

    def test_validate_dependency_list_depth_level(self):
        cluster = mock.Mock()
        cluster.get_vpath.return_value = 'cluster vpath'
        cs1 = mock.Mock(item_id='cs1', dependency_list='')
        cs2 = mock.Mock(item_id='cs2', dependency_list='cs1')
        cs3 = mock.Mock(item_id='cs3', dependency_list='cs2')
        cs4 = mock.Mock(item_id='cs4', dependency_list='cs3')
        cs5 = mock.Mock(item_id='cs5', dependency_list='cs4')
        cs6 = mock.Mock(item_id='cs6', dependency_list='cs5')
        cluster.services = [cs1, cs2, cs3, cs4, cs5, cs6]
        errors = self.csh._validate_dependency_list(cluster)
        expected_errors = '[<cluster vpath - ValidationError - The dependency tree depth for the vcs clustered services for this cluster is "6". The maximum dependency depth supported is "5".>]'
        self.assertEqual(str(errors), expected_errors)

    def test_validate_dependencies_node_list(self):
        cluster = mock.Mock()
        cs1 = mock.Mock(item_id='cs1', standby="0", active="2", node_list='node1,node2', dependency_list='')
        cs2 = mock.Mock(item_id='cs2', standby="0", active="2", node_list='node1,node2', dependency_list='cs1')

        clustered_service = mock.Mock(standby="0", active="4", node_list='node1,node2,node3,node4', dependency_list='cs1', item_id="clustered_service")
        clustered_service.get_vpath.return_value = 'clustered service vpath'
        cluster.services = [clustered_service, cs1, cs2]

        errors = self.csh._validate_dependencies_node_list(cluster, clustered_service)
        expected_errors = '[<clustered service vpath - ValidationError - The node_list for dependency "cs1" does not contain node "node3" which is part of the node_list for "clustered_service". This is required if both the service and the dependency are in parallel>, <clustered service vpath - ValidationError - The node_list for dependency "cs1" does not contain node "node4" which is part of the node_list for "clustered_service". This is required if both the service and the dependency are in parallel>]'
        self.assertEqual(str(errors), expected_errors)

    def test_validate_dependencies_node_list_dependency_in_list(self):
        cluster = mock.Mock()
        cs1 = mock.Mock(item_id='cs1', standby="0", active="3", node_list='node1,node2,node3', dependency_list='')
        cs2 = mock.Mock(item_id='cs2', standby="0", active="1", node_list='node1', dependency_list='cs1')

        clustered_service = mock.Mock(standby="0", active="2", node_list='node1,node2', dependency_list='cs1')
        clustered_service.get_vpath.return_value = 'clustered service vpath'
        cluster.services = [clustered_service, cs1, cs2]

        errors = self.csh._validate_dependencies_node_list(cluster, clustered_service)
        self.assertEqual(errors, [])

    def test_validate_dependency_list_non_exist_cs7(self):
        cluster = mock.Mock()
        cluster.get_vpath.return_value = 'cluster vpath'
        cs1 = mock.Mock(item_id='cs1', dependency_list='')
        cs2 = mock.Mock(item_id='cs2', dependency_list='cs1')
        cs3 = mock.Mock(item_id='cs3', dependency_list='cs2')
        cs4 = mock.Mock(item_id='cs4', dependency_list='cs3')
        cs5 = mock.Mock(item_id='cs5', dependency_list='cs4,cs7')
        cluster.services = [cs1, cs2, cs3, cs4, cs5]
        errors = self.csh._validate_dependency_list(cluster)
        self.assertEqual(errors, [])

    def test_validate_dependency_list_depend_itself(self):
        cluster = mock.Mock()
        cluster.get_vpath.return_value = 'cluster vpath'
        cs1 = mock.Mock(item_id='cs1', dependency_list='')
        cs2 = mock.Mock(item_id='cs2', dependency_list='cs1')
        cs3 = mock.Mock(item_id='cs3', dependency_list='cs2')
        cs4 = mock.Mock(item_id='cs4', dependency_list='cs3')
        cs5 = mock.Mock(item_id='cs5', dependency_list='cs4,cs5')
        cluster.services = [cs1, cs2, cs3, cs4, cs5]
        errors = self.csh._validate_dependency_list(cluster)
        self.assertEqual(errors, [])

    def test_validate_dependency_not_one_node(self):
        cluster = mock.Mock()
        cs1 = mock.Mock(item_id='cs1', standby="0", active="1", node_list='node1', dependency_list='', is_for_removal=lambda: False)

        clustered_service = mock.Mock(standby="0", active="2", node_list='node1,node2', dependency_list='cs1')
        clustered_service.get_vpath.return_value = 'clustered service vpath'
        cluster.services = [clustered_service, cs1]

        errors = self.csh._validate_dependency_not_one_node(cluster, clustered_service)
        expected_errors = '[<clustered service vpath - ValidationError - The dependency "cs1" is a one node vcs-clustered-service. Only a one node vcs-clustered-service with the same node_list can depend on a one node vcs-clustered-service.>]'
        self.assertEqual(str(errors), expected_errors)

    def test_validate_dependency_not_one_node_same_node_list(self):
        cluster = mock.Mock()
        cs1 = mock.Mock(item_id='cs1', standby="0", active="1", node_list='node1', dependency_list='')

        clustered_service = mock.Mock(standby="0", active="1", node_list='node1', dependency_list='cs1')
        clustered_service.get_vpath.return_value = 'clustered service vpath'
        cluster.services = [clustered_service, cs1]

        errors = self.csh._validate_dependency_not_one_node(cluster, clustered_service)
        self.assertEqual(str(errors), '[]')

    def test_validate_dependency_list_add_initial(self):
        cluster = mock.Mock()
        cs1 = mock.Mock(dependency_list='', item_id='cs1', is_for_removal=lambda: False)
        cs2 = mock.Mock(dependency_list='', item_id='cs2', is_for_removal=lambda: False)
        cs3 = mock.Mock(dependency_list='cs1', item_id='cs3', is_for_removal=lambda: False)
        cs3.vpath = '/service/cs3'
        cs1.applied_properties = {'dependency_list': ''}
        cs2.applied_properties = {'dependency_list': ''}
        cs3.applied_properties = {'dependency_list': 'cs2,cs1'}
        cluster.services = [cs1, cs2, cs3]
        errors = self.csh._validate_dependency_list(cluster)
        self.assertEqual('[</service/cs3 - ValidationError - An applied vcs-clustered-service cannot be updated to depend on a vcs-clustered-service "cs1" in Initial state>]', str(errors))

    def test_validate_service_id_fail(self):
        services = list()
        service1 = create_service("ser-1")
        services.append(service1)

        service2 = create_service("ser_1")
        service2.vpath = "/deployment/local_vm/serv-1"
        services.append(service2)
        cluster = create_cluster(None, services)

        errs = self.csh._validate_cluster_service_id_no_dash_underscore(
            cluster, service1)
        self.assertTrue(len(errs) == 1)

    def test_validate_service_id_ok(self):
        services = list()
        service1 = create_service("ser-1")
        services.append(service1)

        service2 = create_service("ser_2")
        services.append(service2)
        cluster = create_cluster(None, services)

        errs = self.csh._validate_cluster_service_id_no_dash_underscore(
            cluster, service1)
        self.assertTrue(len(errs) == 0)

    def test_validate_network_name_fail(self):
        ip1 = mock.Mock()
        ip1.network_name = "network-1"
        ip1.vpath = "/deployment/local_vm/serv-1/ip1"
        ip2 = mock.Mock()
        ip2.network_name = "network_1"
        ip2.vpath = "/deployment/local_vm/serv-1/ip2"
        ipaddresses = [ip1, ip2]
        service = create_service("ser-1")
        service.type = "lsb-runtime"
        service.ipaddresses = ipaddresses
        service.query = lambda x : []

        errs = self.csh._validate_network_name_no_dash_underscore(service)
        self.assertTrue(len(errs) == 2)

    def test_validate_network_name_ok(self):
        ip1 = mock.Mock()
        ip1.network_name = "network-1"
        ip2 = mock.Mock()
        ip2.network_name = "network-2"
        ipaddresses = [ip1, ip2]
        service = create_service("ser-1")
        service.type = "lsb-runtime"
        service.ipaddresses = ipaddresses
        service.query = lambda x : []

        errs = self.csh._validate_network_name_no_dash_underscore(service)
        self.assertTrue(len(errs) == 0)


    def test_validate_fs_fail(self):
        fs1 = mock.Mock()
        fs1.item_id = "fs-1"
        fs1.vpath = "/deployment/local_vm/serv-1/fs1"
        fs2 = mock.Mock()
        fs2.item_id = "fs_1"
        fs2.vpath = "/deployment/local_vm/serv-1/fs2"
        fs_list = [fs2, fs1]
        service = create_service("ser-1")
        service.type = "lsb-runtime"
        service.filesystems = fs_list
        service.query = lambda x : []

        errs = self.csh._validate_fs_item_id_no_dash_underscore(service)
        self.assertTrue(len(errs) == 2)

    def test_validate_fs_ok(self):
        fs1 = mock.Mock()
        fs1.item_id = "fs-1"
        fs2 = mock.Mock()
        fs2.item_id = "fs-2"
        fs_list = [fs2, fs1]
        service = create_service("ser-1")
        service.type = "lsb-runtime"
        service.filesystems = fs_list
        service.query = lambda x : []

        errs = self.csh._validate_fs_item_id_no_dash_underscore(service)
        self.assertTrue(len(errs) == 0)
