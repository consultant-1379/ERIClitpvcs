import unittest

from mock import MagicMock, patch, call, Mock
from litp.plan_types.deployment_plan import deployment_plan_tags

from vcsplugin.vcs_plugin import VcsPlugin
from vcsplugin.vcs_sg_helper import (VcsServiceGroupHelper,
                                     OFFLINE_TIMEOUT,
                                     ERROR_DELETION_DEPENDENCY,
                                     ERR_DEACTIVATES_SELF,
                                     ERR_DEACTIVATES_CRITICAL_SERVICE,
                                     ERR_DEACTIVATES_NODE_OVERLAP,
                                     ERR_DEACTIVATES_DEPENDENCY,
                                     ERR_DEACTIVATES_INIT_ONLINE_DEPENDENCY,
                                     ERR_DEACTIVATES_NOT_INITIAL,
                                     ERR_DEACTIVATES_NOT_APPLIED_SERVICE,
                                     ERR_MULTIPLE_DEACTIVATIONS,
                                     ERR_DEACTIVATED_INCORRECTLY_SET,
                                     ERR_DEACTIVATES_UPDATE_INCOMPLETE)
from test_vcs_utils import MockVip

class DummyPluginForTest(object):
    def callback_method(self):
        pass


class TestVcsServiceGroupHelper(unittest.TestCase):
    """
    Test cases for `VcsServiceGroupHelper`.
    """
    def setUp(self):
        self.plugin = VcsPlugin()
        self.sg_helper = VcsServiceGroupHelper(self.plugin)

    def tearDown(self):
        pass

    def test_dependency_cmds(self):
        mock_service = MagicMock()
        mock_service.dependency_list = "cs1,cs2,cs3"
        mock_service.item_id = "test_cs"
        node1 = MagicMock()
        node1.hostname ="node1"
        node2 = MagicMock()
        node2.hostname ="node2"
        mock_service.nodes = [node1, node2]
        self.sg_helper.query_by_vpath = MagicMock(return_value = mock_service)
        self.sg_helper._vcs_api = MagicMock()
        self.sg_helper.nodes = ["n1"]
        cluster = MagicMock()
        cluster_vpath = cluster.get_vpath.return_value = 'cluster vpath'

        mock_cb_api = MagicMock()

        with patch.object(self.sg_helper.vcs_api, "hagrp_link") as mock:
            self.sg_helper.install_callback(mock_cb_api, "service_path",
                                            "test_cluster_id",
                                            cluster_vpath)

        calls = [call("Grp_CS_test_cluster_id_test_cs", "Grp_CS_test_cluster_id_cs1", "online", "global", "soft"),
                 call("Grp_CS_test_cluster_id_test_cs", "Grp_CS_test_cluster_id_cs2", "online", "global", "soft"),
                 call("Grp_CS_test_cluster_id_test_cs", "Grp_CS_test_cluster_id_cs3", "online", "global", "soft")]
        self.assertEqual(3, mock.call_count)
        mock.assert_has_calls(calls)

    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._clustered_service_dependency_list_removals")
    @patch("vcsplugin.vcs_sg_helper.log")
    def test_dependency_cmds_removal(self, patched_log, patch_removals):
        patch_removals.return_value = ["cs1"]
        service = Mock()
        service_name = "CS_Grp_1"
        cluster_item_id = "cluster1"

        self.sg_helper.nodes = ["n1", "n2"]
        vcs_api = MagicMock()
        self.sg_helper._vcs_api = vcs_api

        self.sg_helper._clustered_service_remove_dependencies(service, service_name, cluster_item_id)
        self.assertEqual(patched_log.trace.info.call_args_list,
                         [call("Ensuring service group CS_Grp_1 does not depend on service group Grp_CS_cluster1_cs1")])
        vcs_api.hagrp_unlink.assert_called_once_with("CS_Grp_1", "Grp_CS_cluster1_cs1")

    def test_dependency_cmds_parallel(self):
        mock_service = MagicMock()
        mock_service.dependency_list = "cs1"
        mock_service.item_id = "test_cs"
        mock_service.standby = "0"
        mock_service.get_vpath.return_value = "/deployments/test/clusters/cluster1/services/test_cs"
        node1 = MagicMock()
        node1.hostname ="node1"
        node2 = MagicMock()
        node2.hostname ="node2"
        mock_service.nodes = [node1, node2]
        self.sg_helper._vcs_api = MagicMock()

        mock_service_cs1 = MagicMock()
        mock_service_cs1.item_id = "cs1"
        mock_service_cs1.standby = "0"

        self.sg_helper.query_by_vpath = MagicMock(side_effect = [mock_service, mock_service_cs1])
        self.sg_helper.nodes = ["n1"]

        mock_cb_api = MagicMock()
        cluster = Mock()
        cluster_vpath = cluster.get_vpath.return_value = "/deployments/test/clusters/cluster1"
        self.sg_helper._clustered_service_set_depends = MagicMock()

        with patch.object(self.sg_helper.vcs_api, "hagrp_link") as mock:
            self.sg_helper.install_callback(mock_cb_api, "service_path",
                                            "test_cluster_id", cluster_vpath)

        calls = [call("Grp_CS_test_cluster_id_test_cs", "Grp_CS_test_cluster_id_cs1", "online", "local", "soft")]
        self.assertEqual(1, mock.call_count)
        mock.assert_has_calls(calls)

    def test_get_sg_from_item_id(self):
        callback_api = Mock()
        service = Mock(item_id = 'test_cs')
        service.get_vpath.return_value = "/deployments/test/clusters/cluster1/services/test_cs"
        dep = 'cs3'
        self.sg_helper.query_by_vpath = Mock(return_value = 'return')
        dep_service = self.sg_helper._get_sg_from_item_id(callback_api, service, dep)

        self.assertEqual(dep_service, 'return')
        self.assertEqual(self.sg_helper.query_by_vpath.call_args_list, [
            call(callback_api, '/deployments/test/clusters/cluster1/services/cs3'),
            ])

    def test_get_sg_from_item_id_2(self):
        callback_api = Mock()
        service = Mock(item_id = 'test_cs')
        service.get_vpath.return_value = "/deployments/test_cs/clusters/cluster1/services/test_cs"
        dep = 'cs3'
        self.sg_helper.query_by_vpath = Mock(return_value = 'return')
        dep_service = self.sg_helper._get_sg_from_item_id(callback_api, service, dep)

        self.assertEqual(dep_service, 'return')
        self.assertEqual(self.sg_helper.query_by_vpath.call_args_list, [
            call(callback_api, '/deployments/test_cs/clusters/cluster1/services/cs3'),
            ])

    @patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def test_clustered_service_set_depends_hagrp_link_with_local(self, mock_os_reinstall):
        callback_api = Mock()
        service1 = Mock(dependency_list="service2,service3", standby="0", node_list="n1")
        service1.is_initial.return_value = False
        service1.is_for_removal.return_value = False
        service1.applied_properties = {'standby': "0", "node_list": "n1"}
        service2 = Mock(dependency_list=None, node_list="n1")
        service2.is_initial.return_value = False
        service2.is_for_removal.return_value = False
        service2.applied_properties = {'standby': "0", "node_list": "n1"}
        service4 = Mock(dependency_list="service2,service3", standby="0", node_list="n1")
        service4.is_initial.return_value = True
        service4.is_for_removal.return_value = False
        service4.applied_properties = {'standby': "0", "node_list": "n1"}

        cluster_item_id = Mock()
        cluster = Mock(services=[service1, service2, service4])

        service_name = "service3"
        service = Mock(item_id="service3", standby="0", node_list="n1")
        service.applied_properties = {'standby': "0", "node_list": "n1"}

        self.sg_helper.query_by_vpath = Mock(return_value=cluster)
        self.sg_helper.get_group_name = Mock(side_effect=["group_name1",
                                                          "group_name2"])

        vcs_api = MagicMock()
        self.sg_helper._vcs_api = vcs_api
        self.sg_helper.nodes = ["n1", "n2"]
        mock_os_reinstall.return_value = False

        self.sg_helper._clustered_service_set_depends(
            callback_api, service, cluster_item_id)

        self.sg_helper.vcs_api.hagrp_link.assert_called_once_with(
            "group_name2", "group_name1", "online", "local", "soft")
        self.assertEqual(self.sg_helper.get_group_name.call_count, 2)
        self.assertEqual(service4.is_initial.call_count, 1)

    @patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def test_clustered_service_set_depends_hagrp_link_with_global(self, mock_os_reinstall):
        callback_api = Mock()
        service1 = Mock(dependency_list="service2,service3", standby=1, node_list="n1")
        service1.is_initial.return_value = False
        service1.is_for_removal.return_value = False
        service1.applied_properties = {'standby': 1, "node_list": "n1"}
        service2 = Mock(dependency_list=None, node_list="n1")
        service2.is_initial.return_value = False
        service2.is_for_removal.return_value = False
        service2.applied_properties = {'standby': 1, "node_list": "n1"}

        cluster_item_id = Mock()
        cluster = Mock(services=[service1, service2])

        service_name = "service3"
        service = Mock(item_id="service3", standby=0, node_list="n1")
        service.applied_properties = {'standby': 0, "node_list": "n1"}

        self.sg_helper.query_by_vpath = Mock(return_value=cluster)
        self.sg_helper.get_group_name = Mock(side_effect=["group_name1",
                                                          "group_name2"])

        vcs_api = MagicMock()
        self.sg_helper._vcs_api = vcs_api
        self.sg_helper.nodes = ["n1", "n2"]

        mock_os_reinstall.return_value = False

        self.sg_helper._clustered_service_set_depends(
            callback_api, service, cluster_item_id)
        self.sg_helper.vcs_api.hagrp_link.assert_called_once_with(
            "group_name2", "group_name1", "online", "global", "soft")
        print self.sg_helper.get_group_name.call_count
        self.assertEqual(self.sg_helper.get_group_name.call_count, 2)

    @patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def test_clustered_service_set_depends_srv_for_deactivation(self, mock_os_reinstall):
        service1 = Mock(item_id='CS1', dependency_list='CS4',
                        is_initial=lambda: False,
                        is_for_removal=lambda: False)
        service2 = Mock(deactivates='CS1', dependency_list='CS4',
                        is_initial=lambda: True,
                        is_for_removal=lambda: False)
        service3 = Mock(item_id='CS3', dependency_list='CS4',
                        is_initial=lambda: False,
                        is_for_removal=lambda: False,
                        is_updated=lambda: False,
                        node_list='n1', applied_properties={'node_list':'n1'})
        service4 = Mock(item_id='CS4')
        cluster = Mock(item_id='c1',
                       services=[service1, service2, service3, service4])
        self.sg_helper.query_by_vpath = Mock(return_value=cluster)

        vcs_api = MagicMock()
        self.sg_helper._vcs_api = vcs_api
        self.sg_helper.nodes = ["n1", "n2"]
        mock_os_reinstall.return_value = False

        api = Mock()
        cluster_vpath = Mock()
        self.sg_helper._clustered_service_set_depends(api, service4, cluster_vpath)
        self.sg_helper.vcs_api.hagrp_link.assert_called_once_with(
            "Grp_CS_c1_CS3", "Grp_CS_c1_CS4", "online", "global", "soft")

    def test_validate_deletion_dependency(self):
        service1 = Mock()
        service1.item_id = "CS1"
        service1.get_vpath = Mock(return_value="path_service1")
        service1.dependency_list = "CS2"
        service1.is_for_removal = Mock(return_value=False)
        service2 = Mock()
        service2.item_id = "CS2"
        service2.get_vpath = Mock(return_value="path_service2")
        service2.dependency_list = ""
        service2.is_for_removal = Mock(return_value=True)
        cluster = Mock()
        cluster.services = [service1, service2]
        errors = self.sg_helper._validate_deletion_dependency(cluster)
        self.assertEqual(1, len(errors))
        expected = {'message': ERROR_DELETION_DEPENDENCY.format("CS2"),
                    'uri': 'path_service1',
                    'error': 'ValidationError'}
        self.assertEqual(expected, errors[0].to_dict())

    def test_validate_deletion_dependency_ok(self):
        service1 = Mock()
        service1.item_id = "CS1"
        service1.get_vpath = Mock(return_value="path_service1")
        service1.dependency_list = "CS2"
        service1.is_for_removal = Mock(return_value=True)
        service2 = Mock()
        service2.item_id = "CS2"
        service2.get_vpath = Mock(return_value="path_service2")
        service2.dependency_list = "CS3"
        service2.is_for_removal = Mock(return_value=True)
        service3 = Mock()
        service3.item_id = "CS3"
        service3.get_vpath = Mock(return_value="path_service3")
        service3.dependency_list = ""
        service3.is_for_removal = Mock(return_value=False)
        cluster = Mock()
        cluster.services = [service1, service2, service3]
        errors = self.sg_helper._validate_deletion_dependency(cluster)
        self.assertEqual(0, len(errors))

    @patch("vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes")
    def test_delete_callback(self, mock_os_reinstall):
        node = Mock(hostname="n1")
        service = Mock(nodes=[node], offline_timeout=123)
        mock_os_reinstall.return_value = False
        self.sg_helper.query_by_vpath = Mock(return_value=service)
        self.sg_helper.get_group_name = Mock(return_value="service")
        self.sg_helper._get_ordered_hostnames = Mock(return_value=["n1", "n2"])

        vcs_api = MagicMock()
        vcs_api.readable_conf = MagicMock()
        self.sg_helper._vcs_api = vcs_api

        callback_api = Mock()
        service_vpath = Mock()
        cluster_item_id = Mock()
        self.sg_helper.delete_callback(callback_api, service_vpath,
            cluster_item_id)
        vcs_api.hagrp_offline.assert_called_once_with("service")
        vcs_api.check_hagrp_isoffline.assert_called_once_with(
            callback_api, "service", service.offline_timeout * 3,
            expect_faulted=True)
        vcs_api.hagrp_unlink_all.assert_called_once_with("service")
        vcs_api.hagrp_remove.assert_called_once_with("service")

    def test_get_service_dependencies(self):
        service = Mock(dependency_list="cs2,cs3")
        service.is_updated.return_value = True
        service.applied_properties = {"dependency_list": "cs2"}

        service_deps = self.sg_helper._get_service_dependencies(service)
        self.assertEqual(service_deps, "cs3")

        service = Mock(dependency_list="cs2,cs3")
        service.is_updated.return_value = True
        service.applied_properties = {"dependency_list": ""}

        service_deps = self.sg_helper._get_service_dependencies(service)
        self.assertEqual(service_deps, "cs2,cs3")

        service = Mock(dependency_list="cs2,cs3")
        service.is_updated.return_value = False

        service_deps = self.sg_helper._get_service_dependencies(service)
        self.assertEqual(service_deps, "cs2,cs3")

    @patch("vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes")
    @patch("vcsplugin.vcs_sg_helper.log")
    def test_update_dependencies_callback(self, patched_log,
                                          mock_os_reinstall):
        node = Mock(hostname="n1")
        service = Mock(nodes=[node], offline_timeout=123)
        mock_os_reinstall.return_value = False
        self.sg_helper.query_by_vpath = Mock(return_value=service)
        service_group_name = "service_group_name"

        vcs_api = MagicMock()
        vcs_api.readable_conf = MagicMock()
        self.sg_helper._vcs_api = vcs_api

        self.sg_helper._clustered_service_set_dependencies = Mock()

        callback_api = Mock()
        cluster_item_id = Mock()
        service_vpath = Mock()
        self.sg_helper.update_dependencies_callback(callback_api,
            service_vpath, cluster_item_id, service_group_name)

        self.sg_helper._clustered_service_set_dependencies.\
            assert_called_once_with(callback_api, service,
                                    "service_group_name", cluster_item_id)
        vcs_api.readable_conf.assert_called_once_with()
        self.assertEqual(patched_log.event.info.call_args_list, [
            call('Updating VCS service group dependencies on service "service_group_name"'),
        ])

    @patch("vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes")
    @patch("vcsplugin.vcs_sg_helper.log")
    def test_update_remove_dependencies_callback(self, patched_log,
                                                 mock_os_reinstall):
        node = Mock(hostname="n1")
        service = Mock(
            nodes=[node],
            offline_timeout=123,
            dependency_list='cs2'
        )
        mock_os_reinstall.return_value = False
        service.applied_properties = {"dependency_list": "cs1,cs2"}
        self.sg_helper.query_by_vpath = Mock(return_value=service)
        service_group_name = "service_group_name"

        vcs_api = MagicMock()
        vcs_api.readable_conf = MagicMock()
        self.sg_helper._vcs_api = vcs_api

        self.sg_helper._clustered_service_remove_dependencies = Mock()

        callback_api = Mock()
        cluster_item_id = Mock()
        service_vpath = Mock()
        self.sg_helper.update_remove_dependencies_callback(callback_api,
            service_vpath, cluster_item_id, service_group_name)

        self.sg_helper._clustered_service_remove_dependencies.\
            assert_called_once_with(
                service, "service_group_name", cluster_item_id)
        vcs_api.readable_conf.assert_called_once_with()
        self.assertEqual(patched_log.event.info.call_args_list, [
            call('Updating VCS service group dependencies on service "service_group_name" to remove dependencies'),
        ])

    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_initial_dependency_list_updated")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._generate_update_dependencies_task")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_dependency_list_updated_remove")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_dependency_list_updated_add")
    @patch("vcsplugin.vcs_sg_helper.is_clustered_service_expansion")
    @patch('vcsplugin.vcs_sg_helper.is_being_deactivated')
    @patch("vcsplugin.vcs_sg_helper.is_clustered_service_redeploy_required")
    def test_create_configuration_dependency_list_updated(self, patch_redeploy, is_being_deact,
                            patch_service_exp,patch_dep_list_add,
                            patch_dep_list_remove, patch_gen_update, patch_update_deps):

        patch_redeploy.return_value = False
        patch_service_exp.return_value = False
        patch_dep_list_add.return_value = True
        patch_dep_list_remove.return_value = False
        patch_update_deps.return_value = False
        is_being_deact.return_value = False
        update_task = Mock()
        patch_gen_update.return_value = update_task

        plugin_api_context = Mock()
        cluster = Mock(item_id="cluster1")
        service = Mock(deactivates=None,
                       is_initial=lambda: False,
                       is_for_removal=lambda: False)

        pre_node_tasks, post_node_tasks = self.sg_helper.create_configuration(
            plugin_api_context, cluster, service)

        self.assertEqual(pre_node_tasks, [])
        self.assertEqual(post_node_tasks, [update_task])
        patch_gen_update.assert_called_once_with(service, "cluster1")

    def test_get_dep_list_and_app_dep_list(self):
        service = Mock(dependency_list="cs1,cs2", applied_properties={})
        service.applied_properties['dependency_list'] = "cs2"
        dep_list, app_dep_list =\
            self.sg_helper._get_dep_list_and_app_dep_list(service)
        self.assertEqual(dep_list, ['cs1', 'cs2'])
        self.assertEqual(app_dep_list, ['cs2'])

    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._get_dep_list_and_app_dep_list")
    def test__clustered_service_dependency_list_additions(self, get_lists):
        get_lists.return_value = (['cs1', 'cs2'], ['cs1'])
        service = Mock()
        dep_list_additions =\
            self.sg_helper._clustered_service_dependency_list_additions(service)
        self.assertEqual(dep_list_additions, ['cs2'])

    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._get_dep_list_and_app_dep_list")
    def test__clustered_service_dependency_list_removals(self, get_lists):
        get_lists.return_value = (['cs1'], ['cs1', 'cs2', 'cs3'])
        service = Mock()
        dep_list_additions =\
            self.sg_helper._clustered_service_dependency_list_removals(service)
        self.assertEqual(dep_list_additions, ['cs2', 'cs3'])

    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_initial_dependency_list_updated")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_dependency_list_updated_remove")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_dependency_list_updated_add")
    @patch("vcsplugin.vcs_sg_helper.is_clustered_service_expansion")
    @patch("vcsplugin.vcs_sg_helper.is_clustered_service_redeploy_required")
    @patch("vcsplugin.vcs_sg_helper.is_being_deactivated")
    @patch("vcsplugin.vcs_base_helper.VcsBaseHelper.added_node_hostnames")
    def test_create_configuration_updated(self, patch_added_node_ids, is_being_deact,
                                patch_redeploy, patch_service_exp,
                                patch_dep_list_add, patch_dep_list_remove, initial_deps_updated):
        patch_added_node_ids.return_value = ['node2']
        patch_redeploy.return_value = False
        patch_service_exp.return_value = True
        patch_dep_list_add.return_value = False
        patch_dep_list_remove.return_value = False
        initial_deps_updated.return_value = False
        is_being_deact.return_value = False

        plugin_api_context = Mock()
        cluster = Mock(item_id="cluster1")
        service = Mock(item_id='serv1', deactivates=None)
        service.is_initial.return_value = False
        service.is_for_removal.return_value = False

        self.sg_helper.plugin = DummyPluginForTest

        pre_node_tasks, post_node_tasks = self.sg_helper.create_configuration(
            plugin_api_context, cluster, service)

        self.assertEqual([], pre_node_tasks)
        self.assertEqual(1, len(post_node_tasks))
        self.assertEqual(('Update VCS service group "Grp_CS_cluster1_serv1" '
                          'to add node(s) "node2"'),
                         post_node_tasks[0].description)

    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_initial_dependency_list_updated")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_dependency_list_updated_remove")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_dependency_list_updated_add")
    @patch("vcsplugin.vcs_sg_helper.is_clustered_service_expansion")
    @patch('vcsplugin.vcs_sg_helper.is_being_deactivated')
    @patch("vcsplugin.vcs_sg_helper.is_clustered_service_redeploy_required")
    def test_create_configuration_reconfigure(self, patch_redeploy, is_being_deactivated,
                                    patch_srv_increase, patch_dep_list_add,
                                    patch_dep_list_remove, patch_update_deps):
        patch_redeploy.return_value = True
        patch_dep_list_add.return_value = False
        patch_dep_list_remove.return_value = False
        patch_update_deps.return_value = False
        is_being_deactivated.return_value = False

        plugin_api_context = Mock()
        cluster = Mock(item_id="cluster1")
        service = Mock(item_id='serv1',
                       deactivates=None,
                       is_initial=lambda: False,
                       is_for_removal=lambda: False,
                       node_list="n1")
        service.standby = 1
        service.applied_properties = {'standby': 1, "node_list": "n1"}

        self.sg_helper.plugin = DummyPluginForTest
        vip1 = MockVip(ipaddress='192.168.1.1', network_name='mngt1')
        vip2 = MockVip(ipaddress='192.168.1.2', network_name='mngt2')
        service.ipaddresses = [vip1, vip2]
        service.query.return_value=[vip1, vip2]

        pre_node_tasks, post_node_tasks = self.sg_helper.create_configuration(
            plugin_api_context, cluster, service)

        self.assertEqual([], pre_node_tasks)
        self.assertEqual(2, len(post_node_tasks))
        self.assertEqual('Remove VCS service group "Grp_CS_cluster1_serv1"',
                         post_node_tasks[0].description)
        self.assertEqual('Restore VCS service group "Grp_CS_cluster1_serv1"',
                         post_node_tasks[1].description)

    @patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    @patch("vcsplugin.vcs_sg_helper.is_clustered_service_contraction")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_dependency_list_updated_remove")
    def test_delete_configuration_remove(self, patch_updated_remove,
                                         patch_decrease, mock_os_reinstall):
        patch_updated_remove.return_value = False
        patch_decrease.return_value = False
        mock_os_reinstall.return_value = False

        plugin_api_context = Mock()
        cluster = Mock(item_id="cluster1")
        cluster.is_for_removal.return_value = False
        service = Mock(item_id="serv1", node_list="n1")
        service.is_for_removal.return_value = True
        service.standby = 1
        service.applied_properties = {"standby": 1, "node_list": "n1"}

        self.sg_helper.plugin = DummyPluginForTest

        node_tasks = self.sg_helper.delete_configuration(
            plugin_api_context, cluster, service)

        self.assertEqual(1, len(node_tasks))
        self.assertEqual('Remove VCS service group "Grp_CS_cluster1_serv1"',
                        node_tasks[0].description)
        cluster.is_for_removal.return_value = True
        node_tasks = self.sg_helper.delete_configuration(
            plugin_api_context, cluster, service)
        self.assertEqual(0, len(node_tasks))

    @patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    @patch("vcsplugin.vcs_sg_helper.is_clustered_service_contraction")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_dependency_list_updated_remove")
    def test_delete_configuration_remove_dependencies(self,
                                                      patch_updated_remove,
                                                      patch_decrease, mock_os_reinstall):
        patch_updated_remove.return_value = True
        patch_decrease.return_value = False
        mock_os_reinstall.return_value = False

        plugin_api_context = Mock()
        cluster = Mock(item_id="cluster1")
        service = Mock(item_id="serv1")
        service.node_list = ""
        service.applied_properties = {"node_list": ""}
        service.is_for_removal.return_value = False
        service.standby = 1
        service.applied_properties = {"standby": 1}

        self.sg_helper.plugin = DummyPluginForTest

        node_tasks = self.sg_helper.delete_configuration(
            plugin_api_context, cluster, service)

        self.assertEqual(1, len(node_tasks))
        self.assertEqual(('Update VCS service group "Grp_CS_cluster1_serv1" '
                          'to remove dependencies'),
                         node_tasks[0].description)

    @patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    @patch("vcsplugin.vcs_base_helper.VcsBaseHelper.removed_node_hostnames")
    @patch("vcsplugin.vcs_sg_helper.is_clustered_service_contraction")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_dependency_list_updated_remove")
    def test_delete_configuration_contraction(self, patch_updated_remove,
                                    patch_decrease, patch_removed_nodes,
                                              mock_os_reinstall):
        patch_removed_nodes.return_value = ['node2']
        patch_updated_remove.return_value = False
        patch_decrease.return_value = True
        mock_os_reinstall.return_value = False

        plugin_api_context = Mock()
        cluster = Mock(item_id="cluster1")
        cluster.is_for_removal.return_value = False
        service = Mock(item_id="serv1", node_list="n1")
        service.is_for_removal.return_value = False
        service.standby = 1
        service.applied_properties = {"standby": 1, "node_list": "n1"}

        self.sg_helper.plugin = DummyPluginForTest

        node_tasks = self.sg_helper.delete_configuration(
            plugin_api_context, cluster, service)

        self.assertEqual(1, len(node_tasks))
        self.assertEqual(('Update VCS service group "Grp_CS_cluster1_serv1" '
                          'to remove node(s) "node2"'),
                         node_tasks[0].description)

    @patch('vcsplugin.vcs_sg_helper.same_list_different_order')
    @patch('vcsplugin.vcs_sg_helper.property_updated')
    def test_is_clustered_service_dependency_list_updated(self, prop_updated,
            same_list_different_order):
        prop_updated.return_value = True
        same_list_different_order.return_value = False
        service = Mock(is_updated=Mock(return_value=True))
        self.assertEqual(True,
                         self.sg_helper._is_clustered_service_dependency_list_updated(service))
        prop_updated.return_value = False
        self.assertEqual(False,
                         self.sg_helper._is_clustered_service_dependency_list_updated(service))
        prop_updated.return_value = True
        same_list_different_order.return_value = True
        self.assertEqual(False,
                         self.sg_helper._is_clustered_service_dependency_list_updated(service))

    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._clustered_service_dependency_list_additions")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_dependency_list_updated")
    def test_is_clustered_service_dependency_list_updated_add(self, patch_updated, patch_additions):
        patch_updated.return_value = False
        patch_additions.return_value = []
        service = Mock()
        self.assertEqual(False,
            self.sg_helper._is_clustered_service_dependency_list_updated_add(service))

        patch_updated.return_value = True
        patch_additions.return_value = []
        self.assertEqual(False,
            self.sg_helper._is_clustered_service_dependency_list_updated_add(service))

        patch_updated.return_value = True
        patch_additions.return_value = ['cs1']
        self.assertEqual(True,
            self.sg_helper._is_clustered_service_dependency_list_updated_add(service))

    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._clustered_service_dependency_list_removals")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_dependency_list_updated")
    def test_is_clustered_service_dependency_list_updated_remove(self, patch_updated, patch_removals):
        patch_updated.return_value = False
        patch_removals.return_value = []
        service = Mock()
        self.assertEqual(False,
            self.sg_helper._is_clustered_service_dependency_list_updated_remove(service))

        patch_updated.return_value = True
        patch_removals.return_value = []
        self.assertEqual(False,
            self.sg_helper._is_clustered_service_dependency_list_updated_remove(service))

        patch_updated.return_value = True
        patch_removals.return_value = ['cs1']
        self.assertEqual(True,
            self.sg_helper._is_clustered_service_dependency_list_updated_remove(service))

    @patch("vcsplugin.vcs_sg_helper.CallbackTask")
    def test_generate_update_dependencies_task(self, MockCallbackTask):
        service = Mock(item_id="cs1")
        service.get_vpath.return_value = '/service vpath'
        cluster_item_id = "cluster1"

        pluginClass = Mock()
        plugin = Mock()
        pluginClass.return_value = plugin
        plugin.callback_method = Mock()
        helper = VcsServiceGroupHelper(pluginClass)

        task = helper._generate_update_dependencies_task(service, cluster_item_id)
        self.assertNotEqual(task, [])

        MockCallbackTask.assert_called_once_with(
            service,
            'Update VCS service group "Grp_CS_cluster1_cs1" to add dependencies',
            plugin.callback_method,
            callback_func='update_dependencies_callback',
            callback_class='VcsServiceGroupHelper',
            service_vpath='/service vpath',
            cluster_item_id="cluster1",
            service_group_name="Grp_CS_cluster1_cs1"
        )


    @patch("vcsplugin.vcs_sg_helper.CallbackTask")
    def test_generate_contraction_task(self, MockCallbackTask):
        service = Mock(item_id="cs1",
                       get_vpath=lambda: "cs1_vpath",
                       node_list="n1,n2",
                       applied_properties={"node_list" : "n1,n2,n3"})
        service.name = "Grp_CS_c1_cs1"
        cluster = Mock()
        cluster.nodes = [Mock(hostname="node3", item_id="n3")]
        service.get_cluster.return_value = cluster
        cluster_item_id = "c1"

        plugin = Mock(callback_method = Mock())
        pluginClass = Mock()
        pluginClass.return_value = plugin
        helper = VcsServiceGroupHelper(pluginClass)

        task = helper._generate_contraction_task(service, cluster_item_id)
        self.assertNotEqual(task, [])

        MockCallbackTask.assert_called_once_with(
            service,
            'Update VCS service group "{0}" to remove node(s) "{1}"'.format(
                service.name, "node3"),
            plugin.callback_method,
            callback_class='VcsServiceGroupHelper',
            callback_func="contraction_callback",
            service_vpath=service.get_vpath(),
            cluster_item_id="c1",
            tag_name='DEPLOYMENT_PRE_NODE_CLUSTER_TAG'
        )

    @patch("vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes")
    def test_contraction_callback(self, mock_os_reinstall):
        vcs_api = MagicMock()
        vcs_api.readable_conf = MagicMock()
        self.sg_helper._vcs_api = vcs_api

        node1 = Mock(item_id="n1", hostname="node1")
        node2 = Mock(item_id="n2", hostname="node2")
        cluster = Mock(nodes=[node1, node2])
        service = Mock(nodes=[node1], node_list="n1",
                       applied_properties={"node_list" : "n1,n2"},
                       offline_timeout=10, item_id="cs1",
                       get_cluster=lambda: cluster)
        mock_os_reinstall.return_value = False
        self.sg_helper.query_by_vpath = Mock(return_value=service)

        callback_api = Mock()
        service_vpath = Mock()
        cluster_item_id = "c1"
        self.sg_helper.contraction_callback(callback_api, service_vpath,
                                            cluster_item_id)
        vcs_api.hagrp_offline.assert_called_once_with("Grp_CS_c1_cs1", "node2", forced=True)
        vcs_api.check_hagrp_isoffline.assert_called_once_with(
            callback_api, "Grp_CS_c1_cs1",
            service.offline_timeout * 2, "node2", expect_faulted=True)
        vcs_api.hagrp_delete_in_system_list.assert_called_once_with(
            "Grp_CS_c1_cs1", "node2")

    def test_create_config_service_for_removal(self):
        api = Mock()
        cluster = Mock()
        service = Mock(is_initial=lambda: False,
                       is_updated=lambda: False,
                       is_for_removal=lambda: True)

        self.sg_helper.plugin = DummyPluginForTest

        pre_node_tasks, post_node_tasks = self.sg_helper.create_configuration(
                                                         api, cluster, service)
        self.assertEqual([], pre_node_tasks)
        self.assertEqual([], post_node_tasks)

    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_initial_dependency_list_updated")
    @patch("vcsplugin.vcs_sg_helper.is_clustered_service_redeploy_required")
    @patch("vcsplugin.vcs_sg_helper.is_clustered_service_expansion")
    @patch('vcsplugin.vcs_sg_helper.is_being_deactivated')
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_dependency_list_updated_add")
    def test_create_config_apd_false(self, patch_dep_list_add, is_being_deact, patch_srv_expan,
                                           patch_redeploy_reqd, patch_init_deps):
        patch_dep_list_add.return_value = False
        patch_srv_expan.return_value = False
        patch_redeploy_reqd.return_value = False
        patch_init_deps.return_value = False
        is_being_deact.return_value = False
        api = Mock()
        node1 = Mock(item_id="n1", hostname="node1")
        node2 = Mock(item_id="n2", hostname="node2")
        cluster = Mock(item_id='cluster1')
        service = Mock(item_id='serv1',
                       deactivates=None,
                       is_initial=lambda: False,
                       is_for_removal=lambda: False,
                       applied_properties_determinable=False,
                       nodes=[node1, node2],
                       node_list="n1,n2")

        self.sg_helper.plugin = DummyPluginForTest

        vip1 = MockVip(ipaddress='192.168.1.1', network_name='mngt1')
        vip2 = MockVip(ipaddress='192.168.1.2', network_name='mngt2')
        service.ipaddresses = [vip1, vip2]
        service.query.return_value=[vip1, vip2]
        service.standby = 1
        service.applied_properties = {'standby': 1}
        pre_node_tasks, post_node_tasks = self.sg_helper.create_configuration(
                                                         api, cluster, service)
        self.assertEqual(0, len(pre_node_tasks))
        self.assertEqual(1, len(post_node_tasks))

    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_initial_dependency_list_updated")
    @patch("vcsplugin.vcs_sg_helper.is_clustered_service_redeploy_required")
    @patch("vcsplugin.vcs_sg_helper.does_service_need_to_be_migrated")
    @patch('vcsplugin.vcs_sg_helper.is_being_deactivated')
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_dependency_list_updated_add")
    def test_create_config_fo_to_parallel_apd_false(self, patch_dep_list_add, is_being_deact, patch_migrate_reqd,
                                                          patch_redeploy_reqd, patch_init_deps):
        patch_dep_list_add.return_value = False
        patch_migrate_reqd.return_value = True
        patch_redeploy_reqd.return_value = True
        patch_init_deps.return_value = False
        is_being_deact.return_value = False
        api = Mock()
        cluster = Mock(item_id='cluster1')
        service = Mock(item_id='serv1',
                       deactivates=None,
                       is_initial=lambda: False,
                       is_for_removal=lambda: False,
                       applied_properties_determinable=False)

        self.sg_helper.plugin = DummyPluginForTest
        vip1 = MockVip(ipaddress='192.168.1.1', network_name='mngt1')
        vip2 = MockVip(ipaddress='192.168.1.2', network_name='mngt2')
        service.ipaddresses = [vip1, vip2]
        service.query.return_value=[vip1, vip2]
        service.standby = 1
        service.applied_properties = {'standby': 1}

        pre_node_tasks, post_node_tasks = self.sg_helper.create_configuration(
                                                         api, cluster, service)
        self.assertEqual(1, len(pre_node_tasks))
        self.assertEqual(1, len(post_node_tasks))
        self.assertEqual('Remove VCS service group "Grp_CS_cluster1_serv1"',
                         pre_node_tasks[0].description)
        self.assertEqual('Restore VCS service group "Grp_CS_cluster1_serv1"',
                         post_node_tasks[0].description)

    @patch("vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes")
    @patch("vcsplugin.vcs_base_helper.is_clustered_service_redeploy_required")
    def test_update_callback(self, patch_redeploy_reqd, mock_os_reinstall):
        patch_redeploy_reqd.return_value = False

        vcs_api = MagicMock()
        vcs_api.readable_conf = MagicMock()
        mock_os_reinstall.return_value = False
        self.sg_helper._vcs_api = vcs_api

        node1 = Mock(item_id="n1", hostname="node1")
        node2 = Mock(item_id="n2", hostname="node2")
        service = Mock(nodes=[node1, node2], node_list="n1,n2",
                       applied_properties={"node_list" : "n1"},
                       item_id="cs1", standby="0",
                       is_updated=lambda: True)
        self.sg_helper.query_by_vpath = Mock(return_value=service)
        self.sg_helper.get_group_name = Mock(return_value="service")

        self.sg_helper.update_callback(Mock(), Mock(), "c1")

        vcs_api._clustered_service_set_syslist.assert_called_once_with(
                                              "service", ((0, "node2"),), True)
        vcs_api.hagrp_add_in_auto_start_list.assert_called_once_with(
                                              "service", "node2")

    @patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    @patch("vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._clustered_service_set_dependencies")
    def test_install_callback(self, patch_cs_set_dep, mock_os_reinstall,
                              is_os_reinstall):
        patch_cs_set_dep.return_value = None
        vcs_api = MagicMock()
        vcs_api.readable_conf = MagicMock()
        mock_os_reinstall.return_value = False
        is_os_reinstall.return_value = False
        self.sg_helper._vcs_api = vcs_api

        node1 = Mock(item_id="n1", hostname="node1")
        node2 = Mock(item_id="n2", hostname="node2")
        service = Mock(nodes=[node1, node2], node_list="n1,n2",
                       item_id="cs1", standby='1')

        self.sg_helper.query_by_vpath = Mock(return_value=service)
        self.sg_helper.get_group_name = Mock(return_value="service")

        callback_api = Mock()
        service_vpath = Mock()
        service.standby = 1
        service.applied_properties = {'standby': 1}
        cluster = Mock()
        cluster_vpath = cluster.get_vpath.return_value = 'cluster vpath'

        self.sg_helper.install_callback(callback_api, service_vpath, "c1", cluster_vpath)

        vcs_api._clustered_service_set_attributes.assert_called_once_with(
                                 "service", ((0, "node1"),(1, "node2")), False)
        vcs_api.hagrp_add_in_auto_start_list.assert_called_once_with(
                                  "service", "node1 node2")
        self.sg_helper._clustered_service_set_dependencies.assert_called_once_with(
                                  callback_api, service, "service", "c1")

    def test_update_model(self):
        service1 = Mock(deactivated='true')
        service2 = Mock(applied_properties = {})
        service3 = Mock(applied_properties = {'deactivated': 'false'})
        service4 = Mock(applied_properties = {'deactivated': 'true'},
                        get_vpath = lambda: 'serv4_vpath')

        api = Mock()
        api.query.return_value = [service1, service2, service3, service4]

        self.sg_helper.update_model(api)

        api.remove_item.assert_called_once_with('serv4_vpath')

    def test_get_service_for_deactivation(self):
        service1 = Mock(item_id='CS1', deactivates=None)
        service2 = Mock(item_id='CS1new', deactivates='CS1')
        cluster=Mock(services=[service1, service2])

        old_service = self.sg_helper._get_service_for_deactivation(cluster,
                                             service2, check_is_deployed=False)
        self.assertEqual(service1, old_service)

        service2.deactivates = 'CS3'
        old_service = self.sg_helper._get_service_for_deactivation(cluster,
                                             service2, check_is_deployed=False)
        self.assertEqual(None, old_service)

        service2 = Mock(item_id='CS1new', deactivates='CS1', is_applied=lambda: True)
        old_service = self.sg_helper._get_service_for_deactivation(cluster,
                                                                   service2)
        self.assertEqual(service1, old_service)

        service2.deactivates = 'CS3'
        old_service = self.sg_helper._get_service_for_deactivation(cluster,
                                                                   service2)
        self.assertEqual(None, old_service)

    def test_validate_deactivates_self(self):
        service1 = Mock(item_id='CS1', deactivates='CS1',
                        get_vpath=lambda: 'CS1_vpath')

        errors = self.sg_helper._validate_deactivates_self(service1)

        self.assertEqual(1, len(errors))
        expected = {'message': ERR_DEACTIVATES_SELF.format("CS1"),
                    'uri': 'CS1_vpath',
                    'error': 'ValidationError'}
        self.assertEqual(expected, errors[0].to_dict())

    def test_validate_deactivates_critical_service(self):
        cluster = Mock(critical_service='CS1',
                       get_vpath=lambda: 'cluster_vpath')
        service1 = Mock(item_id='CS2', deactivates='CS1')

        errors = self.sg_helper._validate_deactivates_critical_service(cluster,
                                                                      service1)

        self.assertEqual(1, len(errors))
        expected = {'message': ERR_DEACTIVATES_CRITICAL_SERVICE,
                    'uri': 'cluster_vpath',
                    'error': 'ValidationError'}
        self.assertEqual(expected, errors[0].to_dict())

    def test_validate_deactivation_node_overlap(self):
        service1 = Mock(item_id='CS1', deactivates=None, node_list='n1,n2')
        service2 = Mock(item_id='CS2', deactivates='CS1',
                        node_list='n1,n2,n3,n4',
                        get_vpath=lambda: 'CS2_vpath')
        cluster = Mock(services=[service1, service2])

        errors = self.sg_helper._validate_deactivation_node_overlap(cluster, service2)

        self.assertEqual(1, len(errors))
        expected = {'message': ERR_DEACTIVATES_NODE_OVERLAP.format("CS2", "CS1", "n1, n2"),
                    'uri': 'CS2_vpath',
                    'error': 'ValidationError'}
        self.assertEqual(expected, errors[0].to_dict())

        service2.node_list='n3,n4'
        errors = self.sg_helper._validate_deactivation_node_overlap(cluster, service2)
        self.assertEqual(0, len(errors))

    def test_validate_deactivation_dependency(self):
        service1 = Mock(item_id='CS1', deactivates=None,
                        dependency_list='', initial_online_dependency_list='')
        service2 = Mock(item_id='CS2', deactivates='CS1',
                        dependency_list='', initial_online_dependency_list='')
        service3 = Mock(item_id='CS3', deactivates=None,
                        dependency_list='CS1',
                        initial_online_dependency_list='',
                        get_vpath=lambda: 'CS3_vpath')
        service4 = Mock(item_id='CS4', deactivates=None,
                        dependency_list='',
                        initial_online_dependency_list='CS1',
                        get_vpath=lambda: 'CS4_vpath')
        cluster = Mock(services=[service1,service2,service3,service4])

        errors = self.sg_helper._validate_deactivation_dependency(cluster, service2)

        self.assertEqual(2, len(errors))
        expected = {'message': ERR_DEACTIVATES_DEPENDENCY.format("CS1", "CS2"),
                    'uri': 'CS3_vpath',
                    'error': 'ValidationError'}
        self.assertEqual(expected, errors[0].to_dict())
        expected = {'message': ERR_DEACTIVATES_INIT_ONLINE_DEPENDENCY.format("CS1", "CS2"),
                    'uri': 'CS4_vpath',
                    'error': 'ValidationError'}
        self.assertEqual(expected, errors[1].to_dict())

    def test_validate_deactivating_srv_not_initial(self):
        service2 = Mock(item_id='CS2', deactivates='CS1',
                        is_initial=lambda: True,
                        get_vpath=lambda: 'CS2_vpath')

        # service2 initial, no error
        errors = self.sg_helper._validate_deactivating_srv_not_initial(service2)
        self.assertEqual(0, len(errors))

        # service2 not initial, error
        service2.is_initial=lambda: False
        errors = self.sg_helper._validate_deactivating_srv_not_initial(service2)
        self.assertEqual(1, len(errors))
        expected = {'message': ERR_DEACTIVATES_NOT_INITIAL,
                    'uri': 'CS2_vpath',
                    'error': 'ValidationError'}
        self.assertEqual(expected, errors[0].to_dict())

        # service2 not initial, service for deactivation not in model, error
        service2.deactivates = 'CS0'
        errors = self.sg_helper._validate_deactivating_srv_not_initial(service2)
        self.assertEqual(1, len(errors))

    def test_validate_deactivates_before_completed(self):
        service1 = Mock(item_id='CS1',
                        deactivated='true',
                        applied_properties={'deactivated':'true'},
                        get_vpath=lambda: 'CS1_vpath')
        service2 = Mock(deactivates='CS1',
                        is_applied=lambda: True)
        cluster = Mock(services=[service1, service2])

        # happy path where service2 is applied
        errors = self.sg_helper._validate_update_deactivates_before_completed(cluster, service1)
        self.assertEqual(0, len(errors))

        # service2 is initial with apd false
        service2.is_applied=lambda: False
        service2.is_initial=lambda: True
        service2.applied_properties_determinable=False
        errors = self.sg_helper._validate_update_deactivates_before_completed(cluster, service1)
        self.assertEqual(0, len(errors))

        # service2 is initial with apd true
        service2.applied_properties_determinable=True
        errors = self.sg_helper._validate_update_deactivates_before_completed(cluster, service1)
        self.assertEqual(1, len(errors))
        expected = {'message': ERR_DEACTIVATES_UPDATE_INCOMPLETE,
                    'uri': 'CS1_vpath',
                    'error': 'ValidationError'}
        self.assertEqual(expected, errors[0].to_dict())

        # deactivates property has been updated
        service2.deactivates = 'CS3'
        errors = self.sg_helper._validate_update_deactivates_before_completed(cluster, service1)
        self.assertEqual(1, len(errors))
        self.assertEqual(expected, errors[0].to_dict())

        # deactivates property has been removed
        service2.deactivates = None
        errors = self.sg_helper._validate_update_deactivates_before_completed(cluster, service1)
        self.assertEqual(1, len(errors))
        self.assertEqual(expected, errors[0].to_dict())

    def test_validate_deactivated_set(self):
        service1 = Mock(deactivated='false')
        errors = self.sg_helper._validate_deactivated_set(service1)
        self.assertEqual(0, len(errors))

        service1 = Mock(deactivated='true',
                        applied_properties={'deactivated':'true'})
        errors = self.sg_helper._validate_deactivated_set(service1)
        self.assertEqual(0, len(errors))

        service1 = Mock(deactivated='true',
                        applied_properties={},
                        get_vpath=lambda: 'CS1_vpath')
        errors = self.sg_helper._validate_deactivated_set(service1)
        self.assertEqual(1, len(errors))
        expected = {'message': ERR_DEACTIVATED_INCORRECTLY_SET,
                    'uri': 'CS1_vpath',
                    'error': 'ValidationError'}
        self.assertEqual(expected, errors[0].to_dict())

    def test_validate_one_deactivation(self):
        service1 = Mock(item_id='CS1', deactivates=None,
                        is_for_removal=lambda: False)
        service2 = Mock(item_id='CS2', deactivates=None,
                        is_for_removal=lambda: False)
        service3 = Mock(item_id='CS3', deactivates='CS1',
                        get_vpath=lambda: 'CS3_vpath',
                        is_for_removal=lambda: False)
        service4 = Mock(item_id='CS4', deactivates='CS2',
                        get_vpath=lambda: 'CS4_vpath',
                        is_for_removal=lambda: False)
        cluster = Mock(services=[service1, service2, service3, service4])

        errors = self.sg_helper._validate_one_deactivation(cluster)

        self.assertEqual(2, len(errors))
        expected = {'message': ERR_MULTIPLE_DEACTIVATIONS,
                    'uri': 'CS3_vpath',
                    'error': 'ValidationError'}
        self.assertEqual(expected, errors[0].to_dict())
        expected['uri'] = 'CS4_vpath'
        self.assertEqual(expected, errors[1].to_dict())

    def test_validate_deactivates_applied_srv(self):
        service1 = Mock(item_id='CS1', deactivates=None, applied_properties={},
                        is_initial=lambda: False,
                        is_applied=lambda: True,
                        is_for_removal=lambda: False)
        service2 = Mock(item_id='CS2', deactivates='CS1',
                        get_vpath=lambda: 'CS2_vpath')
        cluster = Mock(services=[service1, service2])

        # service1 applied, no error
        errors = self.sg_helper._validate_deactivates_applied_srv(cluster, service2)
        self.assertEqual(0, len(errors))

        # service1 not applied, error
        service1.is_applied=lambda: False
        errors = self.sg_helper._validate_deactivates_applied_srv(cluster, service2)
        self.assertEqual(1, len(errors))
        expected = {'message': ERR_DEACTIVATES_NOT_APPLIED_SERVICE,
                    'uri': 'CS2_vpath',
                    'error': 'ValidationError'}
        self.assertEqual(expected, errors[0].to_dict())

        # service1 has deactivated set to 'true' in applied properties, no error
        service1.applied_properties = {'deactivated' : 'true'}
        errors = self.sg_helper._validate_deactivates_applied_srv(cluster, service2)
        self.assertEqual(0, len(errors))

    @patch("vcsplugin.vcs_sg_helper.CallbackTask")
    def test_generate_deactivate_task(self, MockCallbackTask):
        MockCallbackTask.return_value = Mock(model_items=set())
        service = Mock(item_id="CS1",
                       get_vpath=lambda: "CS1_vpath")
        cluster = Mock(item_id='c1', is_updated=lambda: False,
                       get_vpath=lambda: "C1_vpath")
        service.get_cluster.return_value = cluster
        service.name = 'Grp_CS_c1_CS1'

        plugin = Mock(callback_method = Mock())
        pluginClass = Mock()
        pluginClass.return_value = plugin
        helper = VcsServiceGroupHelper(pluginClass)

        task = helper._generate_deactivate_task(service, cluster)
        self.assertNotEqual(task, [])

        MockCallbackTask.assert_called_once_with(
            service,
            'Deactivate VCS service group "{0}"'.format(service.name),
            plugin.callback_method,
            callback_class='VcsServiceGroupHelper',
            callback_func="delete_callback",
            service_vpath=service.get_vpath(),
            cluster_vpath=cluster.get_vpath(),
            tag_name='DEPLOYMENT_CLUSTER_TAG'
        )

        self.assertEqual(task.model_items, set())

    @patch("vcsplugin.vcs_sg_helper.CallbackTask")
    def test_generate_deactivate_task_critical_service(self, MockCallbackTask):
        MockCallbackTask.return_value = Mock(model_items=set())
        service = Mock(item_id="CS1",
                       get_vpath=lambda: "CS1_vpath")
        cluster = Mock(item_id='c1', is_updated=lambda: True,
                       critical_service='CS2',
                       get_vpath=lambda: "C1_vpath",
                       applied_properties={'critical_service':'CS1'})
        service.get_cluster.return_value = cluster
        service.name = 'Grp_CS_c1_CS1'

        plugin = Mock(callback_method = Mock())
        pluginClass = Mock()
        pluginClass.return_value = plugin
        helper = VcsServiceGroupHelper(pluginClass)

        task = helper._generate_deactivate_task(service, cluster)
        self.assertNotEqual(task, [])

        MockCallbackTask.assert_called_once_with(
            service,
            'Deactivate VCS service group "{0}"'.format(service.name),
            plugin.callback_method,
            callback_class='VcsServiceGroupHelper',
            callback_func="delete_callback",
            service_vpath=service.get_vpath(),
            cluster_vpath=cluster.get_vpath(),
            tag_name='DEPLOYMENT_CLUSTER_TAG'
        )

        self.assertEqual(task.model_items, set([cluster]))

    @patch("vcsplugin.vcs_sg_helper.is_failover_standby_node_updated")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_initial_dependency_list_updated")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_dependency_list_updated_remove")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_dependency_list_updated_add")
    @patch("vcsplugin.vcs_sg_helper.is_clustered_service_expansion")
    @patch('vcsplugin.vcs_sg_helper.is_being_deactivated')
    @patch("vcsplugin.vcs_sg_helper.is_clustered_service_redeploy_required")
    def test_create_configuration_standby_updated(self, patch_redeploy, is_being_deact,
                            patch_service_exp,patch_dep_list_add,
                            patch_dep_list_remove,
                            patch_update_deps, patch_standby_updated):

        self.sg_helper.plugin = DummyPluginForTest
        patch_redeploy.return_value = False
        patch_service_exp.return_value = False
        patch_dep_list_add.return_value = False
        patch_dep_list_remove.return_value = False
        patch_update_deps.return_value = False
        is_being_deact.return_value = False

        plugin_api_context = Mock()
        n1 = Mock(item_id="n1")
        n2 = Mock(item_id="n2")
        n3 = Mock(item_id="n3")
        cluster = Mock(item_id="cluster1",
                       get_vpath=lambda: "c1_vpath",
                       nodes=[n1,n2,n3])
        service = Mock(deactivates=None,
                       get_vpath=lambda: "s1_vpath",
                       is_initial=lambda: False,
                       is_for_removal=lambda: False,
                       is_updated=lambda: True,
                       node_list="n1,n3",
                       applied_properties={"node_list": "n1,n2"})

        pre_node_tasks, post_node_tasks = self.sg_helper.create_configuration(
            plugin_api_context, cluster, service)

        self.assertEqual(pre_node_tasks, [])
        self.assertEqual(post_node_tasks[0].kwargs,
                         {'cluster_vpath': 'c1_vpath',
                          'service_vpath': 's1_vpath',
                          'callback_func': '_add_standby_node_cb',
                          'callback_class': 'VcsServiceGroupHelper'})


    @patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    @patch("vcsplugin.vcs_sg_helper.is_failover_standby_node_updated")
    @patch("vcsplugin.vcs_sg_helper.is_clustered_service_contraction")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._is_clustered_service_dependency_list_updated_remove")
    def test_delete_configuration_remove_standby(self, patch_updated_remove,
                                                 patch_decrease,
                                                 patch_standby_upd,
                                                 mock_os_reinstall):
        patch_updated_remove.return_value = False
        patch_decrease.return_value = False
        patch_standby_upd.return_value = True
        mock_os_reinstall.return_value = False

        plugin_api_context = Mock()
        n1 = Mock(item_id="n1", hostname="node1")
        n2 = Mock(item_id="n2", hostname="node2")
        n3 = Mock(item_id="n3", hostname="node3")
        cluster = Mock(item_id="cluster1",
                       get_vpath=lambda: "c1_vpath",
                       nodes=[n1,n2,n3])
        service = Mock(item_id="serv1", node_list="n1,n3",
                       get_vpath=lambda: "s1_vpath",
                       nodes=[n1,n3])
        service.is_for_removal.return_value = False
        service.standby = 1
        service.applied_properties = {"standby": 1, "node_list": "n1,n2"}

        self.sg_helper.plugin = DummyPluginForTest

        node_tasks = self.sg_helper.delete_configuration(
            plugin_api_context, cluster, service)

        self.assertEqual(1, len(node_tasks))
        self.assertEqual('Remove standby node "node2" from clustered service "Grp_CS_cluster1_serv1"',
                         node_tasks[0].description)
        self.assertEqual(node_tasks[0].kwargs,
                         {'cluster_vpath': 'c1_vpath',
                          'service_vpath': 's1_vpath',
                          'callback_func': '_remove_standby_node',
                          'callback_class': 'VcsServiceGroupHelper'})

    @patch("vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes")
    @patch("vcsplugin.vcs_sg_helper.VcsUtils.get_service_online_time")
    @patch("vcsplugin.vcs_sg_helper.VcsServiceGroupHelper.get_group_name")
    @patch("vcsplugin.vcs_sg_helper.select_nodes_from_service")
    @patch("vcsplugin.vcs_sg_helper.log")
    def test_remove_standby_node(self, patched_log, patched_select_nodes,
                                 patched_group_name,
                                 patched_online_time, mock_os_reinstall):
        node = Mock(hostname="n1")
        patched_select_nodes.return_value = [node]
        n1 = Mock(item_id="n1",
                  hostname="node1",
                  is_initial=lambda: False,
                  is_for_removal=lambda: False)
        n2 = Mock(item_id="n2",
                  hostname="node2",
                  is_initial=lambda: False,
                  is_for_removal=lambda: False)
        n3 = Mock(item_id="n3",
                  hostname="node3",
                  is_initial=lambda: True,
                  is_for_removal=lambda: False)
        cluster = Mock(item_id="c1",
                       nodes=[n1,n2,n3])
        service = Mock(item_id="s1",
                       active="1",
                       standby="1",
                       node_list="n1,n3",
                       applied_properties={"node_list": "n1,n2"},
                       is_updated=lambda: True,
                       nodes=[n1,n3],
                       offline_timeout="10")
        patched_group_name.return_value = "Group1"
        patched_online_time.return_value = 100
        mock_os_reinstall.return_value = False

        def query_mock(api, path):
            if path == "cvpath":
                return cluster
            if path == "svpath":
                return service
            return None
        self.sg_helper.query_by_vpath = Mock(side_effect=query_mock)
        vcs_api = MagicMock()
        vcs_api.readable_conf = MagicMock()
        vcs_api.get_group_state_on_nodes = Mock(
            return_value="node1:|ONLINE|,node2:|OFFLINE|")
        self.sg_helper._vcs_api = vcs_api
        callback_api = Mock()

        self.sg_helper._remove_standby_node(callback_api, "svpath", "cvpath")

        vcs_api.remove_standby_node.\
            assert_called_once_with(
                "Group1", "node2", "node3")

    @patch("vcsplugin.vcs_sg_helper.VcsUtils.get_service_online_time")
    @patch("vcsplugin.vcs_sg_helper.VcsRPC")
    @patch("vcsplugin.vcs_sg_helper.vip_upd_standby_node")
    @patch("vcsplugin.vcs_sg_helper.select_nodes_from_service")
    def test_add_standby_node(self, patched_select_nodes,
                              patched_vip_upd, patched_rpc,
                              patched_online_time):
        node = Mock(hostname="n1")
        patched_select_nodes.return_value = [node]
        patched_online_time.return_value = 100
        n1 = Mock(item_id="n1",
                  is_initial=lambda: False,
                  is_for_removal=lambda: False)
        n2 = Mock(item_id="n2",
                  hostname="node2",
                  is_initial=lambda: False,
                  is_for_removal=lambda: False)
        n3 = Mock(item_id="n3",
                  hostname="node3",
                  is_initial=lambda: True,
                  is_for_removal=lambda: False)
        cluster = Mock(item_id="c1",
                       nodes=[n1,n2,n3])
        service = Mock(item_id="s1",
                       active="1",
                       standby="1",
                       node_list="n1,n3",
                       applied_properties={"node_list": "n1,n2"},
                       is_updated=lambda: True,
                       nodes=[n1,n3])
        def query_mock(api, path):
            if path == "cvpath":
                return cluster
            if path == "svpath":
                return service
            return None
        self.sg_helper.query_by_vpath = Mock(side_effect=query_mock)
        vcs_api = MagicMock()
        vcs_api.readable_conf = MagicMock()
        vcs_api.get_group_state_on_nodes = Mock(
            return_value="node1:|ONLINE|,node3:|OFFLINE|")
        patched_rpc.return_value = Mock(
            check_ok_to_online=lambda x, y: (0, "", ""))
        self.sg_helper._vcs_api = vcs_api
        callback_api = Mock()

        self.sg_helper._add_standby_node_cb(callback_api, "svpath", "cvpath")

        vcs_api.add_standby_node.assert_called_once_with("Grp_CS_c1_s1",
                                                         "node3")

