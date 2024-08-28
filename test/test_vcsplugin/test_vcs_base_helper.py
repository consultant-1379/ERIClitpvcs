##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from vcsplugin.vcs_base_helper import (VcsBaseHelper,
                                       condense_name,
                                       is_clustered_service_redeploy_required,
                                       is_clustered_service_node_count_updated,
                                       is_clustered_service_node_count_increased,
                                       is_clustered_service_node_count_decreased,
                                       does_service_need_to_be_migrated,
                                       get_updated_properties,
                                       is_serv_grp_allowed_multi_apps,
                                       same_list_different_order,
                                       get_applied_nodes_in_cluster,
                                       is_being_deactivated,
                                       is_node_intersection,
                                       is_deactivating,
                                       added_nodes_item_ids,
                                       removed_nodes_item_ids,
                                       is_failover_standby_node_updated)
import unittest
import mock
from mock import Mock
from mocks import mock_model_item


class DummyQueryItem(object):
    pass


class TestVcsBaseHelper(unittest.TestCase):

    def test_get_group_name(self):
        service_item_id = 'httpd'
        cluster_item_id = '1234'

        expected_group_name = 'Grp_CS_1234_httpd'
        group_name = VcsBaseHelper(None).get_group_name(
            service_item_id, cluster_item_id)

        self.assertEqual(group_name, expected_group_name)

    def test_get_vx_fencing_disk_group_name(self):
        fencing_disks = [DummyQueryItem, DummyQueryItem, DummyQueryItem]
        cluster_id = '1'

        fencing_disk_group_name = VcsBaseHelper(None).get_vx_fencing_disk_group_name(
                fencing_disks, cluster_id)

        self.assertEqual(fencing_disk_group_name, 'vxfencoorddg_1')

    def test_get_vx_fencing_disk_group_name_empty_list(self):
        fencing_disks = []
        cluster_id = '1'

        fencing_disk_group_name = VcsBaseHelper(None).get_vx_fencing_disk_group_name(
                fencing_disks, cluster_id)

        self.assertEqual(fencing_disk_group_name, None)

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def test_is_clustered_service_redeploy_required(self, mock_os_reinstall):
        helper = VcsBaseHelper(None)
        mock_os_reinstall.return_value = False
        cluster = mock.Mock()
        cluster.is_initial = mock.Mock(return_value=False)
        service = mock.Mock(standby='1', applied_properties= {'standby': '0'})
        service.is_for_removal = mock.Mock(return_value=False)
        service.get_cluster = mock.Mock(return_value=cluster)
        cluster.services = [service]
        self.assertEqual(True, is_clustered_service_redeploy_required(service))

    def test_does_service_need_to_be_migrated(self):
        service = mock.Mock(node_list = 'mn4,mn5',
                            applied_properties = {'node_list': 'mn1,mn2,mn3'})
        self.assertEqual(True, does_service_need_to_be_migrated(service))

    def test_does_service_not_need_to_be_migrated(self):
        service = mock.Mock(node_list = 'mn2,mn3',
                            applied_properties = {'node_list': 'mn1,mn2,mn3'})
        self.assertEqual(False, does_service_need_to_be_migrated(service))

    def test_node_intersection(self):
        service = mock.Mock(node_list = 'mn2,mn3',
                            active = '2',
                            standby = '0',
                            applied_properties = {'node_list': 'mn1,mn2'})
        self.assertEqual(True, is_node_intersection(service))

    def test_node_intersection_for_failover_service(self):
        service = mock.Mock(node_list = 'mn2,mn3',
                            active = '1',
                            standby = '1',
                            applied_properties = {'node_list': 'mn1,mn2'})
        self.assertEqual(True, is_node_intersection(service))

    def test_node_intersection_same_list_different_order(self):
        service = mock.Mock(node_list = 'mn2,mn3',
                            active = '2',
                            standby = '0',
                            applied_properties = {'node_list': 'mn3,mn2'})
        self.assertEqual(False, is_node_intersection(service))

    def test_no_node_intersection(self):
        service = mock.Mock(node_list = 'mn5,mn4',
                            active = '2',
                            standby = '0',
                            applied_properties = {'node_list': 'mn3,mn2'})
        self.assertEqual(False, is_node_intersection(service))

    @mock.patch('vcsplugin.vcs_base_helper.is_failover_to_parallel')
    @mock.patch('vcsplugin.vcs_base_helper.does_service_need_to_be_migrated')
    def test_is_clustered_service_redeploy_required_deactivation(self,
                                         patch_need_migrated, patch_fo_to_pl):
        patch_fo_to_pl.return_value = False
        patch_need_migrated.return_value =True

        helper = VcsBaseHelper(None)
        service1 = mock.Mock(item_id='CS1', deactivates=None,
                             is_for_removal=lambda: False)
        service2 = mock.Mock(item_id='CS2', deactivates='CS1',
                             is_for_removal=lambda: False)
        cluster = mock.Mock(services=[service1, service2])
        cluster.is_initial = mock.Mock(return_value=False)
        service1.get_cluster = mock.Mock(return_value=cluster)
        service2.get_cluster = mock.Mock(return_value=cluster)

        self.assertEqual(False, is_clustered_service_redeploy_required(service1))
        self.assertEqual(False, is_clustered_service_redeploy_required(service2))

    def test_is_being_deactivated(self):
        service1 = mock.Mock(deactivates=None, item_id='CS1')
        service2 = mock.Mock(deactivates='CS1', is_for_removal=lambda: False)
        cluster = mock.Mock(services=[service1, service2])
        self.assertEqual(True, is_being_deactivated(cluster, service1))

        service2.deactivates='CS9'
        self.assertEqual(False, is_being_deactivated(cluster, service1))

        service2 = mock.Mock(deactivates='CS1', is_for_removal=lambda: True)
        self.assertEqual(False, is_being_deactivated(cluster, service1))

    def test_is_deactiving(self):
        service1 = mock.Mock(item_id='CS1', is_for_removal=lambda: False)
        service2 = mock.Mock(deactivates='CS1')
        cluster = mock.Mock(services=[service1, service2])
        self.assertEqual(True, is_deactivating(cluster, service2))

        service2.deactivates='CS9'
        self.assertEqual(False, is_deactivating(cluster, service2))

    def test_get_updated_properties(self):
        item = mock.Mock()
        item.applied_properties = {'foo': 'bar'}
        item.foo = 'bar'
        result = get_updated_properties(('foo',), item)
        self.assertEqual([], result)
        item.foo = 'baz'
        result = get_updated_properties(('foo',), item)
        self.assertEqual(['foo'], result)

    @mock.patch('vcsplugin.vcs_base_helper.get_updated_properties')
    def test_is_clustered_service_node_count_updated(self, get_props):
        get_props.return_value = True
        service = mock.Mock(is_updated=mock.Mock(return_value=True))
        self.assertEqual(True,
                         is_clustered_service_node_count_updated(service))
        get_props.return_value = False
        self.assertEqual(False,
                         is_clustered_service_node_count_updated(service))

    def test_is_clustered_service_node_count_increased(self):
        service = mock.Mock(is_updated=mock.Mock(return_value=True),
                            node_list='n1,n2,n3',
                            applied_properties= {'node_list': 'n1,n2'})
        self.assertEqual(True,
                         is_clustered_service_node_count_increased(service))
        service.node_list='n1'
        self.assertEqual(False,
                         is_clustered_service_node_count_increased(service))

    def test_get_applied_nodes_in_cluster(self):
        cluster = mock_model_item("/cluster", "cluster", cluster_type="sfha",
                                  cluster_id="1234")
        node1 = mock_model_item("/node1", "node1", hostname="node1",
                                is_initial=lambda: False,
                                is_for_removal=lambda: False)
        node2 = mock_model_item("/node2", "node2", hostname="node2",
                                is_initial=lambda: False,
                                is_for_removal=lambda: False)
        node3 = mock_model_item("/node3", "node3", hostname="node3",
                                is_initial=lambda: False,
                                is_for_removal=lambda: True)
        node4 = mock_model_item("/node4", "node4", hostname="node4",
                                is_initial=lambda: True,
                                is_for_removal=lambda: False)
        cluster.nodes = [node1, node2, node3, node4]
        assert get_applied_nodes_in_cluster(cluster) == [node1, node2]

    def test_is_clustered_service_node_count_decreased(self):
        service = mock.Mock(is_updated=mock.Mock(return_value=True),
                            node_list='n1',
                            applied_properties={'node_list': 'n1,n2'})
        self.assertEqual(True,
                         is_clustered_service_node_count_decreased(service))
        service.node_list='n1,n2,n3'
        self.assertEqual(False,
                         is_clustered_service_node_count_decreased(service))

    def test_validate_node_list_contraction(self):
        # mn1,mn2,m3 -> mn1, mn2
        service = mock.Mock(is_updated=mock.Mock(return_value=True),
                            applied_properties= {'node_list': 'n1,n2,n3'})
        service.node_list = 'n1,n2'
        self.assertEqual(False, does_service_need_to_be_migrated(service))

    def test_validate_node_list_expansion(self):
        # mn1,mn2 -> mn1, mn2, mn3
        service = mock.Mock(is_updated=mock.Mock(return_value=True),
                            applied_properties= {'node_list': 'n1,n2'})
        service.node_list = 'n1,n2,n3'
        self.assertEqual(False, does_service_need_to_be_migrated(service))

    def test_validate_node_list_migration(self):
        # mn1,mn2 -> mn1, mn2, mn3
        service = mock.Mock(is_updated=mock.Mock(return_value=True),
                            applied_properties= {'node_list': 'n1,n2'})
        service.node_list = 'n3,n4'
        self.assertEqual(True, does_service_need_to_be_migrated(service))

    def test_is_serv_grp_allowed_multi_apps(self):
        cs = mock.Mock()
        cs.active = "1"
        cs.standby = "1"
        self.assertEqual(True, is_serv_grp_allowed_multi_apps(cs))
        cs.active = "1"
        cs.standby = "0"
        self.assertEqual(True, is_serv_grp_allowed_multi_apps(cs))
        cs.active = "2"
        cs.standby = "0"
        self.assertEqual(False, is_serv_grp_allowed_multi_apps(cs))

    @mock.patch('vcsplugin.vcs_base_helper.is_clustered_service_redeploy_required')
    def test_added_nodes_item_ids(self, redeploy_req):
        redeploy_req.return_value = False
        service = Mock(node_list="n1,n2,n3",
                       applied_properties={"node_list":"n1"},
                       is_updated=Mock(return_value=True))
        added = added_nodes_item_ids(service)
        self.assertEqual(added, ["n2", "n3"])
        redeploy_req.return_value = True
        added = added_nodes_item_ids(service)
        self.assertEqual(added, ["n1", "n2", "n3"])

    @mock.patch('vcsplugin.vcs_base_helper.is_clustered_service_redeploy_required')
    def test_added_node_hostnames(self, redeploy_req):
        redeploy_req.return_value = False
        service = Mock(node_list="n1,n2,n3",
                       applied_properties={"node_list":"n1"},
                       is_updated=Mock(return_value=True))
        service.nodes = [Mock(item_id="n1", hostname="node1"),
            Mock(item_id="n2", hostname="node2"),
            Mock(item_id="n3", hostname="node3")]
        added = VcsBaseHelper.added_node_hostnames(service)
        self.assertEqual(added, ["node2", "node3"])
        redeploy_req.return_value = True
        added = VcsBaseHelper.added_node_hostnames(service)
        self.assertEqual(added, ["node1", "node2", "node3"])

    def test_removed_node_hostnames(self):
        service = Mock(node_list="n1",
                       applied_properties={"node_list":"n1,n2,n3"},
                       is_updated=Mock(return_value=True))
        cluster = Mock(nodes=[Mock(item_id="n1", hostname="node1"),
            Mock(item_id="n2", hostname="node2"),
            Mock(item_id="n3", hostname="node3")])
        service.get_cluster.return_value = cluster
        removed = VcsBaseHelper.removed_node_hostnames(service)
        self.assertEqual(removed, ["node2", "node3"])
        service.is_updated.return_value = False
        removed = VcsBaseHelper.removed_node_hostnames(service)
        self.assertEqual(removed, [])

    def test_removed_nodes_item_ids(self):
        service = Mock(node_list="n1",
                       applied_properties={"node_list":"n1,n2,n3"},
                       is_updated=Mock(return_value=True))
        removed = removed_nodes_item_ids(service)
        self.assertEqual(removed, ["n2", "n3"])
        service.is_updated.return_value = False
        removed = removed_nodes_item_ids(service)
        self.assertEqual(removed, [])

    def test_is_failover_standby_node_updated1(self):
        service = Mock(node_list="n1,n3",
                       active='1',
                       standby='1',
                       applied_properties={"node_list":"n1,n2"},
                       is_updated=lambda: True)
        node1 = Mock(item_id='n1',
                     is_initial=lambda: False,
                     is_for_removal=lambda: False)
        node2 = Mock(item_id='n2',
                     is_initial=lambda: False,
                     is_for_removal=lambda: True)
        node3 = Mock(item_id='n3',
                     is_initial=lambda: False,
                     is_for_removal=lambda: False)
        cluster = Mock(nodes=[node1, node2, node3])
        self.assertTrue(is_failover_standby_node_updated(cluster, service))

    def test_is_failover_standby_node_updated2(self):
        service = Mock(node_list="n1,n3",
                       active='1',
                       standby='1',
                       applied_properties={"node_list":"n1,n2"},
                       is_updated=lambda: True)
        node1 = Mock(item_id='n1',
                     is_initial=lambda: False,
                     is_for_removal=lambda: False)
        node2 = Mock(item_id='n2',
                     is_initial=lambda: False,
                     is_for_removal=lambda: False)
        node3 = Mock(item_id='n3',
                     is_initial=lambda: True,
                     is_for_removal=lambda: False)
        cluster = Mock(nodes=[node1, node2, node3])
        self.assertTrue(is_failover_standby_node_updated(cluster, service))

    def test_is_failover_standby_node_updated3(self):
        service = Mock(node_list="n1,n3",
                       active='1',
                       standby='1',
                       applied_properties={"node_list":"n1,n2"},
                       is_updated=lambda: True)
        node1 = Mock(item_id='n1',
                     is_initial=lambda: False,
                     is_for_removal=lambda: False)
        node2 = Mock(item_id='n2',
                     is_initial=lambda: False,
                     is_for_removal=lambda: False)
        node3 = Mock(item_id='n3',
                     is_initial=lambda: False,
                     is_for_removal=lambda: False)
        cluster = Mock(nodes=[node1, node2, node3])
        self.assertTrue(is_failover_standby_node_updated(cluster, service))


class TestCondenseName(unittest.TestCase):

    def test_string_length_78(self):
        name = "Res_IP_cluster1_cs1_apache_10_10_10_155_10_10_10_156_10_10_10_157_10_10_10_158"
        expected_condensed_string = 'Res_IP_cluster1_cs1_apache_10_10_10_155_10_10_10_1_4bf2fb7b'

        self.assertEqual(condense_name(name), expected_condensed_string)

    def test_string_length_59(self):
        name = "Res_IP_cluster1_cs1_apache_10_10_10_155_10_10_10_156_10_10_"
        expected_condensed_string = 'Res_IP_cluster1_cs1_apache_10_10_10_155_10_10_10_156_10_10_'

        self.assertEqual(condense_name(name), expected_condensed_string)


    def test_string_length_60(self):
        name = "Res_IP_cluster1_cs1_apache_10_10_10_155_10_10_10_156_10_10_1"
        expected_condensed_string = 'Res_IP_cluster1_cs1_apache_10_10_10_155_10_10_10_1_94f0c9d9'

        self.assertEqual(condense_name(name), expected_condensed_string)


class TestSameListDifferentOrder(unittest.TestCase):
    def test_true_None(self):
        item = mock.Mock(dependency_list=None)
        applied_props = {'dependency_list': ''}
        item.applied_properties = applied_props
        prop = 'dependency_list'

        self.assertEqual(same_list_different_order(item, prop), True)

    def test_true(self):
        item = mock.Mock(dependency_list="cs1,cs2")
        applied_props = {'dependency_list': "cs2,cs1"}
        item.applied_properties = applied_props
        prop = 'dependency_list'

        self.assertEqual(same_list_different_order(item, prop), True)

    def test_false(self):
        item = mock.Mock(dependency_list="cs1,cs2,cs3")
        applied_props = {'dependency_list': "cs2,cs1"}
        item.applied_properties = applied_props
        prop = 'dependency_list'

        self.assertEqual(same_list_different_order(item, prop), False)
