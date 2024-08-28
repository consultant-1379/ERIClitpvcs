import unittest

import mock

from litp.core.execution_manager import CallbackTask

from test_vcs_model import tree
from vcsplugin.legacy.vcs_mount_resource import (
    get_disk_group_res_name,
    get_mount_res_name,
    get_mount_res_names,
    VcsMountLegacyResource,
    _add_disk_group_resource,
    _add_mount_resource,
    _find_fs_item_in_service,
    _get_source_item_id,
    _is_service_failover,
    dict_compare
)


class TestVCSMountLegacyResource(unittest.TestCase):
    """
    Test suite for vcs_mount_resource.
    NOTE: This test suite is not exhaustive.
    """
    def setUp(self):
        self.helper = VcsMountLegacyResource(mock.MagicMock())

    def test_is_service_failover(self):
        class DummyService(object):
            active = 0
            standby = 0
        service = DummyService()
        service.active, service.standby = 1, 1
        self.assertTrue(_is_service_failover(service))
        service.active, service.standby = 0, 0
        self.assertFalse(_is_service_failover(service))
        service.active, service.standby = 1, 0
        self.assertFalse(_is_service_failover(service))
        service.active, service.standby = 0, 1
        self.assertFalse(_is_service_failover(service))

    def test_get_fs_name(self):
        rt_fs_item = mock.Mock()
        source = mock.MagicMock(item_id=1)
        get_source = mock.Mock(return_value=source)
        rt_fs_item.get_source = get_source
        res = _get_source_item_id(rt_fs_item)

        get_source.assert_called_with()
        self.assertEqual(res, source.item_id)

    def test_find_fs_item_in_service(self):
        service = tree()
        service['runtimes']['rt1']['filesystems'] = ('fs1', 'fs2', 'fs3')
        service['runtimes']['rt2']['filesystems'] = ('fs4', 'fs5')
        patched_get_fs_name = lambda x: x
        # TODO: look at a nicer way to test this.
        with mock.patch('vcsplugin.legacy.vcs_mount_resource._get_source_item_id',
                        new_callable=lambda: patched_get_fs_name):
            self.assertEquals(
                    'fs5',
                _find_fs_item_in_service(service, 'fs5'))

    def test_get_mount_res_names(self):
        cluster = mock.Mock(item_id=1)
        service = mock.Mock(item_id=2)
        runtime = tree()
        runtime['item_id'] = 3
        runtime['filesystems']['fs1']['item_id'] = 'fsid1'
        runtime['filesystems']['fs2']['item_id'] = 'fsid2'
        patched_get_mount_res_name = lambda *x: x
        with mock.patch('vcsplugin.legacy.vcs_mount_resource.get_mount_res_name',
                        new_callable=lambda: patched_get_mount_res_name):
            self.assertEqual(
                [(1, 2, 3, 'fsid1'), (1, 2, 3, 'fsid2')],
                get_mount_res_names(cluster, service, runtime))

    @mock.patch('vcsplugin.legacy.vcs_mount_resource.condense_name')
    def test_get_mount_res_name(self, patch):
        _ = get_mount_res_name('1', '2', '3', '4')
        patch.assert_called_once_with('Res_Mnt_1_2_3_4')

    @mock.patch('vcsplugin.legacy.vcs_mount_resource.condense_name')
    def test_get_disk_group_res_name(self, patch):
        _ = get_disk_group_res_name('1', '2', '3', '4')
        patch.assert_called_once_with('Res_DG_1_2_3_4')

    def test_add_mount_resource(self):
        patch = mock.MagicMock()
        _ = _add_mount_resource(patch, 1, 2, 3, 4, 5, 6, 7)
        patch.hares_add.assert_called_with(1, 'Mount', 2)
        self.assertEquals(patch.hares_modify.call_count, 7)
        patch.hares_link.assert_called_with(1, 7)

    def test_add_disk_group_resource(self):
        patch = mock.MagicMock()
        _ = _add_disk_group_resource(patch, 1, 2, 3)
        patch.hares_add.assert_called_with(1, 'DiskGroup', 2)
        self.assertEquals(patch.hares_modify.call_count, 3)

    def test_generate_dskgrp_res_task(self):
        self.assertTrue(
            isinstance(
                self.helper._generate_dskgrp_res_task(
                    mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock(),
                    mock.Mock()),
                CallbackTask))

    def test_get_fs_vpaths(self):
        cluster = tree()
        cluster['storage_profile']['sp1']['volume_driver'] = 'vxvm'
        cluster['storage_profile']['sp1']['volume_groups']['vg1']['file_systems']['fs1']['get_vpath'] = lambda: 'fs1_vpath'
        cluster['storage_profile']['sp2']['volume_driver'] = 'other'
        cluster['storage_profile']['sp2']['volume_groups']['vg1']['file_systems']['fs2']['get_vpath'] = lambda: 'fs2_vpath'
        cluster['storage_profile']['sp3']['volume_driver'] = 'vxvm'
        cluster['storage_profile']['sp3']['volume_groups']['vg1']['file_systems']['fs3']['get_vpath'] = lambda: 'fs3_vpath'
        cluster['storage_profile']['sp4']['volume_driver'] = 'vxvm'
        cluster['storage_profile']['sp4']['volume_groups']['vg1']['file_systems']['fs4']['get_vpath'] = lambda: 'fs1_vpath'

        self.assertEqual(
            set(['fs1_vpath', 'fs3_vpath']),
            self.helper.get_fs_vpaths(cluster))

    @mock.patch('vcsplugin.legacy.vcs_mount_resource._get_source_item_id')
    def test_generate_mount_res_task(self, patch):
        cluster = mock.Mock(item_id=1)
        service = mock.Mock(item_id=2)
        service.get_vpath.return_value = 'service_vpath'
        runtime = mock.Mock(item_id=3)
        fs = mock.Mock(item_id=4, mount_point='/')
        patch.return_value = 'fs_name'
        task = self.helper._generate_mount_res_task(
            cluster, service, runtime, fs, 'disk_group_name')
        self.assertTrue(isinstance(task, CallbackTask))

    @mock.patch('vcsplugin.legacy.vcs_mount_resource._add_disk_group_resource')
    def test_cb_create_diskgroup(self, patch):
        callback_api = mock.Mock()
        res_name = 'foores'
        sg_name = 'foosg'
        vx_dg_name = 'foovxdg'
        service_vpath = '/foo/'

        self.helper.nodes = ["n1"]

        service = tree()
        service['nodes']['node1']['hostname'] = 'mn1'
        service['nodes']['node2']['hostname'] = 'mn2'
        service['nodes']['node3']['hostname'] = 'mn3'

        self.helper.query_by_vpath = lambda x, y: service
        api = mock.Mock()
        api.haconf = mock.Mock()
        self.helper._vcs_api = api
        self.helper._vcs_api.readable_conf = mock.MagicMock()

        self.helper.cb_create_diskgroup(
            callback_api, res_name, sg_name, vx_dg_name, service_vpath)

        patch.assert_called_with(api, res_name, sg_name, vx_dg_name)
        self.assertEqual(set(['mn1', 'mn2', 'mn3']), set(self.helper.nodes))

    def test_dict_compare(self):
        a = {1: 1, 2: 2, 3: 3}
        b = {1: 2, 2: 2}
        self.assertEquals((1, 3), tuple(dict_compare(a, b)))

    def test_compare_filesystem_properties(self):
        parent = mock.MagicMock(properties={'foo': 'bar'})
        child = mock.MagicMock(properties={'foo': 'baz'})
        self.assertEqual(
            1,
            len(self.helper._compare_filesystem_properties(parent, child)))
        self.assertEqual(
            'Property "foo" changed from parent item.',
            self.helper._compare_filesystem_properties(
                parent, child)[0].error_message)

    def test_parent_child_filesystems(self):
        query = mock.MagicMock()
        api_context = mock.Mock(query=query)
        _ = list(self.helper._parent_child_filesystems(api_context))
        query.assert_any_call('vcs-cluster', cluster_type='sfha')

    def test_filesystem_is_initial(self):
        plugin_api_context = mock.Mock()
        cluster = mock.Mock(**{'is_valid_cluster.return_value': True})
        service = tree()
        service['runtimes']['runtime1']['filesystems']['fs1']['is_initial'] = lambda: False
        self.assertEqual(([], []), self.helper.create_configuration(
            plugin_api_context, cluster, service))
