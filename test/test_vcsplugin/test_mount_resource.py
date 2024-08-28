import unittest

import mock

from litp.core.execution_manager import CallbackTask

from test_vcs_model import tree
from vcsplugin.mount_resource import (
    get_disk_group_res_name,
    get_mount_res_name,
    get_mount_res_names,
    MountResource,
    _add_disk_group_resource,
    _add_mount_resource,
    _find_fs_item_in_service,
    _get_source_item_id,
    _is_service_failover,
    dict_compare,
    get_apps,
    FSCK_OPT,
    VXVM_VOLUME_DRIVER,
)


class TestMountResource(unittest.TestCase):
    """
    Test suite for vcs_mount_resource.
    NOTE: This test suite is not exhaustive.
    """
    def setUp(self):
        self.helper = MountResource(mock.MagicMock())

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

    def test_get_mount_res_names(self):
        cluster = mock.Mock(item_id=1)
        service = tree()
        service['item_id'] = 2
        service['filesystems']['fs1']['item_id'] = 'fsid1'
        service['filesystems']['fs2']['item_id'] = 'fsid2'
        runtime = tree()
        runtime['item_id'] = 3
        patched_get_mount_res_name = lambda *x: x
        with mock.patch('vcsplugin.mount_resource.get_mount_res_name',
                        new_callable=lambda: patched_get_mount_res_name):
            self.assertEqual(
                [(1, 2, 3, 'fsid1'), (1, 2, 3, 'fsid2')],
                get_mount_res_names(cluster, service, runtime))

    @mock.patch('vcsplugin.mount_resource.condense_name')
    def test_get_mount_res_name(self, patch):
        _ = get_mount_res_name('1', '2', '3', '4')
        patch.assert_called_once_with('Res_Mnt_1_2_3_4')

    @mock.patch('vcsplugin.mount_resource.condense_name')
    def test_get_mount_res_name_multi(self, patch):
        _ = get_mount_res_name('1', '2', '', '4')
        patch.assert_called_once_with('Res_Mnt_1_2_4')

    @mock.patch('vcsplugin.mount_resource.condense_name')
    def test_get_disk_group_res_name(self, patch):
        _ = get_disk_group_res_name('1', '2', '3', '4')
        patch.assert_called_once_with('Res_DG_1_2_3_4')

    @mock.patch('vcsplugin.mount_resource.condense_name')
    def test_get_disk_group_res_name_multi(self, patch):
        _ = get_disk_group_res_name('1', '2', '', '4')
        patch.assert_called_once_with('Res_DG_1_2_4')

    def test_add_mount_resource(self):
        patch = mock.MagicMock()
        _ = _add_mount_resource(patch, 1, 2, 3, 4, 5, 6, 7, [8])
        patch.hares_add.assert_called_with(1, 'Mount', 2)
        self.assertEquals(patch.hares_modify.call_count, 7)
        patch.hares_link.assert_any_call(1, 7)
        patch.hares_link.assert_any_call([8][0], 1)

    def test_add_disk_group_resource(self):
        patch = mock.MagicMock()
        _ = _add_disk_group_resource(patch, 1, 2, 3)
        patch.hares_add.assert_called_with(1, 'DiskGroup', 2)
        self.assertEquals(patch.hares_modify.call_count, 3)

    def test__get_app_id_from_list(self):
        service = mock.MagicMock()
        apps = [mock.Mock(item_id='app1')]
        service.applications = apps
        app_id = self.helper._get_app_id_from_list(service, apps)
        self.assertEqual('app1', app_id)

        apps = [mock.Mock(item_id='app1'), mock.Mock(item_id='app2')]
        service.applications = apps
        app_id = self.helper._get_app_id_from_list(service, apps)
        self.assertEqual('', app_id)

    def test_generate_dskgrp_res_task(self):
        self.assertTrue(
            isinstance(
                self.helper._generate_dskgrp_res_task(
                    mock.Mock(), mock.MagicMock(), [mock.MagicMock()], mock.Mock(),
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

    @mock.patch('vcsplugin.mount_resource._get_source_item_id')
    def test_generate_mount_res_task(self, patch):
        cluster = mock.Mock(item_id=1)
        service = mock.MagicMock(item_id=2)
        service.get_vpath.return_value = 'service_vpath'
        runtime = [mock.Mock(item_id=3)]
        fs = mock.Mock(item_id=4, mount_point='/')
        patch.return_value = 'fs_name'
        task = self.helper._generate_mount_res_task(
            cluster, service, runtime, fs, 'disk_group_name')
        self.assertTrue(isinstance(task, CallbackTask))

    @mock.patch("vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes")
    @mock.patch('vcsplugin.mount_resource._add_disk_group_resource')
    def test_cb_create_diskgroup(self, patch, mock_os_reinstall):
        callback_api = mock.Mock()
        res_name = 'foores'
        sg_name = 'foosg'
        vx_dg_name = 'foovxdg'
        service_vpath = '/foo/'
        mock_os_reinstall.return_value = False

        orig_query_by_vpath = self.helper.query_by_vpath

        service = tree()
        service['nodes']['node1']['hostname'] = 'mn1'
        service['nodes']['node1']['is_initial'] = lambda: False
        service['nodes']['node1']['is_for_removal'] = lambda: False
        service['nodes']['node2']['hostname'] = 'mn2'
        service['nodes']['node2']['is_initial'] = lambda: False
        service['nodes']['node2']['is_for_removal'] = lambda: False
        service['nodes']['node3']['hostname'] = 'mn3'
        service['nodes']['node3']['is_initial'] = lambda: False
        service['nodes']['node3']['is_for_removal'] = lambda: False
        service.get_cluster = lambda: 'foo'

        self.helper.query_by_vpath = lambda x, y: service
        api = mock.Mock()
        api.haconf = mock.Mock()
        self.helper._vcs_api = api
        self.helper._vcs_api.readable_conf = mock.MagicMock()
        self.helper.cb_create_diskgroup(
            callback_api, res_name, sg_name, vx_dg_name, service_vpath)

        patch.assert_called_with(api, res_name, sg_name, vx_dg_name)
        self.assertEqual(set(['mn1', 'mn2', 'mn3']), set(self.helper.nodes))

        self.helper.query_by_vpath = orig_query_by_vpath

    def test_dict_compare(self):
        a = {1: 1, 2: 2, 3: 3}
        b = {1: 2, 2: 2}
        self.assertEquals((1, 3), tuple(dict_compare(a, b)))

    def test_compare_filesystem_properties(self):
        parent = mock.MagicMock(properties={'foo': 'bar'})
        parent.get_vpath.return_value = "/mock/path"
        child = mock.MagicMock(properties={'foo': 'baz'})
        self.assertEqual(
            1,
            len(self.helper._compare_filesystem_properties(parent, child)))
        self.assertEqual(
            'You cannot change the properties of a file-system '
            'inherited under a vcs-clustered-service. Please update the '
            'file-system at /mock/path',
            self.helper._compare_filesystem_properties(
                parent, child)[0].error_message)

    def test_parent_child_filesystems(self):
        query = mock.MagicMock()
        api_context = mock.Mock(query=query)
        _ = list(self.helper._parent_child_filesystems(api_context))
        query.assert_any_call('vcs-cluster', cluster_type='sfha')

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def test_filesystem_is_not_initial(self, mock_os_reinstall):
        mock_os_reinstall.return_value = False
        plugin_api_context = mock.Mock()
        cluster = mock.Mock()

        service = mock.Mock()
        apache = mock.Mock(return_value=True)
        apache.item_id = 'apache'

        service.applications = mock.MagicMock()
        service.applications.__iter__.return_value = [apache]

        service.ha_configs = mock.Mock()
        service.ha_configs.query = mock.Mock(return_value=[])

        service.node_list = 'n1'
        service.applied_properties = {'standby': 1, "node_list":"n1" }
        service.standby =  1

        service.filesystems = mock.MagicMock()
        fs1 = mock.Mock()
        fs1.is_initial.return_value = False
        service.filesystems.__iter__.return_value = [fs1]

        self.assertEqual(([], []), self.helper.create_configuration(
            plugin_api_context, cluster, service))

    def test_filesystem_with_mount_point_updated_in_initial_state(self):
        services = list()
        service = mock.Mock()
        service.filesystems = mock.MagicMock()
        fs1 = mock.Mock()
        fs1.is_initial.return_value = True
        fs1.mount_point = "/opt"
        service.filesystems.__iter__.return_value = [fs1]
        services.append(service)
        self.assertEqual([], self.helper._validate_filesystem_mount_point_not_updated(services))

    def test_filesystem_with_mount_point_updated(self):
        services = list()
        service = mock.Mock(
                            node_list='n1',
                            standby='1',
                            applied_properties = {'standby': 1, "node_list":"n1"},
                            applied_properties_determinable=False)
        service.filesystems = mock.MagicMock()
        fs1 = mock.Mock(mount_point='/opt',
                        applied_properties = {'mount_point': "/tmp"})
        fs1.is_initial.return_value = False
        service.filesystems.__iter__.return_value = [fs1]
        services.append(service)
        res = self.helper._validate_filesystem_mount_point_not_updated(services)
        self.assertEqual(len(res), 1)

    def test_filesystem_with_mount_point_updated_service_redeploy(self):
        cluster = mock.Mock()
        cluster.is_initial = mock.Mock(return_value=False)
        services = list()
        service = mock.Mock(applied_properties_determinable=False,
                            node_list = 'n1',
                            standby = 1,
                            applied_properties = {'standby': 1, "node_list":"n1"})
        service.is_for_removal = mock.Mock(return_value=False)
        service.filesystems = mock.MagicMock()
        service.get_cluster = mock.Mock(return_value=cluster)
        fs1 = mock.Mock(mount_point = "/opt",
                        applied_properties = {'mount_point': "/tmp"})
        fs1.is_initial.return_value = False
        service.filesystems.__iter__.return_value = [fs1]
        services.append(service)
        cluster.services = services
        res = self.helper._validate_filesystem_mount_point_not_updated(services)
        self.assertEqual(len(res), 1)

    @mock.patch('vcsplugin.mount_resource.MountResource.create_diskgroup_tasks')
    @mock.patch('vcsplugin.mount_resource.MountResource.get_diskgroup_name')
    @mock.patch('vcsplugin.mount_resource._get_source_item_id')
    def untest_filesystem_is_initial(self, get_src_id, get_dg_name, create_dg_tasks):
        plugin_api_context = mock.Mock()
        cluster = mock.Mock(storage_profile=mock.Mock())
        service = tree()
        service['applications']['apache'] = lambda: True
        service['filesystems']['fs1']['is_initial'] = lambda: True
        get_src_id.return_value = 'filesys1'
        get_dg_name.return_value = 'vol1'
        create_dg_tasks.return_value = [mock.Mock(requires=set())]
        #create_dg_tasks.side_effect = lambda *x: self.fail("moo")

        self.helper.create_configuration(plugin_api_context, cluster, service)
        create_dg_tasks.assert_called_with(cluster, service,
                service['applications']['apache'],
                service['filesystems']['fs1'], 'vol1', 'filesys1')

    def test_get_apps(self):
        service = mock.Mock()
        service1 = mock.Mock()
        service1.item_id = 'service1'

        service.applications = mock.MagicMock()
        service.applications.__iter__.return_value = [service1]
        service.applications.service1 = service1

        ha_config1 = mock.Mock()
        ha_config1.dependency_list = None
        ha_config1.service_id = None

        service.ha_configs = mock.Mock()
        service.ha_configs.query = mock.Mock(return_value=[ha_config1])

        self.assertEqual(list(service.applications), get_apps(service))

        ha_config1.service_id = 'service1'

        self.assertEqual(list(service.applications), get_apps(service))

        service3 = mock.Mock()
        service3.item_id = 'service3'

        service.applications.__iter__.return_value = [service1, service3]
        service.applications.service3 = service3

        ha_config1.service_id = 'service1'
        ha_config2 = mock.Mock()
        ha_config2.dependency_list = 'mock_service2'
        ha_config2.service_id = 'service2'
        ha_config3 = mock.Mock()
        ha_config3.dependency_list = None
        ha_config3.service_id = 'service3'
        service.ha_configs.query = mock.Mock(return_value=[ha_config1,
                                                           ha_config2,
                                                           ha_config3])

        self.assertEqual(list(service.applications), get_apps(service))

    @mock.patch('vcsplugin.mount_resource.MountResource._get_dg')
    def test_get_diskgroup_name(self, _get_dg):
        dg = tree()
        dg['volume_group_name'] = 'vol1'
        _get_dg.return_value = dg
        self.assertEqual('vol1', self.helper.get_diskgroup_name(mock.Mock()))

    @mock.patch('vcsplugin.mount_resource.MountResource._generate_dskgrp_res_task')
    @mock.patch('vcsplugin.mount_resource.MountResource._generate_mount_res_task')
    @mock.patch('vcsplugin.mount_resource.MountResource._generate_deport_task')
    def test_create_diskgroup_tasks(self, _gen_deport_res, _gen_mnt_res, _gen_dg_res):
        self.helper.create_diskgroup_tasks(1, 2, 3, 4, 5)
        _gen_deport_res.assert_called_with(1, 4, 5, 2)
        _gen_mnt_res.assert_called_with(1, 2, 3, 4, 5)
        _gen_dg_res.assert_called_with(1, 2, 3, 4, 5)

    @mock.patch("vcsplugin.mount_resource.is_os_reinstall_on_peer_nodes")
    @mock.patch("vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes")
    @mock.patch('vcsplugin.mount_resource.MountResource.vcs_api')
    def test_deport_diskgroup_successfully(self, vcs_api, mock_os_reinstall,
                                           is_os_reinstall_on_peer_nodes):
        callback_api = mock.Mock()
        vx_dg_name = 'foovxdg'
        service_vpath = '/foo/'
        mock_os_reinstall.return_value = False
        is_os_reinstall_on_peer_nodes.return_value = False

        cluster = tree()
        cluster['nodes']['node1']['hostname'] = 'mn1'
        cluster['nodes']['node1']['is_for_removal'] = lambda: False
        cluster['nodes']['node1']['is_initial'] = lambda: False
        cluster['nodes']['node2']['hostname'] = 'mn2'
        cluster['nodes']['node2']['is_for_removal'] = lambda: False
        cluster['nodes']['node2']['is_initial'] = lambda: False
        service = tree()
        service['service_name'] = 'test1'
        vcs_api.get_diskgroup_hostname.return_value = "storeg:[],exit_code:0"
        self.helper.query_by_vpath = lambda x, y: service
        service.get_cluster = lambda: cluster
        self.helper.cb_deport_diskgroup(callback_api, vx_dg_name, service_vpath)
        vcs_api.deport_disk_group.assert_called_with(vx_dg_name)

    @mock.patch("vcsplugin.mount_resource.is_os_reinstall_on_peer_nodes")
    @mock.patch("vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes")
    @mock.patch('vcsplugin.mount_resource.MountResource.vcs_api')
    def test_deport_diskgroup_unsuccessfully(self, vcs_api,
                                             mock_os_reinstall,
                                             is_os_reinstall_on_peer_nodes):
        callback_api = mock.Mock()
        mock_os_reinstall.return_value = False
        is_os_reinstall_on_peer_nodes.return_value = False
        vx_dg_name = 'foovxdg'
        service_vpath = '/foo/'
        cluster = tree()
        cluster['nodes']['node1']['hostname'] = 'mn1'
        cluster['nodes']['node1']['is_for_removal'] = lambda: False
        cluster['nodes']['node1']['is_initial'] = lambda: False
        cluster['nodes']['node2']['hostname'] = 'mn2'
        cluster['nodes']['node2']['is_for_removal'] = lambda: False
        cluster['nodes']['node2']['is_initial'] = lambda: False
        service = tree()
        service['service_name'] = 'test1'
        vcs_api.return_value.get_diskgroup_hostname.return_value = None
        self.helper.query_by_vpath = lambda x, y: service
        service.get_cluster = lambda: cluster
        self.helper.cb_deport_diskgroup(callback_api, vx_dg_name, service_vpath)
        vcs_api.return_value.deport_disk_group.assert_not_called_with(vx_dg_name)

    @mock.patch("vcsplugin.mount_resource.is_os_reinstall_on_peer_nodes")
    @mock.patch("vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes")
    @mock.patch('vcsplugin.mount_resource.MountResource.vcs_api')
    def test_deport_diskgroup_os_reinstall_true(self, vcs_api,
                                                mock_os_reinstall,
                                                is_os_reinstall_on_peer_nodes):
        callback_api = mock.Mock()
        vx_dg_name = 'foovxdg'
        service_vpath = '/foo/'
        mock_os_reinstall.return_value = True
        is_os_reinstall_on_peer_nodes.return_value = True

        cluster = tree()
        cluster['nodes']['node1']['hostname'] = 'mn1'
        cluster['nodes']['node1']['is_for_removal'] = lambda: False
        cluster['nodes']['node1']['is_initial'] = lambda: True
        cluster['nodes']['node2']['hostname'] = 'mn2'
        cluster['nodes']['node2']['is_for_removal'] = lambda: False
        cluster['nodes']['node2']['is_initial'] = lambda: True
        cluster['nodes']['node3']['hostname'] = 'mn3'
        cluster['nodes']['node3']['is_for_removal'] = lambda: False
        cluster['nodes']['node3']['is_initial'] = lambda: True

        service = tree()
        service['service_name'] = 'test1'
        service['applied_properties'] = {"foo": "foo"}
        service['nodes']['node1']['hostname'] = 'mn1'
        service['nodes']['node1']['is_for_removal'] = lambda: False
        service['nodes']['node1']['is_initial'] = lambda: True
        service['nodes']['node2']['hostname'] = 'mn2'
        service['nodes']['node2']['is_for_removal'] = lambda: False
        service['nodes']['node2']['is_initial'] = lambda: True

        vcs_api.get_diskgroup_hostname.return_value = "storeg:[],exit_code:0"
        self.helper.query_by_vpath = lambda x, y: service
        service.get_cluster = lambda: cluster
        self.helper.cb_deport_diskgroup(callback_api, vx_dg_name, service_vpath)
        vcs_api.deport_disk_group.assert_called_once_with(vx_dg_name)
        self.assertEqual(['mn3'], self.helper.nodes)

        # Test new SG in os-reinstall (has no applied_properties)
        vx_dg_name = 'foovxdg_2'
        service['applied_properties'] = None
        self.helper.cb_deport_diskgroup(callback_api, vx_dg_name, service_vpath)
        vcs_api.deport_disk_group.assert_called_with(vx_dg_name)
        self.assertEqual(['mn1', 'mn3', 'mn2'], self.helper.nodes)

    @mock.patch('os.path.join')
    @mock.patch("vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes")
    @mock.patch('vcsplugin.mount_resource._add_mount_resource')
    @mock.patch('vcsplugin.mount_resource.MountResource.vcs_api')
    @mock.patch('vcsplugin.mount_resource.MountResource.query_by_vpath')
    @mock.patch('vcsplugin.mount_resource._find_fs_item_in_service')
    def test_cb_create_mount(self, _find_fs, _query_by_vpath, vcs_api,
                             _add_mnt, mock_os_reinstall, _os_join):
        service = mock.Mock(nodes=[mock.Mock(hostname='mn1'),
                                   mock.Mock(hostname='mn2')])
        _query_by_vpath.return_value = service
        _find_fs.return_value = mock.Mock(type='vxvm')
        _os_join.return_value = 'blockdev'
        mock_os_reinstall.return_value = False

        self.helper.cb_create_mount(mock.Mock(item_id=1), '2', '3', '/mock',
                                    '5', '6', '7', '8', '9')
        _add_mnt.assert_called_with(vcs_api, '2', '3', '/mock', 'blockdev',
                                    'vxvm', FSCK_OPT, '7', '8')

    def test_get_fs_vpaths_ignores_non_vxvm_profiles(self):
        cluster = tree()
        cluster['storage_profile']['prof1']['volume_driver'] = 'lvm'
        cluster['storage_profile']['prof1']['volume_groups']['vg1']['file_systems']['fs1']['get_vpath'] = lambda: 'bad'

        cluster['storage_profile']['prof2']['volume_driver'] = VXVM_VOLUME_DRIVER
        cluster['storage_profile']['prof2']['volume_groups']['vg1']['file_systems']['fs1']['get_vpath'] = lambda: 'good'
        self.assertEquals(set(['good']), self.helper.get_fs_vpaths(cluster))

    @mock.patch('vcsplugin.mount_resource.MountResource.get_fs_vpaths')
    def test_check_fs_in_cluster_storage_neg(self, _get_fs_vpaths):
        _get_fs_vpaths.return_value = set(['in0'])
        cluster = tree()
        cluster['storage_profile']['get_vpath'] = lambda:'mock'
        cluster['services']['cs1']['is_for_removal'] = lambda: False
        cluster['services']['cs1']['filesystems']['fs1']['item_id'] = 'fs1'
        cluster['services']['cs1']['filesystems']['fs1']['get_vpath'] = lambda: 'cs1/fs1'
        cluster['services']['cs1']['filesystems']['fs1']['get_source'] = lambda: mock.Mock(get_vpath=(lambda: 'out0'))

        cluster['services']['cs2']['is_for_removal'] = lambda: False
        cluster['services']['cs2']['filesystems']['fs2']['item_id'] = 'fs1'
        cluster['services']['cs2']['filesystems']['fs2']['get_vpath'] = lambda: 'cs2/fs2'
        cluster['services']['cs2']['filesystems']['fs2']['get_source'] = lambda: mock.Mock(get_vpath=(lambda: 'in0'))
        res = self.helper._check_fs_in_cluster_storage(cluster)
        self.assertEquals(1, len(res))
        self.assertEquals('cs1/fs1', res[0].item_path)

    @mock.patch('vcsplugin.mount_resource.MountResource.get_fs_vpaths')
    def test_check_fs_in_cluster_storage_pos(self, _get_fs_vpaths):
        _get_fs_vpaths.return_value = set(['in0', 'in1'])
        cluster = tree()
        cluster['storage_profile']['get_vpath'] = lambda:'mock'
        cluster['services']['cs1']['is_for_removal'] = lambda: False
        cluster['services']['cs1']['filesystems']['fs1']['item_id'] = 'fs1'
        cluster['services']['cs1']['filesystems']['fs1']['get_vpath'] = lambda: 'cs1/fs1'
        cluster['services']['cs1']['filesystems']['fs1']['get_source'] = lambda: mock.Mock(get_vpath=(lambda: 'in0'))

        cluster['services']['cs2']['is_for_removal'] = lambda: False
        cluster['services']['cs2']['filesystems']['fs2']['item_id'] = 'fs1'
        cluster['services']['cs2']['filesystems']['fs2']['get_vpath'] = lambda: 'cs2/fs2'
        cluster['services']['cs2']['filesystems']['fs2']['get_source'] = lambda: mock.Mock(get_vpath=(lambda: 'in1'))
        self.assertEquals([], self.helper._check_fs_in_cluster_storage(cluster))

    def test_validate_fs_linked_only_in_sfha_clusters_pos_01(self):
        _query = tree()
        _query['cluster1']['cluster_type'] = 'vcs'
        _query['cluster1']['services']['cs1']['is_for_removal'] = lambda: False
        _query['cluster1']['services']['cs1']['filesystems'] = []

        self.assertEquals([],
                self.helper._validate_fs_linked_only_in_sfha_clusters(_query))

    def test_validate_fs_linked_only_in_sfha_clusters_pos_02(self):
        _query = tree()
        _query['cluster1']['cluster_type'] = 'sfha'
        _query['cluster1']['services']['cs1']['filesystems']['fs1']['item_id'] = 'fs1'
        _query['cluster1']['services']['cs1']['filesystems']['fs1']['get_vpath'] = lambda: 'vpath1'

        self.assertEquals([],
                self.helper._validate_fs_linked_only_in_sfha_clusters(_query))

    def test_validate_fs_linked_only_in_sfha_clusters_neg_01(self):
        _query = tree()
        _query['cluster1']['cluster_type'] = 'vcs'
        _query['cluster1']['services']['cs1']['is_for_removal'] = lambda: False
        _query['cluster1']['services']['cs1']['filesystems']['fs1']['item_id'] = 'fs1'
        _query['cluster1']['services']['cs1']['filesystems']['fs1']['get_vpath'] = lambda: 'vpath1'

        res = self.helper._validate_fs_linked_only_in_sfha_clusters(_query)
        self.assertEquals(1, len(res))
        self.assertEquals('vpath1', res[0].item_path)

    @mock.patch('vcsplugin.vcs_base_helper.VcsBaseHelper.services_not_for_removal')
    def test_validate_fs_has_mount_point_no_mount_point(self, get_services):
        services = tree()
        services['cs1']['filesystems']['fs1']['get_vpath'] = lambda: 'vpath1'
        services['cs1']['filesystems']['fs1']['mount_point'] = False
        get_services.return_value = services
        res = self.helper._validate_filesystem_has_mount_point(services)
        self.assertEquals(1, len(res))
        self.assertEquals('vpath1', res[0].item_path)

    @mock.patch('vcsplugin.vcs_base_helper.VcsBaseHelper.services_not_for_removal')
    def test_validate_fs_has_mount_point_with_mount_point(self, get_services):
        services = tree()
        services['cs1']['filesystems']['fs1']['get_vpath'] = lambda: 'vpath1'
        services['cs1']['filesystems']['fs1']['mount_point'] = '/mount_point'
        get_services.return_value = services
        self.assertEquals([],
                self.helper._validate_filesystem_has_mount_point(services))
