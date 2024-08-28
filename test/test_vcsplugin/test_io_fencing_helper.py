##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from vcsplugin.vcs_io_fencing_helper import VcsIOFencingHelper
from vcsplugin.vcs_exceptions import VCSRuntimeException, VcsCmdApiException
from vcsplugin.vcs_plugin import VcsPlugin
from litp.core.execution_manager import CallbackExecutionException
from base_vcs_integration import VCSIntegrationBase

import mock
import unittest

class DummyPluginForTest(object):
    pass

class TestVcsVerifyVXAdmin(unittest.TestCase):

    @mock.patch('vcsplugin.vcs_io_fencing_helper.VcsIOFencingHelper.vcs_api')
    def test_success(self, vcs_api):
        vcs_io_fencing_helper = VcsIOFencingHelper(None)

        vcs_api.vxfen_admin.return_value =\
            '\nI/O Fencing Cluster Information:\n================================\n\n '\
            'Fencing Protocol Version: 201\n Fencing Mode: SCSI3\n Fencing SCSI3 Disk Policy: '\
            'dmp\n Cluster Members:  \n\n\t  0 (mn2)\n\t* 1 (mn1)\n\n RFSM State Information:\n\t'\
            'node   0 in state  8 (running)\n\tnode   1 in state  8 (running)\n\t'

        vcs_io_fencing_helper.verify_vxfen_admin()

        self.assertEqual(vcs_api.vxfen_admin.call_args_list, [mock.call()])

    @mock.patch('vcsplugin.vcs_io_fencing_helper.VcsIOFencingHelper.vcs_api')
    def test_fencing_mode_error(self, vcs_api):
        vcs_io_fencing_helper = VcsIOFencingHelper(None)

        vcs_api.vxfen_admin.return_value =\
            '\nI/O Fencing Cluster Information:\n================================\n\n '\
            'Fencing Protocol Version: 201\n Fencing Mode: Not SCSI3\n Fencing SCSI3 Disk Policy: '\
            'dmp\n Cluster Members:  \n\n\t  0 (mn2)\n\t* 1 (mn1)\n\n RFSM State Information:\n\t'\
            'node   0 in state  8 (running)\n\tnode   1 in state  8 (running)\n\t'

        try:
            vcs_io_fencing_helper.verify_vxfen_admin()
        except VCSRuntimeException, e:
            pass

        self.assertEqual(e.args, ('The Fencing mode configuration was not set up correctly.'\
            ' "Fencing Mode: SCSI3" is not visible in the output of "vxfenadm -d"',))
        self.assertEqual(vcs_api.vxfen_admin.call_args_list, [mock.call()])

    @mock.patch('vcsplugin.vcs_io_fencing_helper.VcsIOFencingHelper.vcs_api')
    def test_fencing_scsi3_disk_policy_error(self, vcs_api):
        vcs_io_fencing_helper = VcsIOFencingHelper(None)

        vcs_api.vxfen_admin.return_value =\
            '\nI/O Fencing Cluster Information:\n================================\n\n '\
            'Fencing Protocol Version: 201\n Fencing Mode: SCSI3\n Fencing SCSI3 Disk Policy: '\
            'Not dmp\n Cluster Members:  \n\n\t  0 (mn2)\n\t* 1 (mn1)\n\n RFSM State Information:\n\t'\
            'node   0 in state  8 (running)\n\tnode   1 in state  8 (running)\n\t'

        try:
            vcs_io_fencing_helper.verify_vxfen_admin()
        except VCSRuntimeException, e:
            pass

        self.assertEqual(e.args, ('The Fencing mode configuration was not set up correctly.'\
            ' "Fencing SCSI3 Disk Policy: dmp" is not visible in the output of "vxfenadm -d"',))
        self.assertEqual(vcs_api.vxfen_admin.call_args_list, [mock.call()])


class TestVcsVerifyVXConfig(unittest.TestCase):

    @mock.patch('vcsplugin.vcs_io_fencing_helper.VcsIOFencingHelper.vcs_api')
    def test_success(self, vcs_api):
        vcs_io_fencing_helper = VcsIOFencingHelper(None)

        vcs_api.vxfen_config.return_value =\
            '\nI/O Fencing Configuration Information:\n======================================\n\n'\
            ' Single Disk Flag     : 0\n Count                : 3\n Disk List\n'\
            ' Disk Name                Major      Minor    Serial Number            Policy\n'\
            ' /dev/vx/rdmp/disk_0        201         64    30000000DBC0F9C6         dmp   \n'\
            ' /dev/vx/rdmp/disk_2        201         48    30000000FC85C928         dmp   \n'\
            ' /dev/vx/rdmp/disk_1        201         32    30000000EF27515F         dmp   \n'

        vcs_io_fencing_helper.verify_vxfen_config()

        self.assertEqual(vcs_api.vxfen_config.call_args_list, [mock.call()])

    @mock.patch('vcsplugin.vcs_io_fencing_helper.VcsIOFencingHelper.vcs_api')
    def test_fencing_not_setup(self, vcs_api):
        vcs_io_fencing_helper = VcsIOFencingHelper(None)

        vcs_api.vxfen_config.return_value =\
            '\nI/O Fencing Configuration Information:\n======================================\n\n'\
            ' Single Disk Flag     : 0\n Count                : 0\n Disk List\n'\
            ' Disk Name                Major      Minor    Serial Number            Policy\n'

        try:
            vcs_io_fencing_helper.verify_vxfen_config()
        except VCSRuntimeException, e:
            pass

        self.assertEqual(e.args, ('The Fencing mode configuration was not set up correctly.'\
            ' "Count: 3" is not visible in the output of "vxfenconfig -l"',))
        self.assertEqual(vcs_api.vxfen_config.call_args_list, [mock.call()])


class TestVxVerifyIOFencing(unittest.TestCase):

    def test_success(self):
        callback_api = mock.Mock()
        vcs_io_fencing_helper = VcsIOFencingHelper(None)
        vcs_io_fencing_helper.verify_vxfen_admin = mock.Mock()
        vcs_io_fencing_helper.verify_vxfen_config = mock.Mock()

        vcs_io_fencing_helper.vx_verify_io_fencing(callback_api, ['mn1', 'mn2'])
        self.assertEqual(vcs_io_fencing_helper.verify_vxfen_admin.call_args_list, [mock.call()])
        self.assertEqual(vcs_io_fencing_helper.verify_vxfen_config.call_args_list, [mock.call()])


class TestCreateConfiguration(unittest.TestCase):

    def test_no_fencing_disks(self):
        vcs_io_fencing_helper = VcsIOFencingHelper(None)
        node1 = mock.Mock(hostname = 'mn1')
        node2 = mock.Mock(hostname = 'mn2')
        cluster = mock.Mock(nodes = [node1, node2], fencing_disks = [])
        cluster.is_initial.return_value = True

        self.assertEqual(([], []),
                         vcs_io_fencing_helper.create_configuration(None,
                                                                    cluster))

    @mock.patch('vcsplugin.vcs_io_fencing_helper.CallbackTask')
    def test_cluster_is_initial(self, callback_task_patch):
        plugin = DummyPluginForTest
        plugin_callback_method_mock = mock.Mock()
        plugin.callback_method = plugin_callback_method_mock

        requires_mock = mock.Mock(['add'])
        callback_task = mock.Mock(requires=requires_mock)
        callback_task_patch.return_value = callback_task

        vcs_io_fencing_helper = VcsIOFencingHelper(plugin)
        node1 = mock.Mock(hostname = 'mn1')
        node1.is_for_removal.return_value = False
        node2 = mock.Mock(hostname = 'mn2')
        node2.is_for_removal.return_value = False
        fencing_disk1 = mock.Mock(uuid = '30000000fc85c926')
        fencing_disk2 = mock.Mock(uuid = '30000000fc85c927')
        fencing_disk3 = mock.Mock(uuid = '30000000fc85c928')
        cluster = mock.Mock(nodes = [node1, node2], fencing_disks = [fencing_disk1, fencing_disk2, fencing_disk3], item_id = 'cluster1')
        cluster.is_initial.return_value = True

        pre_node_tasks, post_node_tasks = \
            vcs_io_fencing_helper.create_configuration(None, cluster)

        self.assertEqual(3, len(post_node_tasks))
        self.assertEqual(0, len(pre_node_tasks))
        tasks = post_node_tasks + pre_node_tasks
        self.assertEqual(tasks, [callback_task, callback_task, callback_task])
        self.assertEqual(callback_task_patch.call_args_list, [
            mock.call(cluster,
                      'Configure VCS to use VX fencing on cluster "cluster1"',
                      plugin_callback_method_mock,
                      callback_class='VcsIOFencingHelper',
                      callback_func="vx_io_fencing",
                      nodes=['mn1', 'mn2'],
                      cluster_name="cluster1"),
            mock.call(cluster,
                      'Check VCS engine is running on cluster "cluster1"',
                      plugin_callback_method_mock,
                      callback_class='VcsCluster',
                      callback_func="vcs_poll_callback",
                      nodes=['mn1', 'mn2']),
            mock.call(cluster,
                      'Check VX fencing is configured on cluster "cluster1"',
                      plugin_callback_method_mock,
                      callback_class='VcsIOFencingHelper',
                      callback_func="vx_verify_io_fencing",
                      nodes=['mn1', 'mn2']),
            ])
        self.assertEqual(requires_mock.add.call_args_list, [
            mock.call([fencing_disk1, fencing_disk2, fencing_disk3]),
            mock.call([fencing_disk1, fencing_disk2, fencing_disk3]),
            mock.call([fencing_disk1, fencing_disk2, fencing_disk3]),
            ])

    @mock.patch('vcsplugin.vcs_io_fencing_helper.CallbackTask')
    def test_cluster_is_expansion_fencing(self, callback_task_patch):
        plugin = DummyPluginForTest
        plugin_callback_method_mock = mock.Mock()
        plugin.callback_method = plugin_callback_method_mock

        requires_mock = mock.Mock(['add'])
        callback_task = mock.Mock(requires=requires_mock)
        callback_task_patch.return_value = callback_task

        vcs_io_fencing_helper = VcsIOFencingHelper(plugin)
        node1 = mock.Mock(hostname='mn1')
        node1.is_initial.return_value = False
        node1.is_for_removal.return_value = False
        node2 = mock.Mock(hostname='mn2')
        node2.is_initial.return_value = False
        node2.is_for_removal.return_value = False
        node3 = mock.Mock(hostname='mn3')
        node3.is_initial.return_value = True
        node3.is_for_removal.return_value = False
        fencing_disk1 = mock.Mock(uuid='30000000fc85c926')
        fencing_disk2 = mock.Mock(uuid='30000000fc85c927')
        fencing_disk3 = mock.Mock(uuid='30000000fc85c928')
        cluster = mock.Mock(nodes=[node1, node2, node3], fencing_disks=[fencing_disk1,fencing_disk2, fencing_disk3], item_id='cluster1')
        cluster.is_initial.return_value = False

        pre_node_tasks, post_node_tasks = \
            vcs_io_fencing_helper.create_configuration(None, cluster)

        self.assertEqual(1, len(post_node_tasks))
        self.assertEqual(0, len(pre_node_tasks))
        tasks = post_node_tasks + pre_node_tasks
        self.assertEqual(tasks, [callback_task])
        self.assertEqual(callback_task_patch.call_args_list, [
            mock.call(cluster,
                      'Check VX fencing is configured on cluster "cluster1"',
                      plugin_callback_method_mock,
                      callback_class='VcsIOFencingHelper',
                      callback_func="vx_verify_io_fencing",
                      nodes=['mn1', 'mn2', 'mn3']),
            ])
        self.assertEqual(requires_mock.add.call_args_list, [
            mock.call([fencing_disk1, fencing_disk2, fencing_disk3]),
            ])


class TestVxIOFencing(unittest.TestCase):
    @mock.patch('vcsplugin.vcs_io_fencing_helper.VcsIOFencingHelper.vcs_api')
    @mock.patch('vcsplugin.vcs_io_fencing_helper.log')
    @mock.patch('vcsplugin.vcs_plugin.VcsUtils.wait_on_state')
    def test_success(self, wait_on_state, log, vcs_api):
        wait_on_state.return_value = True
        vcs_io_fencing_helper = VcsIOFencingHelper(None)

        vcs_io_fencing_helper.vx_io_fencing(None, ['mn1', 'mn2'], 'cluster1')

        self.assertEqual(log.event.info.call_args_list, [
            mock.call('Starting Vx Fencing on node "mn1"'),
            mock.call('Starting Vx Fencing on node "mn2"'),
            mock.call('Editing main.cf to use fencing on node "mn1"'),
            mock.call('Editing main.cf to use fencing on node "mn2"'),
            mock.call('Verifying main.cf on node "mn1"'),
            mock.call('Verifying main.cf on node "mn2"'),
            mock.call('Ensure that haconf is read-only on node "mn1"'),
            mock.call('Ensure that haconf is read-only on node "mn2"'),
            mock.call('Stopping VCS on all nodes'),
            mock.call("Successfully stopped VCS on all nodes"),
            mock.call('Starting VCS on node "mn1"'),
            mock.call('Starting VCS on node "mn2"'),
            ])
        self.assertEqual(vcs_api.start_vx_fencing.call_args_list, [mock.call(), mock.call()])
        self.assertEqual(vcs_api.edit_maincf_use_fence.call_args_list, [mock.call('cluster1'), mock.call('cluster1')])
        self.assertEqual(vcs_api.verify_main_cf.call_args_list, [mock.call(), mock.call()])
        self.assertEqual(vcs_api.haconf.call_args_list, [mock.call("dump", read_only="True"), mock.call("dump", read_only="True")])
        self.assertEqual(vcs_api.stop_vcs.call_args_list, [mock.call()])
        self.assertEqual(vcs_api.start_vcs.call_args_list, [mock.call(), mock.call()])

    @mock.patch('vcsplugin.vcs_io_fencing_helper.VcsIOFencingHelper.vcs_api')
    @mock.patch('vcsplugin.vcs_io_fencing_helper.log')
    @mock.patch('vcsplugin.vcs_plugin.VcsUtils.wait_on_state')
    def test_fail(self, wait_on_state, log, vcs_api):
        wait_on_state.return_value = False
        vcs_io_fencing_helper = VcsIOFencingHelper(None)

        self.assertRaises(CallbackExecutionException,
                          vcs_io_fencing_helper.vx_io_fencing,
                          None, ['mn1', 'mn2'], 'cluster1')
        self.assertEqual(log.event.info.call_args_list, [
            mock.call('Starting Vx Fencing on node "mn1"'),
            mock.call('Starting Vx Fencing on node "mn2"'),
            mock.call('Editing main.cf to use fencing on node "mn1"'),
            mock.call('Editing main.cf to use fencing on node "mn2"'),
            mock.call('Verifying main.cf on node "mn1"'),
            mock.call('Verifying main.cf on node "mn2"'),
            mock.call('Ensure that haconf is read-only on node "mn1"'),
            mock.call('Ensure that haconf is read-only on node "mn2"'),
            mock.call('Stopping VCS on all nodes')])

        self.assertEqual(vcs_api.start_vx_fencing.call_args_list, [mock.call(), mock.call()])
        self.assertEqual(vcs_api.edit_maincf_use_fence.call_args_list, [mock.call('cluster1'), mock.call('cluster1')])
        self.assertEqual(vcs_api.verify_main_cf.call_args_list, [mock.call(), mock.call()])
        self.assertEqual(vcs_api.haconf.call_args_list, [mock.call("dump", read_only="True"), mock.call("dump", read_only="True")])
        self.assertEqual(vcs_api.stop_vcs.call_args_list, [mock.call()])


class TestGetVcsApi(unittest.TestCase):

    @mock.patch('vcsplugin.vcs_base_helper.log')
    def test_nodes_not_initialised(self, log):
        vcs_io_fencing_helper = VcsIOFencingHelper(None)
        try:
            vcs_io_fencing_helper.vcs_api()
        except VCSRuntimeException, e:
            pass

        self.assertEqual(log.trace.error.call_args_list, [
            mock.call('Nodes have not been initialised'),
            ])
        self.assertEqual(e.args, ('Nodes have not been initialised',))

    @mock.patch('vcsplugin.vcs_base_helper.VcsCmdApi')
    @mock.patch('vcsplugin.vcs_base_helper.log')
    def test_successs(self, log, vcs_cmd_api_patch):
        vcs_io_fencing_helper = VcsIOFencingHelper(None)
        vcs_io_fencing_helper.nodes = ['mn1', 'mn2']
        vcs_vcs_api_mock = mock.Mock(['set_node'])
        vcs_cmd_api_patch.return_value = vcs_vcs_api_mock

        vcs_api = vcs_io_fencing_helper.vcs_api
        self.assertEqual(vcs_cmd_api_patch.call_args_list, [mock.call(node='mn1')])
        self.assertEqual(vcs_api, vcs_vcs_api_mock)


class TestIOFencingHelper(VCSIntegrationBase):

    def setUp(self):
        super(TestIOFencingHelper, self).setUp()
        self.vcs_io_fencing_helper = VcsIOFencingHelper(VcsPlugin)

    def query(self, item_type=None, **kwargs):
        # Use ModelManager.query to find items in the model
        # properties to match desired item are passed as kwargs.
        # The use of this method is not required, but helps
        # plugin developer mimic the run-time environment
        # where plugin sees QueryItem-s.
        return self.model.query(item_type, **kwargs)

    def test_cluster_with_one_fencing_disk(self):
        # If we have one fencing disk setup in deployment
        # the validation error should be raised
        self.setup_model(num_of_nodes=2, fencing_num=1)
        errors = self.vcs_io_fencing_helper.validate_model(self)
        self.assertEqual(1, len(errors))

    def test_cluster_with_three_fencing_disk_vcs_type(self):
        self.setup_model(num_of_nodes=2, fencing_num=3, vcs_cluster_type="vcs")
        errors = self.vcs_io_fencing_helper.validate_model(self)
        self.assertEqual(1, len(errors))
        expected_errors = "[</deployments/test/clusters/cluster1 - ValidationError - Wrong cluster type. When using I/O fencing, the cluster type must be 'sfha' and not 'vcs'>]"
        self.assertEqual(str(errors), expected_errors)

    def test_cluster_with_fencing_disks_with_duplicate_uuids(self):
        # The disk UUIDs have to be unique for all fencing disks to prevent
        # using the same disk twice as a fancing disk
        self.setup_model(num_of_nodes=2, vcs_cluster_type="sfha")
        cluster_uuids = [1111, 1112, 1112]
        for i in range(0, 3):
            self._add_item_to_model("disk",
                "/deployments/test/clusters/cluster1/fencing_disks/fd%d" % i,
                name='fencing_disk_{0}'.format(i),
                uuid='%d' % cluster_uuids[i], size='1G')
        errors = self.vcs_io_fencing_helper.validate_model(self)
        expected_errors = [
            "</deployments/test/clusters/cluster1/fencing_disks/fd1 - ValidationError - Duplicate disk UUID detected: '1112'. Fencing disk with the same UUID already defined under cluster: 'cluster1'>",
            "</deployments/test/clusters/cluster1/fencing_disks/fd2 - ValidationError - Duplicate disk UUID detected: '1112'. Fencing disk with the same UUID already defined under cluster: 'cluster1'>"]
        self.assertEqual(expected_errors,
            sorted([str(error) for error in errors]))

    def test_clusters_with_duplicate_uuid_fencing_disks_between_clusters(self):
        # We need to make sure there are no disks with duplicate UUIDs
        # between VCS clusters as well
        self.setup_model(num_of_nodes=2, vcs_cluster_type="sfha",
                         num_of_clusters=2)

        cluster1_uuids = [1111, 1112, 1113]
        cluster2_uuids = [1111, 1114, 1115]
        # Setup fencing disks for first cluster
        for i, uuid  in enumerate(cluster1_uuids):
            self._add_item_to_model("disk",
                "/deployments/test/clusters/cluster1/fencing_disks/fd%d" % i,
                name='fencing_disk_{0}'.format(i),
                uuid='%d' % cluster1_uuids[i], size='1G')
        # Setup fencing disks for second cluster
        for i, uuid  in enumerate(cluster2_uuids):
            self._add_item_to_model("disk",
                "/deployments/test/clusters/cluster2/fencing_disks/fd%d" % i,
                name='fencing_disk_{0}'.format(i),
                uuid='%d' % cluster2_uuids[i], size='1G')

        errors = self.vcs_io_fencing_helper.validate_model(self)

        expected_errors = [
            "</deployments/test/clusters/cluster1/fencing_disks/fd0 - ValidationError - Duplicate disk UUID detected: '1111'. Fencing disk with the same UUID already defined under cluster: 'cluster2'>",
            "</deployments/test/clusters/cluster2/fencing_disks/fd0 - ValidationError - Duplicate disk UUID detected: '1111'. Fencing disk with the same UUID already defined under cluster: 'cluster1'>"]
        self.assertEqual(expected_errors,
            sorted([str(error) for error in errors]))

    def test_clusters_with_duplicate_uuid_fencing_disks_in_the_model(self):
        # We need to make sure fencing disks uuid are unique accross the model
        self.setup_model(num_of_nodes=2, vcs_cluster_type="sfha",
                         num_of_clusters=2)

        cluster1_uuids = [1111, 1112, 1113]
        # Setup fencing disks for cluster
        for i, uuid  in enumerate(cluster1_uuids):
            self._add_item_to_model("disk",
                "/deployments/test/clusters/cluster1/fencing_disks/fd%d" % i,
                name='fencing_disk_{0}'.format(i),
                uuid='%d' % cluster1_uuids[i], size='1G')
        self._add_item_to_model("disk",
                "/infrastructure/systems/system_1/disks/d1",
                name='disk1',
                uuid='1112', size='1G')
        errors = self.vcs_io_fencing_helper.validate_model(self)
        self.assertEqual(1, len(errors))
        expected_errors = "[</infrastructure/systems/system_1/disks/d1 - ValidationError - Duplicate disk UUID detected:  '1112'. Disk 'disk1' has the same disk UUID.>]"
        self.assertEqual(expected_errors, str(errors))

    def test_cluster_with_fencing_disks_with_no_uuids(self):
        # Test that no errors are thrown if there are three disks with no uuids at create_plan time
        self.setup_model(num_of_nodes=2, vcs_cluster_type="sfha")
        cluster_uuids = [1111, 1112, 1112]
        for i in range(0, 3):
            self._add_item_to_model("disk",
                "/deployments/test/clusters/cluster1/fencing_disks/fd%d" % i,
                name='fencing_disk_{0}'.format(i),
                uuid=None, size='1G')
        errors = self.vcs_io_fencing_helper.validate_model(self)
        self.assertEqual(0, len(errors))
        expected_errors = "[]"
        self.assertEqual(str(errors), expected_errors)

    def test_cluster_with_fencing_disks_two_have_uuids(self):
        # Test that no errors are thrown if there are three disks with one disk
        # has no uuid at create_plan time
        self.setup_model(num_of_nodes=2, vcs_cluster_type="sfha")
        cluster_uuids = [1111, 1112, 1112]
        for i in range(0, 2):
            self._add_item_to_model("disk",
                "/deployments/test/clusters/cluster1/fencing_disks/fd%d" % i,
                name='fencing_disk_{0}'.format(i),
                uuid='10%d' % i, size='1G')
        self._add_item_to_model("disk",
            "/deployments/test/clusters/cluster1/fencing_disks/fd3",
            name='fencing_disk_3',
            uuid=None, size='1G')
        errors = self.vcs_io_fencing_helper.validate_model(self)
        self.assertEqual(0, len(errors))
        expected_errors = "[]"
        self.assertEqual(str(errors), expected_errors)

    def test_only_fencing_disk_uuid_updatable(self):
        # Test that no errors are thrown if UUID is updated
        self.setup_model(num_of_nodes=2, vcs_cluster_type="sfha")
        for i in range(0, 2):
            self._add_item_to_model("disk",
                "/deployments/test/clusters/cluster1/fencing_disks/fd%d" % i,
                name='fencing_disk_{0}'.format(i),
                uuid='10%d' % i, size='1G')
        self._add_item_to_model("disk",
            "/deployments/test/clusters/cluster1/fencing_disks/fd3",
            name='fencing_disk_3',
            uuid=None, size='1G')
        self._set_model_applied()

        self._update_item_in_model(
            "/deployments/test/clusters/cluster1/fencing_disks/fd3",
            uuid='test_uuid_3')

        errors = self.vcs_io_fencing_helper.validate_model(self.context_api)
        self.assertEqual(0, len(errors))
        expected_errors = "[]"
        self.assertEqual(str(errors), expected_errors)
        self._set_model_applied()

        self._update_item_in_model(
            "/deployments/test/clusters/cluster1/fencing_disks/fd3",
            size='1030M')

        errors = self.vcs_io_fencing_helper.validate_model(self.context_api)
        self.assertEqual(1, len(errors))
        expected_errors = '[</deployments/test/clusters/cluster1/fencing_disks/fd3 - ValidationError - Fencing disk: "fencing_disk_3" Only the UUID and storage_container of the Fencing disk can be updated when it is in an "Applied" state>]'
        self.assertEqual(str(errors), expected_errors)


    def test_cluster_with_bootable_fencing_disks(self):
        # Disk used for the fencing should not be bootable
        self.setup_model(num_of_nodes=2, vcs_cluster_type="sfha")
        for i in range(0, 3):
            self._add_item_to_model("disk",
                "/deployments/test/clusters/cluster1/fencing_disks/fd%d" % i,
                name='fencing_disk_{0}'.format(i),
                uuid='10%d' % i, size='1G', bootable='true')
        errors = self.vcs_io_fencing_helper.validate_model(self)
        self.assertEqual(3, len(errors))
        error_msgs = [str(msg) for msg in errors]
        expected_errors = ["</deployments/test/clusters/cluster1/fencing_disks/fd0 - ValidationError - Fencing disk: 'fencing_disk_0' can't be defined as a bootable device>", "</deployments/test/clusters/cluster1/fencing_disks/fd1 - ValidationError - Fencing disk: 'fencing_disk_1' can't be defined as a bootable device>", "</deployments/test/clusters/cluster1/fencing_disks/fd2 - ValidationError - Fencing disk: 'fencing_disk_2' can't be defined as a bootable device>"]
        self.assertEqual(sorted(error_msgs), expected_errors)

    def test_cluster_with_three_fencing_disk(self):
        # When we have 3 fencing create all is fine and we can
        # configure fencing protection for our cluster.
        self.setup_model(num_of_nodes=2, fencing_num=3, vcs_cluster_type="sfha")#also testing with sfha type cluster
        errors = self.vcs_io_fencing_helper.validate_model(self)
        self.assertEqual(0, len(errors))


class TestCheckStoppedNodes(unittest.TestCase):

    @mock.patch('vcsplugin.vcs_io_fencing_helper.VcsRPC')
    @mock.patch('vcsplugin.vcs_io_fencing_helper.log')
    def test_return_code_one(self, log, vcs_rpc_patch):
        vcsrpc_mock = mock.Mock()
        vcs_rpc_patch.return_value = vcsrpc_mock
        vcsrpc_mock.cluster_stopped.return_value = (1, "", "error msg")

        vcs_io_fencing_helper = VcsIOFencingHelper(None)
        nodes = ["mn1", "mn2"]
        stopped = vcs_io_fencing_helper._check_stopped_nodes(nodes)

        self.assertEqual(stopped, False)
        self.assertEqual(log.event.debug.call_args_list, [
            mock.call('VCS is not stopped on node "mn1", error: "error msg", output: ""')])

    @mock.patch('vcsplugin.vcs_io_fencing_helper.VcsRPC')
    @mock.patch('vcsplugin.vcs_io_fencing_helper.log')
    def test_vcscmd_exception(self, log, vcs_rpc_patch):
        vcsrpc_mock = mock.Mock()
        vcs_rpc_patch.return_value = vcsrpc_mock
        vcsrpc_mock.cluster_stopped.side_effect = VcsCmdApiException

        vcs_io_fencing_helper = VcsIOFencingHelper(None)
        nodes = ["mn1", "mn2"]
        stopped = vcs_io_fencing_helper._check_stopped_nodes(nodes)

        self.assertEqual(stopped, False)
        self.assertEqual(log.event.debug.call_args_list, [
            mock.call('VCS is not stopped on node "mn1", error: ""')])

    @mock.patch('vcsplugin.vcs_io_fencing_helper.VcsRPC')
    def test_success(self, vcs_rpc_patch):
        vcsrpc_mock = mock.Mock()
        vcs_rpc_patch.return_value = vcsrpc_mock
        vcsrpc_mock.cluster_stopped.return_value = (0, "", "")

        vcs_io_fencing_helper = VcsIOFencingHelper(None)
        nodes = ["mn1", "mn2"]
        stopped = vcs_io_fencing_helper._check_stopped_nodes(nodes)

        self.assertEqual(stopped, True)
        self.assertEqual(vcsrpc_mock.cluster_stopped.call_count, 2)
