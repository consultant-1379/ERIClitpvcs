##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

# pylint: disable=W0212

import mock
import unittest
from itertools import cycle
mock.patch('litp.core.litp_logging.LitpLogger').start()
hostnamepatch = mock.patch(
    'litp.extensions.core_extension.MSValidator.get_hostname').start()
hostnamepatch.return_value = "ms1"

from vcsplugin.vcs_plugin import (VcsPlugin, LOCK_FUDGE_FACTOR,
                                  SWITCH_TIMEOUT)
from vcsplugin import vcs_plugin
from vcsplugin.vcs_exceptions import VCSRuntimeException, VcsCmdApiException
from base_vcs_integration import VCSIntegrationBase
from litp.core.execution_manager import CallbackExecutionException
from litp.core.task import CallbackTask
from mocks import mock_model_item
from test_vcs_model import tree


class TestLockFailOver(VCSIntegrationBase):

    @mock.patch('vcsplugin.vcs_plugin.VcsPlugin.toggle_nofailover_triggers')
    @mock.patch('vcsplugin.vcs_plugin.VcsRPC', autospec=True)
    def test_lock(self, mco, toggle):
        self.setup_model()
        self._add_service_to_model(1)
        self._set_model_applied()
        self._add_item_to_model(
            'package',
            '/software/items/pkg1',
            name='httpd',
            repository='OS'
        )
        self._add_inherit_to_model(
            '/software/items/pkg1',
            '/deployments/test/clusters/cluster1/nodes/node1/items/pkg1',
        )
        self.execution_manager._validate_model = mock.MagicMock()
        plan = self.execution_manager.create_plan()

        vcs_rpc = mock.MagicMock()
        vcs_rpc.check_evacuated.return_value = (0, "", "")
        mco.return_value = vcs_rpc

        # pylint: disable=E1103
        for task in plan.get_tasks():
            if task.call_type == VcsPlugin.lock_node.__name__:
                task.callback(self.callback_api, *task.args, **task.kwargs)

        vcs_rpc.lock.assert_called_once_with("mn1", '60', '')
        self.assertEqual(1, vcs_rpc.check_evacuated.call_count)

    @mock.patch('vcsplugin.vcs_plugin.PuppetMcoProcessor.disable_puppet')
    @mock.patch('vcsplugin.vcs_plugin.VcsPlugin.toggle_nofailover_triggers')
    @mock.patch('vcsplugin.vcs_plugin.VcsRPC', autospec=True)
    @mock.patch('vcsplugin.vcs_plugin.VcsCmdApi', autospec=True)
    def test_unlock(self, mco, VcsRPC, toggle, disable_puppet):
        self.setup_model()
        self._add_service_to_model(1)
        self._set_model_applied()
        self._add_item_to_model(
            'package',
            '/software/items/pkg1',
            name='httpd',
            repository='OS'
        )
        self._add_inherit_to_model(
            '/software/items/pkg1',
            '/deployments/test/clusters/cluster1/nodes/node1/items/pkg1',
        )
        self.execution_manager._validate_model = mock.MagicMock()
        plan = self.execution_manager.create_plan()

        vcs_cmd_api = mock.MagicMock()
        vcs_rpc = mock.MagicMock()
        mco.return_value = vcs_cmd_api
        VcsRPC.return_value = vcs_rpc
        vcs_cmd_api.probes_pending.return_value = "0"
        vcs_cmd_api.hasys_state.return_value = "RUNNING"

        vcs_rpc.check_cluster_online.return_value = (0, "", "")
#        mco.return_value = {"retcode": 0, "out": "", "err": ""}

        # pylint: disable=E1103
        for task in plan.get_tasks():
            if task.call_type == VcsPlugin.unlock_node.__name__:
                task.callback(self.callback_api, *task.args, **task.kwargs)

        vcs_rpc.unlock.assert_called_once_with("mn1", "70", '')


class TestUnlockPoll(unittest.TestCase):

    def setUp(self):
        self.plugin = vcs_plugin.VcsPlugin()

    @mock.patch('vcsplugin.vcs_plugin.PuppetMcoProcessor.disable_puppet')
    @mock.patch('vcsplugin.vcs_plugin.VcsPlugin.toggle_nofailover_triggers')
    @mock.patch('vcsplugin.vcs_plugin.VcsRPC', autospec=True)
    @mock.patch('vcsplugin.vcs_plugin.VcsCmdApi', autospec=True)
    @mock.patch('vcsplugin.vcs_plugin.VcsBaseHelper', autospec=True)
    @mock.patch('vcsplugin.vcs_plugin.VcsUtils', autospec=True)
    def test_unlock_with_poll(self, vcs_utils, base, mco, VcsRPC, toggle,
                              disable_puppet):
        vcs_cmd_api = mock.MagicMock()
        mco.return_value = vcs_cmd_api

        vcs_rpc = mock.Mock(['unlock', 'check_cluster_online'])
        vcs_rpc.check_cluster_online.return_value = (0, "", "")
        VcsRPC.return_value = vcs_rpc

        callback = mock.MagicMock()

        node = mock.MagicMock()
        node.hostname = "node1"

        cluster = mock.MagicMock()
        base.query_by_vpath.side_effect = [node, cluster]
        vcs_cmd_api.probes_pending.return_value = 0

        vcs_utils.wait_on_state.return_value = True

        self.plugin._probe_nics = mock.MagicMock()

        self.plugin.unlock_node(callback, "/node", "/cluster", 200)

        vcs_rpc.unlock.assert_called_once_with("node1", "70", '')
        mco.assert_has_calls([mock.call("node1"), mock.call("node1")])
        self.assertEqual(2, mco.call_count)

    @mock.patch('vcsplugin.vcs_plugin.VcsUtils', autospec=True)
    def test__probe_nics(self, vcs_utils):
        hostname = "node1"

        vcs_cmd_api = mock.MagicMock()
        vcs_rpc = mock.MagicMock()
        cb_api = mock.Mock()
        cb_api.is_running.return_value = True

        vcs_utils.wait_on_state.return_value = True
        self.plugin._probe_nics(cb_api, vcs_cmd_api, vcs_rpc, hostname)
        self.assertTrue(1)

    @mock.patch('vcsplugin.vcs_plugin.VcsCmdApi', autospec=True)
    @mock.patch('vcsplugin.vcs_plugin.VcsBaseHelper', autospec=True)
    @mock.patch('vcsplugin.vcs_plugin.VcsUtils', autospec=True)
    def test_unlock_with_poll_raises_exception(self, vcs_utils, base, mco):
        vcs_cmd_api = mock.MagicMock()

        def raise_exception():
            raise VcsCmdApiException("RAISE TO THE ROOF")

        vcs_cmd_api.hastatus.side_effect = raise_exception
        mco.return_value = vcs_cmd_api

        callback = mock.MagicMock()

        node = mock.MagicMock()
        node.hostname = "node1"

        cluster = mock.MagicMock()
        base.query_by_vpath.side_effect = [node, cluster]
        vcs_utils.wait_on_state.return_value = False

        vcs_plugin.ENGINE_WAIT_TIMEOUT = 15
        self.assertRaises(CallbackExecutionException,
                          self.plugin.unlock_node,
                          callback,
                          "/node",
                          "/cluster",
                          200)
        mco.assert_called_once_with("node1")
        self.assertEqual(1, mco.call_count)


class TestLockParallel(VCSIntegrationBase):

    @mock.patch('vcsplugin.vcs_plugin.VcsPlugin.toggle_nofailover_triggers')
    @mock.patch('vcsplugin.vcs_plugin.VcsRPC', autospec=True)
    def test_lock(self, mco, toggle):
        self.setup_model()
        self._add_service_to_model(1, active="2", standby="0", no_of_ips=2)
        self._set_model_applied()
        self._add_item_to_model(
            'package',
            '/software/items/pkg1',
            name='httpd',
            repository='OS'
        )
        self._add_inherit_to_model(
            '/software/items/pkg1',
            '/deployments/test/clusters/cluster1/nodes/node1/items/pkg1',
        )
        self.execution_manager._validate_model = mock.MagicMock()
        plan = self.execution_manager.create_plan()

        vcs_rpc = mock.MagicMock()
        vcs_rpc.check_evacuated.return_value = (0, "", "")
        mco.return_value = vcs_rpc
#        mco.return_value = {"retcode": 0, "out": "", "err": ""}

        # pylint: disable=E1103
        for task in plan.get_tasks():
            if task.call_type == VcsPlugin.lock_node.__name__:
                task.callback(self.callback_api, *task.args, **task.kwargs)

        vcs_rpc.lock.assert_called_once_with("mn1", "60", '')
        self.assertEqual(1, vcs_rpc.check_evacuated.call_count)

    @mock.patch('vcsplugin.vcs_plugin.PuppetMcoProcessor.disable_puppet')
    @mock.patch('vcsplugin.vcs_plugin.VcsPlugin.toggle_nofailover_triggers')
    @mock.patch('vcsplugin.vcs_plugin.VcsRPC', autospec=True)
    @mock.patch('vcsplugin.vcs_plugin.VcsCmdApi', autospec=True)
    def test_unlock(self, VcsCmdApi, VcsRPC, toggle, disable_puppet):
        vcs_cmd_api = mock.MagicMock()
        VcsCmdApi.return_value = vcs_cmd_api
        vcs_cmd_api.probes_pending.return_value = "0"
        vcs_cmd_api.hasys_state.return_value = "RUNNING"

        vcs_rpc = mock.MagicMock(["unlock", "check_cluster_online"])
        vcs_rpc.check_cluster_online.return_value = (0, "", "")
        vcs_rpc.probe_all_nics = mock.MagicMock(return_value = (0, "", ""))

        VcsRPC.return_value = vcs_rpc

        self.setup_model()
        self._add_service_to_model(1, active="2", standby="0", no_of_ips=2)
        self._set_model_applied()
        self._add_item_to_model(
             'package',
            '/software/items/pkg1',
            name='httpd',
            repository='OS'
        )
        self._add_inherit_to_model(
            '/software/items/pkg1',
            '/deployments/test/clusters/cluster1/nodes/node1/items/pkg1',
        )
        self.execution_manager._validate_model = mock.MagicMock()
        plan = self.execution_manager.create_plan()

        # pylint: disable=E1103
        for task in plan.get_tasks():
            if task.call_type == VcsPlugin.unlock_node.__name__:
                task.callback(self.callback_api, *task.args, **task.kwargs)

        vcs_rpc.unlock.assert_called_once_with("mn1", "70", '')


class TestLockGeneral(unittest.TestCase):

    def setUp(self):
        self.plugin = VcsPlugin()

    def test_check_evacuated(self):
        vcs_api = mock.MagicMock()
        vcs_api.check_evacuated.return_value = (0, "", "")
        self.plugin._check_evacuated(vcs_api, "node")
        vcs_api.check_evacuated.assert_called_once_with("node")


class TestDifferingClusteredServices(unittest.TestCase):

    def setUp(self):
        self.plugin = VcsPlugin()

    def _create_nodes(self, number_of_nodes):
        nodes = []
        for i in xrange(1, number_of_nodes + 1):
            name = "node{0}".format(i)
            node = mock.MagicMock()
            node.hostname = name
            node.get_vpath.return_value = "/{0}".format(name)
            nodes.append(node)
        return nodes

    @mock.patch('vcsplugin.vcs_plugin.is_failover_standby_node_updated')
    @mock.patch('vcsplugin.vcs_plugin.VcsPlugin.toggle_nofailover_triggers')
    @mock.patch('vcsplugin.vcs_plugin.VcsRPC')
    @mock.patch('vcsplugin.vcs_plugin.VcsBaseHelper.query_by_vpath')
    def test_lock_node(self, base_helper, vcs_rpc, toggle, change_standby):
        change_standby.return_value = False
        vcs_api = mock.MagicMock()
        vcs_rpc.return_value = vcs_api
        self.plugin._validate_cluster_state_is_consistent = mock.Mock()

        nodes = self._create_nodes(4)
        service1 = mock.MagicMock()
        service1.nodes = nodes[0:2]
        service1.is_initial.return_value = False
        service1.item_id = "service1"
        service2 = mock.MagicMock()
        service2.nodes = nodes[2:4]
        service2.is_initial.return_value = False
        service1.item_id = "service2"
        cluster = mock.Mock()
        cluster.item_id = "cluster"
        cluster.services = [service1, service2]

        base_helper.side_effect = [nodes[0], cluster]

        vcs_api.check_evacuated.return_value = (0, "", "")

        self.plugin.lock_node(mock.Mock(), "", "", "60", "")
        self.assertEquals(1, vcs_api.check_evacuated.call_count)


class TestValidateSnapshot(unittest.TestCase):
    def setUp(self):
        self.plugin = VcsPlugin()
        self.context = mock.MagicMock()

    def test_create_snapshot_plan(self):
        snapshot = mock.MagicMock()
        snapshot.is_applied.return_value = True
        self.context.snapshot_action.return_value = 'restore'
        self.context.query.return_value = [snapshot]
        self.plugin._add_hastop_task = mock.MagicMock(return_value=["task1"])

        result = self.plugin.create_snapshot_plan(self.context)
        self.assertEquals(1, len(result))
        self.context.snapshot_action.return_value = 'create'
        snapshot.is_applied.return_value = False
        result = self.plugin.create_snapshot_plan(self.context)
        self.assertEquals(0, len(result))
        self.context.snapshot_action.return_value = 'remove'
        snapshot.is_applied.return_value = True
        result = self.plugin.create_snapshot_plan(self.context)
        self.assertEquals(0, len(result))

    def test_add_hastop_task(self):

        cluster = mock.MagicMock()
        cluster.item_id = 'c1'
        node1 = mock.MagicMock()
        node1.hostname = "node1"
        node1.is_initial.return_value = False
        node2 = mock.MagicMock()
        node2.hostname = "node2"
        node2.is_initial.return_value = False

        cluster.query.return_value = [node1, node2]
        cluster.is_initial.return_value = False

        snapshot_model = mock.MagicMock()
        snapshot_model.query = mock.Mock(return_value=[cluster])
        self.context.snapshot_model = mock.Mock(return_value=snapshot_model)

        result = self.plugin._add_hastop_task(self.context, [])
        self.assertEquals(1, len(result))
        self.assertEquals("cb_stop_vcs", result[0].call_type)
        result = self.plugin._add_hastop_task(self.context, ['c1'])
        self.assertEquals(0, len(result))

    def test_add_hastop_task_with_fencing(self):

        cluster = mock.MagicMock()
        cluster.item_id = 'c1'
        node1 = mock.MagicMock()
        node1.hostname = "node1"
        node1.is_initial.return_value = False
        node2 = mock.MagicMock()
        node2.hostname = "node2"
        node2.is_initial.return_value = False

        cluster.query.return_value = [node1, node2]
        cluster.is_initial.return_value = False
        disk1 = mock.Mock()
        disk1.is_initial.return_value = False
        disk2 = mock.Mock()
        disk2.is_initial.return_value = False
        disk3 = mock.Mock()
        disk3.is_initial.return_value = False
        cluster.fencing_disks = [disk1, disk2, disk3]

        snapshot_model = mock.MagicMock()
        snapshot_model.query = mock.Mock(return_value=[cluster])
        self.context.snapshot_model = mock.Mock(return_value=snapshot_model)

        result = self.plugin._add_hastop_task(self.context, [])
        self.assertEquals(2, len(result))
        self.assertEquals("cb_stop_vcs", result[0].call_type)
        self.assertEquals("cb_stop_vxfen", result[1].call_type)

    def test__add_hastop_task_only_for_applied_nodes(self):
        cluster = mock.MagicMock()
        cluster.item_id = 'c1'
        node1 = mock.MagicMock()
        node1.hostname = "node1"
        node1.is_applied = mock.MagicMock(return_value=True)
        node1.is_initial = mock.MagicMock(return_value=False)
        node2 = mock.MagicMock()
        node2.hostname = "node2"
        node2.is_applied = mock.MagicMock(return_value=True)
        node2.is_initial = mock.MagicMock(return_value=False)
        node3 = mock.MagicMock()
        node3.hostname = "node3"
        node3.is_applied = mock.MagicMock(return_value=False)
        node3.is_updated = mock.MagicMock(return_value=False)
        node3.is_for_removal = mock.MagicMock(return_value=False)
        node3.is_initial = mock.MagicMock(return_value=True)
        node4 = mock.MagicMock()
        node4.hostname = "node4"
        node4.is_applied = mock.MagicMock(return_value=False)
        node4.is_updated = mock.MagicMock(return_value=False)
        node4.is_for_removal = mock.MagicMock(return_value=True)
        node4.is_initial = mock.MagicMock(return_value=False)
        cluster.query.return_value = [node1, node2, node3, node4]
        cluster.is_initial.return_value = False

        snapshot_model = mock.MagicMock()
        snapshot_model.query = mock.Mock(return_value=[cluster])
        self.context.snapshot_model = mock.Mock(return_value=snapshot_model)

        result = self.plugin._add_hastop_task(self.context, [])
        self.assertEquals(1, len(result))
        self.assertEquals("cb_stop_vcs", result[0].call_type)
        #check only three correct nodes in arg passed
        self.assertEquals(['node1', 'node2', 'node4'], result[0].args[0])
        result = self.plugin._add_hastop_task(self.context, ['c1'])
        self.assertEquals(0, len(result))

    def test_stop_vcs_for_non_initial_clusters(self):
        def side_ef1(item_id):
            if item_id == 'vcs-cluster':
                return [cluster_initial, cluster_applied]
            elif item_id == 'node':
                return [node]
        def side_ef2(item_id):
            if item_id == 'vcs-cluster':
                return [cluster_initial, cluster_initial]
            elif item_id == 'node':
                return [node]
        def side_ef3(item_id):
            if item_id == 'vcs-cluster':
                return [cluster_applied, cluster_applied]
            elif item_id == 'node':
                return [node]
        def side_ef_sysq_disk(item_id):
            if item_id == 'disk':
                return [mock.MagicMock()]
        def side_ef_sysq_nodisk(item_id):
            if item_id == 'disk':
                return []
        node = mock.MagicMock(hostname='node')
        node.is_applied.return_value = True
        node.is_initial.return_value = False
        cluster_initial, cluster_applied = mock.MagicMock(), mock.MagicMock()
        cluster_initial.is_initial = mock.MagicMock()
        cluster_initial.is_initial.return_value = True
        node.system.query = mock.MagicMock(side_effect=side_ef_sysq_disk)
        cluster_applied.is_initial = mock.MagicMock()
        cluster_applied.is_initial.return_value = False
        node.system.query = mock.MagicMock(side_effect=side_ef_sysq_disk)
        api = mock.MagicMock()
        snapshot_model = api.snapshot_model()
        snapshot_model.query = mock.MagicMock(side_effect=side_ef1)
        cluster_initial.query = mock.MagicMock(side_effect=side_ef1)
        cluster_applied.query = mock.MagicMock(side_effect=side_ef1)
        self.assertEqual(1, len(self.plugin._add_hastop_task(api, [])))
        cluster_initial.query = mock.MagicMock(side_effect=side_ef2)
        cluster_applied.query = mock.MagicMock(side_effect=side_ef2)
        snapshot_model.query = mock.MagicMock(side_effect=side_ef2)
        self.assertEqual(0, len(self.plugin._add_hastop_task(api, [])))
        snapshot_model.query = mock.MagicMock(side_effect=side_ef3)
        cluster_initial.query = mock.MagicMock(side_effect=side_ef3)
        cluster_applied.query = mock.MagicMock(side_effect=side_ef3)
        self.assertEqual(2, len(self.plugin._add_hastop_task(api, [])))
        node.system.query = mock.MagicMock(side_effect=side_ef_sysq_nodisk)
        self.assertEqual(0, len(self.plugin._add_hastop_task(api, [])))

    @mock.patch('vcsplugin.vcs_plugin.VcsRPC')
    def test_check_offline(self, VcsRPC):
        vcs_rpc = mock.Mock()
        VcsRPC.return_value = vcs_rpc
        vcs_rpc.cluster_stopped.side_effect = [(0, "", ""),
                                               (1, "", ""),
                                               (1, "", ""),
                                               (0, "", ""),
                                               (0, "", ""),
                                               (0, "", "")
                                               ]
        while not self.plugin._check_offline(["mn1", "mn2"]):
            pass
        self.assertEqual(vcs_rpc.cluster_stopped.call_count, 6)

    @mock.patch('vcsplugin.vcs_plugin.VcsRPC')
    @mock.patch('vcsplugin.vcs_plugin.log')
    def test_check_offline_vcs_not_installed(self, log_patch, vcs_rpc_patch):
        vcs_rpc = mock.MagicMock()
        vcs_rpc_patch.return_value = vcs_rpc

        vcs_rpc.cluster_stopped.return_value = (0, "", "hastatus: command not found")

        offline = self.plugin._check_offline(["mn1", "mn2"],
                                             ignore_cmd_not_found=True)

        self.assertEqual(vcs_rpc.cluster_stopped.call_count, 2)
        self.assertEqual(offline, True)
        self.assertEqual(log_patch.trace.info.call_args_list, [
            mock.call('Checked for VCS offline, but VCS is not installed on '
                      'node: "mn1". Message: "hastatus: command not found"'),
            mock.call('Checked for VCS offline, but VCS is not installed on '
                      'node: "mn2". Message: "hastatus: command not found"')])


class TestRebootCheck(unittest.TestCase):

    def test_vcs_poll(self):
        api = mock.MagicMock()
        api.hastatus.return_value = "VCS ERROR V-16-1-10600 Cannot connect "
        plugin = VcsPlugin()
        self.assertFalse(plugin._vcs_poll(api))
        api.hastatus.return_value = "VCS WARNING V-16-1-11030 HAD not ready "
        self.assertFalse(plugin._vcs_poll(api))
        api.hastatus.return_value = "iuhafuhsaoiufenliaewwq poiyuhfewihfpiuwe"
        self.assertTrue(plugin._vcs_poll(api))

    def test_node_state_poll(self):
        def raise_exception(hostname):
            raise VcsCmdApiException("RAISE TO THE ROOF")

        api = mock.MagicMock()
        api.hasys_state.side_effect = raise_exception
        plugin = VcsPlugin()

        self.assertFalse(plugin._node_state_poll(api, 'mn1'))
        api.hastatus.return_value = "RUNNING"
        self.assertTrue(plugin._vcs_poll(api))

class TestGetLockTimeHelpers(unittest.TestCase):

    def setUp(self):
        self.plugin = VcsPlugin()

    def test__get_lock_timeout(self):
        cluster = tree()
        cs1 = tree()
        cs1['is_initial'] = lambda: False
        cs1['online_timeout'] = '200'
        cs1['offline_timeout'] = '300'
        cs1['query'] = (lambda _type: {'ha-service-config':
            cs1['ha_configs']}.get(_type))
        cs1['ha_configs']['ha_cfg1']['startup_retry_limit'] = 3
        cluster['services']['cs1'] = cs1
        self.assertEquals(1100 + LOCK_FUDGE_FACTOR + SWITCH_TIMEOUT,
                self.plugin._get_lock_timeout(cluster))

    def test__get_lock_timeout_no_startup_retries(self):
        cluster = tree()
        cs1 = tree()
        cs1['is_initial'] = lambda: False
        cs1['online_timeout'] = '200'
        cs1['offline_timeout'] = '300'
        cs1['query'] = (lambda _type: {'ha-service-config':
            cs1['ha_configs']}.get(_type))
        cs1['ha_configs'] = []
        cluster['services']['cs1'] = cs1
        self.assertEquals(500 + LOCK_FUDGE_FACTOR + SWITCH_TIMEOUT,
                self.plugin._get_lock_timeout(cluster))


    @mock.patch("vcsplugin.vcs_plugin.is_os_reinstall_on_peer_nodes")
    def test__get_lock_timeout_ignores_initial(self, is_os_reinstall_mock):
        cluster = tree()
        cs1 = tree()
        is_os_reinstall_mock.return_value = False
        cluster['services']['cs1'] = cs1
        cs1['is_initial'] = lambda: False
        cs1['applied_properties_determinable'] = True
        cs1['online_timeout'] = '200'
        cs1['offline_timeout'] = '300'
        cs1['query'] = (lambda _type: {'ha-service-config':
            cs1['ha_configs']}.get(_type))
        cs1['ha_configs']['ha_cfg1']['startup_retry_limit'] = 3

        cs2 = tree()
        cluster['services']['cs2'] = cs2
        cs2['is_initial'] = lambda: True
        cs2['applied_properties_determinable'] = True
        cs2['online_timeout'] = '400'
        cs2['offline_timeout'] = '300'
        cs2['query'] = (lambda _type: {'ha-service-config':
            cs1['ha_configs']}.get(_type))
        cs2['ha_configs']['ha_cfg2']['startup_retry_limit'] = 6
        # If cs2 was really there, we'd have 2800 + LOCK_FUDGE_FACTOR
        self.assertEquals(1100 + LOCK_FUDGE_FACTOR + SWITCH_TIMEOUT,
                          self.plugin._get_lock_timeout(cluster))

    @mock.patch("vcsplugin.vcs_plugin.is_os_reinstall_on_peer_nodes")
    def test__get_lock_timeout_os_reinstall_false(self, is_os_reinstall_mock):
        cluster = tree()
        cs1 = tree()
        is_os_reinstall_mock.return_value = False
        cluster['services']['cs1'] = cs1
        cs1['is_initial'] = lambda: True
        cs1['applied_properties_determinable'] = True
        self.assertEquals( LOCK_FUDGE_FACTOR + SWITCH_TIMEOUT,
                          self.plugin._get_lock_timeout(cluster))

    def test__get_lock_timeout_initial_no_determinable(self):
        cluster = tree()
        cs1 = tree()
        cluster['services']['cs1'] = cs1
        cs1['is_initial'] = lambda: False
        cs1['applied_properties_determinable'] = False
        cs1['online_timeout'] = '200'
        cs1['offline_timeout'] = '300'
        cs1['query'] = (lambda _type: {'ha-service-config':
                                           cs1['ha_configs']}.get(_type))
        cs1['ha_configs']['ha_cfg1']['startup_retry_limit'] = 3

        cs2 = tree()
        cluster['services']['cs2'] = cs2
        cs2['is_initial'] = lambda: True
        cs2['applied_properties_determinable'] = False
        cs2['online_timeout'] = '400'
        cs2['offline_timeout'] = '300'
        cs2['query'] = (lambda _type: {'ha-service-config':
                                           cs1['ha_configs']}.get(_type))
        cs2['ha_configs']['ha_cfg2']['startup_retry_limit'] = 6
        # If cs2 was really there, we'd have 2800 + LOCK_FUDGE_FACTOR
        self.assertEquals(1900 + LOCK_FUDGE_FACTOR  + SWITCH_TIMEOUT,
                          self.plugin._get_lock_timeout(cluster))

    def test__get_lock_timeout_with_no_groups(self):
        cluster = tree()
        cluster['services'] = []
        self.assertEquals(LOCK_FUDGE_FACTOR + SWITCH_TIMEOUT,
                self.plugin._get_lock_timeout(cluster))

    def test__get_unlock_timeout(self):
        cluster = tree()
        cs1 = tree()
        cs1['is_initial'] = lambda: False
        cs1['online_timeout'] = '200'
        cs1['offline_timeout'] = '300'
        cs1['query'] = (lambda _type: {'ha-service-config':
            cs1['ha_configs']}.get(_type))
        cs1['ha_configs']['ha_cfg1']['startup_retry_limit'] = 3
        cluster['services']['cs1'] = cs1
        self.assertEquals(800 + LOCK_FUDGE_FACTOR,
                self.plugin._get_unlock_timeout(cluster))

    def test__get_unlock_timeout_no_retries(self):
        cluster = tree()
        cs1 = tree()
        cs1['is_initial'] = lambda: False
        cs1['online_timeout'] = '200'
        cs1['offline_timeout'] = '300'
        cs1['query'] = (lambda _type: {'ha-service-config':
            cs1['ha_configs']}.get(_type))
        cs1['ha_configs'] = []
        cluster['services']['cs1'] = cs1
        self.assertEquals(200 + LOCK_FUDGE_FACTOR,
                self.plugin._get_unlock_timeout(cluster))

    def test__get_unlock_timeout_with_no_groups(self):
        cluster = tree()
        cluster['services'] = []
        self.assertEquals(LOCK_FUDGE_FACTOR,
                self.plugin._get_unlock_timeout(cluster))


    @mock.patch("vcsplugin.vcs_plugin.is_os_reinstall_on_peer_nodes")
    def test__get_unlock_timeout_ignores_initial(self, is_os_reinstall_mock):
        cluster = tree()
        cs1 = tree()
        is_os_reinstall_mock.return_value = False
        cluster['services']['cs1'] = cs1
        cs1['is_initial'] = lambda: False
        cs1['applied_properties_determinable'] = True
        cs1['online_timeout'] = '200'
        cs1['offline_timeout'] = '300'
        cs1['query'] = (lambda _type: {'ha-service-config':
            cs1['ha_configs']}.get(_type))
        cs1['ha_configs']['ha_cfg1']['startup_retry_limit'] = 3

        cs2 = tree()
        cluster['services']['cs2'] = cs2
        cs2['is_initial'] = lambda: True
        cs2['applied_properties_determinable'] = True
        cs2['online_timeout'] = '400'
        cs2['offline_timeout'] = '300'
        cs2['query'] = (lambda _type: {'ha-service-config':
            cs1['ha_configs']}.get(_type))
        cs2['ha_configs']['ha_cfg2']['startup_retry_limit'] = 6
        # If cs2 was really there, we'd have 2400 + LOCK_FUDGE_FACTOR
        self.assertEquals(800 + LOCK_FUDGE_FACTOR,
                self.plugin._get_unlock_timeout(cluster))

    @mock.patch("vcsplugin.vcs_plugin.is_os_reinstall_on_peer_nodes")
    def test__get_unlock_timeout_os_reinstall_true(self, is_os_reinstall_mock):
        cluster = tree()
        cs1 = tree()
        is_os_reinstall_mock.return_value = True
        cluster['services']['cs1'] = cs1
        cs1['is_initial'] = lambda: True
        cs1['applied_properties_determinable'] = True
        cs1['online_timeout'] = '200'
        cs1['query'] = (lambda _type: {'ha-service-config':
            cs1['ha_configs']}.get(_type))
        cs1['ha_configs']['ha_cfg1']['startup_retry_limit'] = 3
        self.assertEquals(800 + LOCK_FUDGE_FACTOR,
                self.plugin._get_unlock_timeout(cluster))

    def test__get_unlock_timeout_initial_no_determinable(self):
        cluster = tree()
        cs1 = tree()
        cluster['services']['cs1'] = cs1
        cs1['is_initial'] = lambda: False
        cs1['applied_properties_determinable'] = False
        cs1['online_timeout'] = '200'
        cs1['offline_timeout'] = '300'
        cs1['query'] = (lambda _type: {'ha-service-config':
            cs1['ha_configs']}.get(_type))
        cs1['ha_configs']['ha_cfg1']['startup_retry_limit'] = 3

        cs2 = tree()
        cluster['services']['cs2'] = cs2
        cs2['is_initial'] = lambda: True
        cs2['applied_properties_determinable'] = False
        cs2['online_timeout'] = '400'
        cs2['offline_timeout'] = '300'
        cs2['query'] = (lambda _type: {'ha-service-config':
            cs1['ha_configs']}.get(_type))
        cs2['ha_configs']['ha_cfg2']['startup_retry_limit'] = 6
        # If cs2 was really there, we'd have 2400 + LOCK_FUDGE_FACTOR
        self.assertEquals(1600 + LOCK_FUDGE_FACTOR,
                self.plugin._get_unlock_timeout(cluster))

    def test__remove_dependencies_first(self):
        task1 = mock.Mock(kwargs={'callback_func':''},
                          is_deconfigure=lambda: True,  requires=set([]))
        task2 = mock.Mock(kwargs={'callback_func':''},
                          is_deconfigure=lambda: False, requires=set([]))
        task3 = mock.Mock(kwargs={'callback_func':
                                  'update_remove_dependencies_callback'},
                          requires=set([]))
        tasks = [task1, task2, task3]

        tasks = self.plugin._remove_dependencies_first(tasks)

        self.assertEquals(task1.requires, set([]))
        self.assertEquals(task2.requires, set([task3]))
        self.assertEquals(task3.requires, set([]))

    @mock.patch('vcsplugin.vcs_plugin.is_clustered_service_redeploy_required')
    @mock.patch('vcsplugin.vcs_plugin.VcsUtils.get_parent_with_type')
    def test_toggle_nofailover(self, get_parent_mock, redeploy_mock):
        vcs_api_mock = mock.Mock()
        vcs_api_mock.readable_conf = mock.MagicMock()
        vcs_api_mock.hagrp_add_in_triggers_enabled = mock.Mock()
        vcs_api_mock.hagrp_delete_in_triggers_enabled = mock.Mock()
        node = mock.Mock(item_id="n1")
        cluster = mock.Mock(item_id="c1")
        s1 = mock.Mock(item_id="svc1",
                       node_list="n1,n2",
                       triggers=[],
                       is_initial=mock.Mock(return_value=False),
                       is_for_removal=mock.Mock(return_value=False),
                       is_removed=mock.Mock(return_value=False))
        t2 = mock.Mock(trigger_type="nofailover",
                       is_initial=mock.Mock(return_value=False),
                       is_for_removal=mock.Mock(return_value=False),
                       is_removed=mock.Mock(return_value=False))
        s2 = mock.Mock(item_id="svc2",
                       node_list="n1,n2",
                       triggers=[t2],
                       is_initial=mock.Mock(return_value=False),
                       is_for_removal=mock.Mock(return_value=False),
                       is_removed=mock.Mock(return_value=False))
        cluster.services = [s1, s2]
        get_parent_mock.return_value =  cluster
        redeploy_mock.return_value = False
        self.plugin.toggle_nofailover_triggers(vcs_api_mock, node, enable=True)
        self.assertEqual(1, get_parent_mock.call_count)
        self.assertEqual(1,
                         vcs_api_mock.hagrp_add_in_triggers_enabled.call_count)
        self.assertEqual(0,
                         vcs_api_mock.hagrp_delete_in_triggers_enabled.call_count)

    @mock.patch('vcsplugin.vcs_plugin.is_clustered_service_redeploy_required')
    @mock.patch('vcsplugin.vcs_plugin.VcsUtils.get_parent_with_type')
    def test_toggle_nofailover_trigger_initial(self, get_parent_mock, redeploy_mock):
        vcs_api_mock = mock.Mock()
        vcs_api_mock.readable_conf = mock.MagicMock()
        vcs_api_mock.hagrp_add_in_triggers_enabled = mock.Mock()
        vcs_api_mock.hagrp_delete_in_triggers_enabled = mock.Mock()
        node = mock.Mock(item_id="n1")
        cluster = mock.Mock(item_id="c1")
        s1 = mock.Mock(item_id="svc1",
                       node_list="n1,n2",
                       triggers=[],
                       is_initial=mock.Mock(return_value=False),
                       is_for_removal=mock.Mock(return_value=False))
        t2 = mock.Mock(trigger_type="nofailover",
                       is_initial=mock.Mock(return_value=True),
                       is_for_removal=mock.Mock(return_value=False),
                       is_removedl=mock.Mock(return_value=False))
        s2 = mock.Mock(item_id="svc2",
                       node_list="n1,n2",
                       triggers=[t2],
                       is_initial=mock.Mock(return_value=False),
                       is_for_removal=mock.Mock(return_value=False))
        cluster.services = [s1, s2]
        get_parent_mock.return_value = cluster
        redeploy_mock.return_value = False
        self.plugin.toggle_nofailover_triggers(vcs_api_mock, node, enable=True)
        self.assertEqual(1, get_parent_mock.call_count)
        self.assertEqual(0,
                         vcs_api_mock.hagrp_add_in_triggers_enabled.call_count)
        self.assertEqual(0,
                         vcs_api_mock.hagrp_delete_in_triggers_enabled.call_count)

    @mock.patch('vcsplugin.vcs_plugin.is_ha_manager_only_on_nodes')
    @mock.patch('vcsplugin.vcs_plugin.log')
    def test_is_ha_manager_only_flag_set(self, log_patch, mock_is_ha_manager_only):
        node1 = mock.Mock(hostname='mn1')
        node2 = mock.Mock(hostname='mn2')

        cluster = mock.Mock()
        cluster.app_agent_num_threads = 10
        cluster.nodes = [node1, node2]

        cluster_b = mock.Mock()
        cluster_b.app_agent_num_threads = None
        cluster_b.nodes = [node1, node2]

        cluster_c = mock.Mock()
        cluster_c.app_agent_num_threads = 11
        cluster_c.nodes = [node1, node2]

        cluster_d = mock.Mock()
        cluster_d.app_agent_num_threads = 13
        cluster_d.nodes = [node1, node2]

        clusters_mock = [cluster, cluster_b, cluster_c]

        vcs_plug = VcsPlugin()
        api_mock = mock.Mock()
        api_mock.query = mock.Mock(return_value=clusters_mock)
        mock_is_ha_manager_only.return_value = True
        tasks = vcs_plug.create_configuration(api_mock)

        self.assertEqual(log_patch.trace.debug.call_args_list, [])
        self.assertEqual(2, len(tasks))
        self.assertEqual(1, mock_is_ha_manager_only.call_count)
