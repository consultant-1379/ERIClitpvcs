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
import unittest

from litp.core.execution_manager import CallbackExecutionException
from vcsplugin.vcs_plugin import VcsPlugin
from vcsplugin.vcs_online_helper import VcsSGOnlineHelper
from vcsplugin.vcs_exceptions import VcsCmdApiException
from vcsplugin.vcs_utils import TimeoutParameters
from test_vcs_utils import truthtable


class Service(object):
    online_timeout = '10'
    node_list = ['n1','n2']
    node = mock.Mock()
    node.hostname = "mn1"
    nodes = [node]
    active = "2"
    standby = "0"
    applied_properties = {}
    applied_properties_determinable = True
    dependencies =[]
    item_id ='cs1'
    state = 'Initial'

    def init(self):
        pass


class TestOnlineHelper(unittest.TestCase):

    def setUp(self):
        super(TestOnlineHelper, self).setUp()

    @mock.patch('vcsplugin.vcs_online_helper.VcsSGOnlineHelper.get_group_name')
    @mock.patch("vcsplugin.vcs_online_helper.VcsUtils.attach_child_items_to_task")
    @mock.patch("litp.core.execution_manager.CallbackTask")
    def test_generate_online_task(self, call_back_task, child_items, group_name):

        def child_items_impl(task, service):
            return task

        vcs_online_helper = VcsSGOnlineHelper(VcsPlugin)
        cluster = mock.Mock()
        service = mock.Mock()
        service.get_vpath.return_value = '/deployments/test/clusters/cluster1/services/cs1'
        group_name.return_value = 'Grp_CS_cluster1_cs1'

        task = mock.Mock()
        task.kwargs={'callback_class': 'VcsSGOnlineHelper',
                        'callback_func': 'online_callback'}
        call_back_task.return_value = task
        child_items.side_effect = child_items_impl

        online_task = vcs_online_helper._generate_online_task( cluster, service)

        self.assertEquals(online_task.call_type, 'callback_method')
        self.assertEquals(online_task.kwargs['callback_class'], 'VcsSGOnlineHelper')
        self.assertEquals(online_task.kwargs['vcs_grp_name'],  'Grp_CS_cluster1_cs1')
        self.assertEquals(online_task.kwargs['callback_func'],  'online_callback')
        self.assertEquals(online_task.kwargs['service_vpath'],
                          '/deployments/test/clusters/cluster1/services/cs1')
        self.assertEquals(online_task.state, 'Initial')

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    @mock.patch('vcsplugin.vcs_base_helper.is_clustered_service_redeploy_required')
    @mock.patch('vcsplugin.vcs_base_helper.is_clustered_service_expansion')
    @mock.patch('vcsplugin.vcs_online_helper.is_being_deactivated')
    @mock.patch('vcsplugin.vcs_base_helper.VcsBaseHelper.added_node_hostnames')
    @mock.patch('vcsplugin.vcs_online_helper.VcsSGOnlineHelper._generate_online_task')
    def test_create_configuration(self, online_task, added_nodes,
                                  is_being_deact, node_count, redeploy, mock_os_reinstall):
        online_task.return_value = 'task'
        added_nodes.return_value = ['n2']
        is_being_deact.return_value = False

        for test_vector in truthtable(8):

            cluster = mock.Mock()
            service = mock.Mock()
            service.node_list = 'n1,n2'
            service.standby = '1'
            service.applied_properties = {'standby': '1', 'node_list': 'n1'}
            app = mock.Mock()
            service.applications = [app]
            service.ipaddresses = []
            vcs_online_helper = VcsSGOnlineHelper(VcsPlugin)

            service.is_for_removal = mock.Mock(return_value= test_vector[0])
            service.is_initial = mock.Mock(return_value= test_vector[1])
            cluster.cs_initial_online = 'on' if test_vector[2] == True else 'off'
            app.is_initial = mock.Mock(return_value= test_vector[3])
            service.runtimes.has_initial_dependencies = mock.Mock(return_value= test_vector[4])
            node_count.return_value = test_vector[5]
            redeploy.return_value = test_vector[6]
            mock_os_reinstall.return_value = False
            service.applied_properties_determinable = test_vector[7]
            inf = mock.Mock()
            inf.query = mock.Mock(return_value=[])
            context = mock.Mock()
            context.query_by_vpath = mock.Mock(return_value=inf)

            pre_tasks, post_tasks = vcs_online_helper.create_configuration(context, cluster, service)

            if ((not (cluster.cs_initial_online == 'off'))
                and not service.is_for_removal()
                and(app.is_initial()
                    or service.is_initial()
                    or service.runtimes.has_initial_dependencies()
                    or node_count
                    or redeploy
                    or not service.applied_properties_determinable
                    )):
                self.assertEquals(len(post_tasks), 1)
                self.assertEquals(len(pre_tasks), 0)
                # Task returned by create_configuration is the same as _generate_online_task
                self.assertEquals(post_tasks, [online_task.return_value])
                # cluster and service IDs are the same as the originally created mocked items
                online_task.assert_called_with(cluster,service)

            else:
                self.assertEquals(len(post_tasks), 0)
                self.assertEquals(len(pre_tasks), 0)

    @mock.patch("vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes")
    @mock.patch("vcsplugin.vcs_online_helper.VcsUtils.wait_on_state")
    @mock.patch("vcsplugin.vcs_online_helper.VcsUtils.get_service_online_time")
    def test_online_callback1(self, mock_get_online_time, mock_wait_on_state,
                             mock_os_reinstall):
        service = Service()
        service.get_cluster = lambda: 'foo'
        callback_api = mock.Mock()
        callback_api.query_by_vpath = mock.Mock(return_value=service)
        vcs_grp_name = "Group1"
        service_vpath = "vpath"
        vcs_cmd_api = mock.Mock()
        vcs_cmd_api.probes_pending = mock.Mock(return_value='0')
        vcs_cmd_api.bring_hagrp_online = mock.Mock(return_value=["node1"])
        vcs_online_helper = VcsSGOnlineHelper(VcsPlugin)
        vcs_online_helper._vcs_api = vcs_cmd_api
        mock_get_online_time.return_value = "mocktime"
        mock_wait_on_state.return_value = True
        mock_os_reinstall.return_value = False

        vcs_online_helper.online_callback(callback_api,
                                          vcs_grp_name,
                                          service_vpath)
        self.assertEquals(vcs_cmd_api.check_main_cf_is_readonly.call_count, 1)

        vcs_cmd_api.check_vcs_group_has_resources.assert_called_once_with('Group1')
        self.assertEquals(vcs_cmd_api.check_main_cf_is_readonly.call_count, 1)
        self.assertEquals(vcs_cmd_api.verify_main_cf.call_count, 1)
        vcs_cmd_api.bring_hagrp_online.assert_called_once_with('Group1')

    def test_bring_service_group_online(self):
        service = Service()
        vcs_cmd_api = mock.MagicMock()
        vcs_online_helper = VcsSGOnlineHelper(VcsPlugin)
        vcs_online_helper._vcs_api = vcs_cmd_api
        with mock.patch("vcsplugin.vcs_online_helper.time.sleep",
                        return_value=None):
            vcs_online_helper.check_for_pending_probes_on_service_group \
                                                  = mock.Mock(return_value='0')
        vcs_online_helper.nodes = ["n1"]
        vcs_cmd_api.bring_hagrp_online = mock.Mock(return_value=[])
        vcs_online_helper._bring_service_group_online(service, "Grp1")

    def test_successfully_check_for_pending_probes_on_service_group(self):
        vcs_cmd_api = mock.Mock()
        vcs_online_helper = VcsSGOnlineHelper(VcsPlugin)
        vcs_online_helper._vcs_api = vcs_cmd_api
        vcs_online_helper.nodes = ['MN1', 'MN2']
        vcs_cmd_api.probes_pending = mock.Mock(return_value='0')
        with mock.patch("vcsplugin.vcs_online_helper.time.sleep",
                        return_value=None):
            try:
                vcs_online_helper.check_for_pending_probes_on_service_group(
                                        "GroupA", 60)
            except VcsCmdApiException:
                self.fail("Unexpected exception raised")

    def test_unsuccessfully_check_for_pending_probes_on_service_group(self):
        vcs_online_helper = VcsSGOnlineHelper(VcsPlugin)
        vcs_online_helper.are_there_probes_pending = mock.Mock(return_value=True)
        self.assertRaises(VcsCmdApiException,
                            vcs_online_helper.check_for_pending_probes_on_service_group,
                            "GroupA", '3')

    def test_bring_online_group_successfully(self):
        vcs_online_helper = VcsSGOnlineHelper(VcsPlugin)
        vcs_online_helper._vcs_api = mock.Mock()
        service_gp_name = 'Group1'
        service = Service()
        vcs_online_helper.nodes = ["n1"]
        with mock.patch("vcsplugin.vcs_online_helper.time.sleep",
                        return_value=None):
            vcs_online_helper.check_for_pending_probes_on_service_group \
                = mock.Mock(return_value='0')
        vcs_online_helper.check_service_group_is_running_on_relevant_nodes \
                                                  = mock.Mock(return_value='0')
        vcs_online_helper._bring_service_group_online(service, service_gp_name)
        self.assert_(True)


class TestVcsOnlineHelperPolling(unittest.TestCase):
    def setUp(self):
        self.helper = VcsSGOnlineHelper(mock.MagicMock())
        self.service = Service()
        self.grp_name = "Grp_CS_mock_mock"

    @mock.patch('vcsplugin.vcs_online_helper.VcsSGOnlineHelper.vcs_api')
    def test__check_group_online_not_online(self, _vcs_api):
        _vcs_api.get_group_state.return_value= 'ONLINING'

        self.assertEquals(False, self.helper._check_group_online(
                                            self.service, self.grp_name))
        _vcs_api.get_group_state.assert_called_once_with(
                group_name=self.grp_name,
                active_count=self.service.active,
                offline_count=self.service.standby)

    @mock.patch('vcsplugin.vcs_online_helper.VcsSGOnlineHelper.vcs_api')
    def test__check_group_online_is_online(self, _vcs_api):
        _vcs_api.get_group_state.return_value = 'ONLINE'

        self.assertEquals(True, self.helper._check_group_online(
                                            self.service, self.grp_name))
        _vcs_api.get_group_state.assert_called_once_with(
                group_name=self.grp_name,
                active_count=self.service.active,
                offline_count=self.service.standby)

    @mock.patch("vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes")
    @mock.patch('vcsplugin.vcs_utils.VcsUtils.get_service_online_time')
    @mock.patch('vcsplugin.vcs_online_helper.VcsSGOnlineHelper'
                '._bring_service_group_online')
    @mock.patch('vcsplugin.vcs_online_helper.query_by_vpath')
    @mock.patch('vcsplugin.vcs_utils.VcsUtils.wait_on_state')
    def test_online_callback_pos(self, _wait_on_state, _query,
            _bring_sg_online, _get_online_time, mock_os_reinstall):
        self._wait_on_state = True
        _query.return_value = self.service
        _cb_api = mock.Mock()
        _get_online_time.return_value = 'mock'
        self.service.get_cluster = lambda: 'foo'
        mock_os_reinstall.return_value = False

        self.helper.online_callback(_cb_api, self.grp_name,
                '/mock/vpath')

        _query.assert_called_with(_cb_api, '/mock/vpath')
        _wait_on_state.assert_called_with(_cb_api,
                self.helper._check_group_online,
                TimeoutParameters(max_wait='mock'), self.service,
                self.grp_name)

    @mock.patch("vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes")
    @mock.patch('vcsplugin.vcs_utils.VcsUtils.get_service_online_time')
    @mock.patch('vcsplugin.vcs_online_helper.VcsSGOnlineHelper'
                '._bring_service_group_online')
    @mock.patch('vcsplugin.vcs_online_helper.query_by_vpath')
    @mock.patch('vcsplugin.vcs_utils.VcsUtils.wait_on_state')
    def test_online_callback_raises_on_fault(self, _wait_on_state, _query,
            _bring_sg_online, _get_online_time, mock_os_reinstall):
        _wait_on_state.return_value = False
        _query.return_value = self.service
        _get_online_time.return_value = 'mock'
        _cb_api = mock.Mock()
        self.service.get_cluster = lambda: 'foo'
        mock_os_reinstall.return_value = False

        self.assertRaises(CallbackExecutionException,
                self.helper.online_callback,
                _cb_api,
                self.grp_name,
                '/mock/vpath')
        _wait_on_state.assert_called_with(_cb_api,
                self.helper._check_group_online,
                TimeoutParameters(max_wait='mock'), self.service,
                self.grp_name)
