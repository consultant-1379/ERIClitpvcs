import operator
import unittest

from mock import Mock
from mock import patch
from mocks import mock_model_item

from vcsplugin.vcs_utils import (VcsUtils, ShowTimeElapsed,
                                 group, format_list, select_nodes_from_cluster,
                                 select_nodes_from_service,
                                 is_os_reinstall_on_peer_nodes,
                                 is_pre_os_reinstall_on_peer_nodes,
                                 is_ha_manager_only_on_nodes)
from litp.core.execution_manager import PlanStoppedException


from test_vcs_model import tree

class MockVip(object):
    """Mock vip item for testing.
    """
    def __init__(self, ipaddress=None, network_name=None):
        self.ipaddress = ipaddress
        self.network_name = network_name

    def get_vpath(self):
        return 'mock vip vpath'

def truthtable(n):
    """
    Returns a truth table of length n
    """
    if n < 1:
        return [[]]
    subtable = truthtable(n-1)
    return [ row + [v] for row in subtable for v in [False,True] ]


def test_group():
    items = []
    expected = {}
    assert expected == group(items)
    items = [1, 1, 2, 3]
    expected = {
        1: (1, 1),
        2: (2,),
        3: (3,),
    }
    assert expected == group(items)
    items = [{'a': 1}, {'a': 2}, {'a': 1}]
    expected = {
        1: ({'a': 1}, {'a': 1}),
        2: ({'a': 2},),
    }
    assert expected == group(items, key=operator.itemgetter('a'))
    m1 = Mock(attr=2)
    m2 = Mock(attr=1)
    m3 = Mock(attr=2)
    items = [m1, m2, m3]
    expected = {
        1: (m2,),
        2: (m1, m3),
    }
    assert expected == group(items, key=operator.attrgetter('attr'))


def test_format_list_error():
    assert '' == format_list([])

    assert '"vpath1"' == format_list(["vpath1"])

    assert '"vpath1" and "vpath2"' == format_list(['vpath1', 'vpath2'])

    assert '"vpath1", "vpath2" and "vpath3"' == format_list(['vpath1', 'vpath2', 'vpath3'])

    assert '"vpath1", "vpath2", "vpath3" and "vpath4"' == format_list(['vpath2', 'vpath1', 'vpath3', "vpath4"])

    assert '"aaa", "bbb", "ccc" and "zzz"' == format_list(['aaa', 'ccc', 'zzz', 'bbb'])


class TestVcsUtils(unittest.TestCase):

    def test_get_dependency_tree(self):
        cs_item = Mock(item_id='cs1', dependency_list='')
        clustered_service_items = [cs_item]

        dependency_tree = VcsUtils().get_dependency_tree(clustered_service_items)
        expected_dependency_tree = {'cs1': []}

        self.assertEqual(dependency_tree, expected_dependency_tree)

    def test_get_dependency_tree_2(self):
        cs1_item = Mock(item_id='cs1', dependency_list='')
        cs2_item = Mock(item_id='cs2', dependency_list='cs1')
        cs3_item = Mock(item_id='cs3', dependency_list='cs2')
        cs4_item = Mock(item_id='cs4', dependency_list='cs3')
        cs5_item = Mock(item_id='cs5', dependency_list='cs2,cs3')
        cs6_item = Mock(item_id='cs6', dependency_list=None)
        clustered_service_items = [cs1_item, cs2_item, cs3_item, cs4_item,
                                   cs5_item, cs6_item]

        dependency_tree = VcsUtils().get_dependency_tree(clustered_service_items)
        expected_dependency_tree = {'cs1': [],
                                    'cs2': ['cs1'],
                                    'cs3': ['cs2'],
                                    'cs4': ['cs3'],
                                    'cs5': ['cs2', 'cs3'],
                                    'cs6': [],
                                    }

        self.assertEqual(dependency_tree, expected_dependency_tree)

    def test_get_dependency_tree_initial_deps(self):
        cs1_item = Mock(item_id='cs1', dependency_list='', initial_online_dependency_list=None)
        cs2_item = Mock(item_id='cs2', dependency_list='cs1', initial_online_dependency_list='')
        cs3_item = Mock(item_id='cs3', dependency_list='cs2', initial_online_dependency_list='cs1')
        cs4_item = Mock(item_id='cs4', dependency_list='cs3', initial_online_dependency_list=None)
        cs5_item = Mock(item_id='cs5', dependency_list='cs2,cs3', initial_online_dependency_list='cs4')
        cs6_item = Mock(item_id='cs6', dependency_list=None, initial_online_dependency_list='')
        clustered_service_items = [cs1_item, cs2_item, cs3_item, cs4_item,
                                   cs5_item, cs6_item]

        dependency_tree = VcsUtils().get_dependency_tree(clustered_service_items, include_initial_deps=True)
        expected_dependency_tree = {'cs1': [],
                                    'cs2': ['cs1'],
                                    'cs3': ['cs2', 'cs1'],
                                    'cs4': ['cs3'],
                                    'cs5': ['cs2', 'cs3', 'cs4'],
                                    'cs6': [],
                                    }

        self.assertEqual(dependency_tree, expected_dependency_tree)

    def test_order_service_creation(self):
        ordered_item_ids = ['cs2', 'cs3', 'cs1']
        clustered_service_1 = Mock(item_id='cs1')
        clustered_service_2 = Mock(item_id='cs2')
        clustered_service_3 = Mock(item_id='cs3')
        clustered_service_items = [clustered_service_1, clustered_service_2, clustered_service_3]

        expected_ordered_sg_creation = [clustered_service_2, clustered_service_3, clustered_service_1]
        ordered_sg_creation = VcsUtils()._order_service_creation(
            ordered_item_ids, clustered_service_items)

        self.assertEqual(ordered_sg_creation, expected_ordered_sg_creation)

    def test_get_ordered_sg_creation(self):
        vcs_utils = VcsUtils()
        dependency_tree = {'cs6': [], 'cs5': [], 'cs4': ['cs5'], 'cs3': ['cs4'],
                           'cs2': ['cs3'], 'cs1': ['cs2', 'cs3']}
        vcs_utils.get_dependency_tree = Mock(return_value=dependency_tree)
        vcs_utils._order_service_creation = Mock(return_value='mapped_items')
        order = vcs_utils.get_ordered_sg_creation([])

        self.assertEqual(order, 'mapped_items')
        expected_order = ['cs5', 'cs6', 'cs4', 'cs3', 'cs2', 'cs1']
        vcs_utils._order_service_creation.assert_called_with(expected_order, [])
        vcs_utils.get_dependency_tree.assert_called_once_with([], include_initial_deps=True)

    def test_get_ordered_sg_creation_check_for_removal(self):
        clustered_service_1 = Mock(item_id='cs1', dependency_list='', initial_online_dependency_list='', is_for_removal=lambda: False)
        clustered_service_2 = Mock(item_id='cs2', dependency_list='cs1', initial_online_dependency_list='', is_for_removal=lambda: False)
        clustered_service_3 = Mock(item_id='cs3', dependency_list='cs2', initial_online_dependency_list='', is_for_removal=lambda: True)
        clustered_service_items = [clustered_service_1, clustered_service_2, clustered_service_3]
        expected_order = [clustered_service_1, clustered_service_2]

        vcs_utils = VcsUtils()
        order = vcs_utils.get_ordered_sg_creation(clustered_service_items)
        self.assertEquals(expected_order, order)

    def test_get_ordered_sg_removal(self):
        vcs_utils = VcsUtils()
        applied_dependency_tree = {u'cs5': [], u'cs4': [], u'cs7': [u'cs6'],
                                   u'cs6': [], u'cs1': [], u'cs3': [u'cs1', u'cs2'], u'cs2': [u'cs1']}
        vcs_utils.get_dependency_tree_applied = Mock(return_value=applied_dependency_tree)
        vcs_utils._order_service_creation = Mock(return_value='mapped_items')
        order = vcs_utils.get_ordered_sg_removal([])

        self.assertEqual(order, 'mapped_items')
        expected_order = ['cs1', 'cs4', 'cs5', 'cs6', 'cs2', 'cs7', 'cs3']
        vcs_utils._order_service_creation.assert_called_with(expected_order, [], reverse=True)
        vcs_utils.get_dependency_tree_applied.assert_called_once_with([])

    def test_get_dependency_tree_applied(self):
        cs1_item = Mock(item_id='cs1', applied_properties={})
        cs2_item = Mock(item_id='cs2', applied_properties={})
        cs2_item.applied_properties['dependency_list'] = "cs1"
        cs3_item = Mock(item_id='cs3', applied_properties={})
        cs3_item.applied_properties['dependency_list'] = None
        cs4_item = Mock(item_id='cs4', applied_properties={})
        cs4_item.applied_properties['dependency_list'] = "cs1,cs2"
        cs5_item = Mock(item_id='cs5', applied_properties={})
        cs5_item.applied_properties['dependency_list'] = "cs1,cs2,cs3"
        cs6_item = Mock(item_id='cs6', applied_properties={})
        cs6_item.applied_properties['dependency_list'] = ""

        clustered_service_items = [cs1_item, cs2_item, cs3_item, cs4_item,
                                   cs5_item, cs6_item]
        dependency_tree = VcsUtils().get_dependency_tree_applied(clustered_service_items)
        expected_dependency_tree = {'cs1': [],
                                    'cs2': ['cs1'],
                                    'cs3': [],
                                    'cs4': ['cs1', 'cs2'],
                                    'cs5': ['cs1', 'cs2', 'cs3'],
                                    'cs6': [],
                                    }
        self.assertEqual(dependency_tree, expected_dependency_tree)

    def test_get_ordered_sg_creation_no_dependencies(self):
        vcs_utils = VcsUtils()
        dependency_tree = {'cs6': [], 'cs5': [], 'cs3': [], 'cs4': [],
                           'cs2': [], 'cs1': []}
        vcs_utils.get_dependency_tree = Mock(return_value = dependency_tree)
        vcs_utils._order_service_creation = Mock(return_value = 'mapped_items')
        order = vcs_utils.get_ordered_sg_creation([])

        self.assertEqual(order, 'mapped_items')
        expected_order = ['cs1', 'cs2', 'cs3', 'cs4', 'cs5', 'cs6']
        vcs_utils._order_service_creation.called_with(expected_order)

    def test_get_ordered_sg_creation_no_services(self):
        vcs_utils = VcsUtils()
        dependency_tree = {}
        vcs_utils.get_dependency_tree = Mock(return_value = dependency_tree)
        vcs_utils._order_service_creation = Mock(return_value = 'mapped_items')
        order = vcs_utils.get_ordered_sg_creation([])

        self.assertEqual(order, 'mapped_items')
        expected_order = []
        vcs_utils._order_service_creation.called_with(expected_order)


    @patch('vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes')
    def test_select_nodes_from_service(self, mock_is_os_reinstall):
        cluster = tree()
        service = cluster['service']['s1']
        service['nodes']['node1']['hostname'] = 'mn1'
        service['nodes']['node1']['is_for_removal'] = lambda: False
        service['nodes']['node1']['is_initial'] = lambda: False
        service['nodes']['node2']['hostname'] = 'mn2'
        service['nodes']['node2']['is_for_removal'] = lambda: False
        service['nodes']['node2']['is_initial'] = lambda: False
        service.get_cluster = lambda: cluster

        mock_is_os_reinstall.return_value = False
        # Not os_reinstall and mn1 & mn2 are not Initial or For_Removal
        self.assertEqual(select_nodes_from_service(service), ['mn1', 'mn2'])

        # Not os_reinstall and mn1 is For_Removal
        service['nodes']['node1']['is_for_removal'] = lambda: True
        self.assertEqual(select_nodes_from_service(service), ['mn2'])
        # Not os_reinstall and mn1 is For_Removal ms2 is Initial
        service['nodes']['node2']['is_initial'] = lambda: True
        self.assertEqual(select_nodes_from_service(service), [])

        # os_reinstall and mn1 is Initial mn2 is For_Removal
        mock_is_os_reinstall.return_value = True
        self.assertEqual(select_nodes_from_service(service), ['mn2'])

        # os_reinstall and mn1 node is For_Removal
        service['nodes']['node2']['is_initial'] = lambda: False
        self.assertEqual(select_nodes_from_cluster(service), ['mn2'])
        service['nodes']['node2']['is_initial'] = lambda: True
        self.assertEqual(select_nodes_from_service(service), ['mn2'])

        # os_reinstall and both nodes are For_Removal
        service['nodes']['node2']['is_for_removal'] = lambda: True
        self.assertEqual(select_nodes_from_service(service), [])

    def test_is_os_reinstall_on_peer_nodes(self):
        cluster = mock_model_item("/c1", item_type_id="vcs-cluster")
        service = mock_model_item("/service1",
                                  item_type_id="vcs-clustered-service")
        node1 = mock_model_item("/node1", item_type_id="node")
        node2 = mock_model_item("/node2", item_type_id="node")
        upgrade_true = mock_model_item("/upgrade", os_reinstall="true")
        upgrade_false = mock_model_item("/upgrade", os_reinstall="false")

        cluster.get_cluster.return_value = cluster
        cluster.nodes = [node1, node2]
        node1.query.side_effect = [[upgrade_true], [upgrade_false],
                                   [upgrade_true], [], [upgrade_false], []]
        node2.query.side_effect = [[upgrade_true], [upgrade_true],
                                   [upgrade_false], [upgrade_true],
                                   [upgrade_false], []]

        # Assert True if os_reinstall=="true" on any node
        self.assertTrue(is_os_reinstall_on_peer_nodes(cluster))
        self.assertTrue(is_os_reinstall_on_peer_nodes(cluster))
        self.assertTrue(is_os_reinstall_on_peer_nodes(cluster))
        self.assertTrue(is_os_reinstall_on_peer_nodes(cluster))
        # Assert False if os_reinstall!="true" on any node
        self.assertFalse(is_os_reinstall_on_peer_nodes(cluster))
        # Assert False if no upgrade item
        self.assertFalse(is_os_reinstall_on_peer_nodes(cluster))

    @patch('vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes')
    def test_is_pre_os_reinstall_on_peer_nodes(self, mock_is_os_reinstall):
        mock_is_os_reinstall.side_effect = [True, False, True, False]

        cluster = tree()
        # Check options where it's a is_pre_os_reinstall_on_peer_nodes plan
        cluster['is_initial'] = lambda: False
        self.assertTrue(is_pre_os_reinstall_on_peer_nodes(cluster))

        # Check all options where it's not is_pre_os_reinstall_on_peer_nodes
        cluster['is_initial'] = lambda: True
        self.assertFalse(is_pre_os_reinstall_on_peer_nodes(cluster))

        cluster['is_initial'] = lambda: True
        self.assertFalse(is_pre_os_reinstall_on_peer_nodes(cluster))

        cluster['is_initial'] = lambda: False
        self.assertFalse(is_pre_os_reinstall_on_peer_nodes(cluster))

    def test_is_ha_manager_only_on_nodes(self):
        node1 = mock_model_item("/node1", item_type_id="node")
        node2 = mock_model_item("/node2", item_type_id="node")

        upgrade_true = mock_model_item("/upgrade", ha_manager_only="true")
        upgrade_false = mock_model_item("/upgrade", ha_manager_only="false")

        node1.query.side_effect = [[upgrade_true], [upgrade_false],
                                   [upgrade_true], [], [upgrade_false], []]
        node2.query.side_effect = [[upgrade_true], [upgrade_true],
                                   [upgrade_false], [upgrade_true],
                                   [upgrade_false], []]

        mock_api = Mock(query=lambda x: [node1, node2])

        # Assert True if ha_manager_only=="true" on any node
        self.assertTrue(is_ha_manager_only_on_nodes(mock_api))
        self.assertTrue(is_ha_manager_only_on_nodes(mock_api))
        self.assertTrue(is_ha_manager_only_on_nodes(mock_api))
        self.assertTrue(is_ha_manager_only_on_nodes(mock_api))
        # Assert False if ha_manager_only!="true" on any node
        self.assertFalse(is_ha_manager_only_on_nodes(mock_api))
        # Assert False if no upgrade item
        self.assertFalse(is_ha_manager_only_on_nodes(mock_api))

    @patch('time.time')
    @patch('vcsplugin.vcs_utils.ShowTimeElapsed')
    def test_wait_on_state_callback_function_notsuccess(self, show_time_elapsed, time):
        time.side_effect = [0, 0, 61, 123, 181]

        cb_api = Mock()
        cb_api.is_running.return_value = True

        show_time_elapsed = Mock()
        show_time_elapsed.log = Mock(return_value = None)

        vcs_utils = VcsUtils()
        callback_function = Mock(return_value = False)
        callback_function.__name__ = "my_function"

        timing_parameters = Mock()
        timing_parameters.max_wait = 180
        timing_parameters.sleep_function = Mock(return_value = True)
        timing_parameters.sleep_time = 60
        timing_parameters.interruptible = True
        self.assertFalse(
            VcsUtils.wait_on_state(cb_api, callback_function,
                timing_parameters))

    @patch('time.time')
    @patch('vcsplugin.vcs_utils.ShowTimeElapsed')
    def test_wait_on_state_callback_function_success(self, show_time_elapsed, time):
        time.side_effect = [0, 0, 61, 123, 181]

        cb_api = Mock()
        cb_api.is_running.return_value = True

        show_time_elapsed = Mock()
        show_time_elapsed.log = Mock(return_value = None)

        callback_function_value = [True, False, False]
        def callback_function_return(*args):
            return time_value.pop()
        vcs_utils = VcsUtils()
        callback_function = Mock(return_value = callback_function_return)
        callback_function.__name__ = "my_function"

        timing_parameters = Mock()
        timing_parameters.max_wait = 180
        timing_parameters.sleep_function = Mock(return_value = True)
        timing_parameters.sleep_time = 60
        self.assertTrue(
            VcsUtils.wait_on_state(cb_api, callback_function,
                timing_parameters))

    @patch('time.time')
    @patch('vcsplugin.vcs_utils.ShowTimeElapsed')
    def test_wait_on_state_raises_when_litpd_shutting_down(self,
            show_time_elapsed, time):
        time.side_effect = [0, 0, 61, 123, 181]

        cb_api = Mock()
        cb_api.is_running.side_effect = [True, True, False, False, False]

        show_time_elapsed = Mock()
        show_time_elapsed.log = Mock(return_value = None)

        vcs_utils = VcsUtils()
        callback_function = Mock(side_effect = [False, False, False, True, True])
        callback_function.__name__ = "my_function"

        timing_parameters = Mock()
        timing_parameters.max_wait = 180
        timing_parameters.sleep_function = Mock(return_value = True)
        timing_parameters.sleep_time = 60
        timing_parameters.interruptible = True

        self.assertRaises(PlanStoppedException,
            VcsUtils.wait_on_state, cb_api, callback_function,
                timing_parameters)

    @patch('time.time')
    @patch('vcsplugin.vcs_utils.ShowTimeElapsed')
    def test_wait_on_state_does_not_stop_when_interruptible_is_false(self,
            show_time_elapsed, time):
        time.side_effect = [0, 0, 61, 123, 181]

        cb_api = Mock()
        # LITP reports it wants to shut down after 2 calls
        cb_api.is_running.side_effect = [True, True, False, False, False]

        show_time_elapsed = Mock()
        show_time_elapsed.log = Mock(return_value = None)

        vcs_utils = VcsUtils()
        callback_function = Mock(side_effect = [False, False, False, False, False])
        callback_function.__name__ = "my_function"

        timing_parameters = Mock()
        timing_parameters.max_wait = 180
        timing_parameters.sleep_function = Mock(return_value = True)
        timing_parameters.sleep_time = 60
        timing_parameters.interruptible = False

        self.assertFalse(
                vcs_utils.wait_on_state(cb_api, callback_function,
                    timing_parameters))

    def test_get_service_online_time(self):
        service = tree()
        service['online_timeout'] = '200'
        service['offline_timeout'] = '300'
        service['query'] = (lambda _type: {'ha-service-config':
            service['ha_configs']}.get(_type))
        service['ha_configs']['ha_config1']['startup_retry_limit'] = 3
        self.assertEquals(800, VcsUtils.get_service_online_time(service))

    def test_get_service_online_time_no_ha_conf(self):
        service = tree()
        service['online_timeout'] = '200'
        service['offline_timeout'] = '300'
        service['query'] = (lambda _type: {'ha-service-config':
            service['ha_configs']}.get(_type))
        self.assertEquals(200, VcsUtils.get_service_online_time(service))

    def test_attach_child_items_to_task(self):
        vcs_utils = VcsUtils()
        service = Mock()
        mock_task = Mock(model_items=set())
        service.query.side_effect =  [['vip1','vip2'],
                                    ['fs1', 'fs2'],
                                    ['ha1', 'ha2'],
                                    ['app1', 'app2']]

        task = vcs_utils.attach_child_items_to_task(mock_task, service)
        self.assertEqual(8, len(task.model_items))
        test_data = ['vip1','vip2','fs1', 'fs2','ha1', 'ha2', 'app1', 'app2']
        for data in test_data: 
            assert data in list(task.model_items)


class TestShowTimeElapsed(unittest.TestCase):
    @patch('time.time')
    @patch('vcsplugin.vcs_utils.log')
    def test_log(self, log, time):
        # Test 10 seconds have elapsed, therefore log message, next at 20 secs

        # First variable to pop is the start_time
        # Other variable is called in the 'log' method
        time_value = [11, 1]
        def side_effect(*args):
            return time_value.pop()
        time.side_effect= side_effect

        show_elapsed = ShowTimeElapsed('my_function')
        self.assertEqual(show_elapsed.function_name, "my_function")
        self.assertEqual(show_elapsed.start_time, 1)
        self.assertEqual(show_elapsed.step_number, 0)

        show_elapsed.log()
        log.trace.debug.assert_called_once_with('Waiting for my_function. 10 seconds elapsed')

    @patch('time.time')
    @patch('vcsplugin.vcs_utils.log')
    def test_no_log(self, log, time):
        # Test 2 seconds have elapsed, therefore no log message

        # First variable to pop is the start_time
        # Other variable is called in the 'log' method
        time_value = [5, 3]
        def side_effect(*args):
            return time_value.pop()
        time.side_effect= side_effect

        show_elapsed = ShowTimeElapsed('my_function2')
        self.assertEqual(show_elapsed.function_name, "my_function2")
        self.assertEqual(show_elapsed.start_time, 3)
        self.assertEqual(show_elapsed.step_number, 0)

        show_elapsed.log()
        self.assertEqual(log.trace.info.call_count, 0)
