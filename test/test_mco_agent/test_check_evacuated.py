import unittest
import mock
import sys

sys.path.append('./puppet/mcollective_agents/files')
from vcs_cmd_api import VcsCmdApi

RUN_VCS_CMD_NO_ERROR = {'retcode': 0, 'err': '', 'out': ''}
HEADER_GROUP_DISPLAY = "#Group              Attribute             System     Value\n"
HEADER_GROUP_DEPS = "#Parent          Child            Relationship\n"

ATTRIBUTTE_STATE = "hagrp -display  -attribute State"
GET_SYSTEM_LIST = "hagrp -value Grp_CS_cluster1_cs2 SystemList"
GET_INTENT_ONLINE = "hagrp -value Grp_CS_cluster1_cs2 IntentOnline mn2"
CLEAR = "hagrp -clear Grp_CS_cluster1_cs2 -sys mn1"
GROUP_STATES =("Grp_CS_cluster1_cs2 State      mn1        |{state_node_mn1}| \n"
               "Grp_CS_cluster1_cs2 State     mn2        |{state_node_mn2}| \n")
SYSTEM_LIST_TWO_NODES = "{node_1} 0	{node_2} 0"
SYSTEM_LIST_ONE_NODES = "{node_n} 0"
GET_GROUP_DEPS = "hagrp -dep Grp_CS_cluster1_cs2"
GROUP_DEPS = "Grp_CS_cluster1_cs1 Grp_CS_cluster1_cs2 online global soft"


class TestCheckEvacuated(unittest.TestCase):
    def setUp(self):
        self.api = VcsCmdApi()

    def _request(self, node_to_lock):
        return {"sys":node_to_lock}

    def _side_effect(self, all_cmds):
        def side_effect(arg, expected_errors=[], rewrite_retcode=False):
            return all_cmds[arg]
        return side_effect

    def all_vcs_cmd(self, groups_states, system_list):
        #TODO: replace args groups_states, etc with kwargs
        #add something like add_side_effect
        return {
            ATTRIBUTTE_STATE: (0, HEADER_GROUP_DISPLAY + groups_states, ""),
            GET_SYSTEM_LIST: (0, system_list, ""),
            CLEAR: (0, 0, ""),
            GET_GROUP_DEPS: (0, HEADER_GROUP_DEPS + GROUP_DEPS, "")
        }

    def get_deps_cmd(self, system_list):
        return {
            GET_SYSTEM_LIST: (0, system_list, ""),
            GET_GROUP_DEPS: (0, HEADER_GROUP_DEPS + GROUP_DEPS, "")
        }

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_positive_api_check_evacuated_force_node_lock_false(self, run_vcs_command):
        groups_states = GROUP_STATES.format(state_node_mn1="OFFLINE",
                                            state_node_mn2="ONLINE")
        system_list = SYSTEM_LIST_TWO_NODES.format(node_1="mn1",
                                                   node_2="mn2")
        run_vcs_command.side_effect = self._side_effect(
            self.all_vcs_cmd(groups_states, system_list))

        out = self.api.check_evacuated(
            self._request(node_to_lock="mn1"))

        self.assertEqual(out, RUN_VCS_CMD_NO_ERROR)
        run_vcs_command.assert_has_calls(
            [mock.call(ATTRIBUTTE_STATE, ['VCS WARNING V-16-1-50031 No Groups are configured']),
             mock.call(GET_SYSTEM_LIST),
             mock.call(GET_SYSTEM_LIST)])

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_force_false_no_nodes_in_system_list(self, run_vcs_command):
        groups_states = GROUP_STATES.format(state_node_mn1="OFFLINE",
                                            state_node_mn2="ONLINE")
        system_list = SYSTEM_LIST_TWO_NODES.format(node_1="mn4",
                                                   node_2="mn3")

        run_vcs_command.side_effect = self._side_effect(
            self.all_vcs_cmd(groups_states, system_list))

        out = self.api.check_evacuated(
            self._request(node_to_lock="mn1"))

        self.assertEqual(out, RUN_VCS_CMD_NO_ERROR)
        run_vcs_command.assert_has_calls(
            [mock.call(ATTRIBUTTE_STATE, ['VCS WARNING V-16-1-50031 No Groups are configured']),
             mock.call(GET_SYSTEM_LIST),
             mock.call(GET_SYSTEM_LIST)])

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_force_false_no_nodes_in_system_list_return_false(self, run_vcs_command):
        groups_states = GROUP_STATES.format(state_node_mn1="ONLINE",
                                            state_node_mn2="OFFLINE")
        system_list = SYSTEM_LIST_TWO_NODES.format(node_1="mn4",
                                                   node_2="mn3")

        run_vcs_command.side_effect = self._side_effect(
            self.all_vcs_cmd(groups_states, system_list))

        out = self.api.check_evacuated(
            self._request(node_to_lock="mn1"))

        self.assertEqual(out, RUN_VCS_CMD_NO_ERROR)
        run_vcs_command.assert_has_calls(
            [mock.call(ATTRIBUTTE_STATE, ['VCS WARNING V-16-1-50031 No Groups are configured']),
             mock.call(GET_SYSTEM_LIST),
             mock.call(GET_SYSTEM_LIST)])


    @mock.patch('vcs_cmd_api.VcsCmdApi._get_triggers_enabled')
    @mock.patch('vcs_cmd_api.VcsCmdApi._group_intent_online')
    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_positive_api_check_evacuated_force_node_lock_true_service_offline(self, run_vcs_command, group_intent_online, get_triggers_enabled):
        group_intent_online.return_value = False
        get_triggers_enabled.return_value = ""
        groups_states = GROUP_STATES.format(state_node_mn1="OFFLINE",
                                            state_node_mn2="OFFLINE")
        system_list = SYSTEM_LIST_TWO_NODES.format(node_1="mn1",
                                                   node_2="mn2")

        run_vcs_command.side_effect = self._side_effect(
            self.all_vcs_cmd(groups_states, system_list))

        out = self.api.check_evacuated(
            self._request(node_to_lock="mn1"))

        self.assertEqual(out, RUN_VCS_CMD_NO_ERROR)
        run_vcs_command.assert_has_calls(
            [mock.call(ATTRIBUTTE_STATE, ['VCS WARNING V-16-1-50031 No Groups are configured']),
             mock.call(GET_SYSTEM_LIST),
             mock.call(GET_SYSTEM_LIST)])

    @mock.patch('vcs_cmd_api.VcsCmdApi._get_triggers_enabled')
    @mock.patch('vcs_cmd_api.VcsCmdApi._group_intent_online')
    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_positive_api_check_evacuated_force_node_lock_true_service_faulted(self, run_vcs_command, group_intent_online, get_triggers_enabled):
        group_intent_online.return_value = False
        get_triggers_enabled.return_value = ""
        groups_states = GROUP_STATES.format(state_node_mn1="FAULTED",
                                            state_node_mn2="OFFLINE")
        system_list = SYSTEM_LIST_TWO_NODES.format(node_1="mn1",
                                                   node_2="mn2")

        run_vcs_command.side_effect = self._side_effect(
            self.all_vcs_cmd(groups_states, system_list))

        out = self.api.check_evacuated(
            self._request(node_to_lock="mn1"))

        self.assertEqual(out, RUN_VCS_CMD_NO_ERROR)
        run_vcs_command.assert_has_calls(
            [mock.call(ATTRIBUTTE_STATE, ['VCS WARNING V-16-1-50031 No Groups are configured']),
             mock.call(GET_SYSTEM_LIST),
             mock.call(CLEAR),
             mock.call(GET_SYSTEM_LIST)])

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_positive_is_dependent_svc_only_on_node_to_lock(self, run_vcs_command):
        system_list = SYSTEM_LIST_ONE_NODES.format(node_n="mn1")

        run_vcs_command.side_effect = self._side_effect(
             self.get_deps_cmd(system_list))

        out = self.api.is_dependent_svc_only_on_node_to_lock(node_to_lock="mn1",
                                                             group="Grp_CS_cluster1_cs2")
        self.assertEqual(out, True)
        run_vcs_command.assert_has_calls(
           [mock.call(GET_GROUP_DEPS,
            rewrite_retcode=True,
            expected_errors=['VCS WARNING V-16-1-50035 No Group dependencies are configured']),
            mock.call(GET_SYSTEM_LIST)])

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_negative_is_dependent_svc_only_on_node_to_lock(self, run_vcs_command):
        system_list = SYSTEM_LIST_TWO_NODES.format(node_1="mn1", node_2="mn2")

        run_vcs_command.side_effect = self._side_effect(
                self.get_deps_cmd(system_list))

        out = self.api.is_dependent_svc_only_on_node_to_lock(node_to_lock="mn1",
                                                             group="Grp_CS_cluster1_cs2")

        self.assertEqual(out, False)
        run_vcs_command.assert_has_calls(
            [mock.call(GET_GROUP_DEPS,
             rewrite_retcode=True,
             expected_errors=['VCS WARNING V-16-1-50035 No Group dependencies are configured']),
             mock.call(GET_SYSTEM_LIST)])


