import unittest
import mock
import os
import sys
from nose.tools import nottest

sys.path.append('./puppet/mcollective_agents/files')

from vcs_cmd_api import (VcsCmdApi,
                         RPCAgent,
                         VCSCommandException,
                         VCSException,
                         NO_GRP_DEP_ERROR,
                         #GRP_WAIT_ALL_ERROR,
                         VCS_GROUP_NOT_EXIST_WARN_10133,
                         NO_RES_DEP_ERROR,
                         VCS_RESOURCE_NOT_EXIST,
                         ChildParentDependencies,
                         VCS_UNFREEZE_REMOTE_BUILD_STATE)


class TestRPCAgent(unittest.TestCase):

    def setUp(self):
        self.agent = RPCAgent()

    @mock.patch('vcs_cmd_api.subprocess')
    def test_rpcagent_run(self, sub_proc):
        sub_proc.Popen = mock.Mock()
        communicate = mock.Mock(return_value=("expected out",
                                              "expected err"))
        process = mock.Mock(returncode=0,
                            communicate=communicate)
        sub_proc.Popen.return_value = process
        code, out, err = self.agent.run("ls")
        self.assertEqual(code, 0)
        self.assertEqual(out, "expected out")
        self.assertEqual(err, "expected err")

    @mock.patch('vcs_cmd_api.sys')
    @mock.patch('vcs_cmd_api.json')
    @mock.patch('__builtin__.open')
    def test_rpcagent_action(self, mock_open, mock_json, mock_sys):
        os.environ["MCOLLECTIVE_REQUEST_FILE"] = "/tmp/request"
        os.environ["MCOLLECTIVE_REPLY_FILE"] = "/tmp/reply"

        infile = mock.MagicMock()
        outfile = mock.MagicMock()

        mock_json.load.return_value = {
            "action": "my_action",
            "data": "my_data",
        }

        action_response = "action response"
        self.agent.my_action = mock.Mock(return_value=action_response)

        mock_open.__enter__.side_effect = [infile, outfile]

        self.agent.action()

        mock_open.assert_any_call('/tmp/request', 'r')
        mock_open.assert_any_call('/tmp/reply', 'w')

        mock_json.load.assert_called_once_with(
            mock_open().__enter__())
        mock_json.dump.assert_called_once_with(
            "action response", mock_open().__enter__())
        mock_open().__exit__.assert_called_with(None, None, None)
        self.assertEqual(2, mock_open().__exit__.call_count)
        mock_sys.assert_has_calls([mock.call.exit(0)])


class TestVcsCmdApi(unittest.TestCase):

    def setUp(self):
        self.api = VcsCmdApi()

    @mock.patch('vcs_cmd_api.RPCAgent.run')
    def test_api_run_vcs_command(self, mock_run):
        mock_run.return_value = 0, "output", ""
        c, o, e = self.api.run_vcs_command("ls")
        mock_run.assert_called_once_with("ls")
        self.assertEqual(c, 0)
        self.assertEqual(o, "output")
        self.assertEqual(e, "")

        mock_run.return_value = 1, "", "error"
        self.assertRaises(VCSCommandException, self.api.run_vcs_command, "ls")

    @mock.patch('vcs_cmd_api.RPCAgent.run')
    def test_api_open_haconf(self, mock_run):
        mock_run.return_value = 0, "output", ""
        c, o, e = self.api.open_haconf()
        mock_run.assert_called_once_with("haconf -makerw")
        self.assertEqual(c, 0)
        self.assertEqual(o, "output")
        self.assertEqual(e, "")

    @mock.patch('vcs_cmd_api.RPCAgent.run')
    def test_api_close_haconf_pos(self, mock_run):
        mock_run.side_effect = lambda a: {
                "haconf": (0, "output", ""),
                "haclus": (0, "wait_output", "")}[a.split()[0]]
        c, o, e = self.api.close_haconf()
        mock_run.assert_any_call("haconf -dump -makero")
        mock_run.assert_any_call("haclus -wait DumpingMembership 0 -time 60")
        self.assertEqual(c, 0)
        self.assertEqual(o, "wait_output")
        self.assertEqual(e, "")

    @mock.patch('vcs_cmd_api.RPCAgent.run')
    def test_api_close_haconf_only_waits_if_successful(self, mock_run):
        mock_run.return_value = (1, "",
                "VCS WARNING V-16-1-10369 Cluster not writable")
        c, o, e = self.api.close_haconf()
        mock_run.assert_called_once_with("haconf -dump -makero")
        self.assertEqual(c, 1)
        self.assertEqual(o, "")
        self.assertEqual(e, "VCS WARNING V-16-1-10369 Cluster not writable")

    @mock.patch('vcs_cmd_api.RPCAgent.run')
    def test_api_close_haconf_wait_raises_error(self, mock_run):
        mock_run.side_effect = lambda a: {
                "haconf": (0, "output", ""),
                "haclus": (1, "wait_output", "")}[a.split()[0]]
        self.assertRaises(VCSCommandException, self.api.close_haconf)
        mock_run.assert_any_call("haconf -dump -makero")
        mock_run.assert_any_call("haclus -wait DumpingMembership 0 -time 60")

    @mock.patch('vcs_cmd_api.RPCAgent.run')
    def test_api_close_haconf_gives_message_on_timeout(self, mock_run):
        mock_run.side_effect = lambda a: {
                "haconf": (0, "output", ""),
                "haclus": (1, "", "VCS WARNING V-16-1-10805 Connection timed "
                                  "out")}[a.split()[0]]
        c, o, e = self.api.close_haconf()
        mock_run.assert_any_call("haconf -dump -makero")
        mock_run.assert_any_call("haclus -wait DumpingMembership 0 -time 60")
        self.assertEqual(c, 1)
        self.assertEqual(o, "")
        self.assertEqual(e, "VCS WARNING V-16-1-10805 Connection timed out\n"
                            "VCS took more than 60 seconds to dump its "
                            "configuration to disk.")

    @mock.patch('vcs_cmd_api.VcsCmdApi._haconf')
    def test_rpc_haconf(self, mock_haconf):
        mock_haconf.return_value = (5, "output", "error")
        ret_dict = self.api.haconf({'read_only': 7})
        self.assertEquals(ret_dict, {"retcode": 5,
                                     "out": "output",
                                     "err": "error"
            })
        mock_haconf.assert_called_once_with(7, rewrite_retcode=True)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_rpc_haconf_exception(self, patch_run_vcs_cmd):
        patch_run_vcs_cmd.side_effect = VCSCommandException("no such command")
        ret_dict = self.api.haconf({'read_only': False})
        self.assertEquals(ret_dict, {"retcode": 1,
                                     "out": "",
                                     "err": "no such command"
            })
        patch_run_vcs_cmd.assert_called_once_with('haconf -makerw',
                                                  ['VCS WARNING V-16-1-10364 Cluster already writable'],
                                                  True)
    @mock.patch('vcs_cmd_api.RPCAgent.run')
    def test_api_hagrp_display_attribute_and_system_params_are_set(self, mock_run):

        header = \
            "#Group              Attribute             System     Value\n"

        attributes = ["Grp_CS_cluster1_cs2  IntentOnline    global     0",
                      "Grp_CS_cluster1_cs2  IntentOnline   node1     0"]

        mock_run.side_effect = [(0, "", ""),
                                (0, header + attributes[0], ""),]

        global_cmd_output = self.api.hagrp_display("Grp_CS_cluster1_cs2", "IntentOnline", "node3")
        self.assertEqual(global_cmd_output, attributes[0].splitlines())
        mock_run.assert_has_calls([mock.call("hagrp -display Grp_CS_cluster1_cs2 -attribute IntentOnline")])

        mock_run.reset_mock()
        mock_run.side_effect = [(0, header + attributes[1], ""),]

        o = self.api.hagrp_display("Grp_CS_cluster1_cs2", "IntentOnline", "node1")
        self.assertEqual(o, attributes[1].splitlines())
        mock_run.assert_has_calls([mock.call("hagrp -display Grp_CS_cluster1_cs2 -attribute IntentOnline -sys node1")])

        mock_run.reset_mock()
        mock_run.side_effect = [(0, header + attributes[1], ""),]

        o = self.api.hagrp_display("Grp_CS_cluster1_cs2")
        self.assertEqual(o, attributes[1].splitlines())
        mock_run.assert_has_calls([mock.call("hagrp -display Grp_CS_cluster1_cs2")])

    @mock.patch('vcs_cmd_api.RPCAgent.run')
    def test_api_hagrp_display(self, mock_run):

        attributes = \
            "Grp_CS_cluster1_cs2 AdministratorGroups   global     \n"\
            "Grp_CS_cluster1_cs2 Administrators        global     \n"\
            "Grp_CS_cluster1_cs2 Authority             global     \n"
        header = \
            "#Group              Attribute             System     Value\n"

        mock_run.return_value = 0, header + attributes, ""
        o = self.api.hagrp_display("Grp_CS_cluster1_cs2")
        mock_run.assert_called_once_with("hagrp -display Grp_CS_cluster1_cs2")
        self.assertEqual(o, attributes.splitlines())

        mock_run.reset_mock()
        mock_run.return_value = 0, header + attributes.splitlines()[0], ""
        o = self.api.hagrp_display("Grp_CS_cluster1_cs2",
                                   "AdministratorGroups")

        expected = "hagrp -display Grp_CS_cluster1_cs2"\
            + " -attribute AdministratorGroups"
        mock_run.assert_called_once_with(expected)
        self.assertEqual(o, [attributes.splitlines()[0]])

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_api_hares_display(self, mock_run):
        header = "#Resource                Attribute              "\
                 "System     Value\n"
        attributes = \
            "Res_App_c1_FO_vcs1_cups  State                  node1"\
            "      ONLINE\n"\
            "Res_App_c1_FO_vcs1_cups  State                  node2"\
            "      OFFLINE\n"\
            "Res_App_c1_PL_vcs1_httpd State                  node1"\
            "      ONLINE\n"\
            "Res_App_c1_PL_vcs1_httpd State                  node2"\
            "      ONLINE\n"\
            "Res_App_c1_cs1_sleepy    State                  node1"\
            "      ONLINE|RESTARTING\n"
        mock_run.return_value = 0, header + attributes, ""
        res = self.api.hares_display()
        self.assertEqual(res, attributes.splitlines())

        mock_run.assert_called_once_with("hares -display ")

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_api_hares_display_returns_empty_list_on_no_result(self, mock_run):
        mock_run.return_value = 0, None, ""
        self.assertEqual(self.api.hares_display(), [])

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_api_hares_display_calls_hares_with_attribute(self, mock_run):
        mock_run.return_value = 0, None, ""
        self.api.hares_display(attribute="State")
        mock_run.assert_called_once_with("hares -display  -attribute State")

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_api_hares_display_calls_hares_with_resource(self, mock_run):
        mock_run.return_value = 0, None, ""
        self.api.hares_display(resource="TestResource")
        mock_run.assert_called_once_with("hares -display TestResource")

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_api_hares_display_calls_hares_with_system(self, mock_run):
        mock_run.return_value = 0, None, ""
        self.api.hares_display(system="node")
        mock_run.assert_called_once_with("hares -display  -sys node")

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_api_hagrp_resources(self, mock_run):
        mock_run.return_value = 0, "CS_Grp_1_resources", ""

        o = self.api.hagrp_resources("CS_Grp_1")
        self.assertEqual(o, "CS_Grp_1_resources")

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_api_node_list(self, mock_run_cmd):
        mock_run_cmd.return_value = 0, "mn1\nmn2", ""
        o = self.api._node_list()
        mock_run_cmd.assert_called_once_with("hasys -list")
        self.assertEqual(o, ["mn1", "mn2"])

    @mock.patch('vcs_cmd_api.VcsCmdApi._node_list')
    @mock.patch('vcs_cmd_api.RPCAgent.run')
    def test_api_validate_all_nodes_are_unlocked(self, mock_run,
                                                 mock_node_list):
        mock_node_list.return_value = ["mn1", "mn2"]
        mock_run.side_effect = [(0, "0", ""),
                                (0, "0", ""),
                                ]
        self.api._validate_all_nodes_are_unlocked("mn1")
        mock_run.assert_has_calls([mock.call("hasys -value mn2 Frozen"),
                                   mock.call("hasys -value mn2 TFrozen")])

        mock_run.reset_mock()
        mock_run.side_effect = [(0, "0", ""),
                                (0, "1", ""),
                                ]
        self.assertRaises(VCSException,
                          self.api._validate_all_nodes_are_unlocked,
                          "mn1")

    @mock.patch('vcs_cmd_api.VcsCmdApi.hagrp_display')
    @mock.patch('vcs_cmd_api.VcsCmdApi.hagrp_resources')
    def test_get_online_failover_sgs(self, mock_hagrp_resources, mock_hagrp_display):

        def _mock_hagrp_display(attribute, **kwargs):
            if attribute == "State":
                return ["Grp_CS_c1_cups  State             node1      |ONLINE|"]
            else:
                # return the Parallel command for specific group
                return ["Grp_CS_c1_cups  Parallel          global      0"]

        mock_hagrp_display.side_effect = _mock_hagrp_display
        mock_hagrp_resources.return_value = "Res_App_c1_FO_vcs1_cups\nRes_IP_c1_FO_vcs1_cups"

        online_failover_sgs = self.api._get_online_failover_sgs("node1")
        self.assertEqual(online_failover_sgs, ["Grp_CS_c1_cups"])
        self.assertEqual(mock_hagrp_resources.call_args_list, [mock.call(group='Grp_CS_c1_cups')])
        self.assertEqual(mock_hagrp_display.call_args_list, [mock.call(attribute="State"),
                                                             mock.call(attribute="Parallel", group='Grp_CS_c1_cups')])
    @mock.patch('vcs_cmd_api.VcsCmdApi.hagrp_display')
    @mock.patch('vcs_cmd_api.VcsCmdApi.hagrp_resources')
    def test_get_online_failover_sgs_no_ip(self, mock_hagrp_resources, mock_hagrp_display):

        def _mock_hagrp_display(attribute, **kwargs):
            if attribute == "State":
                return ["Grp_CS_c1_cups  State             node1      |ONLINE|"]
            else:
                # return the Parallel command for specific group
                return ["Grp_CS_c1_cups  Parallel          global      0"]

        mock_hagrp_display.side_effect = _mock_hagrp_display
        mock_hagrp_resources.return_value = "Res_App_c1_FO_vcs1_cups"

        online_failover_sgs = self.api._get_online_failover_sgs("node1")
        self.assertEqual(online_failover_sgs, [])
        self.assertEqual(mock_hagrp_resources.call_args_list, [mock.call(group='Grp_CS_c1_cups')])
        self.assertEqual(mock_hagrp_display.call_args_list, [mock.call(attribute="State"),
                                                             mock.call(attribute="Parallel", group='Grp_CS_c1_cups')])

    @mock.patch('vcs_cmd_api.VcsCmdApi._wait_on_groups_with_timeout')
    @mock.patch('vcs_cmd_api.syslog.syslog')
    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    @mock.patch('vcs_cmd_api.VcsCmdApi._get_online_failover_sgs')
    def test_switch_online_failover_service_groups(self,
                                                   mock_get_online_failover_sgs,
                                                   mock_run_command,
                                                   mock_syslog,
                                                   mock_wait_on_groups):
        node_to_lock = "node1"
        mock_get_online_failover_sgs.return_value = ["fo_service_online"]

        self.api._switch_online_failover_service_groups(node_to_lock, 60, "")
        mock_syslog.assert_called_once_with("[VCS mco] hagrp -switch fo_service_online -any")
        mock_run_command.assert_called_once_with("hagrp -switch fo_service_online -any", ['VCS WARNING V-16-1-51055'])
        mock_wait_on_groups.assert_called_once_with("OFFLINE", "node1", ["fo_service_online"], 60)

    @mock.patch('vcs_cmd_api.VcsCmdApi._wait_on_groups_with_timeout')
    @mock.patch('vcs_cmd_api.syslog.syslog')
    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    @mock.patch('vcs_cmd_api.VcsCmdApi._get_online_failover_sgs')
    def test_switch_online_failover_service_groups_error(self,
                                                   mock_get_online_failover_sgs,
                                                   mock_run_command,
                                                   mock_syslog,
                                                   mock_wait_on_groups):
        node_to_lock = "node1"
        mock_get_online_failover_sgs.return_value = ["fo_service_online"]
        mock_wait_on_groups.side_effect = VCSException("Timeout error message")

        self.api._switch_online_failover_service_groups(node_to_lock, 60, "")
        self.assertEqual(mock_syslog.call_args_list, [
            mock.call("[VCS mco] hagrp -switch fo_service_online -any"),
            mock.call('[VCS mco] Timeout error message')])
        mock_run_command.assert_called_once_with("hagrp -switch fo_service_online -any", ['VCS WARNING V-16-1-51055'])
        mock_wait_on_groups.assert_called_once_with("OFFLINE", "node1", ["fo_service_online"], 60)

    @mock.patch('vcs_cmd_api.time.sleep')
    @mock.patch('vcs_cmd_api.syslog.syslog')
    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_wait_on_groups_with_timeout_error(self, mock_run_command,
                                               mock_syslog, mock_sleep):
        desired_state = "OFFLINE"
        node_name = "node1"
        groups = ["VCS_Group_1"]
        timeout = 60

        mock_run_command.side_effect = VCSCommandException
        try:
            self.api._wait_on_groups_with_timeout(desired_state, node_name,
                                                  groups, timeout)
        except VCSException as e:
            pass
        self.assertEqual(e.args, ('Failed to bring OFFLINE service groups: VCS_Group_1',))
        self.assertEqual(mock_sleep.call_args_list,
                         [mock.call(10), mock.call(10), mock.call(10),
                          mock.call(10), mock.call(10), mock.call(10)])
        self.assertEqual(mock_syslog.call_count, 6)

    @mock.patch('vcs_cmd_api.time.sleep')
    @mock.patch('vcs_cmd_api.syslog.syslog')
    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_wait_on_groups_with_timeout(self, mock_run_command,
                                               mock_syslog, mock_sleep):
        desired_state = "OFFLINE"
        node_name = "node1"
        groups = ["VCS_Group_1"]
        timeout = 60

        mock_run_command.return_value = 0, "success", ""
        self.api._wait_on_groups_with_timeout(desired_state, node_name, groups,
                                              timeout)
        self.assertEqual(0, mock_sleep.call_count)
        self.assertEqual(0, mock_syslog.call_count)
        self.assertEqual([mock.call("hagrp -wait VCS_Group_1 State OFFLINE -sys node1 -time 1")],
                         mock_run_command.call_args_list)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    @mock.patch('vcs_cmd_api.VcsCmdApi.close_haconf')
    @mock.patch('vcs_cmd_api.VcsCmdApi.open_haconf')
    @mock.patch('vcs_cmd_api.VcsCmdApi._switch_online_failover_service_groups')
    @mock.patch('vcs_cmd_api.VcsCmdApi._validate_all_nodes_are_unlocked')
    def test_api_lock(self,
                      mock_val_nodes_unlocked,
                      mock_switch_online_failover_service_groups,
                      mock_open_haconf,
                      mock_close_haconf,
                      mock_run_command):
        req = {"sys": "mn1", "switch_timeout": "60"}
        output = self.api.lock(req)
        self.assertEqual(output, {'retcode': 0, 'out': "", 'err': ""})
        mock_val_nodes_unlocked.assert_called_once_with("mn1")
        mock_open_haconf.assert_called_once_with()
        mock_close_haconf.assert_called_once_with()
        expected = "hasys -freeze -persistent -evacuate mn1"
        mock_run_command.assert_called_once_with(expected)
        mock_switch_online_failover_service_groups.assert_called_once_with("mn1", 60, "")

    @mock.patch('vcs_cmd_api.VcsCmdApi._get_triggers_enabled')
    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    @mock.patch('vcs_cmd_api.VcsCmdApi.hagrp_display')
    @mock.patch('vcs_cmd_api.VcsCmdApi._system_list')
    @mock.patch('vcs_cmd_api.VcsCmdApi._hagrp_frozen')
    def test_api_group_evacuated(self, mock_hagrp_frozen, mock_sys_list,
                                 hagrp_disp, mock_run_cmd, mock_trig_enab):
        mock_sys_list.return_value = "mn2", "mn1"
        mock_trig_enab.return_value = ""
        mock_run_cmd.return_value = ("", 1, "")
        mock_hagrp_frozen.return_value = False
        # correct node and offline so is evacuated
        res = self.api._group_evacuated("mn1",
                                        "Grp_CS_cluster1_cs2",
                                        "mn1",
                                        "|OFFLINE|")
        self.assertEqual(res, True)
        # correct node and online so False
        res = self.api._group_evacuated("mn1",
                                        "Grp_CS_cluster1_cs2",
                                        "mn1",
                                        "|ONLINE|")
        self.assertEqual(res, False)
        # NIC service group so considered evacuated even though online
        res = self.api._group_evacuated("mn1",
                                        "Grp_NIC_cluster1_eth0",
                                        "mn1",
                                        "|ONLINE|")
        self.assertEqual(res, True)
        # not node to be locked and OFFLINE so false
        intentonline = "Grp_CS_cluster1 IntentOnline global 1"

        def _mock_hagrp_display(attribute, **kwargs):
            if attribute == "IntentOnline":
                return ["Grp_CS_cluster1 IntentOnline global 1"]
            else:
                return [None]
        hagrp_disp.side_effect = _mock_hagrp_display
        res = self.api._group_evacuated("mn2",
                                        "Grp_CS_cluster1_cs2",
                                        "mn1",
                                        "|OFFLINE|")
        self.assertEqual(res, False)
        # not in system list so True even though online
        res = self.api._group_evacuated("mn3",
                                        "Grp_CS_cluster1_cs2",
                                        "mn1",
                                        "|ONLINE|")
        self.assertEqual(res, True)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_api_system_list(self, mock_run_cmd):
        mock_run_cmd.return_value = 0, "mn2	0	mn1	0", ""
        output = self.api._system_list("Grp_CS_cluster1_cs2")
        expected_cmd = "hagrp -value Grp_CS_cluster1_cs2 SystemList"
        mock_run_cmd.assert_called_once_with(expected_cmd)
        self.assertEqual(output, ["mn2", "mn1"])

    @mock.patch('vcs_cmd_api.VcsCmdApi._group_evacuated')
    @mock.patch('vcs_cmd_api.VcsCmdApi.hagrp_display')
    def test_api_check_evacuated(self, mock_grp_disp, mock_evac):
        state_output = [
            "Grp_CS_cluster1_cs2 State                 mn1        |ONLINE|",
            "Grp_CS_cluster1_cs2 State                 mn2        |ONLINE|"]
        mock_evac.return_value = True
        mock_grp_disp.return_value = state_output
        out = self.api.check_evacuated({"sys": "mn1"})
        self.assertEqual(out, {"retcode": 0, "out": "", "err": ""})
        mock_evac.return_value = False
        out = self.api.check_evacuated({"sys": "mn1"})
        err = 'Group Grp_CS_cluster1_cs2 is in state |ONLINE| on node mn1'
        e = {'retcode': 1,
             'err': err,
             'out': ''}
        self.assertEqual(out, e)

    @mock.patch('vcs_cmd_api.VcsCmdApi.hagrp_display')
    @mock.patch('vcs_cmd_api.VcsCmdApi._bring_group_online')
    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    @mock.patch('vcs_cmd_api.VcsCmdApi.close_haconf')
    @mock.patch('vcs_cmd_api.VcsCmdApi.open_haconf')
    @mock.patch('vcs_cmd_api.VcsCmdApi._check_nic_groups_online')
    @mock.patch('vcs_cmd_api.VcsCmdApi._hagrp_frozen')
    @nottest
    def test_api_unlock(self,
                        mock_hagrp_frozen,
                        mock_check_nics_online,
                        mock_open_haconf,
                        mock_close_haconf,
                        mock_run_command,
                        mock_bring_grp_online,
                        mock_hagrp_display):
        req = {"sys": "mn1",
               "nic_wait_timeout": "70", }

        grp_list_output = "Grp_CS_cluster1_cs2\nGrp_NIC_cluster1_eth0\n" +\
            "Grp_NIC_cluster1_eth4\nGrp_NIC_cluster1_eth5"

        mock_run_command.side_effect = [None,
                                        (0, grp_list_output, ""),
                                        (0, "ONLINE", ""),
                                        (0, "ONLINE", ""),
                                        (0, "ONLINE", ""),
                                        None,
                                        None,
                                        None,
                                        (0, "", "")]

        mock_hagrp_display.side_effect = [
            'Grp_CS_cluster1_cs2 IntentOnline          node1      1',
            'Grp_CS_cluster1_cs2 Frozen                node1      0',
            ]

        def _mock_hagrp_display(attribute, **kwargs):
            if attribute == "IntentOnline":
                return ["Grp_CS_cluster1 IntentOnline global 1"]
            else:
                return [None]
        mock_hagrp_display.side_effect = _mock_hagrp_display
        mock_hagrp_frozen.return_value = False
        output = self.api.unlock(req)

        self.assertEqual(output, {'retcode': 0, 'out': "", 'err': ""})
        mock_open_haconf.assert_called_once_with()
        mock_close_haconf.assert_called_once_with()
        expected = [mock.call('hasys -unfreeze -persistent mn1',
                              ['VCS WARNING V-16-1-40205 System is not '
                              'persistently frozen']),
                    mock.call('hagrp -list Parallel=1 | '
                              'awk \'$2=="mn1" {print $1}\' | uniq'),
                    mock.call('hagrp -state Grp_NIC_cluster1_eth0 -sys mn1 '),
                    mock.call('hagrp -state Grp_NIC_cluster1_eth4 -sys mn1 '),
                    mock.call('hagrp -state Grp_NIC_cluster1_eth5 -sys mn1 '),
                    mock.call('hagrp -online Grp_NIC_cluster1_eth0 -sys mn1'),
                    mock.call('hagrp -online Grp_NIC_cluster1_eth4 -sys mn1'),
                    mock.call('hagrp -online Grp_NIC_cluster1_eth5 -sys mn1')]

        mock_run_command.assert_has_calls(expected)
        c = [mock.call('Grp_CS_cluster1_cs2', 'mn1')]
        mock_bring_grp_online.assert_has_calls(c)

    @mock.patch('vcs_cmd_api.time.sleep')
    @mock.patch('vcs_cmd_api.VcsCmdApi.hagrp_display')
    @mock.patch('vcs_cmd_api.VcsCmdApi._bring_group_online')
    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    @mock.patch('vcs_cmd_api.VcsCmdApi.close_haconf')
    @mock.patch('vcs_cmd_api.VcsCmdApi.open_haconf')
    @mock.patch('vcs_cmd_api.VcsCmdApi._hagrp_frozen')
    def test_api_unlock_remote_build_pass_in_timeout(self,
                        mock_hagrp_frozen,
                        mock_open_haconf,
                        mock_close_haconf,
                        mock_run_command,
                        mock_bring_grp_online,
                        mock_hagrp_display,
                        mock_sleep):
        time_out = 90
        sleep_time = 5
        req = {"sys": "mn1",
               "nic_wait_timeout": "70", }

        grp_list_output = "Grp_CS_cluster1_cs2\nGrp_NIC_cluster1_eth0\n" + \
                          "Grp_NIC_cluster1_eth4\nGrp_NIC_cluster1_eth5"

        mock_run_command.side_effect = [(1, "", VCS_UNFREEZE_REMOTE_BUILD_STATE),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (0, "RUNNING", ""),
                                        None,
                                        ("", "", ""),
                                        (0, grp_list_output, ""),
                                        (0, "ONLINE", ""),
                                        (0, "ONLINE", ""),
                                        (0, "ONLINE", ""),
                                        None,
                                        None,
                                        None,
                                        (0, "", "")]

        mock_hagrp_display.side_effect = [
            'Grp_CS_cluster1_cs2 IntentOnline          node1      1',
            'Grp_CS_cluster1_cs2 Frozen                node1      0',
        ]

        def _mock_hagrp_display(attribute, **kwargs):
            if attribute == "IntentOnline":
                return ["Grp_CS_cluster1 IntentOnline global 1"]
            else:
                return [None]

        mock_hagrp_display.side_effect = _mock_hagrp_display
        mock_hagrp_frozen.return_value = False
        output = self.api.unlock(req)

        self.assertEqual(output, {'retcode': 0, 'out': "", 'err': ""})
        mock_open_haconf.assert_called_once_with()
        mock_close_haconf.assert_called_once_with()
        self.assertEqual(3, mock_sleep.call_count)
        self.assertLessEqual(sleep_time * mock_sleep.call_count, time_out)

    @mock.patch('vcs_cmd_api.time.sleep')
    @mock.patch('vcs_cmd_api.VcsCmdApi.hagrp_display')
    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    @mock.patch('vcs_cmd_api.VcsCmdApi.close_haconf')
    @mock.patch('vcs_cmd_api.VcsCmdApi.open_haconf')
    @mock.patch('vcs_cmd_api.VcsCmdApi._hagrp_frozen')
    def test_api_unlock_remote_build_error_reach_timeout(self,
                                                     mock_hagrp_frozen,
                                                     mock_open_haconf,
                                                     mock_close_haconf,
                                                     mock_run_command,
                                                     mock_hagrp_display,
                                                     mock_sleep):
        time_out = 90
        sleep_time = 5
        req = {"sys": "mn1",
               "nic_wait_timeout": "70", }
        grp_list_output = "Grp_CS_cluster1_cs2\nGrp_NIC_cluster1_eth0\n" + \
                          "Grp_NIC_cluster1_eth4\nGrp_NIC_cluster1_eth5"

        mock_run_command.side_effect = [(1, "", VCS_UNFREEZE_REMOTE_BUILD_STATE),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        (1, "REMOTE_BUILD", ""),
                                        VCSCommandException(
                                            "Error running '{0}': "
                                            "Out: ""'{1}' "
                                            "Err: '{2}'".format(
                                                "hasys -unfreeze "
                                                "-persistent".format(req["sys"]),
                                                "",
                                                VCS_UNFREEZE_REMOTE_BUILD_STATE)
                                        ),
                                        ("", "", ""),
                                        (0, grp_list_output, ""),
                                        (0, "ONLINE", ""),
                                        (0, "ONLINE", ""),
                                        (0, "ONLINE", ""),
                                        None,
                                        None,
                                        None,
                                        (0, "", "")
                                        ]
        mock_hagrp_display.side_effect = [
            'Grp_CS_cluster1_cs2 IntentOnline          node1      1',
            'Grp_CS_cluster1_cs2 Frozen                node1      0',
        ]

        def _mock_hagrp_display(attribute, **kwargs):
            if attribute == "IntentOnline":
                return ["Grp_CS_cluster1 IntentOnline global 1"]
            else:
                return [None]
        mock_hagrp_display.side_effect = _mock_hagrp_display
        mock_hagrp_frozen.return_value = False
        output = self.api.unlock(req)
        mock_run_command.assert_any_call("hasys -state {0}".format(req["sys"]))
        self.assertEqual(18, mock_sleep.call_count)
        self.assertLessEqual(time_out, sleep_time * mock_sleep.call_count)
        mock_run_command.assert_any_call("hasys -unfreeze -persistent {0}".format(req["sys"]),
                            ["VCS WARNING V-16-1-40205 System is not persistently frozen"])
        self.assertEqual(output["err"], "Error running 'hasys -unfreeze -persistent': "
                                        "Out: '' "
                                        "Err: 'VCS WARNING V-16-1-50129 Operation "
                                        "'hasys -unfreeze -persistent' rejected as the node "
                                        "is in REMOTE_BUILD state'")

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_api_ok_to_online_group(self, mock_run_cmd):
        grp = "Grp_CS_cluster1_cs2"
        node = "mn1"
        hagrp_output = (0,
                        "Grp_CS_cluster1_cs2 AutoDisabled  mn1  1\n"
                        "Grp_CS_cluster1_cs2 ProbesPending  mn1  0",
                        "")
        mock_run_cmd.return_value = hagrp_output
        res = self.api._ok_to_online_group(grp, node)
        self.assertFalse(res)
        hagrp_output = (0,
                        "Grp_CS_cluster1_cs2 AutoDisabled  mn1  0\n"
                        "Grp_CS_cluster1_cs2 ProbesPending  mn1  0",
                        "")
        mock_run_cmd.return_value = hagrp_output
        res = self.api._ok_to_online_group(grp, node)
        self.assertTrue(res)

    @mock.patch('vcs_cmd_api.time.sleep')
    @mock.patch('vcs_cmd_api.VcsCmdApi._ok_to_online_group')
    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    @nottest
    def test_api_ok_do_online_group(self,
                                    mock_run_cmd,
                                    mock_ok_to_online,
                                    mock_sleep):
        grp = "Grp_CS_cluster1_cs2"
        node = "mn1"
        mock_ok_to_online.side_effect = [False, False, True]
        mock_run_cmd.return_value = {'retcode': 0, 'out': "", 'err': ""}
        self.api._bring_group_online(grp, node)
        mock_sleep.assert_has_calls([mock.call(5),
                                     mock.call(5)])
        mock_ok_to_online.assert_has_calls([mock.call('Grp_CS_cluster1_cs2',
                                                      'mn1'),
                                            mock.call('Grp_CS_cluster1_cs2',
                                                      'mn1'),
                                            mock.call('Grp_CS_cluster1_cs2',
                                                      'mn1')])
        mock_run_cmd.assert_has_calls([mock.call('hagrp -online -propagate '
                                                 'Grp_CS_cluster1_cs2 '
                                                 '-sys mn1')])
        mock_ok_to_online.reset_mock()

        def online_side_effect(grp, node):
            _, _ = grp, node
            return False

        mock_ok_to_online.side_effect = online_side_effect
        self.assertRaises(VCSException,
                          self.api._bring_group_online,
                          grp,
                          node)

    @mock.patch('vcs_cmd_api.VcsCmdApi.hagrp_display')
    @mock.patch('vcs_cmd_api.VcsCmdApi._group_intent_online')
    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_api_check_cluster_online(self, mock_run_cmd, mock_intent,
                                      mock_grp_disp):
        req = {"sys": "mn1"}
        failover_grp_output = "Grp_CS_cluster1_cs1"
        grp_list_output = "Grp_CS_cluster1_cs2\nGrp_NIC_cluster1_eth0\n" +\
            "Grp_NIC_cluster1_eth4\nGrp_NIC_cluster1_eth5"
        grp_value_output_on = "|ONLINE|"
        grp_value_output_off = "|OFFLINE|"
        mock_intent.return_value = True
        state_output = [
            "Grp_CS_cluster1_cs1 State    mn1   |ONLINE|",
            "Grp_CS_cluster1_cs1 State    mn2   |OFFLINE|"]
        mock_grp_disp.side_effect = [state_output]

        mock_run_cmd.side_effect = [(0, grp_list_output, ""),
                                    (0, failover_grp_output, ""),
                                    (0, grp_value_output_on, ""),
                                    (0, grp_value_output_on, ""),
                                    (0, grp_value_output_on, ""),
                                    (0, grp_value_output_on, ""),
                                    (0, grp_value_output_on, "")]
        res = self.api.check_cluster_online(req)
        self.assertEqual(res, {"retcode": 0, "out": "", "err": ""})

        failover_grp_output = ""
        mock_run_cmd.reset_mock()
        mock_run_cmd.side_effect = [(0, grp_list_output, ""),
                                    (0, failover_grp_output, ""),
                                    (0, grp_value_output_on, ""),
                                    (0, grp_value_output_on, ""),
                                    (0, grp_value_output_on, ""),
                                    (0, grp_value_output_off, "")]
        res = self.api.check_cluster_online(req)
        self.assertEqual(res, {"retcode": 1,
                               "out": "",
                               "err": "Group Grp_NIC_cluster1_eth5 is still "
                                      "in state |OFFLINE| on node mn1"})

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_api_cluster_ready(self, mock_run_cmd):
        req = {"systems": "mn1,mn2"}
        hasys_output_ok = 0, "RUNNING", ""
        hasys_output_nok = 0, "NOT RUNNING", ""
        mock_run_cmd.side_effect = [hasys_output_ok, hasys_output_ok]
        res = self.api.cluster_ready(req)
        self.assertEqual(res, {"retcode": 0, "out": "", "err": ""})

        mock_run_cmd.reset_mock()
        mock_run_cmd.side_effect = [hasys_output_ok, hasys_output_nok]
        res = self.api.cluster_ready(req)
        self.assertEqual(res, {"retcode": 1,
                               "out": "",
                               "err": "System mn2 is currently in state "
                                      "NOT RUNNING"})

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_api_cluster_stopped(self, mock_run_cmd):
        req = {"systems": "mn1,mn2"}
        hastatus_sum_output_ok = 33, "", ""
        hastatus_sum_output_nok = 0, "", ""
        mock_run_cmd.return_value = hastatus_sum_output_ok
        res = self.api.cluster_stopped(req)
        self.assertEqual(res, {"retcode": 0, "out": "", "err": ""})

        mock_run_cmd.reset_mock()
        mock_run_cmd.return_value = hastatus_sum_output_nok
        res = self.api.cluster_stopped(req)
        self.assertEqual(res, {"retcode": 1,
                               "out": "",
                               "err": "Not yet stopped"})

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_api_probe_all_nics(self, mock_run_cmd):

        req = {"sys": "mn1"}
        mock_run_cmd.side_effect = [(0, "res_eth0\nres_eth1", 0),
                                     (0, "", ""), (0, "", "")]

        res = self.api.probe_all_nics(req)
        self.assertEquals(3, mock_run_cmd.call_count)

        self.assertEqual(res, {"retcode": 0, "out": "", "err": ""})

        mock_run_cmd.reset_mock()
        mock_run_cmd.side_effect = [(0, "res_eth0", 0),
                                     (0, "probing failed", "")]
        res = self.api.probe_all_nics(req)
        self.assertEqual(res, {"retcode": 1,
                               "out": "",
                               "err": "Error 'probing failed' while probing "
                                      "res_eth0 on node mn1"})
        self.assertEquals(2, mock_run_cmd.call_count)

        mock_run_cmd.reset_mock()
        mock_run_cmd.side_effect = VCSException("test_exception")
        res = self.api.probe_all_nics(req)
        self.assertEqual(res, {"retcode": 1,
                               "out": "",
                               "err": "test_exception"})

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_get_group_state_failover(self, mock_run_cmd):
        req = {"group_name": "Grp_CS_c1_cups",
               "active_count": "1",
               "offline_count": "1"}
        mock_run_cmd.return_value = (0,
                ("#Group         Attribute             System     Value\n"
                    "Grp_CS_c1_cups State                 node1      |ONLINE|"
                    "\nGrp_CS_c1_cups State             node2      |OFFLINE|"),
                "")
        ret_dict = self.api.get_group_state(req)
        self.assertEquals(ret_dict, {"retcode": 0,
                                     "out": "ONLINE",
                                     "err": ""})
        mock_run_cmd.assert_called_with("hagrp -state Grp_CS_c1_cups",
                                        rewrite_retcode=True,
                                        expected_errors=['VCS WARNING V-16-1-40131'])

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_get_group_state_offline(self, mock_run_cmd):
        req = {"group_name": "Grp_CS_c1_cups",
               "active_count": "1",
               "offline_count": "1"}
        mock_run_cmd.return_value = (0,
                ("#Group         Attribute             System     Value\n"
                    "Grp_CS_c1_cups State                 node1      |OFFLINE|"
                    "\nGrp_CS_c1_cups State             node2      |OFFLINE|"),
                "")
        ret_dict = self.api.get_group_state(req)
        self.assertEquals(ret_dict, {"retcode": 0,
                                     "out": "OFFLINE",
                                     "err": ""})
        mock_run_cmd.assert_called_with("hagrp -state Grp_CS_c1_cups",
                                        rewrite_retcode=True,
                                        expected_errors=['VCS WARNING V-16-1-40131'])

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_get_group_state_raise_exception(self, mock_run_cmd):
        mock_run_cmd.side_effect = [VCSCommandException("exception !!")]
        req = {"group_name": "Grp_CS_c1_cups",
               "active_count": "1",
               "offline_count": "1"}
        self.assertEquals(
            {'retcode': 1, 'err': 'Could not get node states for group Grp_CS_c1_cups. Exception: exception !!', 'out': ''},
            self.api.get_group_state(req))


    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test__get_node_states_for_group(self, mock_run_cmd):
        mock_run_cmd.return_value = (0,
                ("#Group         Attribute             System     Value\n"
                    "Grp_CS_c1_cups State                 node1      |ONLINE|"
                    "\nGrp_CS_c1_cups State             node2      |OFFLINE|"),
                "")
        ret_dict = self.api._get_node_states_for_group("Grp_CS_c1_cups")
        self.assertEquals(ret_dict,
                {"node1": "|ONLINE|",
                    "node2": "|OFFLINE|"})
        mock_run_cmd.assert_called_with("hagrp -state Grp_CS_c1_cups",
                                        rewrite_retcode=True,
                                        expected_errors=\
                                            ['VCS WARNING V-16-1-40131'])

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hares_override_attribute(self, mock_run_cmd):
        req = {"resource": "resource", "attribute": "attribute"}
        mock_run_cmd.return_value = 0, "", ""
        res = self.api.hares_override_attribute(req)
        self.assertEqual(res, {"retcode": 0, "out": "", "err": ""})
        mock_run_cmd.assert_called_with("/opt/VRTS/bin/hares -override resource attribute",
                                        ['already overridden', 'not a static attribute'],
                                        True)

    @mock.patch('vcs_cmd_api.RPCAgent.run')
    def test_api_run_vcs_command_error_exit(self, mock_run):
        mock_run.return_value = 1, "", "VCS WARNING V-16-1-13322 CleanProgram is not a static attribute"
        req = {"resource": "resource", "attribute": "attribute"}
        res = self.api.hares_override_attribute(req)
        self.assertEqual(res, {"retcode": 0, "out": "", "err": "VCS WARNING V-16-1-13322 CleanProgram is not a static attribute"})

    @mock.patch('vcs_cmd_api.VcsCmdApi._get_node_states_for_group')
    def test_hagrp_check_states_with_node_online(self, get_node_states):
        get_node_states.return_value = {"n1": "ONLINE",
                                        "n2": "OFFLINE"}
        req = {"group_name": "grp",
               "state": "OFFLINE",
               "timeout": 1,
               "node_name": "n1"}
        result = self.api.hagrp_check_states(req)
        self.assertEqual({"retcode": 1, "out": "", "err": ""},
                         result)

    @mock.patch('vcs_cmd_api.VcsCmdApi._get_node_states_for_group')
    def test_hagrp_check_states_with_node_offline(self, get_node_states):
        get_node_states.return_value = {"n1": "OFFLINE"}
        req = {"group_name": "grp",
               "state": "OFFLINE",
               "timeout": 1,
               "node_name": "n1"}
        result = self.api.hagrp_check_states(req)
        self.assertEqual({"retcode": 0, "out": "", "err": ""},
                         result)

    @mock.patch('vcs_cmd_api.VcsCmdApi._get_node_states_for_group')
    def test_hagrp_check_states_with_unknown_node(self, get_node_states):
        get_node_states.return_value = {"n2": "OFFLINE"}
        req = {"group_name": "grp",
               "state": "OFFLINE",
               "timeout": 1,
               "node_name": "n1"}
        result = self.api.hagrp_check_states(req)
        self.assertEqual({"retcode": 0, "out": "",
                          "err": "node n1 not in system list"},
                         result)

    @mock.patch('vcs_cmd_api.VcsCmdApi._get_node_states_for_group')
    def test_hagrp_check_states_with_exception(self, get_node_states):
        def side_effect(command, **kwargs):
            msg = 'hagrp -wait grp State OFFLINE -sys n1 -time 1'
            raise VCSCommandException(msg)
        get_node_states.side_effect = side_effect
        req = {"group_name": "grp",
               "state": "OFFLINE",
               "timeout": 1,
               "node_name": "n1"}
        result = self.api.hagrp_check_states(req)
        err_msg = "hagrp -wait grp State OFFLINE -sys n1 -time 1"
        self.assertEqual({"retcode": 1, "out": "", "err": err_msg},
                         result)

    @mock.patch('vcs_cmd_api.VcsCmdApi._get_node_states_for_group')
    def test_hagrp_check_states_all_nodes_with_valie_states(self,
                                                            get_node_states):
        get_node_states.return_value = {"n1": "OFFLINE|FAULTED",
                                        "n2": "OFFLINE"}
        req = {"group_name": "grp",
               "state": "OFFLINE,OFFLINE|FAULTED",
               "timeout": 1}
        result = self.api.hagrp_check_states(req)
        self.assertEqual({"retcode": 0, "out": "", "err": ""},
                         result)

    @mock.patch('vcs_cmd_api.VcsCmdApi._get_node_states_for_group')
    def test_hagrp_check_states_all_nodes_with_wrong_states(self,
                                                            get_node_states):
        get_node_states.return_value = {"n1": "ONLINE",
                                        "n2": "OFFLINE"}
        req = {"group_name": "grp",
               "state": "OFFLINE,OFFLINE|FAULTED",
               "timeout": 1}
        result = self.api.hagrp_check_states(req)
        self.assertEqual({"retcode": 1, "out": "", "err": ""},
                         result)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_unlink_all(self, run_vcs_cmd):
        def side_effect(command, **kwargs):
            if command == 'hagrp -dep grp':
                return (0,
                        "#Parent        Child           Relationship\n"
                        "grp child_grp online global soft",
                        "")
            elif command == 'hagrp -unlink grp child_grp':
                return (0, "", "")
            else:
                self.fail('Unexpected vcs call')

        run_vcs_cmd.side_effect = side_effect

        req = {"group": "grp"}
        ret_dict = self.api.hagrp_unlink_all(req)

        run_vcs_cmd.assert_called_with(
            "hagrp -unlink {0} {1}".format("grp",
                                           "child_grp"))

        self.assertEqual({"retcode": 0, "out": "", "err": ""}, ret_dict)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_unlink_all_run_cmd_raise_exception(self, run_vcs_cmd):
        def side_effect(command, **kwargs):
            if command == 'hagrp -dep grp':
                return (0,
                        "#Parent        Child           Relationship\n"
                        "grp child_grp online global soft",
                        "")
            elif command == 'hagrp -unlink grp child_grp':
                raise VCSCommandException('hagrp -unlink grp child_grp')
            else:
                self.fail('Unexpected vcs call')

        run_vcs_cmd.side_effect = side_effect
        req = {"group": "grp"}

        ret_dict = self.api.hagrp_unlink_all(req)

        run_vcs_cmd.assert_called_with(
            "hagrp -unlink {0} {1}".format("grp",
                                           "child_grp"))

        self.assertEqual({"retcode": 1, "out": "",
                          "err": 'hagrp -unlink grp child_grp'},
                         ret_dict)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hares_unlink_pattern(self, run_vcs_cmd):
        def side_effect(command, **kwargs):
            if command == 'hares -dep res':
                return (0, "#Group        Parent                       Child\n"
                           "grp app1 res\n"
                           "grp app2 res\n"
                           "grp app3 res\n"
                           "grp res nic", "")

            elif command == 'hares -unlink app1 res':
                return (0, "", "")
            elif command == 'hares -unlink app2 res':
                return (0, "", "")
            elif command == 'hares -unlink app3 res':
                return (0, "", "")
            else:
                self.fail('Unexpected vcs call')

        run_vcs_cmd.side_effect = side_effect

        req = {"resource": "res", "pattern": "app.*"}
        ret_dict = self.api.hares_unlink_pattern(req)

        run_vcs_cmd.assert_has_calls([
            mock.call('hares -dep {0}'.format("res"),
                      rewrite_retcode=True,
                      expected_errors=[NO_RES_DEP_ERROR,
                                       VCS_RESOURCE_NOT_EXIST]),
            mock.call("hares -unlink {0} {1}".format("app1", "res")),
            mock.call("hares -unlink {0} {1}".format("app2", "res")),
            mock.call("hares -unlink {0} {1}".format("app3", "res"))
        ])
        self.assertEqual(4, run_vcs_cmd.call_count)
        self.assertEqual({"retcode": 0, "out": "", "err": ""}, ret_dict)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_unlink_no_dependency(self, run_vcs_cmd):
        run_vcs_cmd.return_value = (0, "", NO_GRP_DEP_ERROR)
        req = {"group": "grp"}
        ret_dict = self.api.hagrp_unlink_all(req)
        expected_errors = [NO_GRP_DEP_ERROR, VCS_GROUP_NOT_EXIST_WARN_10133]
        run_vcs_cmd.assert_called_once_with('hagrp -dep grp',
                                            rewrite_retcode=True,
                                            expected_errors=expected_errors)
        self.assertEqual(ret_dict, {'retcode': 0, 'err': '', 'out': ''})

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_get_dependency_for_group(self, run_vcs_cmd):
        rvalue = (0,
                  "#Parent        Child           Relationship\n"
                  "CS2 CS3 online global soft\n"
                  "CS2 CS4 online global soft\n"
                  "CS1 CS2 online global soft\n",
                  "")
        run_vcs_cmd.return_value = rvalue
        result = self.api._get_dependency_for_group("CS2")

        self.assertEqual([ChildParentDependencies(child='CS3', parent='CS2'),
                          ChildParentDependencies(child='CS4', parent='CS2'),
                          ChildParentDependencies(child='CS2', parent='CS1')],
                         result)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_stop_resource_online_one_node(self, run_vcs_cmd):
        ha_display_out = ('#Resource   Attribute      System     Value\n'
                          'RES1 State         node1      OFFLINE\n'
                          'RES2 State     node2      ONLINE')

        run_vcs_cmd.side_effect = [(0, ha_display_out, "Err"),
                                   (0, '', ""), (0, '', "")]

        self.api.stop_resource('RES1')
        calls = [mock.call('/opt/VRTS/bin/hares -display RES1 -attribute State',
                            rewrite_retcode=True,
                            expected_errors=['VCS WARNING V-16-1-40130']),
                 mock.call('/opt/VRTS/bin/hares -offline RES1 -sys node2')]
        run_vcs_cmd.assert_has_calls(calls)
        self.assertEqual(2, run_vcs_cmd.call_count)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_stop_resource_online_two_nodes(self, run_vcs_cmd):
        ha_display_out = ('#Resource   Attribute      System     Value\n'
                          'RES1 State         node1      ONLINE\n'
                          'RES2 State     node2      ONLINE')

        run_vcs_cmd.side_effect = [(0, ha_display_out, "Err"),
                                   (0, '', ""), (0, '', "")]

        self.api.stop_resource('RES1')
        calls = [mock.call('/opt/VRTS/bin/hares -display RES1 -attribute State',
                            rewrite_retcode=True,
                            expected_errors=['VCS WARNING V-16-1-40130']),
                 mock.call('/opt/VRTS/bin/hares -offline RES1 -sys node1'),
                 mock.call('/opt/VRTS/bin/hares -offline RES1 -sys node2')]
        run_vcs_cmd.assert_has_calls(calls)
        self.assertEqual(3, run_vcs_cmd.call_count)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_stop_resource_offline_two_nodes(self, run_vcs_cmd):
        ha_display_out = ('#Resource   Attribute      System     Value\n'
                          'RES1 State         node1      OFFLINE\n'
                          'RES2 State     node2      OFFLINE')

        run_vcs_cmd.side_effect = [(0, ha_display_out, "Err")]

        self.api.stop_resource('RES1')
        calls = [mock.call('/opt/VRTS/bin/hares -display RES1 -attribute State',
                            rewrite_retcode=True,
                            expected_errors=['VCS WARNING V-16-1-40130'])]
        run_vcs_cmd.assert_has_calls(calls)
        self.assertEqual(1, run_vcs_cmd.call_count)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_stop_resource_online_unknown_one_node(self, run_vcs_cmd):
        ha_display_out = ('#Resource   Attribute      System     Value\n'
                          'RES1 State         node1      OFFLINE\n'
                          'RES2 State     node2      ONLINE|STATE UNKNOWN')

        run_vcs_cmd.side_effect = [(0, ha_display_out, "Err"),
                                   (0, '', ""), (0, '', "")]

        self.api.stop_resource('RES1')
        calls = [mock.call('/opt/VRTS/bin/hares -display RES1 -attribute State',
                            rewrite_retcode=True,
                            expected_errors=['VCS WARNING V-16-1-40130'])]
        run_vcs_cmd.assert_has_calls(calls)
        self.assertEqual(1, run_vcs_cmd.call_count)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hares_delete(self, run_vcs_cmd):
        ha_display_out = ('#Resource   Attribute      System     Value\n'
                          'RES1 State         node1      ONLINE\n'
                          'RES2 State     node2      OFFLINE')

        run_vcs_cmd.side_effect = [(0, ha_display_out, "Err"),
                                   (0, '', ""), (0, '', ""), (0, '', "")]
        req = {'resource': 'RES1'}
        self.api.hares_delete(req)

        calls = [mock.call('/opt/VRTS/bin/hares -display RES1 -attribute State',
                            rewrite_retcode=True,
                            expected_errors=['VCS WARNING V-16-1-40130']),
                 mock.call('/opt/VRTS/bin/hares -offline RES1 -sys node1'),
                 mock.call('/opt/VRTS/bin/hares -delete RES1',
                           expected_errors=['VCS WARNING V-16-1-10260'],
                           rewrite_retcode=True)]

        run_vcs_cmd.assert_has_calls(calls)
        self.assertEqual(3, run_vcs_cmd.call_count)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hares_add(self, run_vcs_cmd):
        run_vcs_cmd.return_value = (1, "", "Err")
        req = {"resource":"App1",
               "type":"Application",
               "group_name":"Grp1"}
        ret_dict = self.api.hares_add(req)
        run_vcs_cmd.assert_called_once_with(
            '/opt/VRTS/bin/hagrp -resources Grp1')
        self.assertEqual(ret_dict, {'retcode': 1, 'err': 'Err', 'out': ''})

        run_vcs_cmd.return_value = (0, "App2\nApp1", "")
        ret_dict = self.api.hares_add(req)
        self.assertEqual(ret_dict, {'retcode': 0, 'err': '', 'out': ''})

        run_vcs_cmd.side_effect = [(0, "App2\nApp11", ""),
                                   (0, "App created", "")]
        ret_dict = self.api.hares_add(req)
        self.assertEqual(ret_dict, {'retcode': 0,
                                    'err': '',
                                    'out': 'App created'})

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_online_success(self, run_vcs_cmd):
        run_vcs_cmd.side_effect = [(0, "", "")]
        req = {"group_name":"grp"}
        cmd = "/opt/VRTS/bin/hagrp -online grp -any"
        ret_dict = self.api.hagrp_online(req)
        calls = [mock.call(cmd,
                           rewrite_retcode=True,
                           expected_errors=["V-16-1-50997",
                                            "V-16-1-50996",
                                            "V-16-1-50735",
                                            "V-16-1-10165"])]

        run_vcs_cmd.assert_has_calls(calls)
        self.assertEqual({'retcode': 0, 'err': '', 'out': ''}, ret_dict)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_online_unsuccess(self, run_vcs_cmd):
        def side_effect(command, **kwargs):
            msg = ("VCS NOTICE V-16-1-10284 Cannot online a faulted resource:Clear the faulted resource on system node1.\n"
                   "VCS NOTICE V-16-1-10284 Cannot online a faulted resource:Clear the faulted resource on system node2.")
            raise VCSCommandException(msg)
        run_vcs_cmd.side_effect = side_effect
        req = {"group_name":"grp"}
        cmd = "/opt/VRTS/bin/hagrp -online grp -any"
        ret_dict = self.api.hagrp_online(req)
        calls = [mock.call(cmd,
                           rewrite_retcode=True,
                           expected_errors=["V-16-1-50997",
                                            "V-16-1-50996",
                                            "V-16-1-50735",
                                            "V-16-1-10165"])]
        run_vcs_cmd.assert_has_calls(calls)
        self.assertEqual({'retcode': 1,
                          'err': 'VCS NOTICE V-16-1-10284 Cannot online a faulted resource:Clear the faulted resource on system node1.\n'
                                 'VCS NOTICE V-16-1-10284 Cannot online a faulted resource:Clear the faulted resource on system node2.',
                          'out': ''},
                         ret_dict)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_offline_any(self, run_vcs_cmd):
        run_vcs_cmd.side_effect = [(0, "", "")]
        req = {"group_name":"Grp2"}
        cmd = "/opt/VRTS/bin/hagrp -offline Grp2 -any"
        ret_dict = self.api.hagrp_offline(req)
        calls = [mock.call(cmd,
                           rewrite_retcode=True,
                           expected_errors=['VCS WARNING V-16-1-12130',
                                            'VCS WARNING V-16-1-10135',
                                            'VCS WARNING V-16-1-50837'])]
        run_vcs_cmd.assert_has_calls(calls)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_offline_system(self, run_vcs_cmd):
        run_vcs_cmd.side_effect = [(0, "", "")]
        req = {"group_name":"Grp2",
               "system":"sys1"}
        cmd = "/opt/VRTS/bin/hagrp -offline Grp2 -sys sys1"
        ret_dict = self.api.hagrp_offline(req)
        calls = [mock.call(cmd,
                           rewrite_retcode=True,
                           expected_errors=['VCS WARNING V-16-1-12130',
                                            'VCS WARNING V-16-1-10135',
                                            'VCS WARNING V-16-1-50837'])]
        run_vcs_cmd.assert_has_calls(calls)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_offline_except(self, run_vcs_cmd):
        run_vcs_cmd.side_effect = VCSCommandException("Error")
        req = {"group_name":"Grp2",
               "system":"sys1"}
        ret_dict = self.api.hagrp_offline(req)
        self.assertEqual(ret_dict,
                         {'retcode': 1, 'out': '', 'err': 'Error'})

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_remove(self, run_vcs_cmd):
        run_vcs_cmd.side_effect = [(0, "", "")]
        req = {"group_name":"Grp2"}
        cmd = ('for res in $(/opt/VRTS/bin/hagrp -resources Grp2);'
               ' do /opt/VRTS/bin/hares -delete $res; done; '
               '/opt/VRTS/bin/hagrp -delete Grp2')
        ret_dict = self.api.hagrp_remove(req)
        calls = [mock.call(cmd,
                           rewrite_retcode=True,
                           expected_errors=['VCS WARNING V-16-1-12130'])]
        run_vcs_cmd.assert_has_calls(calls)

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_list_success(self, run_vcs_cmd):
        run_vcs_cmd.side_effect = [(0, "Group1 node1", "")]
        ret_dict = self.api.hagrp_list({})

        run_vcs_cmd.assert_any_call('hagrp -list',
                            rewrite_retcode=True,
                            expected_errors=['VCS WARNING V-16-1-50031'])
        self.assertEqual(ret_dict,
                         {'retcode': 0, 'out': {'Group1':['node1']}, 'err': ''})

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_list_success_two_node(self, run_vcs_cmd):
        run_vcs_cmd.side_effect = [(0, "Group1 node1 Group1 node2", "")]
        ret_dict = self.api.hagrp_list({})

        run_vcs_cmd.assert_any_call('hagrp -list',
                            rewrite_retcode=True,
                            expected_errors=['VCS WARNING V-16-1-50031'])
        self.assertEqual(ret_dict,
                         {'retcode': 0, 'out': {'Group1':['node1','node2']}, 'err': ''})

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_list_except(self, run_vcs_cmd):
        run_vcs_cmd.side_effect = VCSCommandException("Error")
        ret_dict = self.api.hagrp_list({})
        self.assertEqual(ret_dict,
                         {'retcode': 1, 'out': '', 'err': 'Error'})

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_remove_except(self, run_vcs_cmd):
        run_vcs_cmd.side_effect = VCSCommandException("Error")
        req = {"group_name":"Grp2"}
        ret_dict = self.api.hagrp_remove(req)
        self.assertEqual(ret_dict,
                         {'retcode': 1, 'out': '', 'err': 'Error'})

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_unlink(self, run_vcs_cmd):
        run_vcs_cmd.return_value = (0, "", "")
        req = {"parent": "Parent_Grp", "child": "Child_Group"}
        ret_dict = self.api.hagrp_unlink(req)

        self.assertEqual(ret_dict, {'retcode': 0, 'out': '', 'err': ''})
        run_vcs_cmd.assert_called_once_with('hagrp -unlink Parent_Grp Child_Group',
                                            rewrite_retcode=True,
                                            expected_errors=['VCS WARNING V-16-1-10133',
                                                             'VCS WARNING V-16-1-10146'])

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_unlink_error(self, run_vcs_cmd):
        run_vcs_cmd.side_effect = VCSCommandException("Error")
        req = {"parent": "Parent_Grp", "child": "Child_Group"}
        ret_dict = self.api.hagrp_unlink(req)
        self.assertEqual(ret_dict,
                         {'retcode': 1, 'out': '', 'err': 'Error'})
        run_vcs_cmd.assert_called_once_with('hagrp -unlink Parent_Grp Child_Group',
                                    rewrite_retcode=True,
                                    expected_errors=['VCS WARNING V-16-1-10133',
                                                     'VCS WARNING V-16-1-10146'])

    @mock.patch('vcs_cmd_api.VcsCmdApi._system_list')
    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_add_in_system_list(self, patch_run_vcs_cmd, patch_system_list):
        # add 1 node to exisiting 1 node
        patch_run_vcs_cmd.return_value = (0, "", "")
        patch_system_list.return_value = ['node1']
        req = {"group_name":"GroupName",
               "attribute_val":"node1 0 node2 0"}

        ret_dict = self.api.hagrp_add_in_system_list(req)

        calls = [mock.call('/opt/VRTS/bin/hagrp -modify GroupName SystemList -add node2 0')]
        patch_run_vcs_cmd.assert_has_calls(calls)
        self.assertEquals(ret_dict, {"retcode": 0, "out": '', "err": ''})

        # add 2 nodes to exisiting 1 node
        req["attribute_val"] = "node1 0 node2 0 node3 0"

        ret_dict = self.api.hagrp_add_in_system_list(req)

        calls = [mock.call('/opt/VRTS/bin/hagrp -modify GroupName SystemList -add node3 0 node2 0')]
        patch_run_vcs_cmd.assert_has_calls(calls)
        self.assertEquals(ret_dict, {"retcode": 0, "out": '', "err": ''})

        # add initial 2 nodes
        patch_system_list.return_value = set()
        req["attribute_val"] = "node1 0 node2 0"

        ret_dict = self.api.hagrp_add_in_system_list(req)

        calls = [mock.call('/opt/VRTS/bin/hagrp -modify GroupName SystemList -add node1 0 node2 0')]
        patch_run_vcs_cmd.assert_has_calls(calls)
        self.assertEquals(ret_dict, {"retcode": 0, "out": '', "err": ''})

    @mock.patch('vcs_cmd_api.VcsCmdApi._system_list')
    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_delete_in_system_list(self, patch_run_vcs_cmd,
                                               patch_system_list):
        # delete 1 node from exisiting 2 nodes
        patch_run_vcs_cmd.return_value = (0, "", "")
        patch_system_list.return_value = set(['node1', 'node2'])
        req = {"group_name":"GroupName",
               "attribute_val":"node1"}

        ret_dict = self.api.hagrp_delete_in_system_list(req)

        calls = [mock.call('/opt/VRTS/bin/hagrp -modify GroupName SystemList -delete node1', ['VCS WARNING V-16-1-10200', 'VCS WARNING V-16-1-10180'], rewrite_retcode=True)]
        patch_run_vcs_cmd.assert_has_calls(calls)
        self.assertEquals(ret_dict, {"retcode": 0, "out": '', "err": ''})

        # delete both exisiting 2 nodes
        req["attribute_val"] = "node1 node2"

        ret_dict = self.api.hagrp_delete_in_system_list(req)

        calls = [mock.call('/opt/VRTS/bin/hagrp -modify GroupName SystemList -delete node1', ['VCS WARNING V-16-1-10200', 'VCS WARNING V-16-1-10180'], rewrite_retcode=True)]
        patch_run_vcs_cmd.assert_has_calls(calls)
        self.assertEquals(ret_dict, {"retcode": 0, "out": '', "err": ''})

    @mock.patch('vcs_cmd_api.VcsCmdApi._auto_start_list')
    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_add_in_auto_start_list(self, patch_run_vcs_cmd,
                                                patch_auto_start_list):
        # add 2 nodes
        patch_run_vcs_cmd.return_value = (0, "", "")
        patch_auto_start_list.return_value = []
        req = {"group_name":"GroupName",
               "attribute_val":"node2 node1"}
        ret_dict = self.api.hagrp_add_in_auto_start_list(req)
        calls = [mock.call('/opt/VRTS/bin/hagrp -modify GroupName AutoStartList -add node2 node1')]

        patch_run_vcs_cmd.assert_has_calls(calls)
        self.assertEquals(ret_dict, {"retcode": 0, "out": '', "err": ''})

        # add 1 node
        patch_run_vcs_cmd.return_value = (0, "", "")
        patch_auto_start_list.return_value = ["node1"]
        req = {"group_name":"GroupName",
               "attribute_val":"node2"}
        ret_dict = self.api.hagrp_add_in_auto_start_list(req)
        calls = [mock.call('/opt/VRTS/bin/hagrp -modify GroupName AutoStartList -add node2')]

        patch_run_vcs_cmd.assert_has_calls(calls)
        self.assertEquals(ret_dict, {"retcode": 0, "out": '', "err": ''})

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hastop_all(self, patch_run_vcs_cmd):
        patch_run_vcs_cmd.return_value = (0, "success", "")
        req = {}
        ret_dict = self.api.stop_vcs(req)
        self.assertEqual(patch_run_vcs_cmd.call_args_list, [mock.call("hastop -all ")])
        self.assertEquals(ret_dict, {"retcode": 0, "out": 'success', "err": ''})

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hastop_force(self, patch_run_vcs_cmd):
        patch_run_vcs_cmd.return_value = (0, "success", "")
        req = {"force": "force"}
        ret_dict = self.api.stop_vcs(req)
        self.assertEqual(patch_run_vcs_cmd.call_args_list, [mock.call("hastop -force -all ")])
        self.assertEquals(ret_dict, {"retcode": 0, "out": 'success', "err": ''})

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hastop_sys(self, patch_run_vcs_cmd):
        patch_run_vcs_cmd.return_value = (0, "success", "")
        req = {"sys": "mn1"}
        ret_dict = self.api.stop_vcs(req)
        self.assertEqual(patch_run_vcs_cmd.call_args_list, [mock.call("hastop -sys mn1")])
        self.assertEquals(ret_dict, {"retcode": 0, "out": 'success', "err": ''})

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hastop_error(self, patch_run_vcs_cmd):
        patch_run_vcs_cmd.side_effect = VCSCommandException("could not find command")
        req = {"sys": "mn1"}
        ret_dict = self.api.stop_vcs(req)
        self.assertEqual(patch_run_vcs_cmd.call_args_list, [mock.call("hastop -sys mn1")])
        self.assertEquals(ret_dict, {"retcode": 1, "out": '', "err": 'could not find command'})

    @mock.patch('vcs_cmd_api.VcsCmdApi.hagrp_display')
    @mock.patch('vcs_cmd_api.VcsCmdApi._hagrp_frozen')
    def test_group_intent_online_0_unfrozen(self, mock_hagrp_frozen,
                                            mock_hagrp_display):
        def _mock_hagrp_display(attribute, **kwargs):
            if attribute == "IntentOnline":
                return ["Grp_CS_test_1 IntentOnline global 0"]
            else:
                return [None]
        mock_hagrp_display.side_effect = _mock_hagrp_display
        mock_hagrp_frozen.return_value = False
        self.assertFalse(self.api._group_intent_online("Grp_CS_test_1"))

    @mock.patch('vcs_cmd_api.VcsCmdApi.hagrp_display')
    @mock.patch('vcs_cmd_api.VcsCmdApi._hagrp_frozen')
    def test_group_intent_online_0_frozen(self, mock_hagrp_frozen,
                                           mock_hagrp_display):
        def _mock_hagrp_display(attribute, **kwargs):
            if attribute == "IntentOnline":
                return ["Grp_CS_test_1 IntentOnline global 0"]
            else:
                return [None]
        mock_hagrp_display.side_effect = _mock_hagrp_display
        mock_hagrp_frozen.return_value = True
        self.assertFalse(self.api._group_intent_online("Grp_CS_test_1"))

    @mock.patch('vcs_cmd_api.VcsCmdApi.hagrp_display')
    @mock.patch('vcs_cmd_api.VcsCmdApi._hagrp_frozen')
    def test_group_intent_online_1_unfrozen(self, mock_hagrp_frozen,
                                             mock_hagrp_display):
        def _mock_hagrp_display(attribute, **kwargs):
            if attribute == "IntentOnline":
                return ["Grp_CS_test_1 IntentOnline global 1"]
            else:
                return [None]
        mock_hagrp_display.side_effect = _mock_hagrp_display
        mock_hagrp_frozen.return_value = False
        self.assertTrue(self.api._group_intent_online("Grp_CS_test_1"))

    @mock.patch('vcs_cmd_api.VcsCmdApi.hagrp_display')
    @mock.patch('vcs_cmd_api.VcsCmdApi._hagrp_frozen')
    def test_group_intent_online_1_frozen(self, mock_hagrp_frozen,
                                          mock_hagrp_display ):
        def _mock_hagrp_display(attribute, **kwargs):
            if attribute == "IntentOnline":
                return ["Grp_CS_test_1 IntentOnline global 1"]
            else:
                return [None]
        mock_hagrp_display.side_effect = _mock_hagrp_display
        mock_hagrp_frozen.return_value = True
        self.assertFalse(self.api._group_intent_online("Grp_CS_test_1"))


    @mock.patch('vcs_cmd_api.VcsCmdApi.hagrp_display')
    @mock.patch('vcs_cmd_api.VcsCmdApi._hagrp_frozen')
    def test_group_intent_online_2_unfrozen(self, mock_hagrp_frozen,
                                            mock_hagrp_display):
        def _mock_hagrp_display(attribute, **kwargs):
            if attribute == "IntentOnline":
                return ["Grp_CS_test_1 IntentOnline global 2"]
            else:
                return [None]
        mock_hagrp_display.side_effect = _mock_hagrp_display
        mock_hagrp_frozen.return_value = False
        self.assertTrue(self.api._group_intent_online("Grp_CS_test_1"))

    @mock.patch('vcs_cmd_api.VcsCmdApi.hagrp_display')
    @mock.patch('vcs_cmd_api.VcsCmdApi._hagrp_frozen')
    def test_group_intent_online_2_frozen(self, mock_hagrp_frozen,
                                           mock_hagrp_display):
        def _mock_hagrp_display(attribute, **kwargs):
            if attribute == "IntentOnline":
                return ["Grp_CS_test_1 IntentOnline global 2"]
            else:
                return [None]
        mock_hagrp_display.side_effect = _mock_hagrp_display
        mock_hagrp_frozen.return_value = True
        self.assertFalse(self.api._group_intent_online("Grp_CS_test_1"))


    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_frozen_False(self, patch_run_vcs_cmd):
        ha_display_out = ('#Resource   Attribute      System     Value\n'
                          'Grp_CS_test_1 Frozen                global    0\n'
                          'Grp_CS_test_1 TFrozen               global    0\n')
        patch_run_vcs_cmd.return_value = (0, ha_display_out ,"")
        self.assertFalse(self.api._hagrp_frozen("Grp_CS_test_1"))

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_frozen_TFrozen_True(self, patch_run_vcs_cmd):
        ha_display_out = ('#Resource   Attribute      System     Value\n'
                          'Grp_CS_test_1 Frozen                global    0\n'
                          'Grp_CS_test_1 TFrozen               global    1\n')
        patch_run_vcs_cmd.return_value = (0, ha_display_out ,"")
        self.assertTrue(self.api._hagrp_frozen("Grp_CS_test_1"))

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_frozen_Frozen_True(self, patch_run_vcs_cmd):
        ha_display_out = ('#Resource   Attribute      System     Value\n'
                          'Grp_CS_test_1 Frozen                global    1\n'
                          'Grp_CS_test_1 TFrozen               global    0\n')
        patch_run_vcs_cmd.return_value = (0, ha_display_out ,"")
        self.assertTrue(self.api._hagrp_frozen("Grp_CS_test_1"))

    @mock.patch('vcs_cmd_api.VcsCmdApi.run_vcs_command')
    def test_hagrp_frozen_True(self, patch_run_vcs_cmd):
        ha_display_out = ('#Resource   Attribute      System     Value\n'
                          'Grp_CS_test_1 Frozen                global    1\n'
                          'Grp_CS_test_1 TFrozen               global    1\n')
        patch_run_vcs_cmd.return_value = (0, ha_display_out ,"")
        self.assertTrue(self.api._hagrp_frozen("Grp_CS_test_1"))

    @mock.patch('vcs_cmd_api.VcsCmdApi.run')
    def test_get_groups_on_system_by_state(self, mock_run):
        mock_run.side_effect = [
            (0,
            "#Group         Attribute             System     Value\n"
            "Grp_CS_c1_cups State                 node1      |OFFLINE|\n"
            "Grp_CS_c1_httpd State             node1      |ONLINE|\n"
            "Grp_CS_c1_apserv State             node1      |OFFLINE|FAULTED|",
            ""),
            (1, "",
             "VCS WARNING V-16-1-10554 No group exists with system of node1")
        ]
        matching_groups = self.api._get_groups_on_system_by_state('node1',
                                                                  ['FAULTED'])
        self.assertEquals(matching_groups, ['Grp_CS_c1_apserv'])

        matching_groups = self.api._get_groups_on_system_by_state('node1',
                                                                  ['FAULTED'])
        self.assertEquals(matching_groups, [])
