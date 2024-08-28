##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################


from vcsplugin.vcs_cmd_api import VcsCmdApi, VcsRPC
from vcsplugin.vcs_cmd_api import VcsCmdApiException

import unittest
import mock


class TestVcsRPC(unittest.TestCase):

    def setUp(self):
        self.csh = VcsRPC("mn1")

    @mock.patch('vcsplugin.vcs_cmd_api.log')
    @mock.patch('vcsplugin.vcs_cmd_api.run_rpc_command')
    def test_call_mco(self, run_rpc_command, log):
        mco_action = 'haconf'
        args = {'read_only': 'False', 'haaction': 'makerw'}

        run_rpc_command.return_value = {
            'mn1': {'errors': 'RPC Failed',
                    'data':
                        {'retcode': 0, 'err': '', 'out': ''}},
            }
        self.assertRaises(VcsCmdApiException,
                          self.csh._call_mco, mco_action, args)
        self.assertEqual(log.trace.debug.call_args_list, [
                mock.call('Running MCO command "mco rpc vcs_cmd_api haconf '\
                          'read_only=False haaction=makerw -I mn1"')
            ])
        run_rpc_command.return_value = {
            'mn1': {'errors': '',
                    'data':
                        {'retcode': 0, 'err': '', 'out': 'OK'}},
            }
        expected = {'retcode': 0, 'err': '', 'out': 'OK'}
        result = self.csh._call_mco(mco_action, args)
        self.assertEqual(expected, result)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsRPC._call_mco')
    def test_lock(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked"}
        self.csh.lock("mn1", "60", "")
        _call_mco.assert_called_once_with('lock', {'sys': 'mn1', 'switch_timeout': '60'},
                                          timeout=120)
        _call_mco.return_value = {"retcode": 1, "err": "Failed"}
        self.assertRaises(VcsCmdApiException, self.csh.lock, "mn1", "60", "")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsRPC._call_mco')
    def test_unlock(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked"}
        self.csh.unlock("mn1", "70")
        _call_mco.assert_called_once_with('unlock', {'sys': 'mn1',
                                            'nic_wait_timeout': "70"},
                                            timeout=80)
        _call_mco.return_value = {"retcode": 1, "err": "Failed"}
        self.assertRaises(VcsCmdApiException, self.csh.unlock, "mn1", "70")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsRPC._call_mco')
    def test_check_evacuated(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked", "err": ""}
        result = self.csh.check_evacuated("mn1")
        expected = 0, "Worked", ""
        self.assertEqual(expected, result)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsRPC._call_mco')
    def test_check_cluster_online(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked", "err": ""}
        result = self.csh.check_cluster_online("mn1")
        expected = 0, "Worked", ""
        self.assertEqual(expected, result)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsRPC._call_mco')
    def test_cluster_ready(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked", "err": ""}
        result = self.csh.cluster_ready("mn1")
        expected = 0, "Worked", ""
        self.assertEqual(expected, result)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsRPC._call_mco')
    def test_cluster_stopped(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked", "err": ""}
        result = self.csh.cluster_stopped()
        expected = 0, "Worked", ""
        self.assertEqual(expected, result)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsRPC._call_mco')
    def test_probe_all_nics(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked", "err": ""}
        result = self.csh.probe_all_nics("node1")
        expected = 0, "Worked", ""
        self.assertEqual(expected, result)


class TestVcsCmdApi(unittest.TestCase):

    def setUp(self):
        self.csh = VcsCmdApi()
        self.csh.set_node("mn1")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_haconf_rw_invalid_action(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException,
                          self.csh.haconf,
                          "makero")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_haconf_rw_invalid_readonly(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException,
                          self.csh.haconf, "makerw", read_only='True')

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_haconf_rw_unsuccessfully(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException,
                          self.csh.haconf,
                          "makerw")

    @mock.patch('vcsplugin.vcs_cmd_api.log')
    @mock.patch('vcsplugin.vcs_cmd_api.run_rpc_command')
    def test_check_haconf_ro_successfully_remote_build(self, run_rpc_command,
                                                       log_mock):
        error_message = ("__main__.VCSCommandException: Error running "
                        "'VCS WARNING V-16-1-50129 Operation 'haconf "
                        "-dump -makero' rejected as the node is in "
                        "REMOTE_BUILD state'")
        run_rpc_command.return_value = {'mn1': {'errors': error_message,
                                                "data":{}}}
        self.csh.haconf("dump", read_only="True", ignore_node_remote_build=True)
        run_rpc_command.assert_called_once_with(['mn1'], 'vcs_cmd_api',
                                          'haconf',
                                          {'haaction': 'dump',
                                           'read_only': 'True'},
                                            None, retries=1)
        self.assertEqual(log_mock.event.info.call_args_list, [
            mock.call("Restore_snaphot: VCS WARNING V-16-1-50129 Operation "
                "'haconf -dump -makero' rejected as the node is in REMOTE_BUILD"
                " state. Node reboot will restart VCS")
            ])

    @mock.patch('vcsplugin.vcs_cmd_api.log')
    @mock.patch('vcsplugin.vcs_cmd_api.run_rpc_command')
    def test_check_haconf_ro_successfully_node_leaving(self, run_rpc_command,
                                                       log_mock):
        error_message = ("__main__.VCSCommandException: Error running "
                         "'haconf -dump -makero': Out: '' Err: "
                         "'VCS WARNING V-16-1-50129 Operation 'haconf -dump "
                         "-makero' rejected as the node is in LEAVING state'")
        run_rpc_command.return_value = {'mn1': {'errors': error_message,
                                                "data":{}}}
        self.csh.haconf("dump", read_only="True", ignore_node_leaving=True)
        run_rpc_command.assert_called_once_with(['mn1'], 'vcs_cmd_api',
                                          'haconf',
                                          {'haaction': 'dump',
                                           'read_only': 'True'},
                                            None, retries=1)
        self.assertEqual(log_mock.event.info.call_args_list, [
                mock.call("Restore_snaphot: VCS WARNING V-16-1-50129 Operation "\
                    "'haconf -dump -makero' rejected as the node is in LEAVING"\
                    " state. Node reboot will restart VCS")
            ])

    @mock.patch('vcsplugin.vcs_cmd_api.log')
    @mock.patch('vcsplugin.vcs_cmd_api.run_rpc_command')
    def test_check_haconf_ro_successfully_vcs_stop(self, run_rpc_command,
                                                   log_mock):
        error_message = ("__main__.VCSCommandException: Error running "
                         "'haconf -dump -makero': Out: "
                         "'VCS ERROR V-16-1-10600 Cannot connect to "
                         "VCS engine' Err: ''")
        run_rpc_command.return_value = {'mn1': {'errors': error_message,
                                        'data': {}}}
        self.csh.haconf("dump", read_only="True", ignore_vcs_stop_err=True)
        run_rpc_command.assert_called_once_with(['mn1'], 'vcs_cmd_api',
                                          'haconf',
                                          {'haaction': 'dump',
                                           'read_only': 'True'},
                                            None, retries=1)
        self.assertEqual(log_mock.event.info.call_args_list, [
                mock.call("Restore_snaphot: VCS ERROR V-16-1-10600 Cannot "\
                    "connect to VCS engine. Node reboot will restart VCS")
            ])

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_haconf_ro_successfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked"}
        self.csh.haconf("dump", read_only="True")
        print _call_mco.call_args_list
        _call_mco.assert_called_once_with('haconf',
                                          {'haaction': 'dump',
                                           'read_only': 'True'},
                                           expected_errors=[])

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_haconf_rw_successfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked"}
        self.csh.haconf("makerw")
        print _call_mco.call_args_list
        _call_mco.assert_called_once_with('haconf',
                                          {'haaction': 'makerw',
                                           'read_only': 'False'},
                                            expected_errors=[])

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_haconf_cmd_not_found(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "", "err": "haconf: command not found"}
        result = self.csh.haconf("dump", read_only="True", ignore_cmd_not_found=True)
        _call_mco.assert_called_once_with('haconf',
                                          {'haaction': 'dump',
                                           'read_only': 'True'},
                                           expected_errors=["command not found"])
        self.assertEqual(None, result)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hagrp_add_unsuccessfully(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException, self.csh.hagrp_add, "group1")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hagrp_add_successfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked"}
        self.csh.hagrp_add("group1")
        print _call_mco.call_args_list
        _call_mco.assert_called_once_with('hagrp_add',
                                          {'group_name': 'group1'})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hagrp_remove_unsuccessfully(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException, self.csh.hagrp_remove, "group1")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hagrp_remove_successfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked"}
        self.csh.hagrp_remove("group1")
        print _call_mco.call_args_list
        _call_mco.assert_called_once_with('hagrp_remove',
                                          {'group_name': 'group1'})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_call_hagrp_list_errors(self, _call_mco):
        _call_mco.return_value = {"retcode": 1, "err": "Expected Test Error"}
        self.assertRaises(VcsCmdApiException, self.csh.hagrp_list)

    @mock.patch('vcsplugin.vcs_cmd_api.log')
    @mock.patch('vcsplugin.vcs_cmd_api.run_rpc_command')
    def test_call_hagrp_list_success(self, run_rpc_command, log):
        run_rpc_command.return_value = {'mn1': {'errors': '',
            'data': {'retcode': 0, 'err': '', 'out': 'Grp_CS_c1_cups'\
                     '\t\tnode1\nGrp_CS_c1_cups'}}}

        expected_return = 'Grp_CS_c1_cups'\
            '\t\tnode1\nGrp_CS_c1_cups'
        self.assertEqual(self.csh.hagrp_list(), expected_return)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hagrp_offline_unsuccessfully(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException,
                          self.csh.hagrp_offline, "group1", "mn1")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hagrp_offline_successfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked"}
        self.csh.hagrp_offline("group1")
        _call_mco.assert_called_once_with('hagrp_offline',
                                          {'group_name': 'group1'})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hasatus_unsuccessfully(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException, self.csh.hastatus)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hastatus_successfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked", "err": ""}
        self.csh.hastatus()
        print _call_mco.call_args_list
        _call_mco.assert_called_once_with('hastatus', {})
#        self.assertTrue(False)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hagrp_modify_unsuccessfully(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException, self.csh.hagrp_modify,
                          "group1", "attr1", "val1")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hagrp_modify_successfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked", "err": ""}
        self.csh.hagrp_modify("group1", "attr1", "val1")
        print _call_mco.call_args_list
        _call_mco.assert_called_once_with('hagrp_modify',
                                          {'attribute': 'attr1',
                                           'attribute_val': 'val1',
                                           'group_name': 'group1'})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hares_add_unsuccessfully(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException, self.csh.hares_add,
                          "test", "type", "group1")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hares_add_successfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked"}
        self.csh.hares_add("test", "type", "group1")
        print _call_mco.call_args_list
        _call_mco.assert_called_once_with('hares_add',
                                          {'type': 'type',
                                           'resource': 'test',
                                           'group_name': 'group1'})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hares_modify_unsuccessfully(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException, self.csh.hares_modify,
                          "test", "Address", "local")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hares_modify_successfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked"}
        self.csh.hares_modify("test", "Address", "local", sys="mn1")
        print _call_mco.call_args_list
        _call_mco.assert_called_once_with('hares_modify',
                                          {'sys': 'mn1',
                                           'attribute': 'Address',
                                           'resource': 'test',
                                           'attribute_val': 'local'})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hares_modufy_modify_warning(self, _call_mco):
        warning_str = "VCS WARNING V-16-1-10566 Entry not found in attribute " \
                      "keylist."
        _call_mco.return_value = {"retcode": 1, "err": warning_str}
        self.csh.hares_modify("test", "Address", "local", sys="mn1")
        _call_mco.assert_called_once_with('hares_modify',
                                          {'sys': 'mn1',
                                           'attribute': 'Address',
                                           'resource': 'test',
                                           'attribute_val': 'local'})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hares_local_unsuccessfully(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException, self.csh.hares_local,
                          "test", "Address")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hares_local_successfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked"}
        self.csh.hares_local("test", "Address")
        print _call_mco.call_args_list
        _call_mco.assert_called_once_with('hares_local',
                                          {'attribute': 'Address',
                                           'resource': 'test'})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hares_override_unsuccessfully(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException,
                          self.csh.hares_override_attribute,
                          "test", "Address")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hares_override_successfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked"}
        self.csh.hares_override_attribute("test", "Address")
        print _call_mco.call_args_list
        _call_mco.assert_called_once_with('hares_override_attribute',
                                          {'attribute': 'Address',
                                           'resource': 'test'})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hagrp_isoffline_unsuccessfully(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        cb_api = mock.Mock()
        cb_api.is_running = mock.Mock(return_value=True)
        self.assertRaises(VcsCmdApiException, self.csh.check_hagrp_isoffline,
                          cb_api, "test", 1, "mn1")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hagrp_isoffline_successfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 0}
        self.csh.check_hagrp_isoffline("test", 30, "mn1")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_bring_hagrp_online_unsuccess(self, _call_mco):
        group_name = "test_group"
        _call_mco.return_value = {"retcode": -1, "err": "error"}
        self.assertRaises(VcsCmdApiException,
                          self.csh.bring_hagrp_online,
                          group_name)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_bring_hagrp_online_successfully(self, _call_mco):
        group_name = "test_group"
        _call_mco.return_value = {"retcode": 0, "err": "",
                                  "out": "V-16-1-50735 MN1"}
        self.csh.bring_hagrp_online(group_name)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_bring_hagrp_already_online(self, _call_mco):
        group_name = "test_group"
        _call_mco.return_value = {"retcode": 0, "err": "",
                                  "out": "V-16-1-50997 MN1"}
        self.csh.bring_hagrp_online(group_name)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_bring_hagrp_online_unexpect_vcs_error(self, _call_mco):
        group_name = "test_group"
        _call_mco.return_value = {"retcode": 1, "err": "",
				  "out": "V-16-1-50000 MN1"}
        self.assertRaises(VcsCmdApiException,
                          self.csh.bring_hagrp_online, group_name)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_bring_hagrp_online_unexpect_vcs_error2(self, _call_mco):
        group_name = "test_group"
        _call_mco.return_value = {"retcode": 1, "err": "Unexpected Error",
				  "out": ""}
        self.assertRaises(VcsCmdApiException,
                          self.csh.bring_hagrp_online, group_name)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_verify_main_cf_successfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 0}
        self.csh.verify_main_cf()

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_verify_main_cf_unsuccessfully(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected Test Error"}
        self.assertRaises(VcsCmdApiException, self.csh.verify_main_cf)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_main_cf_is_ReadOnly_command_fails(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected Test Error"}
        self.assertRaises(VcsCmdApiException,
                          self.csh.check_main_cf_is_readonly)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_main_cf_is_ReadOnly_unsuccessfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": 0}
        self.assertRaises(VcsCmdApiException,
                          self.csh.check_main_cf_is_readonly)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_main_cf_is_ReadOnly_successfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "1"}
        self.csh.check_main_cf_is_readonly()

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_vcs_groups_has_resources_command_fails(self, _call_mco):
        group_name = "test_group"
        _call_mco.return_value = {"retcode": -1, "err": "Expected Test Error"}
        self.assertRaises(VcsCmdApiException,
                          self.csh.check_vcs_group_has_resources, group_name)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_vcs_groups_has_resources_command_unsuccessfully(self, _call_mco):
        group_name = "test_group"
        _call_mco.return_value = {"retcode": 0, "out": None}
        self.assertRaises(VcsCmdApiException,
                          self.csh.check_vcs_group_has_resources, group_name)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_vcs_groups_has_resources_command_successfully(self, _call_mco):
        group_name = "test_group"
        _call_mco.return_value = {"retcode": 0, "out": "Resources"}
        self.csh.check_vcs_group_has_resources(group_name)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_hares_link_unsuccessfully(self, _call_mco):
        parent = "application"
        child = "ipaddress"
        _call_mco.return_value = {"retcode": 1, "err": "Expected Test Error"}
        self.assertRaises(VcsCmdApiException,
                          self.csh.hares_link, parent, child)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_hares_link_successfully(self, _call_mco):
        parent = "application"
        child = "ipaddress"
        _call_mco.return_value = {"retcode": 0, "out": "success"}
        try:
            self.csh.hares_link(parent, child)
        except VcsCmdApiException:
            self.fail("hares_link raised unexpected exception")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_hares_unlink_unsuccessfully(self, _call_mco):
        parent = "application"
        child = "ipaddress"
        _call_mco.return_value = {"retcode": 1, "err": "Expected Test Error"}
        self.assertRaises(VcsCmdApiException,
                          self.csh.hares_unlink, parent, child)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_hares_unlink_successfully(self, _call_mco):
        parent = "application"
        child = "ipaddress"
        _call_mco.return_value = {"retcode": 0, "out": "success"}
        try:
            self.csh.hares_unlink(parent, child)
        except VcsCmdApiException:
            self.fail("hares_link raised unexpected exception")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_hares_probe_unsuccessfully(self, _call_mco):
        res = "resource1"
        sys = "mn2"
        _call_mco.return_value = {"retcode": 1, "err": "Expected Test Error"}
        self.assertRaises(VcsCmdApiException,
                          self.csh.hares_probe, res, sys)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_hares_probe_successfully(self, _call_mco):
        res = "resource1"
        sys = "mn2"
        _call_mco.return_value = {"retcode": 0, "out": "success"}
        try:
            self.csh.hares_probe(res, sys)
        except VcsCmdApiException:
            self.fail("hares_link raised unexpected exception")

    @mock.patch('vcsplugin.vcs_cmd_api.log')
    @mock.patch('vcsplugin.vcs_cmd_api.run_rpc_command')
    def test_call_mco_extra_replies(self, run_rpc_command, log):
        mco_action = 'haconf'
        args = {'read_only': 'False', 'haaction': 'makerw'}

        run_rpc_command.return_value = {
            'mn1': {'errors': '',
                    'data':
                        {'retcode': 0, 'err': '', 'out': ''}},
            'mn2': {'errors': '',
                    'data':
                        {'retcode': 0, 'err': '', 'out': ''}}
            }
        self.assertRaises(VcsCmdApiException,
                          self.csh._call_mco, mco_action, args)
        self.assertEqual(log.trace.debug.call_args_list, [
            mock.call('Running MCO VCS command \"mco rpc vcs_cmd_api haconf '\
                      'read_only=False haaction=makerw -I mn1\" '),
            ])

    @mock.patch('vcsplugin.vcs_cmd_api.log')
    @mock.patch('vcsplugin.vcs_cmd_api.run_rpc_command')
    def test_call_mco_unexpected_node(self, run_rpc_command, log):
        mco_action = 'haconf'
        args = {'read_only': 'False', 'haaction': 'makerw'}

        run_rpc_command.return_value = {
            'mn2': {'errors': '',
                    'data':
                        {'retcode': 0, 'err': '', 'out': ''}}
            }
        self.assertRaises(VcsCmdApiException,
                          self.csh._call_mco, mco_action, args)
        self.assertEqual(log.trace.debug.call_args_list, [
            mock.call('Running MCO VCS command \"mco rpc vcs_cmd_api haconf '\
                      'read_only=False haaction=makerw -I mn1\" '),
            ])

    @mock.patch('vcsplugin.vcs_cmd_api.log')
    @mock.patch('vcsplugin.vcs_cmd_api.run_rpc_command')
    def test_call_mco_success(self, run_rpc_command, log):
        mco_action = 'haconf'
        args = {'read_only': 'False', 'haaction': 'makerw'}

        run_rpc_command.return_value = {'mn1': {'errors': '',
            'data': {'retcode': 0, 'err': '', 'out': ''}}}
        data_result = self.csh._call_mco(mco_action, args)

        self.assertEqual(data_result, {'retcode': 0, 'err': '', 'out': ''})
        self.assertEqual(log.trace.debug.call_args_list, [
            mock.call('Running MCO VCS command \"mco rpc vcs_cmd_api haconf '\
                      'read_only=False haaction=makerw -I mn1\" '),
            ])

    def test_get_mco_vcs_command(self):
        action = 'hagrp_modify'
        args = {'attribute': 'Parallel', 'attribute_val': '0',
                'group_name': 'Grp_CS_cluster1_cs2'}

        expected_return_command = '\"mco rpc vcs_cmd_api hagrp_modify attribu'\
          'te=Parallel group_name=Grp_CS_cluster1_cs2 attribute_val=0 -I mn1\" '
        command = self.csh._get_mco_vcs_command(action, args)

        self.assertEqual(command, expected_return_command)

    def test_gen_err_str(self):
        action = 'hagrp_modify'
        args = {'attribute': 'Parallel', 'attribute_val': '0',
                'group_name': 'Grp_CS_cluster1_cs2'}

        expected_return_command = 'Failure to execute command: \"mco rpc '\
           'vcs_cmd_api hagrp_modify attribute=Parallel group_name=Grp_CS_'\
           'cluster1_cs2 attribute_val=0 -I mn1\" '
        command = self.csh._gen_err_str(action, args)

        self.assertEqual(command, expected_return_command)

    @mock.patch('vcsplugin.vcs_cmd_api.log')
    @mock.patch('vcsplugin.vcs_cmd_api.run_rpc_command')
    def test_call_mco_errors_returned(self, run_rpc_command, log):
        mco_action = 'haconf'
        args = {'read_only': 'False', 'haaction': 'makerw'}

        run_rpc_command.return_value = {'mn1': {'errors': 'node2: execution expired',
            'data': {'retcode': 0, 'err': '', 'out': ''}}}

        self.assertRaises(VcsCmdApiException, self.csh._call_mco, mco_action, args)
        self.assertEqual(log.trace.error.call_args_list, [
            mock.call('Failure to execute command: "mco rpc vcs_cmd_api '
                      'haconf read_only=False haaction=makerw -I mn1" '
                      'Reason: MCO failure... node2: execution expired '
                      'on node mn1'),
            ])

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_call_hares_list_errors(self, _call_mco):
        _call_mco.return_value = {"retcode": 1, "err": "Expected Test Error"}
        self.assertRaises(VcsCmdApiException, self.csh.hares_list)

    @mock.patch('vcsplugin.vcs_cmd_api.log')
    @mock.patch('vcsplugin.vcs_cmd_api.run_rpc_command')
    def test_call_hares_list_success(self, run_rpc_command, log):
        run_rpc_command.return_value = {'mn1': {'errors': '',
            'data': {'retcode': 0, 'err': '', 'out': 'Res_App_cluster1_cs1_runtime1'\
                     '            \t\tmn1\nRes_App_cluster1_cs1_runtime1'}}}

        expected_return = 'Res_App_cluster1_cs1_runtime1            '\
            '\t\tmn1\nRes_App_cluster1_cs1_runtime1'
        self.assertEqual(self.csh.hares_list(), expected_return)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_call_hasys_freeze_unsuccessful(self, _call_mco):
        _call_mco.return_value = {"retcode": 1, "err": "Expected Test Error"}
        self.assertRaises(VcsCmdApiException, self.csh.hasys_freeze, "mn1")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_call_hasys_freeze_success(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Expected Test Output"}
        expected_return = 'Expected Test Output'
        self.assertEqual(self.csh.hasys_freeze("mn1"), expected_return)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_call_hasys_unfreeze_unsuccessful(self, _call_mco):
        _call_mco.return_value = {"retcode": 1, "err": "Expected Test Error"}
        self.assertRaises(VcsCmdApiException, self.csh.hasys_unfreeze, "mn1")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_call_hasys_unfreeze_success(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Expected Test Output"}
        expected_return = 'Expected Test Output'
        self.assertEqual(self.csh.hasys_unfreeze("mn1"), expected_return)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_call_hasys_state_unsuccessful(self, _call_mco):
        _call_mco.return_value = {"retcode": 1, "err": "Expected Test Error"}
        self.assertRaises(VcsCmdApiException, self.csh.hasys_state, "mn1")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_call_hasys_state_success(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Expected Test Output"}
        expected_return = 'Expected Test Output'
        self.assertEqual(self.csh.hasys_state("mn1"), expected_return)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_start_vx_fencing_unsuccessful(self, _call_mco):
        _call_mco.return_value = {"retcode": 1, "err": "VX Fencing Failed"}
        self.assertRaises(VcsCmdApiException, self.csh.start_vx_fencing)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_start_vx_fencing(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "VX Fencing Worked"}
        self.csh.start_vx_fencing()
        _call_mco.assert_called_once_with('start_vx_fencing', {})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_start_vcs_unsuccessful(self, _call_mco):
        _call_mco.return_value = {"retcode": 1, "err": "Start VCS Failed"}
        self.assertRaises(VcsCmdApiException, self.csh.start_vcs)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_start_vcs(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Start VCS Worked"}
        self.csh.start_vcs()
        _call_mco.assert_called_once_with('start_vcs', {})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_stop_vcs(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Stop VCS Worked"}
        self.csh.stop_vcs()
        _call_mco.assert_called_once_with('stop_vcs', {})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_stop_vcs_error(self, _call_mco):
        _call_mco.return_value = {"retcode": 1, "err": "",
                "out": "VCS ERROR V-16-1-10600 Cannot connect to VCS engine"}
        self.assertRaises(VcsCmdApiException, self.csh.stop_vcs,
                           ignore_vcs_stop_err=False)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_stop_vcs_error_ignore(self, _call_mco):
        _call_mco.return_value = {"retcode": 1, "out": "",
                "err": "VCS ERROR V-16-1-10600 Cannot connect to VCS engine"}
        try:
            self.csh.stop_vcs(self, ignore_vcs_stop_err=True)
        except VcsCmdApiException:
            self.fail("stop_vcs() raised unexpected VcsCmdApiException type")

    @mock.patch('vcsplugin.vcs_cmd_api.log')
    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_stop_vcs_cmd_not_found(self, _call_mco, log_patch):
        _call_mco.return_value = {
            "retcode": 1,
            "err": "Error running 'hastop -sys node1': Out: '' Err: '/bin/sh: hastop: command not found'",
            "out": ""}

        self.csh.stop_vcs(self, ignore_cmd_not_found=True)
        log_patch.event.info.assert_called_once_with(
            "Stop VCS: VCS command was not found on node. Ignoring this issue.")
        _call_mco.assert_called_once_with("stop_vcs", {"force": "force"})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_vxfen_admin(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Admin Worked"}
        out = self.csh.vxfen_admin()
        _call_mco.assert_called_once_with('vxfen_admin', {})
        self.assertEqual(out, 'Admin Worked')

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_vxfen_admin_error(self, _call_mco):
        _call_mco.return_value = {"retcode": 1, "out": "", "err": "ERROR"}
        self.assertRaises(VcsCmdApiException, self.csh.vxfen_admin)
        _call_mco.assert_called_once_with('vxfen_admin', {})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_vxfen_config(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Config Worked"}
        out = self.csh.vxfen_config()
        _call_mco.assert_called_once_with('vxfen_config', {})
        self.assertEqual(out, 'Config Worked')

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_vxfen_config_error(self, _call_mco):
        _call_mco.return_value = {"retcode": 1, "out": "", "err": "ERROR"}
        self.assertRaises(VcsCmdApiException, self.csh.vxfen_config)
        _call_mco.assert_called_once_with('vxfen_config', {})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_edit_maincf_use_fence(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Config Worked"}
        out = self.csh.edit_maincf_use_fence('cluster1')
        _call_mco.assert_called_once_with('edit_maincf_use_fence', {"cluster_name": 'cluster1'})
        self.assertEqual(out, None)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_edit_maincf_use_fence_error(self, _call_mco):
        _call_mco.return_value = {"retcode": 1, "out": "", "err": "ERROR"}
        self.assertRaises(VcsCmdApiException, self.csh.edit_maincf_use_fence, 'cluster2')
        _call_mco.assert_called_once_with('edit_maincf_use_fence', {"cluster_name": 'cluster2'})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_hagrp_value(self, _call_mco):
        _call_mco.return_value = {"retcode": 1, "out": "0",
                                  "err": "hagrp_value Failed"}
        self.assertRaises(VcsCmdApiException,
                          self.csh.hagrp_value, "group", "attribute")

        _call_mco.return_value = {"retcode": 0, "out": "0", "err": ""}
        result = self.csh.hagrp_value("group", "attribute")
        _call_mco.assert_called_with('hagrp_value',
                                     {"group_name": "group",
                                      "attribute": "attribute"})
        self.assertEqual(result, "0")

        result = self.csh.hagrp_value("group", "attribute", "node")
        _call_mco.assert_called_with('hagrp_value',
                                     {"group_name": "group",
                                      "attribute": "attribute",
                                      "system": "node"})
        self.assertEqual(result, "0")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_probes_pending_unsuccessful(self, _call_mco):
        _call_mco.return_value = {
            "retcode": 1,
            "out": "",
            "err": "Probes Pending Failed"}
        self.assertRaises(VcsCmdApiException,
                          self.csh.probes_pending)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_probes_pending(self, _call_mco):
        _call_mco.return_value = {
            "retcode": 0,
            "out": "",
            "err": "VCS WARNING V-16-1-50031 No Groups are configured"}
        self.assertEqual("0", self.csh.probes_pending())
        _call_mco.return_value = {
            "retcode": 0,
            "out": "1",
            "err": ""}
        self.assertEqual("1", self.csh.probes_pending())

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_hagrp_link_unsuccessful(self, _call_mco):
        _call_mco.return_value = {
            "retcode": 1,
            "out": "",
            "err": "Probes Pending Failed"}
        self.csh._gen_err_str = mock.Mock(return_value='error message')
        self.assertRaises(VcsCmdApiException,
                          self.csh.hagrp_link, "parent", "child", "online",
                          "global", "soft")
        self.assertEqual(self.csh._gen_err_str.call_count, 1)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_hagrp_link(self, _call_mco):

        _call_mco.return_value = {
            "retcode": 0,
            "out": "worked",
            "err": ""}
        self.csh._gen_err_str = mock.Mock()

        try:
            self.csh.hagrp_link("parent", "child", "online", "global", "soft")
        except VcsCmdApiException:
            self.fail("hagrp_link raised unexpected exception")
        self.assertEqual(self.csh._gen_err_str.call_count, 0)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    @mock.patch('vcsplugin.vcs_cmd_api.log')
    def test_hagrp_link_ignore(self, log_patch, _call_mco):
        _call_mco.return_value = {
            "retcode": 1,
            "out": "",
            "err": "VCS WARNING V-16-1-10905 Dependency between 'Grp_CS_c1_CS10' and 'Grp_CS_c1_CS12' already exists"}

        self.csh.hagrp_link("parent", "child", "online", "global", "soft")
        self.assertEqual(log_patch.trace.debug.call_args_list, [
            mock.call("Ignoring hagrp_link warning... VCS WARNING V-16-1-10905 Dependency between 'Grp_CS_c1_CS10' and 'Grp_CS_c1_CS12' already exists")
        ])

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_get_diskgroup_hostname(self, _call_mco):
        _call_mco.return_value = {'retcode': 0, 'out': "", 'err': ''}
        result = self.csh.get_diskgroup_mounted_status("disk1")
        self.assertEquals(True, result)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_get_diskgroup_hostname_unsuccessfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 1, "err": "disk group not imported"}
        result = self.csh.get_diskgroup_mounted_status("storeg")
        self.assertEquals(False, result)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_deport_disk_group(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": True, "err": ""}
        result = self.csh.deport_disk_group("disk1")
        self.assertEqual(True, result)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_deport_disk_group_unsuccessfully(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException, self.csh.deport_disk_group,
                          "disk1")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_get_group_state_pos(self, _call_mco):
        _call_mco.return_value = {'retcode': 0, 'out': 'MOCK', 'err': ''}
        self.assertEquals('MOCK', self.csh.get_group_state('mock_vcs_group',
            active_count='1', offline_count='1'))

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_get_group_state_raises(self, _call_mco):
        _call_mco.return_value = {'retcode': 2, 'out': 'FAULTED',
                                    'err': 'Some error string'}
        self.assertRaises(VcsCmdApiException, self.csh.get_group_state,
                'mock_vcs_group', active_count='1', offline_count='1')

    def test_format_nodes_priorities_parallel(self):
        nodes = ["mn1", "mn2", "mn3"]
        hname_tuples = tuple(enumerate(nodes))
        parallel = True
        expected = "mn1 0 mn2 0 mn3 0"
        self.assertEqual(expected,
                         self.csh._format_nodes_priorities(hname_tuples,
                                                           parallel))

    def test_format_nodes_priorities_failover(self):
        nodes = ["mn1", "mn2"]
        hname_tuples = tuple(enumerate(nodes))
        parallel = False
        expected = "mn1 0 mn2 1"
        self.assertEqual(expected,
                         self.csh._format_nodes_priorities(hname_tuples,
                                                           parallel))

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_clustered_service_set_attributes(self, _call_mco):
        _call_mco.return_value = {'retcode': 0, 'out': 'MOCK', 'err': ''}

        nodes = ["mn2", "mn1", "mn3", "mn5"]
        self.csh.hagrp_add = mock.Mock()
        self.csh.hagrp_modify = mock.Mock()
        self.csh.hagrp_add_in_system_list = mock.Mock()
        hostnames = ["mn1", "mn2"]
        hnames_tuple = tuple(enumerate(hostnames))
        self.csh._clustered_service_set_attributes('gr', hnames_tuple, True)

        self.csh.hagrp_add.assert_called_once_with('gr')
        self.csh.hagrp_modify.assert_any_call('gr', "Parallel", str(int(True)))
        self.csh.hagrp_add_in_system_list.assert_any_call('gr',"mn1 0 mn2 0")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hagrp_delete_in_system_list_unsuccessful(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException,
                        self.csh.hagrp_delete_in_system_list, "group1", "val1")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hagrp_delete_in_system_list_successful(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked", "err": ""}
        self.csh.hagrp_delete_in_system_list("group1", "val1")
        _call_mco.assert_called_once_with('hagrp_delete_in_system_list',
                                          {'attribute_val': 'val1',
                                           'group_name': 'group1'})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hagrp_add_in_system_list_unsuccessful(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException,
                        self.csh.hagrp_add_in_system_list, "group1", "val1")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hagrp_add_in_system_list_successful(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked", "err": ""}
        self.csh.hagrp_add_in_system_list("group1", "val1")
        _call_mco.assert_called_once_with('hagrp_add_in_system_list',
                                          {'attribute_val': 'val1',
                                           'group_name': 'group1'})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hagrp_add_in_auto_start_list_unsuccessful(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException,
                       self.csh.hagrp_add_in_auto_start_list, "group1", "val1")

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_hagrp_add_in_auto_start_list_successful(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked", "err": ""}
        self.csh.hagrp_add_in_auto_start_list("group1", "val1")
        _call_mco.assert_called_once_with('hagrp_add_in_auto_start_list',
                                          {'attribute_val': 'val1',
                                           'group_name': 'group1'})

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_clustered_service_set_syslist_unsuccessfully(self, _call_mco):
        _call_mco.return_value = {"retcode": -1, "err": "Expected error"}
        self.assertRaises(VcsCmdApiException,
                          self.csh._clustered_service_set_syslist,
                          "group1", tuple(enumerate(['node1', 'node2'])), True)

    @mock.patch('vcsplugin.vcs_cmd_api.VcsCmdApi._call_mco')
    def test_check_clustered_service_set_syslist_successfully(self, _call_mco):
        _call_mco.return_value = {"retcode": 0, "out": "Worked"}
        self.csh._clustered_service_set_syslist("group1",
                                    tuple(enumerate(['node1', 'node2'])), True)
        _call_mco.assert_called_once_with('hagrp_add_in_system_list',
                                          {'attribute_val': 'node1 0 node2 0',
                                           'group_name': 'group1'})
