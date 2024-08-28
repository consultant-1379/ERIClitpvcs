##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import functools
import unittest
import mock
import sys

sys.path.append('./puppet/mcollective_agents/files')

from vcs_plugin_api.api_ip_resource_update import (
                                        ApiUpdateIPResource,
                                        ApiUpdateIPResourceNotFoundException,
                                        ApiUpdateIPResourceMissingAttributeException,
                                        ApiUpdateIPResourceUnknownAttributeException,
                                        ApiUpdateIPResourceNoFormattedDataException,
                                        ApiUpdateIPResourceDataFromJSONException,
                                        ApiUpdateIPResourceFailoverAlreadyOnlineException,
                                        ApiUpdateIPResourceFailToOnlineException,
                                        VCS_IP_RESOURCE_TARGET_ATTRIBUTE_NAMES,
                                        VCS_RESOURCE_ALREADY_ONLINE,
                                        VCS_HARES_DISPLAY,
                                        VCS_HARES_LIST,)

from vcs_cmd_api import (VCSException,
                         VCSCommandException,
                         VCSCommandUnknownException,)

# =========================================================
# Constants
# =========================================================
HARES_DISPLAY_OUTPUT = (
        """#Resource          Attribute             System     Value
           r1                 a1                    s1         v1
           r1                 a2                    s2         v2
           r2                 a2                    s2         v3""")

HARES_LIST_OUTPUT = (
        """r1                 s1
           r1                 s2
           r2                 s2""")

# =========================================================
# Decorators
# =========================================================
def _step_tester(tester):

    def generate_res_data():
        res_data = mock.MagicMock()
        for parallel in True, False:
            res_data.Parallel = parallel
            for attrs in ({}, {"a1":[]}, {"a1": ["d1"]},
                          {"a1": ["d1"], "a2": ["d2a", "d2b"]}):
                res_data.Attributes = attrs
                for online in [], ["onl1"], ["onl1", "onl2"]:
                    for offline in [], ["off1"], ["off1", "off2"]:
                        for faulted in [], ["fau1"], ["fau1", "fau2"]:
                            res_data.State.ONLINE = online
                            res_data.State.OFFLINE = offline
                            res_data.State.FAULTED = faulted
                            yield res_data

    @functools.wraps(tester)
    def wrapper(self):
        for res_data in generate_res_data():
            tester(self, res_data)

    return wrapper

# =========================================================
# Test Class
# =========================================================
class TestApiUpdateIPResource(unittest.TestCase):

    def setUp(self):
        self.api = ApiUpdateIPResource()
        self.api.logger = mock.MagicMock()

    def test_get_namedtuple_obj(self):
        ntuple = self.api.get_namedtuple_obj("test", {"x": 1, "y": 2})
        self.assertEqual("test_NT", ntuple.__class__.__name__)
        self.assertTrue(ntuple.x == 1)
        self.assertTrue(ntuple.y == 2)

    @mock.patch("vcs_plugin_api.api_ip_resource_update.VCS_NORMALIZED_DATA")
    def test_normalize_vcs_cmd_output(self, mock_data):

        @mock.patch.object(self.api, "run_vcs_command")
        def check_normalize_function(cmd, cmd_tag, header, skip, mock_run):
            data = {cmd_tag: {"header": header}}
            if skip is not None:
                data[cmd_tag]["skip"] = skip
            lines = "a1 a2 more\nb1 b2\nc1  c2   more"
            mock_run.return_value = (0, lines, "")
            mock_data.__getitem__.side_effect = data.__getitem__
            result = self.api.normalize_vcs_cmd_output(cmd, cmd_tag)
            mock_run.assert_called_once_with(cmd)
            mock_data.__getitem__.assert_called_with(cmd_tag)
            expected_result = ["bar_NT(h1='a1', h2='a2 more')",
                               "bar_NT(h1='b1', h2='b2')",
                               "bar_NT(h1='c1', h2='c2   more')"][skip:]
            for e, r in zip(expected_result, result):
                self.assertEqual(e, str(r))

        check_normalize_function("foo", "bar", ["h1", "h2"], None)
        check_normalize_function("foo", "bar", ["h1", "h2"], 0)
        check_normalize_function("foo", "bar", ["h1", "h2"], 1)
        check_normalize_function("foo", "bar", ["h1", "h2"], 2)

    def test_vcs_hacmd_display_multi(self):

        @mock.patch.object(self.api, "normalize_vcs_cmd_output")
        def check_normalized_result(expected_cmd, normalize, **kwargs):
            self.api.vcs_hacmd_display_multi(**kwargs)
            normalize.assert_called_once_with(expected_cmd, kwargs["hacmd_tag"])

        check_normalized_result("foo -display",
                                hacmd="foo",
                                hacmd_tag="bar")

        check_normalized_result("foo -display res",
                                hacmd="foo",
                                hacmd_tag="bar",
                                entity="res")

        check_normalized_result("foo -display res -attribute attr1 attr2",
                                hacmd="foo",
                                hacmd_tag="bar",
                                entity="res",
                                attr_names=["attr1", "attr2"])

        check_normalized_result("foo -display res -attribute attr1 attr2 -sys node",
                                hacmd="foo",
                                hacmd_tag="bar",
                                entity="res",
                                attr_names=["attr1", "attr2"],
                                system="node")

    def test_vcs_hacmd_list_multi(self):

        with mock.patch.object(self.api, "normalize_vcs_cmd_output") as \
                                                          mock_normalize:
            self.api.vcs_hacmd_list_multi("foo", "bar", {"k1": "v1", "k2": "v2"})
            mock_normalize.assert_called_once_with("foo -list k2=v2 k1=v1", "bar")

    def test_hares_display_multi(self):

        with mock.patch.object(self.api, "run_vcs_command") as mock_run:
            mock_run.return_value = (0, HARES_DISPLAY_OUTPUT, "")
            result = self.api.normalize_vcs_cmd_output("hares", "HaresDisplay")
            expected_result = (
                "[HaresDisplay_NT(Resource='r1', Attribute='a1', System='s1', Value='v1'),"
                " HaresDisplay_NT(Resource='r1', Attribute='a2', System='s2', Value='v2'),"
                " HaresDisplay_NT(Resource='r2', Attribute='a2', System='s2', Value='v3')]")
            self.assertEqual(str(result), expected_result)

    def test_hares_list_multi(self):

        with mock.patch.object(self.api, "run_vcs_command") as mock_run:
            mock_run.return_value = (0, HARES_LIST_OUTPUT, "")
            result = self.api.normalize_vcs_cmd_output("hares", "HaresList")
            expected_result = (
                "[HaresList_NT(Resource='r1', System='s1'),"
                " HaresList_NT(Resource='r1', System='s2'),"
                " HaresList_NT(Resource='r2', System='s2')]")
            self.assertEqual(str(result), expected_result)

    def test_get_ip_resource_name(self):

        @mock.patch.object(self.api, "logger")
        def check_result_and_log(old_ip, new_ip, expected_ip,
                                 mock_hares, mock_logger):
            res_name = self.api.get_ip_resource_name(old_ip,
                                                     new_ip)

            msg = "Found IP Address '{0}' linked to Resource '{1}'".format(
                                                                expected_ip,
                                                                res_name)
            mock_logger.info.assert_called_once_with(msg)

        @mock.patch.object(self.api, "hares_list_multi")
        def check_if_get_old_ip(old_ip, new_ip, mock_hares):
            mock_hares.return_value = [
                    mock.MagicMock(Resource="foo_bar_1"),
                    mock.MagicMock(Resource="foo_bar_2")]
            check_result_and_log(old_ip, new_ip, old_ip, mock_hares)
            mock_hares.assert_called_once_with({"Type": "IP", "Address": "old_ip"})

        @mock.patch.object(self.api, "hares_list_multi")
        def check_if_get_new_ip(old_ip, new_ip, mock_hares):
            mock_hares.side_effect = [
                    [],
                    [mock.MagicMock(Resource="foo_bar_1"),
                     mock.MagicMock(Resource="foo_bar_2")]]
            check_result_and_log(old_ip, new_ip, new_ip, mock_hares)
            mock_hares.assert_has_calls(
                    [mock.call({'Type': 'IP', 'Address': 'old_ip'}),
                     mock.call({'Type': 'IP', 'Address': 'new_ip'})])

        check_if_get_old_ip("old_ip", "old_ip")
        check_if_get_old_ip("old_ip", "new_ip")
        check_if_get_old_ip("old_ip", "new_ip")

        check_if_get_new_ip("old_ip", "new_ip")
        check_if_get_new_ip("old_ip", "new_ip")

        self.assertRaises(ApiUpdateIPResourceNotFoundException,
                          check_if_get_new_ip, "old_ip", "old_ip")

        with mock.patch.object(self.api, "hares_list_multi") as mock_hares:
            with mock.patch.object(self.api, "logger") as mock_logger:
                mock_hares.side_effect = VCSCommandUnknownException
                # Trick to force stopping before raise
                # ApiUpdateIPResourceNotFoundException
                mock_logger.warning.side_effect = VCSCommandUnknownException
                self.assertRaises(VCSCommandUnknownException,
                                  self.api.get_ip_resource_name, "ip1", "ip2")

    def test_get_systems_to_online(self):
        res_data = mock.MagicMock()
        result = self.api.get_systems_to_online(res_data)
        res_data.assertEqual(res_data.State.ONLINE, result)

    @mock.patch("vcs_plugin_api.api_ip_resource_update.VIPAddress")
    def test_format_api_res_data(self, mock_vipaddress):
        mock_vipaddress.side_effect = lambda vip: mock.MagicMock(ip=vip)
        vips = [mock.MagicMock() for i in xrange(4)]
        service_name = ["service1", "service2"]
        res_data = {service_name[0]: {"Parallel": True, "VIPs": [vips[:2]]},
                    service_name[1]: {"Parallel": False, "VIPs": [vips[2:]]}}
        with mock.patch.object(self.api, "get_ip_resource_name") as mock_name:
            result = self.api.format_api_res_data(res_data)
            for vip in vips:
                mock_vipaddress.assert_any_call(vip)

    def test_get_network_value(self):
        self.assertEqual("bar", self.api.get_network_value({"foo": "bar"}, "foo"))
        self.assertEqual("", self.api.get_network_value({}, "NetMask"))
        self.assertEqual("1000", self.api.get_network_value({}, "PrefixLen"))
        self.assertRaises(ApiUpdateIPResourceMissingAttributeException,
                          self.api.get_network_value,
                          {}, "Address")

    @mock.patch("vcs_plugin_api.api_ip_resource_update.VIPAddress")
    def test_get_attribute_obj(self, mock_vipaddress):
        mock_vipaddress.side_effect = lambda vip: mock.MagicMock(ip=vip)
        api_data = mock.MagicMock()

        @mock.patch.object(self.api, "get_namedtuple_obj")
        def check_address(res_elem, has_result, mock_tuple):
            item = mock.MagicMock(Attribute="Address", System="n1", Value="old")
            result = self.api.get_attribute_obj(api_data, res_elem, item)
            if has_result:
                expected_fields = {"Value": "new", "System": "n1"}
                mock_tuple.assert_called_once_with(item.Attribute, expected_fields)
                self.assertEqual(mock_tuple(), result)
            else:
                self.assertTrue(result is None)

        @mock.patch.object(self.api, "get_network_value")
        @mock.patch.object(self.api, "get_namedtuple_obj")
        def check_net_attribute(attribute, net_value, has_result, mock_tuple, mock_net):
            mock_net.return_value = net_value
            item = mock.MagicMock(Attribute=attribute, System="n1", Value="old")
            result = self.api.get_attribute_obj(api_data, None, item)
            if has_result:
                mock_net.assert_called_once_with(api_data, attribute)
                expected_fields = {"Value": mock_net(), "System": "n1"}
                mock_tuple.assert_called_once_with(attribute, expected_fields)
                self.assertEqual(mock_tuple(), result)
            else:
                self.assertTrue(result is None)

        check_address({"VIPs": {"old": "new"}}, True)
        check_address({"VIPs": {"old": "old"}}, False)
        check_address({"VIPs": {}}, False)

        for attribute in ("NetMask", "PrefixLen"):
            check_net_attribute(attribute, "new", True)
            check_net_attribute(attribute, "old", False)

        self.assertRaises(ApiUpdateIPResourceUnknownAttributeException,
                          check_net_attribute, "foo", None, None)

    def test_get_state_and_attributes_objs(self):

        @mock.patch("vcs_plugin_api.api_ip_resource_update.defaultdict")
        @mock.patch.object(self.api, "hares_display_multi")
        @mock.patch.object(self.api, "get_attribute_obj")
        @mock.patch.object(self.api, "get_namedtuple_obj")
        def check(mock_tuple, mock_attr, mock_hares, mock_dict):
            attr_dict = {"Address": []}
            mock_dict().__getitem__.side_effect = attr_dict.__getitem__
            items_state_data = {"ONLINE": "n1", "OFFLINE": "n2",
                                "FAULTED": "n3", "UNKNOWN": "n4"}
            items = [mock.MagicMock(Attribute="State", Value=k, System=v)
                        for k, v in items_state_data.iteritems()]
            items.append(mock.MagicMock(Attribute="Group", Value="g1", System="global"))
            items.append(mock.MagicMock(Attribute="Address", Value="a1", System="n1"))
            mock_hares.return_value = items
            api_data = res_elem = None
            result = self.api.get_state_and_attributes_objs(api_data, "foo", res_elem)
            mock_hares.assert_called_once_with("foo", VCS_IP_RESOURCE_TARGET_ATTRIBUTE_NAMES)
            expected_state_data = {"ONLINE": ["n1"],
                                   "OFFLINE": ["n2"],
                                   "FAULTED": ["n3", "n4"]}
            mock_tuple.assert_any_call("State", expected_state_data)
            mock_attr.assert_any_call(api_data, res_elem, items[5])
            mock_tuple.assert_any_call("Attributes", mock_dict())
            mock_dict().__getitem__.assert_called_once_with("Address")
            self.assertEqual(attr_dict, {"Address": [mock_attr()]})

        check()

    def test_get_data_to_update(self):

        @mock.patch.object(self.api, "get_namedtuple_obj")
        @mock.patch.object(self.api, "format_api_res_data")
        @mock.patch.object(self.api, "get_state_and_attributes_objs")
        def check_no_exception(mock_attr, mock_fmt, mock_tuple):
            api_data = {"Data": {"r1": {"Parallel": False}, "r2": {"Parallel": True}}}
            mock_fmt.side_effect = lambda x: x
            state_attr_data = {"r1": ("s1", "a1"), "r2": ("s2", "a2")}
            mock_attr.side_effect = lambda a, r, e: state_attr_data[r]
            result = self.api.get_data_to_update(api_data)
            mock_fmt.assert_called_once_with(api_data["Data"])
            for r, e in api_data["Data"].iteritems():
                mock_attr.assert_any_call(api_data, r, e)
                mock_tuple.assert_any_call(r, {"State": state_attr_data[r][0],
                                               "Parallel": e["Parallel"],
                                               "Attributes": state_attr_data[r][1]})
        check_no_exception()

        with mock.patch.object(self.api, "format_api_res_data") as mock_fmt:
            self.assertRaises(ApiUpdateIPResourceNoFormattedDataException,
                              self.api.get_data_to_update, {"Data": {}})

    @mock.patch("vcs_plugin_api.api_ip_resource_update.json")
    def test_decode_data_json(self, mock_json):
        mock_json.loads.side_effect = lambda x: x

        self.assertEqual("foo", self.api.decode_data_json("foo"))
        mock_json.loads.assert_called_once_with("foo")

        self.assertRaises(ApiUpdateIPResourceDataFromJSONException,
                          self.api.decode_data_json, None)

    @mock.patch("vcs_plugin_api.api_ip_resource_update.VCS_RESOURCE_NOT_FAULTED")
    def test_clear_ip_resource(self, mock_const):
        with mock.patch.object(self.api, "run_vcs_command") as mock_run:
            self.api.clear_ip_resource("foo")
            mock_run.assert_called_once_with("hares -clear foo", [mock_const], True)

    def test_offline_ip_resource(self):
        with mock.patch.object(self.api, "run_vcs_command") as mock_run:
            systems = ["n1", "n2"]
            self.api.offline_ip_resource("foo", systems)
            expected_cmd = "hares -offline -ignoreparent foo -sys "
            for s in systems:
                mock_run.assert_any_call(expected_cmd + s)

        with mock.patch.object(self.api, "run_vcs_command") as mock_run:
            self.api.offline_ip_resource("foo", [])
            self.assertFalse(mock_run.called)

    def test_online_ip_resource_with_retries(self):

        @mock.patch("vcs_plugin_api.api_ip_resource_update.time")
        @mock.patch.object(self.api, "logger")
        @mock.patch.object(self.api, "run_vcs_command")
        def check_called_once(resource, parallel, system,
                                        mock_run, mock_logger, mock_time):
            self.api.online_ip_resource_with_retries(resource, parallel, system)
            cmd = "hares -online {0} -sys {1}".format(resource, system)
            mock_run.assert_called_once_with(cmd)
            self.assertFalse(mock_time.sleep.called)
            self.assertFalse(mock_logger.warning.called)

        @mock.patch("vcs_plugin_api.api_ip_resource_update.time")
        @mock.patch.object(self.api, "logger")
        @mock.patch.object(self.api, "run_vcs_command")
        def check_called_with_retries(resource, parallel, system, err_msg, num_tries,
                                                    mock_run, mock_logger, mock_time):
            def raise_exception(*args, **kwargs):
                if mock_run.call_count < num_tries:
                   raise VCSCommandException(err_msg)
            mock_run.side_effect = raise_exception
            self.api.online_ip_resource_with_retries(resource, parallel, system)
            cmd = "hares -online {0} -sys {1}".format(resource, system)
            mock_run.assert_any_call(cmd)
            self.assertTrue(mock_run.call_count == min(6, num_tries))
            num_catches = min(6, num_tries - 1)
            self.assertTrue(mock_time.sleep.call_count == num_catches)
            self.assertTrue(mock_logger.warning.call_count == num_catches)
            if num_catches > 0:
                mock_time.sleep.assert_any_call(5)
                msg = ("Attempt to '{0}' failed due to '{1}'.".format(cmd, err_msg))
                mock_logger.warning.assert_any_call(msg)

        for parallel in True, False:
            check_called_once("foo", parallel, "n1")

        for i in xrange(1, 6):
            for parallel in True, False:
                check_called_with_retries("foo", parallel, "n1", "error", i)

            check_called_with_retries("foo", True, "n1",
                                      VCS_RESOURCE_ALREADY_ONLINE, i)

        for i in xrange(2, 6):
            self.assertRaises(ApiUpdateIPResourceFailoverAlreadyOnlineException,
                              check_called_with_retries,
                              "foo", False, "n1", VCS_RESOURCE_ALREADY_ONLINE, i)

        for parallel in True, False:
            self.assertRaises(ApiUpdateIPResourceFailToOnlineException,
                              check_called_with_retries,
                              "foo", parallel, "n1", "error", 7)


    def test_online_ip_resource(self):

        @mock.patch.object(self.api, "run_vcs_command")
        @mock.patch.object(self.api, "online_ip_resource_with_retries")
        def check_no_fail_to_online(resource, parallel, systems, call_to_stop,
                                                     mock_retries, mock_run):
            def raise_exception(*args, **kwargs):
                if mock_run.call_count == call_to_stop - 1:
                   raise ApiUpdateIPResourceFailoverAlreadyOnlineException
            mock_retries.side_effect = raise_exception
            self.api.online_ip_resource(resource, parallel, systems)
            if parallel:
                self.assertEqual(call_to_stop, mock_retries.call_count)
                for i in xrange(call_to_stop):
                    mock_retries.assert_any_call(resource, parallel, systems[i])
            else:
                num_calls = min(1, call_to_stop)
                self.assertEqual(num_calls, mock_retries.call_count)
                if num_calls > 0:
                    mock_retries.assert_called_once_with(resource, parallel,
                                                         systems[0])

        @mock.patch.object(self.api, "logger")
        @mock.patch.object(self.api, "run_vcs_command")
        @mock.patch.object(self.api, "online_ip_resource_with_retries")
        def check_with_fail_to_online(resource, parallel, systems,
                                      mock_retries, mock_run, mock_logger):
            mock_retries.side_effect = ApiUpdateIPResourceFailToOnlineException("error")
            self.api.online_ip_resource(resource, parallel, systems)
            num_systems = len(systems)
            warn_msg = "Failed to online IP Resource:'{0}' System:'{1}'"
            self.assertEqual(num_systems, mock_retries.call_count)
            self.assertEqual(num_systems, mock_logger.warning.call_count)
            for i in xrange(num_systems):
                mock_retries.assert_any_call(resource, parallel, systems[i])
                mock_logger.warning.assert_any_call(warn_msg.format(
                                               resource, systems[i]))

        def check_no_exceptions(resource, parallel, systems):
            check_no_fail_to_online(resource, parallel, systems, len(systems))

        for parallel in True, False:
            check_no_exceptions("foo", parallel, [])
            check_no_exceptions("foo", parallel, ["n1"])
            check_no_exceptions("foo", parallel, ["n1", "n2"])

            check_no_fail_to_online("foo", parallel, [], 0)
            check_no_fail_to_online("foo", parallel, ["n1"], 1)
            check_no_fail_to_online("foo", parallel, ["n1", "n2"], 1)
            check_no_fail_to_online("foo", parallel, ["n1", "n2"], 2)

            check_with_fail_to_online("foo", parallel, [])
            check_with_fail_to_online("foo", parallel, ["n1"])
            check_with_fail_to_online("foo", parallel, ["n1", "n2"])

    def test_modify_ip_resource_attributes(self):
        with mock.patch.object(self.api, "run_vcs_command") as mock_run:
            mock_attr1_1 = mock.MagicMock(Value="v1_1", System="n1")
            mock_attr1_2 = mock.MagicMock(Value="", System="n2")
            mock_attr1_3 = mock.MagicMock(Value=None, System="n2")
            mock_attr2_1 = mock.MagicMock(Value="v2_1", System="global")
            mock_attr2_2 = mock.MagicMock(Value="", System="global")
            mock_attr2_3 = mock.MagicMock(Value=None, System="global")
            attr_dict = {"a1": [mock_attr1_1, mock_attr1_2, mock_attr1_3],
                         "a2": [mock_attr2_1, mock_attr2_2, mock_attr2_3],
                         "a3": []}
            attr_mock = mock.MagicMock()
            attr_mock._asdict.return_value = attr_dict
            self.api.modify_ip_resource_attributes("foo", attr_mock)
            self.assertEqual(4, mock_run.call_count)
            cmd_tpl = "hares -modify foo {0} {1}"
            for attr_name, attr_data in attr_dict.iteritems():
                for attr_obj in attr_data:
                    if not attr_obj or attr_obj.Value is None:
                        continue
                    if attr_obj.Value == "":
                        attr_value = "' '"
                    else:
                        attr_value = attr_obj.Value
                    cmd = cmd_tpl.format(attr_name, attr_value)
                    if attr_obj.System != "global":
                        cmd = "{0} -sys {1}".format(cmd, attr_obj.System)
                    mock_run.assert_any_call(cmd)

    @_step_tester
    def test_step_raise_ip_resource_tolerance_limit(self, res_data):
        with mock.patch.object(self.api, "run_vcs_command") as mock_run:
            self.api.step_raise_ip_resource_tolerance_limit("foo", res_data)
            self.assertEqual(2, mock_run.call_count)
            cmd = "hares -override foo ToleranceLimit"
            expected_errors = ["already overridden", "not a static attribute"]
            mock_run.assert_any_call(cmd, expected_errors, True)
            cmd = "hares -modify foo ToleranceLimit 2"

    @_step_tester
    def test_step_clear_ip_resource(self, res_data):
        with mock.patch.object(self.api, "clear_ip_resource") as mock_clear:
            self.api.step_clear_ip_resource("foo", res_data)
            if res_data.State.FAULTED:
                mock_clear.assert_called_once_with("foo")
            else:
                self.assertFalse(mock_clear.called)

    @_step_tester
    def step_offline_ip_resource(self):
        with mock.patch.object(self.api, "offline_ip_resource") as mock_offline:
            self.api.step_offline_ip_resource("foo", res_data)
            systems = res_data.State.ONLINE + res_data.State.FAULTED
            if all(res_data.Attributes, systems):
                mock_offline.assert_called_once_with("foo")
            else:
                self.assertFalse(mock_offline.called)

    @_step_tester
    def test_step_modify_ip_resource(self, res_data):
        with mock.patch.object(self.api, "modify_ip_resource_attributes") as mock_modify:
            self.api.step_modify_ip_resource("foo", res_data)
            if res_data.Attributes:
                mock_modify.assert_called_once_with("foo", res_data.Attributes)
            else:
                self.assertFalse(mock_modify.called)

    @_step_tester
    def test_step_online_ip_resource_and_wait(self, res_data):
        with mock.patch.object(self.api, "online_ip_resource") as mock_online:
            with mock.patch.object(self.api, "get_systems_to_online") as mock_get:
                mock_get.return_value = res_data.State.ONLINE
                self.api.step_online_ip_resource("foo", res_data)
                mock_get.assert_called_once_with(res_data)
                if res_data.State.ONLINE:
                    mock_online.assert_called_once_with("foo",
                                                        res_data.Parallel,
                                                        res_data.State.ONLINE)
                else:
                    self.assertFalse(mock_online.called)

    @_step_tester
    def test_step_wait_online_ip_resource(self, res_data):
        with mock.patch.object(self.api, "wait_for_res_state_on_node") as mock_wait:
            with mock.patch.object(self.api, "get_systems_to_online") as mock_get:
                mock_get.return_value = res_data.State.ONLINE
                self.api.step_wait_online_ip_resource("foo", res_data)
                mock_get.assert_called_once_with(res_data)
                if res_data.State.ONLINE:
                    mock_wait.assert_called_once_with("foo", res_data.State.ONLINE, "ONLINE")
                else:
                    self.assertFalse(mock_wait.called)

    @_step_tester
    def test_step_flush_ip_resource(self, res_data):
        with mock.patch.object(self.api, "execute_flush_resource") as mock_flush:
            self.api.step_flush_ip_resource("foo", res_data)
            mock_flush.assert_called_once_with()

    @_step_tester
    def test_step_reset_ip_resource_tolerance_limit(self, res_data):
        with mock.patch.object(self.api, "run_vcs_command") as mock_run:
            self.api.step_reset_ip_resource_tolerance_limit("foo", res_data)
            cmd = "hares -undo_override foo ToleranceLimit"
            mock_run.assert_called_once_with(cmd)

    def test_api_update_ip_resources_of_a_network(self):

        @mock.patch.object(self.api, "decode_data_json")
        @mock.patch.object(self.api, "get_data_to_update")
        @mock.patch.object(self.api, "step_raise_ip_resource_tolerance_limit")
        @mock.patch.object(self.api, "step_clear_ip_resource")
        @mock.patch.object(self.api, "step_offline_ip_resource")
        @mock.patch.object(self.api, "step_modify_ip_resource")
        @mock.patch.object(self.api, "step_online_ip_resource")
        @mock.patch.object(self.api, "step_wait_online_ip_resource")
        @mock.patch.object(self.api, "step_flush_ip_resource")
        @mock.patch.object(self.api, "step_reset_ip_resource_tolerance_limit")
        @mock.patch.object(self.api, "logger")
        def check_no_exception(request,
                               mock_logger,
                               mock_step_reset_ip_resource_tolerance_limit,
                               mock_step_flush_ip_resource,
                               mock_step_wait_online_ip_resource,
                               mock_step_online_ip_resource,
                               mock_step_modify_ip_resource,
                               mock_step_offline_ip_resource,
                               mock_step_clear_ip_resource,
                               mock_step_raise_ip_resource_tolerance_limit,
                               mock_get_data_to_update,
                               mock_decode_data_json):
            request_mock = mock.MagicMock(data=request["data_json"])
            mock_decode_data_json.return_value = request_mock
            mock_get_data_to_update.return_value = request_mock.data
            result = self.api.api_update_ip_resources_of_a_network(request)
            self.assertEqual({"retcode": 0, "out": "", "err": ""}, result)
            self.assertFalse(mock_logger.called)
            mock_decode_data_json.assert_called_once_with(request["data_json"])
            mock_get_data_to_update.assert_called_once_with(request_mock)
            mock_steps = [
                    mock_step_reset_ip_resource_tolerance_limit,
                    mock_step_flush_ip_resource,
                    mock_step_wait_online_ip_resource,
                    mock_step_online_ip_resource,
                    mock_step_modify_ip_resource,
                    mock_step_offline_ip_resource,
                    mock_step_clear_ip_resource,
                    mock_step_raise_ip_resource_tolerance_limit]

            for mock_step in mock_steps:
                self.assertEqual(len(request_mock.data), mock_step.call_count)
                for resource, res_data in request_mock.data.iteritems():
                    mock_step.assert_any_call(resource, res_data)

        @mock.patch.object(self.api, "decode_data_json")
        @mock.patch.object(self.api, "get_data_to_update")
        @mock.patch.object(self.api, "step_raise_ip_resource_tolerance_limit")
        @mock.patch.object(self.api, "step_clear_ip_resource")
        @mock.patch.object(self.api, "step_offline_ip_resource")
        @mock.patch.object(self.api, "step_modify_ip_resource")
        @mock.patch.object(self.api, "step_online_ip_resource")
        @mock.patch.object(self.api, "step_wait_online_ip_resource")
        @mock.patch.object(self.api, "step_flush_ip_resource")
        @mock.patch.object(self.api, "step_reset_ip_resource_tolerance_limit")
        def check_raise_exception(request, exception,
                                  mock_step_reset_ip_resource_tolerance_limit,
                                  mock_step_flush_ip_resource,
                                  mock_step_wait_online_ip_resource,
                                  mock_step_online_ip_resource,
                                  mock_step_modify_ip_resource,
                                  mock_step_offline_ip_resource,
                                  mock_step_clear_ip_resource,
                                  mock_step_raise_ip_resource_tolerance_limit,
                                  mock_get_data_to_update,
                                  mock_decode_data_json):
            mock_funcs = [
                    mock_decode_data_json,
                    mock_get_data_to_update,
                    mock_step_reset_ip_resource_tolerance_limit,
                    mock_step_flush_ip_resource,
                    mock_step_wait_online_ip_resource,
                    mock_step_online_ip_resource,
                    mock_step_modify_ip_resource,
                    mock_step_offline_ip_resource,
                    mock_step_clear_ip_resource,
                    mock_step_raise_ip_resource_tolerance_limit]

            for mock_func in mock_funcs:
                mock_func.side_effect = exception("MOCK_ERROR")
                with mock.patch.object(self.api, "logger") as mock_logger:
                    result = self.api.api_update_ip_resources_of_a_network(request)
                    err_msg = "Got VCS Exception. Details: MOCK_ERROR"
                    expected_result = {"retcode": 1, "out": "", "err": "MOCK_ERROR"}
                    self.assertEqual(expected_result, result)
                    mock_logger.error.assert_called_once_with(err_msg)

        for data in {}, {"r1": "d1"}, {"r1": "d1", "r2": "d2"}:
            request = {"data_json": data}
            check_no_exception(request)
            for exception in VCSException, VCSCommandException:
                check_raise_exception(request, exception)
