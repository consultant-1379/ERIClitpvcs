#!/usr/bin/env python
##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import logging
import json
import time

from collections import defaultdict, namedtuple

# VCS Plugin API Modules
from vcs_plugin_api.vcs_api_utils.vip_address import VIPAddress
from vcs_cmd_api import (VcsCmdApi,
                         VCSException,
                         VCSCommandException,
                         VCSCommandUnknownException,
                         VCS_RESOURCE_ALREADY_ONLINE,
                         VCS_RESOURCE_NOT_FAULTED)

# VCS related constants
VCS_SYSTEM_GLOBAL_TAG = 'global'
VCS_HARES_DISPLAY = "HaresDisplay"
VCS_HARES_LIST = "HaresList"
VCS_HARES_CMD = "hares"
VCS_NORMALIZED_DATA = {
    VCS_HARES_DISPLAY: {
        "header": ["Resource", "Attribute", "System", "Value"],
        "skip": 1},
    VCS_HARES_LIST: {
        "header": ["Resource", "System"]}}

# VCS IP Resource related constants
VCS_IP_RESOURCE_TOLERANCE_LIMIT_TO_UPDATE = 2
VCS_IP_RESOURCE_NUM_RETRIES_ONLINE = 6
VCS_IP_RESOURCE_RETRY_ONLINE_INTERVAL = 5
VCS_IP_RESOURCE_DEFAULT_PREFIX_LEN = "1000"
VCS_IP_RESOURCE_DEFAULT_NETMASK = ""
VCS_IP_RESOURCE_TARGET_ATTRIBUTE_NAMES = ("State", "Group",
                                          "Address", "NetMask", "PrefixLen")


class ApiUpdateIPResourceDataFromJSONException(VCSException):
    pass


class ApiUpdateIPResourceNoFormattedDataException(VCSException):
    pass


class ApiUpdateIPResourceNotFoundException(VCSException):
    pass


class ApiUpdateIPResourceFailToOnlineException(VCSException):
    pass


class ApiUpdateIPResourceFailoverAlreadyOnlineException(VCSException):
    pass


class ApiUpdateIPResourceMissingAttributeException(VCSException):
    pass


class ApiUpdateIPResourceUnknownAttributeException(VCSException):
    pass


class ApiUpdateIPResource(VcsCmdApi):
    """
    Call abstracting the API for updating IP Resources
    """
    def __init__(self, log_tag="ApiUpdateIPResource", log_level=logging.INFO):
        super(ApiUpdateIPResource, self).__init__(log_tag, log_level)

    def get_namedtuple_obj(self, name, fields):
        """
        Generate a namedtuple
        """
        NamedTuple = namedtuple(name + "_NT", fields)
        NamedTuple.__new__.__defaults__ = (None,) * len(NamedTuple._fields)
        return NamedTuple(**fields)

    def normalize_vcs_cmd_output(self, cmd, cmd_tag):
        """
        Normalize using namedtuples the output from VCS
        commands.
        """
        result = []
        _, o, _ = self.run_vcs_command(cmd)
        if o:
            header = VCS_NORMALIZED_DATA[cmd_tag]["header"]
            skip = VCS_NORMALIZED_DATA[cmd_tag].get("skip", 0)
            NormalizedItem = namedtuple(cmd_tag + "_NT", header)
            item_len = len(header)
            for line in o.splitlines()[skip:]:
                item = (line.split(None, item_len - 1) + [None])[:item_len]
                result.append(NormalizedItem(*item))
        return result

    def vcs_hacmd_display_multi(self, hacmd, hacmd_tag,
                                      entity=None, attr_names=[],
                                      system=None):
        cmd = "{0} -display".format(hacmd)
        if entity:
            cmd = "{0} {1}".format(cmd, entity)
        if attr_names:
            cmd = "{0} -attribute {1}".format(cmd, " ".join(attr_names))
        if system:
            cmd = "{0} -sys {1}".format(cmd, system)
        return self.normalize_vcs_cmd_output(cmd, hacmd_tag)

    def vcs_hacmd_list_multi(self, hacmd, hacmd_tag, conditionals):
        conditional_str = " ".join(["{0}={1}".format(k,v)
                                        for k,v in conditionals.iteritems()])
        cmd = "{0} -list {1}".format(hacmd, conditional_str)
        return self.normalize_vcs_cmd_output(cmd, hacmd_tag)

    def hares_display_multi(self, resource=None, attr_names=None, system=None):
        return self.vcs_hacmd_display_multi(VCS_HARES_CMD,
                                            VCS_HARES_DISPLAY,
                                            entity=resource,
                                            attr_names=attr_names,
                                            system=system)

    def hares_list_multi(self, conditionals):
        return self.vcs_hacmd_list_multi(VCS_HARES_CMD,
                                         VCS_HARES_LIST,
                                         conditionals)

    def get_ip_resource_name(self, old_ipaddress, new_ipaddress):
        # Ordering is important, that is why not using set
        if old_ipaddress == new_ipaddress:
            target_ipaddresses = (old_ipaddress,)
        else:
            target_ipaddresses = (old_ipaddress, new_ipaddress)

        for ipaddress in target_ipaddresses:
            conditionals = {"Type": "IP", "Address": ipaddress}
            try:
                for res in self.hares_list_multi(conditionals):
                        self.logger.info("Found IP Address '{0}' "
                                         "linked to Resource '{1}'"
                                         .format(ipaddress, res.Resource))
                        return res.Resource
            except VCSCommandUnknownException as e:
                self.logger.warning("IP Resource matching Address:'{0}' "
                                    "has not been found.".format(ipaddress))
                continue

        msg = ("Failed to get full IP Resource name using "
               "ipadresses:'{0}'.".format(target_ipaddresses))

        self.logger.error(msg)
        raise ApiUpdateIPResourceNotFoundException(msg)

    def get_systems_to_online(self, res_data):
        return res_data.State.ONLINE

    def format_api_res_data(self, res_data):
        new_res_data = defaultdict(lambda: {"Parallel": None,
                                            "VIPs": {}})
        for _, res_elem in res_data.iteritems():
            parallel = res_elem["Parallel"]
            vips_list = res_elem["VIPs"]
            for old_ip, new_ip in vips_list:
                old_ip = VIPAddress(old_ip).ip
                new_ip = VIPAddress(new_ip).ip
                resource = self.get_ip_resource_name(old_ip, new_ip)
                new_res_data[resource]["Parallel"] = parallel
                new_res_data[resource]["VIPs"][old_ip] = new_ip
        return new_res_data

    def get_network_value(self, api_data, attribute):
        if api_data.get(attribute):
            new_value = api_data[attribute]
        else:
            if attribute == "NetMask":
                new_value = VCS_IP_RESOURCE_DEFAULT_NETMASK
            elif attribute == "PrefixLen":
                new_value = VCS_IP_RESOURCE_DEFAULT_PREFIX_LEN
            else:
                raise ApiUpdateIPResourceMissingAttributeException(
                        "API missing Attribute '{0}'. Data: {1}".format(
                                              attribute, str(api_data)))
        return new_value

    def get_attribute_obj(self, api_data, res_elem, item):
        if item.Attribute == "Address":
            old_value = VIPAddress(item.Value).ip
            new_value = res_elem["VIPs"].get(old_value)
        elif item.Attribute in ("NetMask", "PrefixLen"):
            old_value = item.Value
            new_value = self.get_network_value(api_data, item.Attribute)
        else:
            raise ApiUpdateIPResourceUnknownAttributeException(
                    "Unexpected Attribute '{0}'. Data: {1}".format(
                                             item.Attribute, item))
        if new_value is not None and new_value != old_value:
            fields = {
                "Value": new_value,
                "System": item.System}
            return self.get_namedtuple_obj(item.Attribute, fields)

    def get_state_and_attributes_objs(self, api_data, resource, res_elem):
        attrs_data = defaultdict(list)
        state_data = {"ONLINE": [], "OFFLINE": [], "FAULTED": []}
        hares_data = self.hares_display_multi(resource,
                                    VCS_IP_RESOURCE_TARGET_ATTRIBUTE_NAMES)
        for item in hares_data:
            if item.Attribute == "State":
                if item.Value in ("ONLINE", "OFFLINE"):
                    state_data[item.Value].append(item.System)
                else:
                    state_data["FAULTED"].append(item.System)
            elif item.Attribute == "Group":
                res_group = item.Value
            else:
                attr_obj = self.get_attribute_obj(api_data, res_elem, item)
                if attr_obj:
                    attrs_data[item.Attribute].append(attr_obj)

        state_obj = self.get_namedtuple_obj("State", state_data)

        if attrs_data:
            attrs_obj = self.get_namedtuple_obj("Attributes", attrs_data)
        else:
            attrs_obj = None

        return state_obj, attrs_obj

    def get_data_to_update(self, api_data):
        new_data = {}
        api_data["Data"] = self.format_api_res_data(api_data["Data"])
        for resource, res_elem in api_data["Data"].iteritems():
            state_obj, attrs_obj = self.get_state_and_attributes_objs(api_data,
                                                                      resource,
                                                                      res_elem)
            fields = {
                "State": state_obj,
                "Parallel": res_elem["Parallel"],
                "Attributes": attrs_obj}

            new_data[resource] = self.get_namedtuple_obj(resource, fields)

        if not new_data:
            msg = ("No Data formatted. API Data Request: {0}"
                                                .format(api_data))
            self.logger.error(msg)
            raise ApiUpdateIPResourceNoFormattedDataException(msg)

        return new_data

    def decode_data_json(self, data_json):
        data = json.loads(data_json)
        if not data:
            msg = ("No Data extracted from JSON Data Request: {0}"
                                                .format(data_json))
            self.logger.error(msg)
            raise ApiUpdateIPResourceDataFromJSONException(msg)
        return data

    def clear_ip_resource(self, resource):
        expected_errors = [VCS_RESOURCE_NOT_FAULTED]
        cmd = "{0} -clear {1}".format(VCS_HARES_CMD, resource)
        self.run_vcs_command(cmd, expected_errors, True)

    def offline_ip_resource(self, resource, systems):
        for system in systems:
            self.run_vcs_command("{0} -offline -ignoreparent {1} -sys {2}"
                                    .format(VCS_HARES_CMD, resource, system))

    def online_ip_resource_with_retries(self, resource, parallel, system):
        for i in xrange(VCS_IP_RESOURCE_NUM_RETRIES_ONLINE):
            try:
                cmd = ("{0} -online {1} -sys {2}"
                                .format(VCS_HARES_CMD, resource, system))
                self.run_vcs_command(cmd)
                return
            except VCSCommandException as e:
                if not parallel and (VCS_RESOURCE_ALREADY_ONLINE in str(e)):
                    raise ApiUpdateIPResourceFailoverAlreadyOnlineException()
                msg = ("Attempt to '{0}' failed due to '{1}'.".format(cmd, e))
                self.logger.warning(msg)
                time.sleep(VCS_IP_RESOURCE_RETRY_ONLINE_INTERVAL)

        raise ApiUpdateIPResourceFailToOnlineException()

    def online_ip_resource(self, resource, parallel, systems):
        for system in systems:
            try:
                self.online_ip_resource_with_retries(resource, parallel,
                                                               system)
                if not parallel:
                   break
            except ApiUpdateIPResourceFailoverAlreadyOnlineException:
                break
            except ApiUpdateIPResourceFailToOnlineException as e:
                self.logger.warning("Failed to online IP Resource:'{0}' "
                                    "System:'{1}'".format(resource, system))

    def modify_ip_resource_attributes(self, resource, attributes):
        for attr_name, attr_data in attributes._asdict().iteritems():
            for attr_obj in attr_data:
                if not attr_obj or attr_obj.Value is None:
                    continue

                if attr_obj.Value == "":
                    attr_value = "' '"
                else:
                    attr_value = attr_obj.Value

                cmd = ("{hacmd} -modify {resource} {attr_name} {attr_value}"
                                                .format(hacmd=VCS_HARES_CMD,
                                                        resource=resource,
                                                        attr_name=attr_name,
                                                        attr_value=attr_value))
                if attr_obj.System != VCS_SYSTEM_GLOBAL_TAG:
                    cmd = "{0} -sys {1}".format(cmd, attr_obj.System)

                self.run_vcs_command(cmd)

    def step_raise_ip_resource_tolerance_limit(self, resource, res_data):
        cmd = '{0} -override {1} ToleranceLimit'.format(VCS_HARES_CMD,
                                                             resource)
        expected_errors = ["already overridden", "not a static attribute"]
        self.run_vcs_command(cmd, expected_errors, True)

        cmd = ('{0} -modify {1} ToleranceLimit {2}'.format(VCS_HARES_CMD,
                                resource,
                                VCS_IP_RESOURCE_TOLERANCE_LIMIT_TO_UPDATE))
        self.run_vcs_command(cmd)

    def step_clear_ip_resource(self, resource, res_data):
        if not res_data.State.FAULTED:
                return
        self.clear_ip_resource(resource)

    def step_offline_ip_resource(self, resource, res_data):
        systems = res_data.State.ONLINE + res_data.State.FAULTED
        if not (systems and res_data.Attributes):
                return
        self.offline_ip_resource(resource, systems)

    def step_modify_ip_resource(self, resource, res_data):
        if not res_data.Attributes:
                return
        self.modify_ip_resource_attributes(resource, res_data.Attributes)

    def step_online_ip_resource(self, resource, res_data):
        systems = self.get_systems_to_online(res_data)
        if systems:
            self.online_ip_resource(resource, res_data.Parallel, systems)

    def step_wait_online_ip_resource(self, resource, res_data):
        systems = self.get_systems_to_online(res_data)
        if systems:
            self.wait_for_res_state_on_node(resource, systems, "ONLINE")

    def step_flush_ip_resource(self, resource, res_data):
        self.execute_flush_resource()

    def step_reset_ip_resource_tolerance_limit(self, resource, res_data):
        cmd = '{0} -undo_override {1} ToleranceLimit'.format(VCS_HARES_CMD,
                                                             resource)
        self.run_vcs_command(cmd)

    def api_update_ip_resources_of_a_network(self, request):
        """
        API Entry-Point, implemented with Idempotency
        The Data with the necessary information about
        what changes need to be made comes structured
        as dictionary and mangled on JSON.
        """
        result = {"retcode": 0, "out": "", "err": ""}

        try:
            data = self.decode_data_json(request["data_json"])
            data = self.get_data_to_update(data)

            steps = [self.step_raise_ip_resource_tolerance_limit,
                     self.step_clear_ip_resource,
                     self.step_offline_ip_resource,
                     self.step_modify_ip_resource,
                     self.step_online_ip_resource,
                     self.step_wait_online_ip_resource,
                     self.step_flush_ip_resource,
                     self.step_reset_ip_resource_tolerance_limit,]

            for step in steps:
                for resource, res_data in data.iteritems():
                    step(resource, res_data)

        except (VCSException, VCSCommandException) as e:
            self.logger.error("Got VCS Exception. Details: {0}".format(str(e)))
            result = {"retcode": 1, "out": "", "err": str(e)}

        return result


if __name__ == '__main__':
    ApiUpdateIPResource().action()
