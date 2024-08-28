#!/bin/env python

'''
Results and Exceptions
0   OK
1   OK, failed. All the data parsed ok, we have a action matching the request
    but the requested action could not be completed.  RPCAborted
2   Unknown action  UnknownRPCAction
3   Missing data    MissingRPCData
4   Invalid data    InvalidRPCData
5   Other error     UnknownRPCError

Request format:
{ "callerid": null,
  "agent": "vcs_cmd_api",
  "data":{"process_results":true},
  "uniqid":"e8937c54738d5cb09b3ca8d668d821ce",
  "sender":"ms1",
  "action":"pythontest"
}
'''

import sys
import json
import os
import subprocess
from operator import itemgetter
import time
import syslog
from collections import defaultdict, namedtuple
import itertools
import re
import socket
import logging

# VCS Plugin API Modules
from vcs_plugin_api.vcs_api_utils.vcs_api_logger import VcsApiLogger

MCOLLECTIVE_REPLY_FILE = "MCOLLECTIVE_REPLY_FILE"
MCOLLECTIVE_REQUEST_FILE = "MCOLLECTIVE_REQUEST_FILE"
NO_GRP_DEP_ERROR = ("VCS WARNING V-16-1-50035 "
                    "No Group dependencies are configured")
NO_RES_DEP_ERROR = ("VCS WARNING V-16-1-50034 "
                    "No Resource dependencies are configured")
VCS_GROUP_NOT_EXIST_WARN = "VCS WARNING V-16-1-12130"
VCS_GROUP_NOT_EXIST_IN_CLUSTER_ERR = "VCS WARNING V-16-1-40131"
VCS_GROUP_NOT_EXIST_WARN_10133 = "VCS WARNING V-16-1-10133"
VCS_ERR_REGISTERING_RESOURCE = "VCS WARNING V-16-1-10806"
VCS_COULD_NOT_UNLINK_GROUPS_ERROR = "VCS WARNING V-16-1-10146"
VCS_SYSTEM_NOT_IN_SYSTEM_LIST_WARN = "VCS WARNING V-16-1-10135"
VCS_UNABLE_TO_SWITCH_GROUP = "VCS WARNING V-16-1-51055"
PATH_HAGRP = '/opt/VRTS/bin/hagrp'
VCS_RESOURCE_NOT_EXIST = "VCS WARNING V-16-1-10260"
VCS_DISPLAY_RESOURCE_NOT_EXIST = "VCS WARNING V-16-1-40130"
VCS_FAILOVER_GROUP_IS_ONLINE = "V-16-1-50997"
VCS_PARALLEL_GROUP_IS_ONLINE = "V-16-1-50996"
VCS_ATTEMPTING_TO_ONLINE_GROUP = "V-16-1-50735"
VCS_FAILOVER_IS_NOT_OFFLINE = "V-16-1-10165"
VCS_ENTRY_ALREADY_IN_KEYLIST = "V-16-1-10563"
VCS_ENTRY_NOT_IN_KEYLIST = "V-16-1-10566"
VCS_SYSTEM_IS_NOT_AVAILABLE = "VCS WARNING V-16-1-10200"
VCS_SYSTEM_NOT_EXIST_IN_CLUSTER = "VCS WARNING V-16-1-51051"
VCS_SYSTEM_DOES_NOT_EXIST = "VCS WARNING V-16-1-10357"
VCS_SYSTEM_NOT_DEFINED_OR_GRP_NOT_OFFLINE = "VCS WARNING V-16-1-10180"
VCS_SYSTEM_LIST_EMPTY = "VCS WARNING V-16-1-50837"
VCS_NO_GRPS_CONFIGURED = "VCS WARNING V-16-1-50031"
GRP_WAIT_ALL_ERROR = ("service group '{group_name}' did not go "
                      "'{expected_state}' in '{timeout}' sec.")
VCS_CANNOT_SWITCH_TO_OWN_SYS = "VCS WARNING V-16-1-10192"
VCS_RESOURCE_ALREADY_ONLINE = ("VCS WARNING V-16-1-10286 Cannot online: "
                             "resource's group is not offline elsewhere")
VCS_RESOURCE_NOT_FAULTED = ("VCS WARNING V-16-1-10267 Resource not faulted "
                          "or group in the process of failing over")
VCS_UNFREEZE_REMOTE_BUILD_STATE = ("VCS WARNING V-16-1-50129 Operation 'hasys "
                                   "-unfreeze -persistent' rejected as the "
                                   "node is in REMOTE_BUILD state")


OK = 0
RPCAborted = 1
UnknownRPCAction = 2
MissingRPCData = 3
InvalidRPCData = 4
UnknownRPCError = 5

INTENT_ONLINE_YES = ('1', '2')
GROUP_FROZEN_YES = "1"

ChildParentDependencies = namedtuple('ChildParentDependencies',
                                     ['child', 'parent'])


class VCSException(Exception):
    pass


class VCSCommandException(Exception):
    pass


class VCSCommandUnknownException(VCSCommandException):
    pass


class RPCAgent(object):

    def __init__(self, log_tag="RPCAgent", log_level=logging.INFO):
        self.logger = VcsApiLogger.get_logger(log_tag, log_level)

    def action(self):
        exit_value = OK
        with open(os.environ[MCOLLECTIVE_REQUEST_FILE], 'r') as infile:
            request = json.load(infile)

        action = request["action"]
        method = getattr(self, action, None)
        if callable(method):
            reply = method(request['data'])
        else:
            reply = {}
            exit_value = UnknownRPCAction

        with open(os.environ[MCOLLECTIVE_REPLY_FILE], 'w') as outfile:
            json.dump(reply, outfile)

        sys.exit(exit_value)

    @staticmethod
    def run(command):
        env = dict(os.environ)
        env['PATH'] = "/opt/VRTSvcs/bin:{0}".format(env['PATH'])
        p = subprocess.Popen(command,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=True,
                             env=env)
        out, err = p.communicate()
        return p.returncode, out.strip(), err.strip()


class VcsCmdApi(RPCAgent):

    def __init__(self, log_tag="VcsCmdApi", log_level=logging.INFO):
        super(VcsCmdApi, self).__init__(log_tag, log_level)

    def run_vcs_command(self, command, expected_errors=[],
                        rewrite_retcode=False):
        c, o, e = self.run(command)
        if c:
            for expected_error in expected_errors:
                if expected_error in e:
                    if rewrite_retcode:
                        c = 0
                    return c, o, e
            if e or o:
                raise VCSCommandException(
                    "Error running '{0}': Out: '{1}' Err: '{2}'".format(
                            command, o, e))
            else:
                raise VCSCommandUnknownException(
                    "Unknown VCS Error CMD:'{0}' Retcode:'{1}'".format(
                            command, c))
        return c, o, e

    def haconf(self, args):
        read_only = args['read_only']
        retcode, out, err = self._haconf(read_only, rewrite_retcode=True)
        mco_retval = {"retcode": retcode,
                      "out": out,
                      "err": err}
        return mco_retval

    def _haconf(self, read_only=False, rewrite_retcode=False):
        if not read_only:
            try:
                return self.run_vcs_command(
                    "haconf -makerw",
                    ["VCS WARNING V-16-1-10364 Cluster already writable"],
                    rewrite_retcode)
            except VCSCommandException as e:
                return 1, '', str(e)
        else:
            try:
                c, o, e = self.run_vcs_command(
                    "haconf -dump -makero",
                    ["VCS WARNING V-16-1-10369 Cluster not writable"])
            except VCSCommandException as ex:
                c, o, e = 1, '', str(ex)

            if c == 0:
                wait_c, wait_o, wait_e = self.run_vcs_command(
                    # Wait for up to 60 seconds for the dump to finish
                    "haclus -wait DumpingMembership 0 -time 60",
                    ["VCS WARNING V-16-1-10805 Connection timed out"])
                if wait_c != 0:
                    wait_e = "\n".join([wait_e, "VCS took more than 60 "
                                        "seconds to dump its configuration "
                                        "to disk."])
                return wait_c, wait_o, wait_e
            if rewrite_retcode:
                c = 0
            return c, o, e

    def open_haconf(self):
        return self._haconf(False)

    def close_haconf(self):
        return self._haconf(True)

    def hagrp_display(self, group="", attribute="", system=""):
        cmd = "hagrp -display {0}".format(group)
        global_cmd = "hagrp -display {0} -attribute IntentOnline".format(group)
        if attribute:
            cmd = "{0} -attribute {1}".format(cmd, attribute)

        if system:
            cmd = "{0} -sys {1}".format(cmd, system)
        _, o, _ = self.run_vcs_command(
            cmd,
            ["VCS WARNING V-16-1-50031 No Groups are configured"])

        if o:
            return o.splitlines()[1:]

        elif not o:
            _, g, _ = self.run_vcs_command(
                global_cmd,
                ["VCS WARNING V-16-1-50031 No Groups are configured"])

            if g:
                return g.splitlines()[1:]

        return []

    def hagrp_resources(self, group):
        cmd = '/opt/VRTS/bin/hagrp -resources {0}'.format(group)
        _, o, _ = self.run_vcs_command(cmd)
        return o

    def _hagrp_frozen(self, group):
        """
        :param group: str with the VCS group to check
        :return: True if group is frozen or tfrozen. False otherwise
        """
        cmd = "hagrp -display {0} -attribute TFrozen -attribute "\
            "Frozen ".format(group)
        _, o, _ = self.run_vcs_command(cmd)
        if o:
            lines = o.splitlines()[1:]

            tfrozen = lines[0].split()[3]
            frozen = lines[1].split()[3]

            if GROUP_FROZEN_YES == tfrozen or \
               GROUP_FROZEN_YES == frozen:
                return True
        return False

    def _group_intent_online(self, group, system=""):
        res = self.hagrp_display(group=group, attribute="IntentOnline",
            system=system)[0]

        if (res.split()[3] in INTENT_ONLINE_YES and
                        not self._hagrp_frozen(group)):
            return True
        return False

    def hares_display(self, resource="", attribute="", system=""):
        cmd = "hares -display {0}".format(resource)
        if attribute:
            cmd = "{0} -attribute {1}".format(cmd, attribute)
        if system:
            cmd = "{0} -sys {1}".format(cmd, system)
        _, o, _ = self.run_vcs_command(cmd)
        if o:
            return o.splitlines()[1:]
        return []

    def _node_list(self):
        _, o, _ = self.run_vcs_command("hasys -list")
        return o.splitlines()

    def _validate_all_nodes_are_unlocked(self, node_to_lock):
        '''
        Check if all nodes are not frozen
        '''
        for node in self._node_list():
            if node != node_to_lock:
                _, frozen, _ = self.run("hasys -value {0} Frozen".format(node))
                _, tfrozen, _ = self.run("hasys -value {0} TFrozen"\
                                         .format(node))
                try:
                    if int(frozen) or int(tfrozen):
                        raise VCSException('Cluster is not in a clean state. '
                        'Node "{0}" is frozen'.format(node))
                except ValueError:
                    raise VCSException('Node {0} is not in a clean state.'\
                        .format(node))

    def _group_has_ip_but_no_mount_resource(self, group):
        group_resources = self.hagrp_resources(group=group)
        group_resources_list = group_resources.split('\n')
        mount_resources = [resource for resource in group_resources_list
                           if resource.startswith("Res_Mnt_")]
        ip_resources = [resource for resource in group_resources_list
                        if resource.startswith("Res_IP_")]
        if not mount_resources and len(ip_resources) > 0:
            return True
        return False

    def _get_online_failover_sgs(self, node_to_lock):
        """
        :param node_to_lock: node
        :return: list of service group names
        A method for returning the service groups that are currently online on
        node_to_lock, and are failover. The service group must also have a vip
        (therefore no VMs) and not have a mount resource
        """
        online_failover_sgs = []
        for group_info in self.hagrp_display(attribute="State"):
            group, _, node, state = group_info.split()

            if (group.startswith("Grp_CS_") and node == node_to_lock and
                    state == "|ONLINE|"):
                parallel = self.hagrp_display(group=group,
                                            attribute="Parallel")[0].split()[3]

                if parallel == "0":
                    if self._group_has_ip_but_no_mount_resource(group):
                        online_failover_sgs.append(group)
        return online_failover_sgs

    def _switch_online_failover_service_groups(self, node_to_lock,
                                               switch_timeout,
                                               prevent_failover):
        """
        This method is in relation to LITPCDS-11948, in order to improve
        performance, run a hrgp -switch command on certain FO service groups:
        Get all online failover service groups that meet the criteria
        Run a hagrp -switch command on these service groups
        Wait for each of these groups to come offline on the node
        """
        online_failover_sgs = self._get_online_failover_sgs(node_to_lock)
        prevent_failover_sgs = [grp for grp in prevent_failover.split(",")
                                if grp]
        groups_to_switch = set(online_failover_sgs) - set(prevent_failover_sgs)
        for service_group in groups_to_switch:
            syslog.syslog("[VCS mco] hagrp -switch {0} -any".format(
                    service_group))
            self.run_vcs_command("hagrp -switch {0} -any".format(
                    service_group), [VCS_UNABLE_TO_SWITCH_GROUP])
        for service_group in prevent_failover_sgs:
            syslog.syslog("[VCS mco] hagrp -offline {0} -sys {1}".format(
                    service_group, node_to_lock))
            self.run_vcs_command("hagrp -offline {0} -sys {1}".format(
                    service_group, node_to_lock),
                                 [VCS_UNABLE_TO_SWITCH_GROUP])
        try:
            self._wait_on_groups_with_timeout("OFFLINE", node_to_lock,
                                              online_failover_sgs,
                                              switch_timeout)
        except VCSException as e:
            # In this case we should not fault if the groups do not offline
            # within the timeout but only log the error message
            syslog.syslog("[VCS mco] {0}".format(e))

    def lock(self, request):
        node_to_lock = request["sys"]
        switch_timeout = int(request["switch_timeout"])
        prevent_failover = ""
        if "prevent_failover_grps" in request:
            prevent_failover = request["prevent_failover_grps"]
        try:
            self._validate_all_nodes_are_unlocked(node_to_lock)

            self._switch_online_failover_service_groups(node_to_lock,
                                                        switch_timeout,
                                                        prevent_failover)
            self.open_haconf()
            self.run_vcs_command(
                "hasys -freeze -persistent -evacuate {0}".format(
                    node_to_lock))
            self.close_haconf()

            return {"retcode": 0, "out": "", "err": ""}
        except (VCSException, VCSCommandException) as e:
            return {"retcode": 1, "out": "", "err": str(e)}

    def is_dependent_svc_only_on_node_to_lock(self, node_to_lock, group):
        '''
        TORF-215426.
        Check a group for any dependencys, if one exists check its system
        list size.
        Return true if the system list size is 1 and that node is to be
        locked
        '''
        _, o, _ = self.run_vcs_command(
            "hagrp -dep {0}".format(group),
            expected_errors=[NO_GRP_DEP_ERROR],
            rewrite_retcode=True)

        for l in str(o).splitlines()[1:]:
            grp = l.split()[1]
            sys_list = self._system_list(grp)
            if len(sys_list) == 1 and sys_list[0] == node_to_lock:
                return True
        return False

    def _group_evacuated(self, node_to_lock, group, system, state):
        '''
        Return false if group not evacuated
        Return true if group is evacuated or locked node not in group
        '''

        #Get the node being locked
        if (node_to_lock not in self._system_list(group) or
            system == node_to_lock and "Grp_NIC" in group):
            return True

        if system == node_to_lock:
            if state == "|OFFLINE|":
                return True
            if "FAULTED" in state:
                """ FAULTED in state covers: state = 'ONLINE_FAULTED'
                or 'OFFLINE_FAULTED' or 'FAULTED """
                syslog.syslog("[VCS mco] Clearing faulted SG {0} on node {1}".
                              format(group, node_to_lock))
                c, _, _ = self.run_vcs_command(
                    "hagrp -clear {0} -sys {1}".format(group,
                                                       node_to_lock))
                if c:
                    return False
                return True

        else:
            if (state == "|ONLINE|" or
                "FAULTED" in state or
                (state == "|OFFLINE|" and
                 not self._group_intent_online(group, system)) or
                    self.is_dependent_svc_only_on_node_to_lock(node_to_lock,
                                                               group)):
                return True
        return False

    def _auto_start_list(self, group):
        '''
        AutoStartList is in the format 'mn1 mn2'
        '''
        _, o, _ = self.run_vcs_command("hagrp -value {0} AutoStartList".format(
            group))

        return o.split()

    def _system_list(self, group):
        '''
        SystemList is in the format 'mn1 0 mn2 0'
        '''
        _, o, _ = self.run_vcs_command("hagrp -value {0} SystemList".format(
            group))

        return o.split()[::2]

    def check_evacuated(self, request):
        node_to_lock = request["sys"]
        for group_info in self.hagrp_display(attribute="State"):
            group, _, system, state = group_info.split()
            if not self._group_evacuated(node_to_lock, group, system, state):
                err = "Group {0} is in state {1} on node {2}".format(
                    group, state, system)
                return {"retcode": 1, "out": "", "err": err}
        return {"retcode": 0, "out": "", "err": ""}

    def _check_nic_groups_online(self, node_name, nic_groups,
                                         nic_wait_timeout):
        syslog.syslog("[VCS mco] Checking if faulted NIC SG's are back online")
        syslog.syslog("[VCS mco] Timeout is set to %s" % nic_wait_timeout)

        self._wait_on_groups_with_timeout("ONLINE", node_name, nic_groups,
                                         nic_wait_timeout)

    def _wait_on_groups_with_timeout(self, desired_state, node_name, groups,
                                    timeout):
        success = {}
        total_time = 0

        while total_time < timeout:
            for group in groups:
                try:
                    # wait just 1 second, polling not really waiting
                    rc, out, _ = self.run_vcs_command("hagrp -wait {0} "
                        "State {1} -sys {2} -time 1".format(group,
                                                            desired_state,
                                                            node_name))
                    success[group] = True
                except VCSCommandException:
                    success[group] = False
                    continue
            if all(success.values()):
                break
            syslog.syslog("[VCS mco] Sleeping 10 seconds")
            time.sleep(10)
            total_time += 10
        if not all(success.values()):
            failed_sgs = [k for k, v in success.items() if v is False]
            message = "Failed to bring {0} service groups: {1}".format(
                desired_state, ', '.join(failed_sgs))
            raise VCSException(message)

    def _get_groups_on_system_by_state(self, sys, target_states=[],
                                                  target_groups=[]):
        target_states = set(target_states)
        cmd = ("hagrp -state {groups} -sys {sys}"
                    .format(groups=" ".join(target_groups), sys=sys))
        try:
            _, o, _ = self.run_vcs_command(cmd, ["VCS WARNING V-16-1-10554 "
                           "No group exists with system of {0}".format(sys)])
        except (VCSCommandException) as e:
                "Error running '{0}': Err: '{1}'".format(cmd, e)

        group_states = [(g, set(s.strip('|').split('|')))
                            for line in o.splitlines()[1:]
                                    for g, _, _, s in [line.split()]]
        matching_groups = []
        for group, states in group_states:
            if len(target_states.intersection(states)) > 0:
                matching_groups.append(group)
        return matching_groups

    def _clear_faulted_group_state(self, group, sys):
        cmd = "hagrp -clear {0} -sys {1}".format(group, sys)
        try:
            c, _, _ = self.run_vcs_command(cmd)
        except (VCSCommandException) as e:
                "Error running '{0}': Err: '{1}'".format(cmd, e)
        # Returns True if successfull
        return c == 0

    def _clear_faulted_groups(self, sys):
        """
        It just tries to clear groups with FAULTED state.
        Unsuccessfull clearings are ignored, so the group would
        remain on FAULTED state.
        """
        for group in self._get_groups_on_system_by_state(sys, ['FAULTED']):
            self._clear_faulted_group_state(group, sys)

    def unlock(self, request):
        node_to_unlock = request["sys"]
        nic_wait_timeout = int(request["nic_wait_timeout"])
        prevent_failover = ""
        total_time = 0
        timeout = 90
        if "prevent_failover_grps" in request:
            prevent_failover = request["prevent_failover_grps"]
        try:
            self.open_haconf()
            _, _, err = self.run_vcs_command(
                "hasys -unfreeze -persistent {0}".format(node_to_unlock),
                ["VCS WARNING V-16-1-40205 System is not persistently frozen",
                 VCS_UNFREEZE_REMOTE_BUILD_STATE])
            if err == VCS_UNFREEZE_REMOTE_BUILD_STATE:
                while total_time < timeout:
                    time.sleep(5)
                    _, state, _ = self.run_vcs_command(
                        "hasys -state {0}".format(node_to_unlock))
                    if state != "REMOTE_BUILD":
                        self.run_vcs_command(
                            "hasys -unfreeze -persistent {0}".format(node_to_unlock),
                            ["VCS WARNING V-16-1-40205 System is not persistently frozen"])
                        break
                    syslog.syslog("Wait 5 seconds before "
                                  "retrying 'hasys -unfreeze -persistent'")
                    total_time += 5
                else:
                    self.run_vcs_command(
                        "hasys -unfreeze -persistent {0}".format(node_to_unlock),
                        ["VCS WARNING V-16-1-40205 System is not persistently frozen"])
            self.close_haconf()

            self._clear_faulted_groups(node_to_unlock)

            _, o, _ = self.run_vcs_command(
                "hagrp -list Parallel=1 | awk '$2==\"{0}\" {{print $1}}' "
                "| uniq".format(node_to_unlock))
            groups = o.splitlines()

            nic_groups = []
            service_groups = []

            # Bring nic groups online first
            for group in groups:
                if group[:7] == "Grp_NIC":
                    nic_groups.append(group)
                else:
                    service_groups.append(group)
            groups_to_check = []
            for nic_group in nic_groups:
                rc, out, _ = self.run_vcs_command("hagrp -state {0} -sys {1} "
                                                  "".format(nic_group,
                                                            node_to_unlock))
                if "FAULTED" in out:
                    groups_to_check.append(nic_group)
            self._check_nic_groups_online(node_to_unlock, groups_to_check,
                                          nic_wait_timeout)
            for nic_group in nic_groups:
                self.run_vcs_command(
                    "hagrp -online {0} -sys {1}".format(nic_group,
                                                        node_to_unlock))

            _, o, _ = self.run_vcs_command(
                "hagrp -list Parallel=0 | awk '$2==\"{0}\" {{print $1}}' "
                "| uniq".format(node_to_unlock))
            groups = o.splitlines()

            for group in groups:
                for group_info in self.hagrp_display(group=group,
                                                     attribute="State"):
                    _, _, node, state = group_info.split()
                    if node != node_to_unlock:
                        if state != "|ONLINE|":
                            service_groups.append(group)
                    elif group in prevent_failover:
                        service_groups.append(group)

            for group in service_groups:
                if (self._group_intent_online(group) or
                    group in prevent_failover):
                    self._bring_group_online(group, node_to_unlock)

            return {"retcode": 0, "out": "", "err": ""}
        except (VCSException, VCSCommandException) as e:
            return {"retcode": 1, "out": "", "err": str(e)}

    def _ok_to_online_group(self, group, node):
        '''
        use hagrp -display to get values for ProbesPending and AutoDisabled
        output is similar to the following
            Grp_CS_cluster1_cs1 AutoDisabled          mn2        0
            Grp_CS_cluster1_cs1 ProbesPending         mn2        0

        Then check that both have value 0, otherwise the service group is
        not safe to be onlined
        '''
        cmd = "hagrp -display {0} -attribute ProbesPending -attribute "\
            "AutoDisabled -sys {1} | grep {2}".format(group, node, group)
        _, o, _ = self.run_vcs_command(cmd)
        ok_to_online = True
        for l in o.splitlines():
            val = itemgetter(3)(l.split())
            if val != "0":
                ok_to_online = False
        return ok_to_online

    def _bring_group_online(self, group, node):
        reattempts = 120
        sleep_time = 5
        ok = False
        VCS_CMD_API = ("hagrp -online -propagate {0} -sys {1}".format(group,
                                                                      node))

        while reattempts > 0:
            if self._ok_to_online_group(group, node):
                ok = True
                break
            time.sleep(sleep_time)
            reattempts -= 1
        if ok:
            syslog.syslog("[VCS mco] Bringing SG {0} online via:  {1} ".
                                  format(group, VCS_CMD_API))
            self.run_vcs_command(VCS_CMD_API)
        else:
            raise VCSException(
                "Group {0} on node {1} cannot be brought "
                "online after 10 minutes".format(group, node))

    def check_cluster_online(self, request):
        try:
            node_to_unlock = request["sys"]
            prevent_failover = []
            if "prevent_failover_grps" in request:
                prevent_failover = request["prevent_failover_grps"].split(',')

            _, o, _ = self.run_vcs_command(
                "hagrp -list Parallel=1 | awk '$2==\"{0}\" {{print $1}}' "
                "| uniq".format(node_to_unlock))
            groups = o.splitlines()

            failover_groups = []
            _, o, _ = self.run_vcs_command(
                "hagrp -list Parallel=0 | awk '$2==\"{0}\" {{print $1}}' "
                "| uniq".format(node_to_unlock))
            failover_groups = o.splitlines()

            for group in failover_groups:
                for group_info in self.hagrp_display(group=group,
                                                     attribute="State"):
                    _, _, node, state = group_info.split()
                    if node != node_to_unlock:
                        if state != "|ONLINE|":
                            groups.append(group)

            groups = [group for group in groups
                      if self._group_intent_online(group)]
            for grp in prevent_failover:
                if grp not in groups:
                    groups.append(grp)
            for group in groups:
                _, o, _ = self.run_vcs_command(
                    "hagrp -value {0} State {1}".format(group,
                                                        node_to_unlock))
                if o != "|ONLINE|":
                    err = "Group {0} is still in state {1} on node {2}".format(
                        group, o, node_to_unlock)
                    return {"retcode": 1, "out": "", "err": err}
                else:
                    syslog.syslog("Group {0} is in state {1} on node {2}"
                              .format(group, o, node_to_unlock))
            return {"retcode": 0, "out": "", "err": ""}
        except (VCSException, VCSCommandException) as e:
            return {"retcode": 1, "out": "", "err": str(e)}

    def cluster_ready(self, request):
        try:
            systems = request["systems"]
            for system in systems.split(','):
                _, o, _ = self.run_vcs_command(
                    "hasys -value {0} SysState".format(system))
                if o != "RUNNING":
                    raise VCSException(
                        "System {0} is currently in state {1}".format(system,
                                                                      o))
            return {"retcode": 0, "out": "", "err": ""}
        except (VCSException, VCSCommandException) as e:
            return {"retcode": 1, "out": "", "err": str(e)}

    def cluster_stopped(self, request):
        _ = request
        try:
            c, _, _ = self.run_vcs_command(
                "hastatus -sum",
                expected_errors=["VCS WARNING V-16-1-11046"])
            if c == 0:
                return {"retcode": 1, "out": "", "err": "Not yet stopped"}
            return {"retcode": 0, "out": "", "err": ""}
        except (VCSException, VCSCommandException) as e:
            return {"retcode": 1, "out": "", "err": str(e)}

    def cluster_app_agent_num_threads(self, request):
        app_agent_num_threads = request["app_agent_num_threads"]
        try:
            c, o, _ = self.run_vcs_command(
                "hatype -modify Application NumThreads {0}".
                    format(app_agent_num_threads))
            return {"retcode": 0, "out": o, "err": ""}
        except (VCSException, VCSCommandException) as e:
            return {"retcode": 1, "out": "", "err": str(e)}

    def probe_all_nics(self, request):
        hostname = request["sys"]
        try:
            _, o, _ = self.run_vcs_command(
                "hatype -resources NIC")

            nics = o.splitlines()

            for nic in nics:
                _, o, _ = self.run_vcs_command(
                    "hares -probe {0} -sys {1}".format(nic,
                                                        hostname))
                if o:
                    err = "Error '{0}' while probing {1} on node {2}".format(
                        o, nic, hostname)
                    return {"retcode": 1, "out": "", "err": err}

            return {"retcode": 0, "out": "", "err": ""}
        except (VCSException, VCSCommandException) as e:
            return {"retcode": 1, "out": "", "err": str(e)}

    def hagrp_check_states(self, request):
        """
        Checks the state of a service group on one or all nodes to determine
        if the state is one of a list of expected states.
        """
        group_name = request["group_name"]
        expected_states = request["state"].split(",")

        try:
            node_to_states = self._get_node_states_for_group(group_name)
        except VCSCommandException as ex:
            return {"retcode": 1, "out": "", "err": str(ex)}

        if "node_name" in request:
            node = request["node_name"]
            if node not in node_to_states:
                # for idempotency, if the requested node does not have a state
                # (in the case of service group contraction), the result is
                # success
                return {"retcode": 0, "out": "",
                        "err": "node {0} not in system list".format(node)}
            if node_to_states[node].strip('|') in expected_states:
                return {"retcode": 0, "out": "", "err": ""}
        else:
            for _, state in node_to_states.items():
                # Strip | from the start and end only and not the middle
                state = state.strip('|')
                if state not in expected_states:
                    break
            else:
                return {"retcode": 0, "out": "", "err": ""}

        return {"retcode": 1, "out": "", "err": ""}

    def hagrp_wait(self, request):
        """
        If request has node_name waits for only for that node.
        Else waits for all nodes.
        """
        if "node_name" in request:
            return self._hagrp_wait_per_node(request)
        return self._hagrp_wait_all(request)

    def _hagrp_wait_per_node(self, request):
        grp = request["group_name"]
        state = request["state"]
        timeout = request["timeout"]
        node = request["node_name"]
        expected_errors = [VCS_SYSTEM_NOT_IN_SYSTEM_LIST_WARN]
        try:
            returncode, _, err = self.run_vcs_command(
                "hagrp -state {0} -sys {1}".format(grp, node),
                expected_errors=expected_errors)
            if returncode != 0:
                return {"retcode": 0, "out": "", "err": err}
        except VCSCommandException as ex:
            return {"retcode": 1, "out": "", "err": str(ex)}
        expected_errors = [VCS_ERR_REGISTERING_RESOURCE]
        try:
            returncode, _, err = self.run_vcs_command(
                "hagrp -wait {0} State {1} -sys {2} -time {3}".format(
                    grp, state, node, timeout),
                expected_errors=expected_errors,
                rewrite_retcode=True)
        except VCSCommandException as ex:
            return {"retcode": 1, "out": "", "err": str(ex)}

        return {"retcode": returncode, "out": "", "err": err.strip()}

    def _hagrp_wait_all(self, request):
        group_name = request["group_name"]
        expected_states = request["state"].split(",")
        timeout = request["timeout"]
        total_time = 0
        while total_time < timeout:
            try:
                node_to_states = self._get_node_states_for_group(group_name)
            except VCSCommandException as ex:
                return {"retcode": 1, "out": "", "err": str(ex)}

            for _, state in node_to_states.items():
                # Strip | from the start and end only and not the middle
                state = state.strip('|')
                if state not in expected_states:
                    break
            else:
                return {"retcode": 0, "out": "", "err": ""}

            time.sleep(1)
            total_time += 1

        return {"retcode": 1,
                "out": "",
                "err": GRP_WAIT_ALL_ERROR.format(
                    group_name=group_name, expected_state=expected_states,
                    timeout=timeout)
                }

    def _prepare_hagrp_online_output(self, error):
        """
        Return only the third and tenth word of each line in the error message.
        This output is used in the function :bring_hagrp_online when we get
        the VCS NOTICE V-16-1-5073, to log and return the names of the nodes
        where the service has been started.
        :param group_name: error string returned by the hagrp command
        :type  group_name: string
        """
        output = []
        if error:
            lines = error.split("\n")
            for line in lines:
                words = line.split()
                output.append(words[2] if len(words) > 2 else "")
                output.append(words[9] if len(words) > 9 else "")
        return " ".join(output)

    def hagrp_online(self, request):
        group = request['group_name']
        cmd = ("/opt/VRTS/bin/hagrp -online {group} -any".format(group=group))
        expected_errors = [VCS_FAILOVER_GROUP_IS_ONLINE,
                           VCS_PARALLEL_GROUP_IS_ONLINE,
                           VCS_ATTEMPTING_TO_ONLINE_GROUP,
                           VCS_FAILOVER_IS_NOT_OFFLINE]
        try:
            c, o, e = self.run_vcs_command(cmd,
                                           expected_errors=expected_errors,
                                           rewrite_retcode=True)
            o = self._prepare_hagrp_online_output(o if o else e)
            return {"retcode": c, "out": o, "err": e}
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

    def hagrp_offline(self, request):
        group = request['group_name']
        system = request.get('system')
        forced = request.get('forced')
        expected_errors = [VCS_GROUP_NOT_EXIST_WARN,
                           VCS_SYSTEM_NOT_IN_SYSTEM_LIST_WARN,
                           VCS_SYSTEM_LIST_EMPTY]
        cmd = "/opt/VRTS/bin/hagrp -offline"
        if forced:
            cmd = cmd + " -force"
            expected_errors.append(VCS_SYSTEM_IS_NOT_AVAILABLE)
            expected_errors.append(VCS_SYSTEM_NOT_EXIST_IN_CLUSTER)
        cmd += " {group}".format(group=group)
        if system:
            cmd += ' -sys {system}'.format(system=system)
        else:
            cmd += ' -any'
        try:
            c, o, e = self.run_vcs_command(cmd,
                                           expected_errors=expected_errors,
                                           rewrite_retcode=True)
            return {"retcode": c, "out": o, "err": e}
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

    def hagrp_remove(self, request):
        group = request['group_name']
        expected_errors = [VCS_GROUP_NOT_EXIST_WARN]

        cmd = ('for res in $(/opt/VRTS/bin/hagrp -resources {group});'
               ' do /opt/VRTS/bin/hares -delete $res; done; '
               '/opt/VRTS/bin/hagrp -delete {group}'.format(group=group))
        try:
            c, o, e = self.run_vcs_command(cmd,
                                           expected_errors=expected_errors,
                                           rewrite_retcode=True)
            return {"retcode": c, "out": o, "err": e}
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

    def hagrp_list(self, request):
        expected_errors = [VCS_NO_GRPS_CONFIGURED]
        try:
            retval, out, err = self.run_vcs_command('hagrp -list',
                                            expected_errors=expected_errors,
                                            rewrite_retcode=True)
            out = out.split()
            dict = defaultdict(list)
            for k, v in itertools.izip(out[::2], out[1::2]):
                dict[k].append(v)
            return {"retcode": retval, "out": dict, "err": err}
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

    def _get_node_states_for_group(self, groupname):
        expected_errors = [VCS_GROUP_NOT_EXIST_IN_CLUSTER_ERR]
        retval, out, err = self.run_vcs_command('hagrp -state {group}'.format(
                                                group = groupname),
                                            expected_errors = expected_errors,
                                            rewrite_retcode = True)
        if retval != 0:
            raise VCSCommandException(err)
        # Strip off header
        out = out.splitlines()[1:]
        node_to_states = dict([(line.split()[2], ' '.join(line.split()[3:]))
                                for line in out])
        return node_to_states

    def _get_sys_states_for_nodes(self):
        retval, out, err = self.run_vcs_command('hasys -state')
        if retval != 0:
            raise VCSCommandException(err)
        # Strip off header
        out = out.splitlines()[1:]
        node_to_states = dict([(line.split()[0], line.split()[2])
                                for line in out])
        return node_to_states

    def get_group_state(self, request):
        """Returns 'ONLINE' if the number of expected nodes are online
        Returns 'FAULTED' if one of the instances is faulted
        Returns 'ONLINING' if it's not met either of these states
        """
        group = request['group_name']
        active_count = int(request['active_count'])
        offline_count = int(request['offline_count'])
        try:
            node_to_states = self._get_node_states_for_group(group)
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": "Could not get node "
                        "states for group {0}. Exception: {1}".format(
                            group, str(e))}

        faulted_nodes = [node for node, state in node_to_states.items()
                         if '|FAULTED|' in state]
        if faulted_nodes:
            return {'retcode': 2, 'out': 'FAULTED',
                    'err': 'Group is faulted on nodes: {0}'.format(
                        ', '.join(faulted_nodes))}
        active_nodes = [node for node, state in node_to_states.items()
                        if state == '|ONLINE|']
        offline_nodes = [node for node, state in node_to_states.items()
                        if state == '|OFFLINE|']
        if (len(active_nodes) == active_count and
                len(offline_nodes) == offline_count):
            return {'retcode': 0, 'out': 'ONLINE', 'err': ''}
        if len(offline_nodes) == len(node_to_states):
            return {'retcode': 0, 'out': 'OFFLINE', 'err': ''}
        else:
            return {'retcode': 0, 'out': 'ONLINING', 'err': ''}

    def get_group_state_on_nodes(self, request):
        """
        Returns the state of a group on a particular node, e.g. '|ONLINE|'
        """
        group = request['group_name']
        try:
            node_to_states = self._get_node_states_for_group(group)
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": "Could not get node "
                        "states for group {0}. Exception: {1}".format(
                            group, str(e))}
        return {'retcode': 0,
                'out': ",".join("{0}:{1}".format(i, j)
                                for i, j in node_to_states.items()),
                'err': ''}

    def hares_add(self, request):
        resource = request['resource']
        res_type = request['type']
        group = request['group_name']

        cmd = '/opt/VRTS/bin/hagrp -resources {0}'.format(group)
        try:
            c, o, e = self.run_vcs_command(cmd)
            if c != 0:
                return {"retcode": 1, "out": "", "err": str(e)}
            resources = [line for line in o.split('\n')]
            if resource in resources:
                return {"retcode": 0, "out": "", "err": ""}
            cmd = '/opt/VRTS/bin/hares -add {0} {1} {2}'.format(resource,
                                                                res_type,
                                                                group)
            c, o, e = self.run_vcs_command(cmd)
            return {"retcode": c, "out": o, "err": e}
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

    def stop_resource(self, resource):
        """
        Stop the resource if in ONLINE state.
        """
        cmd = '/opt/VRTS/bin/hares -display {0} -attribute ' \
              'State'.format(resource)

        errors = [VCS_DISPLAY_RESOURCE_NOT_EXIST]
        c, o, e = self.run_vcs_command(cmd, expected_errors=errors,
                                       rewrite_retcode=True)
        if c == 0:
            lines = o.split('\n')[1:]
            for line in lines:
                values = line.split()
                node = values[2]
                status = ' '.join(values[3:])
                if status == 'ONLINE':
                    cmd = '/opt/VRTS/bin/hares -offline {0} -sys ' \
                          '{1}'.format(resource, node)
                    self.run_vcs_command(cmd)

    def hares_delete(self, request):
        resource = request['resource']

        self.stop_resource(resource)

        cmd = '/opt/VRTS/bin/hares -delete {0}'.format(resource)
        try:
            errors = [VCS_RESOURCE_NOT_EXIST]
            c, o, e = self.run_vcs_command(cmd, expected_errors=errors,
                                           rewrite_retcode=True)
            return {"retcode": c, "out": o, "err": e}
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

    def hares_override_attribute(self, request):
        resource = request['resource']
        attr = request['attribute']

        cmd = '/opt/VRTS/bin/hares -override {0} {1}'.format(resource, attr)
        expected_errors = ["already overridden", "not a static attribute"]
        try:
            c, o, e = self.run_vcs_command(cmd, expected_errors, True)
            return {"retcode": c, "out": o, "err": e}
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

    def hagrp_unlink_all(self, request):
        """ Unlink all group resources """
        group = request["group"]

        try:
            for grp_dependencies in self._get_dependency_for_group(group):
                returncode, output, err = self.run_vcs_command(
                    "hagrp -unlink {0} {1}".format(grp_dependencies.parent,
                                                   grp_dependencies.child))
                if returncode:
                    # It's get an error so stop to unlink.
                    return {"retcode": returncode,
                            "out": output,
                            "err": err.strip()}
        except VCSCommandException as ex:
            return {"retcode": 1, "out": "", "err": str(ex)}

        # No errors.
        return {"retcode": 0, "out": "", "err": ""}

    def _get_dependency_for_group(self, groupname):
        retval, out, err = self.run_vcs_command(
            'hagrp -dep {group}'.format(group=groupname),
            expected_errors=[NO_GRP_DEP_ERROR, VCS_GROUP_NOT_EXIST_WARN_10133],
            rewrite_retcode=True)

        if retval:
            raise VCSCommandException(err)

        # Strip off header
        out = out.splitlines()[1:]
        to_return = []
        for line in out:
            line_splited = line.split()
            to_return.append(ChildParentDependencies(child=line_splited[1],
                                                     parent=line_splited[0]))
        return to_return

    def hares_unlink_pattern(self, request):
        """ Unlink all dependencies for a resource matching the pattern """
        res = request["resource"]
        pattern = request["pattern"]

        try:
            for res_dependency in self._get_dependencies_for_resource(res):
                if re.match(pattern, res_dependency.parent):
                    returncode, output, err = self.run_vcs_command(
                        "hares -unlink {0} {1}".format(res_dependency.parent,
                                                       res_dependency.child))
                    if returncode:
                        # It's get an error so stop to unlink.
                        return {"retcode": returncode,
                                "out": output,
                                "err": err.strip()}
        except VCSCommandException as ex:
            return {"retcode": 1, "out": "", "err": str(ex)}

        # No errors.
        return {"retcode": 0, "out": "", "err": ""}

    def _get_dependencies_for_resource(self, resname):
        retval, out, err = self.run_vcs_command(
            'hares -dep {resource}'.format(resource=resname),
            expected_errors=[NO_RES_DEP_ERROR, VCS_RESOURCE_NOT_EXIST],
            rewrite_retcode=True)

        if retval:
            raise VCSCommandException(err)

        # Strip off header
        out = out.splitlines()[1:]
        to_return = []
        for line in out:
            line_splited = line.split()
            to_return.append(ChildParentDependencies(child=line_splited[2],
                                                     parent=line_splited[1]))
        return to_return

    def hagrp_unlink(self, request):
        """
        Unlink the given parent and child VCS service groups
        """
        parent = request['parent']
        child = request['child']

        cmd = ('hagrp -unlink {parent} {child}'.format(parent=parent,
                                                       child=child))
        expected_errors = [VCS_GROUP_NOT_EXIST_WARN_10133,
                           VCS_COULD_NOT_UNLINK_GROUPS_ERROR]
        try:
            c, o, e = self.run_vcs_command(cmd,
                                           expected_errors=expected_errors,
                                           rewrite_retcode=True)
            return {"retcode": c, "out": o, "err": e}
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

    def hagrp_add_in_auto_start_list(self, request):
        """
        Add in AutoStartList values get it from request['attribute_val'].
        """
        group = request['group_name']
        nodes_to_add = request['attribute_val'].split()
        try:
            #nodes already in AutoStartList
            nodes_in_asl = self._auto_start_list(group)
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

        #We want to add in AutoStartList only nodes that aren't in
        #AutoStartList
        nodes_to_add = [node for node in nodes_to_add
                        if not node in nodes_in_asl]
        if not nodes_to_add:
            #Nothing to do
            return {"retcode": 0, "out": '', "err": ''}

        cmd = '{0} -modify {1} AutoStartList -add {2}'.format(
            PATH_HAGRP, group, " ".join(nodes_to_add))

        try:
            c, o, e = self.run_vcs_command(cmd)
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

        return {"retcode": c, "out": o, "err": e}

    def hagrp_add_in_system_list(self, request):
        """
        Add in SystemList values get it from
        request['attribute_val'].
        """
        group = request['group_name']
        value = request['attribute_val']

        try:
            nodes_in_vcs = self._system_list(group)
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

        node_to_add = set(value.split()[::2]).difference(nodes_in_vcs)
        if len(node_to_add) == 0:
            #Nothing to do
            return {"retcode": 0, "out": '', "err": ''}

        node_prio_dict = dict(zip(value.split()[::2], value.split()[1::2]))
        node_to_add_str = ''
        for node in node_to_add:
            node_to_add_str += node + ' ' + node_prio_dict[node] + ' '

        cmd = '{0} -modify {1} SystemList -add {2}'.format(PATH_HAGRP,
                                                group, node_to_add_str[:-1])

        try:
            c, o, e = self.run_vcs_command(cmd)
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

        return {"retcode": c, "out": o, "err": e}

    def hagrp_delete_in_system_list(self, request):
        """ Delete request['attribute_val'] from SystemList. """
        group = request['group_name']
        value = request['attribute_val']
        force = False
        if 'force' in request:
            force = request['force']

        try:
            nodes_in_vcs = set(self._system_list(group))
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

        node_to_delete = ' '.join(nodes_in_vcs.intersection(value.split()))
        if not node_to_delete:
            #Nothing to do
            return {"retcode": 0, "out": '', "err": ''}

        cmd = '{0} -modify {1} SystemList '.format(PATH_HAGRP, group)
        if force:
            cmd += '-force '
        cmd += '-delete {0}'.format(node_to_delete)

        try:
            expected_errs = [VCS_SYSTEM_IS_NOT_AVAILABLE,
                             VCS_SYSTEM_NOT_DEFINED_OR_GRP_NOT_OFFLINE]
            c, o, e = self.run_vcs_command(cmd,
                                           expected_errs,
                                           rewrite_retcode=True)
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

        return {"retcode": c, "out": o, "err": e}

    def _get_triggers_enabled(self, group):
        cmd = '{0} -value {1} TriggersEnabled'.format(PATH_HAGRP, group)
        try:
            _, o, _ = self.run_vcs_command(cmd)
            return o
        except VCSCommandException as e:
            return None

    def hagrp_add_in_triggers_enabled(self, request):
        """
        Add in TriggersEnabled values get it from
        request['attribute_val'].
        """
        group = request['group_name']
        value = request['attribute_val']

        cmd = '{0} -modify {1} TriggersEnabled -add {2}'.format(PATH_HAGRP,
                                                                group,
                                                                value)
        try:
            c, o, e = self.run_vcs_command(cmd,
                                           [VCS_ENTRY_ALREADY_IN_KEYLIST],
                                           rewrite_retcode=True)
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

        return {"retcode": c, "out": o, "err": e}

    def hagrp_delete_in_triggers_enabled(self, request):
        """
        Delete in TriggersEnabled values get it from
        request['attribute_val'].
        """
        group = request['group_name']
        value = request['attribute_val']

        cmd = '{0} -modify {1} TriggersEnabled -delete {2}'.format(PATH_HAGRP,
                                                                group,
                                                                value)
        try:
            c, o, e = self.run_vcs_command(cmd,
                                           [VCS_GROUP_NOT_EXIST_WARN,
                                            VCS_ENTRY_NOT_IN_KEYLIST],
                                           rewrite_retcode=True)
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

        return {"retcode": c, "out": o, "err": e}

    def hagrp_modify(self, request):
        """
        Modify parameter request['attribute'] in request['group_name']

        If you want to add in SystemList it have use hagrp_add_in_system_list.
        If you want to add in AutoStartList it have to use
        hagrp_add_in_auto_start_list.
        If you want to delete from SystemList it have use
        hagrp_delete_in_system_list.
        """
        group = request['group_name']

        attr = request['attribute']
        assert attr != "SystemList" and attr != "AutoStartList" and \
            attr != "TriggersEnabled"

        value = request['attribute_val']

        # Get the current value of the attribute and do not modify if
        # it currently has the same value. Needed for idempotency for
        # attributes (e.g. Parallel) which cannot be set if resources
        # exist under the service group
        cmd = '{0} -value {1} {2}'.format(PATH_HAGRP, group, attr)
        try:
            _, result, e = self.run_vcs_command(cmd)
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

        if result.strip() == value:
            return {"retcode": 0, "out": '', "err": ''}

        cmd = '{0} -modify {1} {2} {3}'.format(PATH_HAGRP, group, attr, value)
        try:
            c, o, e = self.run_vcs_command(cmd)
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

        return {"retcode": c, "out": "", "err": str(e)}

    def stop_vcs(self, request):
        """
        Run the stop VCS command.
        If force is given in the request, use it
        If a system is given, then use it. Otherwise use -all

        :param request: A dictionary with all the request parameters
        :return: A dictionary with return code, out and error
        """
        cmd = "hastop "

        if "force" in request and request["force"]:
            cmd += "-force "

        if "sys" in request and request["sys"]:
            cmd += "-sys " + request["sys"]
        else:
            cmd += "-all "

        try:
            c, o, e = self.run_vcs_command(cmd)
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}

        return {"retcode": c, "out": o, "err": e}

    def is_ipv6(self, address):
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return True
        except socket.error:
            return False

    def ensure_ipv6_nodad(self, request):
        expected_errors = [VCS_NO_GRPS_CONFIGURED]
        group = request["group_name"]
        try:
            resources = self.hagrp_resources(group).split("\n")
            for res in resources:
                cmd = "hares -value " + res + " Type"
                retval, out, err = \
                    self.run_vcs_command(cmd, rewrite_retcode=True)
                if out == "IP":
                    cmd = "hares -value " + res + " Address"
                    retval, out, err = \
                        self.run_vcs_command(cmd, rewrite_retcode=True)
                    addr = out.split('/', 1)[0]
                    if self.is_ipv6(addr):
                        cmd = "hares -value " + res + " IPOptions"
                        retval, out, err = \
                            self.run_vcs_command(cmd, rewrite_retcode=True)
                        if "nodad" not in out:
                            cmd = "hares -modify " + res + " IPOptions nodad"
                            retval, out, err = \
                                self.run_vcs_command(cmd, rewrite_retcode=True)
                            break

        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}
        return {"retcode": 0, "out": out, "err": err}

    def wait_for_res_state_on_node(self, res, nodes, state):
        while True:
            states = set()
            for res_info in self.hares_display(resource=res,
                                               attribute="State"):
                _, _, node, current_state = res_info.split(None, 3)
                if node in nodes:
                    states.add(current_state)
            if len(states) == 1 and states.pop() == state:
                return
            else:
                time.sleep(1)

    def execute_flush_resource(self):
        """
        Execute hares -flushinfo on all resources in Stale state
        """
        for line in self.hares_display(attribute="ResourceInfo"):
            res = line.split()[0]
            sys = line.split()[2]
            state = line.split()[4]
            if state == "Stale":
                cmd = ('/opt/VRTS/bin/hares -flushinfo {0} {1}'
                       ''.format(res,
                                 '-localclus' if sys == 'global' \
                                     else "-sys {0}".format(sys)))
                retval, out, err = \
                    self.run_vcs_command(cmd, rewrite_retcode=True)

    def flush_resource(self, request):
        """
        API Entry-Point to Execute flushinfo on all resources in
        Stale state to update the state from back to Valid.
        """
        try:
            self.execute_flush_resource()
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}
        return {"retcode": 0, "out": "", "err": ""}

    def hasys_delete(self, request):
        node = request["node"]

        cmd = '/opt/VRTS/bin/hasys -delete {0}'.format(node)
        ret, out, err = \
            self.run_vcs_command(cmd,
                                 expected_errors=[VCS_SYSTEM_DOES_NOT_EXIST],
                                 rewrite_retcode=True)
        return {"retcode": ret, "out": out, "err": err}

    def check_ok_to_online(self, request):
        group_name = request["group"]
        node_name = request["node"]

        if self._ok_to_online_group(group_name, node_name):
            return {"retcode": 0, "out": "", "err": ""}
        return {"retcode": 1, "out": "", "err": ""}

    def remove_standby_node(self, request):
        """
        For a given group, set AutoFailOver to 0 and remove a node from the
        SystemList
        """
        try:
            def chunks(l):
                for i in range(0, 4, 2):
                    yield l[i:i + 2]
            group_name = request["group_name"]
            removed_node = request["removed_node"]
            new_node = request["new_node"]
            cmd = '/opt/VRTS/bin/hagrp -value {0} {1}'.format(group_name,
                                                              "SystemList")
            ret, out, err = self.run_vcs_command(cmd, rewrite_retcode=True)
            node_prio = dict([x for x in chunks(out.split()) if x])
            if removed_node in node_prio and not new_node in node_prio:
                removed_node_prio = node_prio[removed_node]
                cmd = ("/opt/VRTS/bin/hagrp -modify {0} "
                       "AutoFailOver 0".format(group_name))
                ret, out, err = self.run_vcs_command(cmd, rewrite_retcode=True)
                cmd = ("/opt/VRTS/bin/hagrp -modify {0} SystemList "
                       "-delete {1}".format(group_name, removed_node))
                ret, out, err = self.run_vcs_command(cmd, rewrite_retcode=True)
        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}
        return {"retcode": 0, "out": "", "err": ""}

    def add_standby_node(self, request):
        """
        For a given group, set AutoFailOver to 1 and add a node to the
        SystemList and AutoStartList
        """
        try:
            def chunks(l):
                for i in range(0, len(l), 2):
                    yield l[i:i + 2]
            group_name = request["group_name"]
            new_node = request["new_node"]
            cmd = '/opt/VRTS/bin/hagrp -value {0} {1}'.format(group_name,
                                                              "SystemList")
            ret, out, err = self.run_vcs_command(cmd, rewrite_retcode=True)
            node_prios = dict([x for x in chunks(out.split()) if x])
            if len(node_prios) > 1:
                err_msg = ('Can not add new node to group "{0}", SystemList '
                           '"{1}"'.format(group_name, out))
                return {"retcode": 1, "out": "", "err": err_msg}
            node_prio = node_prios.values()[0]
            prios = ['0', '1']
            prios.remove(node_prio)
            new_prio = prios[0]
            cmd = ("/opt/VRTS/bin/hagrp -modify {0} "
                   "AutoFailOver 1".format(group_name))
            ret, out, err = self.run_vcs_command(cmd, rewrite_retcode=True)

            exp_errors = [VCS_ENTRY_ALREADY_IN_KEYLIST]
            cmd = ("/opt/VRTS/bin/hagrp -modify {0} SystemList -add {1} "
                   "{2}".format(group_name, new_node, new_prio))
            ret, out, err = self.run_vcs_command(cmd,
                                                 expected_errors=exp_errors,
                                                 rewrite_retcode=True)
            cmd = ("/opt/VRTS/bin/hagrp -modify {0} "
                   "AutoStartList -add {1}".format(group_name, new_node))
            ret, out, err = self.run_vcs_command(cmd,
                                                 expected_errors=exp_errors,
                                                 rewrite_retcode=True)

            for group_info in self.hagrp_display(group=group_name,
                                                 attribute="State"):
                _, _, node, state = group_info.split()
                if node != new_node:
                    if state != "|ONLINE|":
                        if self._group_intent_online(group_name):
                            self._bring_group_online(group_name, new_node)

        except VCSCommandException as e:
            return {"retcode": 1, "out": "", "err": str(e)}
        return {"retcode": 0, "out": "", "err": ""}

    def hagrp_switch_to_node(self, request):
        """
        Calls "hagrp -switch" on a service group to provoke a failover of
        the service to a given node
        """
        group = request["group_name"]
        node = request["node"]
        cmd = '/opt/VRTS/bin/hagrp -switch {0} -to {1}'.format(group, node)
        ret, out, err = \
            self.run_vcs_command(cmd,
                            expected_errors=[VCS_CANNOT_SWITCH_TO_OWN_SYS],
                            rewrite_retcode=True)
        return {"retcode": ret, "out": out, "err": err}


if __name__ == '__main__':
    VcsCmdApi().action()
