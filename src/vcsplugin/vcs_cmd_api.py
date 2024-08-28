# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from contextlib import contextmanager

from litp.core.rpc_commands import run_rpc_command
from litp.core.litp_logging import LitpLogger
from litp.core.constants import BASE_RPC_NO_ANSWER

from .vcs_exceptions import VcsCmdApiException
from .vcs_constants import COMMAND_NOT_FOUND
from .vcs_utils import VcsUtils
from .vcs_utils import TimeoutParameters

log = LitpLogger()


VCS_STOP_ERR = "VCS ERROR V-16-1-10600 Cannot connect to VCS engine"
VCS_NODE_LEAVING_ERR = "VCS WARNING V-16-1-50129 Operation 'haconf -dump " \
                       "-makero' rejected as the node is in LEAVING state"
VCS_NODE_REMOTE_BUILD_ERR = "VCS WARNING V-16-1-50129 Operation 'haconf -dump"\
                       " -makero' rejected as the node is in REMOTE_BUILD"\
                       " state"
VCS_NODE_ADMIN_WAIT_ERR = ("VCS WARNING V-16-1-50129 Operation 'haconf "
                           "-dump -makero' rejected as the node is in "
                           "ADMIN_WAIT state")
MCO_LOCK_TIMEOUT = 60
MIN_UPDATE_IP_TIMEOUT = 60
MAX_UPDATE_IP_TIMEOUT = 300


class VcsRPC(object):

    AGENT = "vcs_cmd_api"

    def __init__(self, node=None):
        self.node = node

    def _get_mco_vcs_command(self, action, args=None):
        command = "mco rpc {0} {1} ".format(self.AGENT, action)
        if args:
            for a, v in args.iteritems():
                command += "{0}={1} ".format(a, v)
        command += "-I {0}".format(self.node)
        return '"{0}"'.format(command)

    def _call_mco(self, mco_action, args, timeout=None, retries=1):
        """
        general method to run MCollective commands using run_rpc_command
        and perform error handling based on MCollective issues
        """
        nodes = [self.node]

        command_run = self._get_mco_vcs_command(mco_action, args)
        log.trace.debug('Running MCO command {0}'.format(command_run))
        results = run_rpc_command(nodes, self.AGENT, mco_action, args, timeout,
                                  retries=retries)

        if len(results[self.node]["errors"]):
            raise VcsCmdApiException(
                "{0} {1}".format(command_run,
                                 results[self.node]["errors"]))

        log.trace.debug('Command succeeded {0}'.format(command_run))
        return results[self.node]["data"]

    def lock(self, node_to_lock, switch_timeout, prevent_failover_grps=None):
        mco_action = "lock"

        args = {"sys": node_to_lock,
                "switch_timeout": switch_timeout}
        if prevent_failover_grps:
            args["prevent_failover_grps"] = prevent_failover_grps

        result = self._call_mco(mco_action, args,
                                timeout=MCO_LOCK_TIMEOUT + int(switch_timeout))
        if result["retcode"]:
            raise VcsCmdApiException(result["err"])

    def unlock(self, node_to_unlock, nic_wait_timeout,
               prevent_failover_grps=None):
        mco_action = "unlock"

        args = {"sys": node_to_unlock,
                "nic_wait_timeout": nic_wait_timeout}
        if prevent_failover_grps:
            args["prevent_failover_grps"] = prevent_failover_grps

        result = self._call_mco(mco_action, args,
                                timeout=int(nic_wait_timeout) + 10)
        if result["retcode"]:
            raise VcsCmdApiException(result["err"])

    def check_evacuated(self, node_to_lock):
        mco_action = "check_evacuated"

        args = {"sys": node_to_lock}

        result = self._call_mco(mco_action, args)
        return result["retcode"], result["out"], result["err"]

    def check_cluster_online(self, node_to_unlock,
                             prevent_failover_grps=None):
        mco_action = "check_cluster_online"

        args = {"sys": node_to_unlock}
        if prevent_failover_grps:
            args["prevent_failover_grps"] = prevent_failover_grps

        result = self._call_mco(mco_action, args)
        return result["retcode"], result["out"], result["err"]

    def cluster_ready(self, nodes):
        mco_action = "cluster_ready"

        args = {"systems": nodes}

        result = self._call_mco(mco_action, args)
        return result["retcode"], result["out"], result["err"]

    def cluster_stopped(self):
        mco_action = "cluster_stopped"

        args = {}

        result = self._call_mco(mco_action, args)
        return result["retcode"], result["out"], result["err"]

    def probe_all_nics(self, hostname):
        mco_action = "probe_all_nics"

        args = {"sys": hostname}

        result = self._call_mco(mco_action, args)
        return result["retcode"], result["out"], result["err"]

    def check_ok_to_online(self, group, node):
        mco_action = "check_ok_to_online"

        args = {"group": group,
                "node": node}

        result = self._call_mco(mco_action, args)
        return result["retcode"], result["out"], result["err"]


class VcsCmdApi(object):
    '''
    '''

    def __init__(self, node=None):
        self.node = node
        self.agent = "vcs_cmd_api"

    @contextmanager
    def readable_conf(self):
        try:
            self.haconf("makerw")
            yield
        finally:
            self.haconf("dump", read_only="True")

    def set_node(self, nodename):
        self.node = nodename

    def _get_mco_vcs_command(self, action, args=None):
        command = "\"mco rpc {0} {1} ".format(self.agent, action)
        if args is not None:
            for a, v in args.iteritems():
                command += "{0}={1} ".format(a, v)
        command += "-I {0}\" ".format(self.node)
        return command

    def _gen_err_str(self, action, args=None):
        return "Failure to execute command: {0}"\
            .format(self._get_mco_vcs_command(action, args))

    def _log_success(self, mco_action, args):
        # Log message once the MCO command returns. This can be useful for
        # commands such as 'hagrp -wait'
        command_run = self._get_mco_vcs_command(mco_action, args)
        log.trace.debug('Command succeeded {0}'.format(command_run))

    def _call_mco(self, mco_action, args, timeout=None, retries=1,
                  expected_errors=None):
        """
        general method to run MCollective commands using run_rpc_command
        and perform error handling based on MCollective issues
        """
        nodes = list()
        nodes.append(self.node)

        log.trace.debug('Running MCO VCS command {0}'.format(
            self._get_mco_vcs_command(mco_action, args)))
        results = run_rpc_command(nodes, self.agent, mco_action, args, timeout,
                                  retries=retries)

        if not len(results) == 1:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Expected 1 response, received %s"\
                % (len(results))
            log.trace.error(err_msg)
            raise VcsCmdApiException(err_msg)
        if not results.keys()[0] == self.node:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Response from unexpected sender %s"\
                       % (results.keys()[0])
            log.trace.error(err_msg)
            raise VcsCmdApiException(err_msg)

        if results[self.node]["errors"]:
            error_expected = False
            if expected_errors:
                for error in expected_errors:
                    if error in results[self.node]["errors"]:
                        log.event.info("Restore_snaphot: " + error +
                                       ". Node reboot will restart VCS")
                        error_expected = True
                        results[self.node]["data"]["retcode"] = 0

            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: MCO failure... {0} on node {1}".format(
                results[self.node]["errors"], self.node)
            if error_expected:
                log.trace.debug(err_msg)
            else:
                log.trace.error(err_msg)
                raise VcsCmdApiException(err_msg)

        return results[self.node]["data"]

    def haconf(self, haconf_action, read_only="False",
               ignore_vcs_stop_err=False, ignore_node_down=False,
               ignore_node_leaving=False, ignore_node_remote_build=False,
               ignore_admin_wait=False, ignore_cmd_not_found=False):
        """
        run haconf vcs command using Mcollective
        :param haconf_action: action to be performed by haconf command
        :type  haconf_action: string
        :param read_only: set read only option (used if using -dump)
        :type  read_only: string
        """
        mco_action = "haconf"

        valid_actions = ["makerw", "dump"]

        if haconf_action not in valid_actions:
            err_msg = "Failure to execute command mco rpc vcs_cmd_api"\
                      " haconf, Reason: Invalid action supplied - %s "\
                      % haconf_action
            raise VcsCmdApiException(err_msg)

        if haconf_action == "makerw" and not read_only == "False":
            err_msg = "Failure to execute command mco rpc vcs_cmd_api "\
                      "haconf, Reason: cannot perform action makerw with"\
                      "read_only equal to True"
            raise VcsCmdApiException(err_msg)

        args = dict()
        args["haaction"] = haconf_action
        args["read_only"] = read_only

        expected_errors = []
        if ignore_vcs_stop_err:
            expected_errors.append(VCS_STOP_ERR)
        if ignore_node_leaving:
            expected_errors.append(VCS_NODE_LEAVING_ERR)
        if ignore_node_remote_build:
            expected_errors.append(VCS_NODE_REMOTE_BUILD_ERR)
        # LITPCDS-13385: VCS in bad state after manual stop
        if ignore_admin_wait:
            expected_errors.append(VCS_NODE_ADMIN_WAIT_ERR)
        if ignore_cmd_not_found:
            expected_errors.append(COMMAND_NOT_FOUND)

        try:
            result = self._call_mco(mco_action, args,
                                    expected_errors=expected_errors)
        except VcsCmdApiException as e:
            if ignore_node_down and BASE_RPC_NO_ANSWER in str(e):
                return
            raise

        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)

    def hagrp_add(self, group_name):
        """
        run hagrp add vcs command using Mcollective
        :param group_name: name of group to be added
        :type  group_name: string
        """
        mco_action = "hagrp_add"

        args = dict()
        args["group_name"] = group_name

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)

    def hagrp_remove(self, group_name):
        """
        run hagrp delete vcs command using Mcollective
        :param group_name: name of group to be added
        :type  group_name: string
        """
        mco_action = "hagrp_remove"

        args = dict()
        args["group_name"] = group_name

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)

    def hagrp_list(self):
        """
        run hagrp list vcs command using Mcollective
        :param group_name: name of group to be added
        :type  group_name: string
        """
        mco_action = "hagrp_list"
        result = self._call_mco(mco_action, {})
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, {})
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)
        return result["out"]

    def hagrp_remove_resources(self, group_name):
        """
        run hares -delete vcs command using Mcollective
        :param group_name: name of group to be added
        :type  group_name: string
        """
        mco_action = "hagrp_remove_resources"

        args = dict()
        args["group_name"] = group_name

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)

    def hagrp_offline(self, group_name, node=None, forced=False):
        """
        run hagrp offline vcs command using Mcollective
        :param group_name: name of group to be added
        :type  group_name: string
        """
        mco_action = "hagrp_offline"

        args = dict()
        args["group_name"] = group_name
        if node:
            args["system"] = node
        if forced:
            args["forced"] = 'True'

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)

    def hastatus(self):
        """
        run hagrp add vcs command using Mcollective
        :param group_name: name of group to be added
        :type  group_name: string
        """
        mco_action = "hastatus"

        args = dict()

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0 or result["err"]:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)
        return result["out"]

    def hagrp_delete_in_system_list(self, group_name, val, force=False):
        """
        run hagrp -modify group_name -delete val
        :param group_name: name of group to be modified
        :type  group_name: string
        :param val: value of nodes to be deleted
        :type  val: string
        """
        mco_action = "hagrp_delete_in_system_list"

        args = {"group_name": group_name, "attribute_val": val}
        if force:
            args['force'] = 'True'

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                .format(result["retcode"],
                        result["err"])
            raise VcsCmdApiException(err_msg)

    def hagrp_add_in_system_list(self, group_name, val):
        """
        run hagrp -modify group_name SystemList -add val
        :param group_name: name of group to be modified
        :type  group_name: string
        :param val: value of nodes and priority
        :type  val: string
        """
        mco_action = "hagrp_add_in_system_list"

        args = {"group_name": group_name, "attribute_val": val}

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                .format(result["retcode"],
                        result["err"])
            raise VcsCmdApiException(err_msg)

    def hagrp_add_in_auto_start_list(self, group_name, val):
        """
        run hagrp -modify group_name AutoStartList -add val
        :param group_name: name of group to be modified
        :type  group_name: string
        :param val: value of nodes
        :type  val: string
        """
        mco_action = "hagrp_add_in_auto_start_list"

        args = {"group_name": group_name, "attribute_val": val}

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += ("Reason: Command failed... retcode {0}, stderr {1}"
                        "".format(result["retcode"], result["err"]))
            raise VcsCmdApiException(err_msg)

    def hagrp_add_in_triggers_enabled(self, group_name, val):
        """
        run hagrp -modify group_name TriggersEnabled -add val
        :param group_name: name of group to be modified
        :type  group_name: string
        :param val: value of nodes and priority
        :type  val: string
        """
        mco_action = "hagrp_add_in_triggers_enabled"

        args = {"group_name": group_name, "attribute_val": val}

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                .format(result["retcode"],
                        result["err"])
            raise VcsCmdApiException(err_msg)

    def hagrp_delete_in_triggers_enabled(self, group_name, val):
        """
        run hagrp -modify group_name TriggersEnabled -delete val
        :param group_name: name of group to be modified
        :type  group_name: string
        :param val: value of nodes and priority
        :type  val: string
        """
        mco_action = "hagrp_delete_in_triggers_enabled"

        args = {"group_name": group_name, "attribute_val": val}

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                .format(result["retcode"],
                        result["err"])
            raise VcsCmdApiException(err_msg)

    def hagrp_modify(self, group_name, attr, val):
        """
        run hagrp modify vcs command using Mcollective
        :param group_name: name of group to be modified
        :type  group_name: string
        :param attr: attribute within group to be modified
        :type  attr: string
        :param val: value to which attribute will be set
        :type  val: string
        """
        mco_action = "hagrp_modify"

        args = dict()
        args["group_name"] = group_name
        args["attribute"] = attr
        args["attribute_val"] = val

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                .format(result["retcode"],
                        result["err"])
            raise VcsCmdApiException(err_msg)

    def hares_delete(self, resource):
        """
        run hares res vcs command using Mcollective
        :param resource: name of resource to be deleted
        :type  resource: string
        """
        mco_action = "hares_delete"

        args = dict()
        args["resource"] = resource

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)

    def hares_add(self, resource, res_type, group_name):
        """
        run hares add vcs command using Mcollective
        :param resource: name of resource to be added
        :type  resource: string
        :param res_type: resource type
        :type  res_type: string
        :param group_name: name of group to which resource is added
        :type  group_name: string
        """
        mco_action = "hares_add"

        args = dict()
        args["resource"] = resource
        args["type"] = res_type
        args["group_name"] = group_name

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)

    def hares_modify(self, resource, attr, val, sys=None, delete=False):
        """
        run hares modify vcs command using Mcollective
        :param resource: name of resource to be modified
        :type  resource: string
        :param attr: attribute within resource to be modified
        :type  attr: string
        :param val: value to which attribute will be set
        :type  val: string
        :param delete: Use the '-delete' flag
        :type delete: bool
        """
        mco_action = "hares_modify"

        args = dict()
        args["resource"] = resource
        args["attribute"] = attr
        args["attribute_val"] = val
        if delete is True:
            args["delete"] = 'true'
        if sys:
            args["sys"] = sys

        result = self._call_mco(mco_action, args)
        if result["retcode"] != 0:
            if ("VCS WARNING V-16-1-10566" in result["err"] and
                    "not found in attribute keylist" in result["err"]):
                log.trace.debug("Ignoring hares_modify warning"
                                "...{0}".format(result["err"]))
            else:
                raise VcsCmdApiException("Failure to modify resource attribute"
                                         ", retcode (%s): %s"
                                         % (result["retcode"], result["err"]))

    def hares_local(self, resource, attr):
        """
        run hares local vcs command using Mcollective
        :param resource: name of resource to be modified
        :type  resource: string
        :param attr: attribute within resource to be modified
        :type  attr: string
        """
        mco_action = "hares_local"

        args = dict()
        args["resource"] = resource
        args["attribute"] = attr

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)

    def hares_override_attribute(self, resource, attr):
        """
        run hares local vcs command using Mcollective
        :param resource: name of resource to be modified
        :type  resource: string
        :param attr: attribute within resource to be overridden
        :type  attr: string
        """
        mco_action = "hares_override_attribute"

        args = dict()
        args["resource"] = resource
        args["attribute"] = attr

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)

    def hares_link(self, parent, child):
        """
        run hares link vcs command using Mcollective
        :param parent: name of parent resource
        :type  parent: string
        :param child: name of child resource
        :type  child: string
        """
        mco_action = "hares_link"

        args = dict()
        args["parent"] = parent
        args["child"] = child

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)

    def hares_unlink(self, parent, child):
        """
        run hares unlink vcs command using Mcollective
        :param parent: name of parent resource
        :type  parent: string
        :param child: name of child resource
        :type  child: string
        """
        mco_action = "hares_unlink"

        args = dict()
        args["parent"] = parent
        args["child"] = child

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            raise VcsCmdApiException("Failure to unlink resource attribute,"
                                     " retcode (%s): %s"
                                     % (result["retcode"], result["err"]))

    def hagrp_unlink_all(self, group):
        """
        run hagp unlink vcs command using MCollective
        :param parent: name of parent resource
        :type  parent: string
        """
        mco_action = "hagrp_unlink_all"

        args = dict(group=group)
        result = self._call_mco(mco_action, args)
        if result["retcode"]:
            raise VcsCmdApiException("Failure to unlink group dependencies,"
                                     " retcode (%s): %s"
                                     % (result["retcode"], result["err"]))

    def hares_unlink_pattern(self, resource, pattern):
        """
        run hares unlink vcs command using MCollective for all
        the resources linked with the resource matching the given pattern
        :param resource: name of parent resource
        :type  resource: string
        :param pattern: pattern for matching resources
        :type  pattern: string
        """
        mco_action = "hares_unlink_pattern"

        args = dict(resource=resource, pattern=pattern)
        result = self._call_mco(mco_action, args)
        if result["retcode"]:
            raise VcsCmdApiException("Failure to unlink resource dependencies,"
                                     " retcode (%s): %s"
                                     % (result["retcode"], result["err"]))

    def hagrp_link(self, parent, child, gd_category, gd_location, gd_type):
        """
        run hagrp link vcs command using Mcollective
        :param parent: name of parent resource
        :type  parent: string
        :param child: name of child resource
        :type  child: string
        :param gd_category: online|offline
        :type  gd_category: string
        :param gd_location: local|remote
        :type  gd_location: string
        :param gd_type: firm|soft
        :type  gd_type: string
        """
        mco_action = "hagrp_link"

        args = dict()
        args["parent"] = parent
        args["child"] = child
        args["gd_category"] = gd_category
        args["gd_location"] = gd_location
        args["gd_type"] = gd_type

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            ignore_fail = False
            if ("VCS WARNING V-16-1-10905" in result["err"] and
                "already exists" in result["err"]):
                log.trace.debug("Ignoring hagrp_link warning... {0}".format(
                    result["err"]))
                ignore_fail = True
            if not ignore_fail:
                err_msg = self._gen_err_str(mco_action, args)
                err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                    .format(result["retcode"], result["err"])
                raise VcsCmdApiException(err_msg)

    def hagrp_unlink(self, parent, child):
        """
        run hagrp unlink <parent> <child> vcs command using MCollective
        :param parent: name of parent group
        :type  parent: string
        :param child: name of parent group
        :type  child: string
        """
        mco_action = "hagrp_unlink"

        args = dict()
        args["parent"] = parent
        args["child"] = child

        result = self._call_mco(mco_action, args)
        if result["retcode"]:
            raise VcsCmdApiException("Failure to unlink group dependency,"
                                     " retcode (%s): %s"
                                     % (result["retcode"], result["err"]))

    def hares_probe(self, resource, sys):
        """
        run hares probe vcs command using Mcollective
        :param resource: name of resource to be modified
        :type  resource: string
        :param sys: system which is to be probed
        :type  sys: string
        """
        mco_action = "hares_probe"

        args = dict()
        args["resource"] = resource
        args["sys"] = sys

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            raise VcsCmdApiException("Failure to probe resource,"
                                     " retcode (%s): %s"
                                     % (result["retcode"], result["err"]))

    def check_hagrp_isoffline(self, callback_api, group_name, cmd_timeout,
                              node_name=None, expect_faulted=False):
        """
        Checks that the service group is offline
        :param callback_api: Api to query the model
        :type  callback_api: CallbackApi
        :param group_name: name of group to be checked
        :type  group_name: string
        :param cmd_timeout: timeout for that particular command
        :type  cmd_timeout: integer
        :param node_name: name of the node where the group is offline
        :type  node_name: string
        :param expect_faulted: if faulted states should be allowed
        :type  expect_faulted: boolean
        """
        timing_parameters = TimeoutParameters(max_wait=cmd_timeout,
                                              interruptible=False)
        success = VcsUtils.wait_on_state(callback_api, self._is_hagrp_offline,
                                         timing_parameters, group_name,
                                         node_name, expect_faulted)
        if not success:
            if node_name:
                message = ("Group %s failed to offline on "
                           "node %s in %s seconds"
                           % (group_name, node_name, cmd_timeout))
            else:
                message = ("Group %s failed to offline. in %s seconds"
                           % (group_name, cmd_timeout))
            raise VcsCmdApiException(message)

        message = ('Command succeeded: check_hagrp_isoffline '
                   'group {0}, timeout {1}'.format(group_name, cmd_timeout))
        if node_name:
            message += ' node {0}'.format(node_name)
        if expect_faulted:
            message += ' Expect Faulted'
        log.trace.debug(message)

    def _is_hagrp_offline(self, group_name, node_name, expect_faulted):
        mco_action = "hagrp_check_states"
        args = {}
        args["group_name"] = group_name
        if node_name:
            args["node_name"] = node_name
            args["state"] = "OFFLINE"
            if expect_faulted:
                args["state"] = "OFFLINE,OFFLINE|FAULTED,FAULTED"
        else:
            args["state"] = "OFFLINE,OFFLINE|FAULTED,FAULTED"

        result = self._call_mco(mco_action, args)
        success = result["retcode"] == 0
        return success

    def hagrp_value(self, group_name, attribute, system=None):
        mco_action = "hagrp_value"
        args = {}
        args["group_name"] = group_name
        args["attribute"] = attribute
        if system:
            args["system"] = system

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            raise VcsCmdApiException("Error is {0}".format(
                result["err"]))
        self._log_success(mco_action, args)
        return result["out"]

    def probes_pending(self):
        mco_action = "probes_pending"
        result = self._call_mco(mco_action, {})
        if not result["retcode"] == 0:
            raise VcsCmdApiException("Error is {0}".format(
                result["err"]))
        self._log_success(mco_action, {})
        if "VCS WARNING V-16-1-50031" in result["err"]:
            return "0"
        return result["out"]

    def bring_hagrp_online(self, group_name):
        """
        Brings the service group online
        :param group_name: name of group to be modified
        :type  group_name: string
        """
        mco_action = "hagrp_online"
        args = dict()
        args["group_name"] = group_name
        retry_cmd = 2
        while retry_cmd > 0:
            result = self._call_mco(mco_action, args)
            if not result["retcode"] == 0:
                raise VcsCmdApiException("VCS raise unexpected error when "
                                         "trying to bring the group %s online."
                                         " Reason: %s"
                                         % (group_name, result["err"]))
            tmp = result["out"].split()
            # V-##-## codes, tell us if group got started ok
            if tmp[0] == "V-16-1-50997" or tmp[0] == "V-16-1-50996":
                log.event.debug("Group %s already installed "
                                "Run command hastatus -sum", group_name)
                retry_cmd = 0
            elif tmp[0] == "V-16-1-50735":
                # tmp contains something like ['V-16-1-50735', 'MN1',
                # 'V-16-1-50735', 'MN2'].
                # tmp[::-2] gives the following output ['MN1', 'MN2']
                node_names = tmp[::-2]
                log.event.info("Service %s is starting up on %s"\
                                     % (group_name, node_names))

                retry_cmd = 0
            elif tmp[0] == "V-16-1-10165":
                retry_cmd -= 1
                continue

    def verify_main_cf(self):
        """
       Verify's main.cf is correct
        """
        mco_action = "hacf_verify"
        result = self._call_mco(mco_action, args=None)
        if not result["retcode"] == 0:
            raise VcsCmdApiException("Failed to verify main.cf"
                                     "Error: %s"
                                     % (result["err"]))

    def check_main_cf_is_readonly(self):
        """
        checks if main.cf is in ReadOnly state
        """
        mco_action = "haclus_ro"
        result = self._call_mco(mco_action, args=None)
        if not result["retcode"] == 0:
            raise VcsCmdApiException("Failed to run haclus_ro "
                                     "Error: %s"
                                     % (result["err"]))
        if not result["out"] == "1":
            raise VcsCmdApiException("main.cf is not in Read Only state "
                                     "Cannot bring group online")

    def check_vcs_group_has_resources(self, group_name):
        """
        Checks if service group has any resources assigned to it
        :param group_name: name of group to which resource is added
        :type  group_name: string
        """
        mco_action = "hagrp_resources"
        args = dict()
        args["group_name"] = group_name

        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            raise VcsCmdApiException("Group resource command failed for "
                                     "group %s, Error is %s"
                                     % (group_name,  result["err"]))

        resources = result["out"]
        if resources is None:
            raise VcsCmdApiException("Error no resources present for group %s"
                                     % (group_name))

        return resources

    def hares_list(self):
        """
        run hares list vcs command using Mcollective
        """
        mco_action = "hares_list"
        args = dict()
        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)

        return result["out"]

    def hasys_freeze(self, system_name):
        """
        run hasys -freeze -persistent -evacuate <sys>
        vcs command using Mcollective
        """
        mco_action = "hasys_freeze"
        args = {"node": system_name}
        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action)
            err_msg += ("Reason: Command failed... "
                        "retcode {0}, stderr {1}").format(result["retcode"],
                                                          result["err"])
            raise VcsCmdApiException(err_msg)

        return result["out"]

    def hasys_unfreeze(self, system_name):
        """
        run hasys -unfreeze -persistent <sys>
        vcs command using Mcollective
        """
        mco_action = "hasys_unfreeze"
        args = {"node": system_name}
        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action)
            err_msg += ("Reason: Command failed... "
                        "retcode {0}, stderr {1}").format(result["retcode"],
                                                          result["err"])
            raise VcsCmdApiException(err_msg)

        return result["out"]

    def hasys_delete(self, system_name):
        """
        run hasys -delete <sys>
        vcs command using Mcollective
        """
        mco_action = "hasys_delete"
        args = {"node": system_name}
        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action)
            err_msg += ("Reason: Command failed... "
                        "retcode {0}, stderr {1}").format(result["retcode"],
                                                          result["err"])
            raise VcsCmdApiException(err_msg)

        return result["out"]

    def hasys_state(self, system_name):
        """
        run hasys -state <sys>
        vcs command using Mcollective
        """
        mco_action = "hasys_state"
        args = {"node": system_name}
        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action)
            err_msg += ("Reason: Command failed... "
                        "retcode {0}, stderr {1}").format(result["retcode"],
                                                          result["err"])
            raise VcsCmdApiException(err_msg)

        return result["out"]

    def start_vx_fencing(self):
        """
        runs "vxfen-startup" using McCollective
        """
        mco_action = "start_vx_fencing"
        args = dict()
        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)

    def stop_vx_fencing(self, ignore_node_down=False,
                        ignore_cmd_not_found=False):
        """
        Runs "service vxfen stop" using McCollective
        """
        mco_action = "stop_vx_fencing"
        args = dict()
        try:
            result = self._call_mco(mco_action, args)
        except VcsCmdApiException as e:
            if ignore_node_down and BASE_RPC_NO_ANSWER in str(e):
                return
            raise
        if not result["retcode"] == 0:
            if ignore_cmd_not_found and COMMAND_NOT_FOUND in result['err']:
                # Mco call could not find the command on the node
                log.event.info("Stop Vxfen: VCS command was not found on "
                               "node. Ignoring this issue.")
            else:
                err_msg = self._gen_err_str(mco_action)
                err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                           .format(result["retcode"], result["err"])
                raise VcsCmdApiException(err_msg)

    def stop_vcs(self, force=False, ignore_vcs_stop_err=False,
                 ignore_node_down=False, sys=None, ignore_cmd_not_found=False):
        """
        runs "hastop <arguments>" command using McCollective
        """
        mco_action = "stop_vcs"
        args = dict()
        if force:
            args['force'] = "force"
        if sys:
            args['sys'] = sys
        try:
            result = self._call_mco(mco_action, args)
        except VcsCmdApiException as e:
            if ignore_node_down and BASE_RPC_NO_ANSWER in str(e):
                return
            raise
        if not result["retcode"] == 0:
            if ignore_vcs_stop_err and VCS_STOP_ERR in result["err"]:
                log.event.info("Restore_snaphot: VCS ERROR V-16-1-10600"
                               "Cannot connect to VCS engine, Node reboot "
                               "will restart VCS")
            elif ignore_cmd_not_found and COMMAND_NOT_FOUND in result['err']:
                # Mco call could not find the command on the node
                log.event.info("Stop VCS: VCS command was not found on "
                               "node. Ignoring this issue.")
            else:
                err_msg = self._gen_err_str(mco_action)
                err_msg += ("Reason: Command failed... retcode {0}, stderr {1}"
                            ", stdout {2}".format(result["retcode"],
                                                  result["err"],
                                                  result["out"]))
                raise VcsCmdApiException(err_msg)

    def start_vcs(self):
        """
        runs "hastart" using McCollective
        """
        mco_action = "start_vcs"
        args = dict()
        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)

    def vxfen_admin(self):
        """
        runs "vxfenadm -d" using McCollective. The result is returned.
        """
        mco_action = "vxfen_admin"
        args = dict()
        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)

        return result["out"]

    def vxfen_config(self):
        """
        runs "vxfenconfig -l" using McCollective. The result is returned.
        """
        mco_action = "vxfen_config"
        args = dict()
        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)

        return result["out"]

    def edit_maincf_use_fence(self, cluster_name):
        """
        edits main.cf to include the UseFence = SCSI3
        """
        mco_action = "edit_maincf_use_fence"
        args = {"cluster_name": cluster_name}
        result = self._call_mco(mco_action, args)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)

    def get_diskgroup_mounted_status(self, vx_dg_name):
        """
        return `True` if the disk belonging to `vx_dg_name` is mounted
        otherwise raise a `VcsCmdApiException`
        """
        #vxvm_nogroup_exist_err = "V-5-1-582"
        mco_action = "get_dg_hostname"
        args = {"dg_name": vx_dg_name}
        result = self._call_mco(mco_action, args)
        if result["retcode"] == 0:
            log.event.info("%s disk is imported on %s", vx_dg_name, self.node)
            return True
        else:
            log.event.debug("%s disk is not imported on %s", vx_dg_name,
                                                             self.node)
            return False

    def deport_disk_group(self, vx_dg_name):
        """
        Will deport a disk from a node
        """
        mco_action = "deport_disk_group"
        args = {"dg_name": vx_dg_name}
        log.event.info("Deporting %s disk  on %s",
                                  vx_dg_name, self.node)
        result = self._call_mco(mco_action, args,)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                       .format(result["retcode"], result["err"])
            raise VcsCmdApiException(err_msg)
        log.event.info("Deporting of %s disk  on %s was successful",
                                  vx_dg_name, self.node)

        return result["out"]

    def get_group_state(self, group_name, active_count, offline_count):
        mco_action = 'get_group_state'
        args = {'group_name': group_name,
                'active_count': active_count,
                'offline_count': offline_count}
        log.event.debug('Checking state of group "{group}" (online: '
                        '{online}, standby: {standby})'.format(
                            group=group_name,
                            online=active_count,
                            standby=offline_count))

        result = self._call_mco(mco_action, args,)
        if not result['retcode'] == 0:
            err_msg = self._gen_err_str(mco_action)
            err_msg += 'Reason: Command failed... retcode {0}, stderr {1}'\
                       .format(result['retcode'], result['err'])
            raise VcsCmdApiException(err_msg)
        log.event.debug('Group "{group}" state: {state}'.format(
                            group=group_name,
                            state=result['out']))

        return result['out']

    def get_group_state_on_nodes(self, group_name):
        mco_action = 'get_group_state_on_nodes'
        args = {'group_name': group_name}
        log.event.debug('Checking state of group "{group}"'.format(
                group=group_name))
        result = self._call_mco(mco_action, args,)
        if not result['retcode'] == 0:
            err_msg = self._gen_err_str(mco_action)
            err_msg += 'Reason: Command failed... retcode {0}, stderr {1}'\
                       .format(result['retcode'], result['err'])
            raise VcsCmdApiException(err_msg)
        log.event.debug('Group "{group}" state: {state}'.format(
                            group=group_name,
                            state=result['out']))
        return result['out']

    def _format_nodes_priorities(self, nodes_prio_tuples, parallel):
        """
        Build a string with systems names and systems numeric priority values
        @nodes_prio_tuples: list of tuples of nodes and their prio value
        @parallel: either True or False. Value 'True', is for paralleled
        service groups. Value "False" means it is a faillover service group.
        """
        if parallel:
            return ' '.join(tup[1] + " 0" for tup in nodes_prio_tuples)
        return ' '.join(tup[1] + " " + str(tup[0])
                        for tup in nodes_prio_tuples)

    def _clustered_service_set_attributes(self, group, nodes_prio_tuples,
                                          parallel):
        """
        Add and set common VCS service group attributes: Parallel, SystemList
        @group - name of a service group,
        @nodes_prio_tuples - list list of tuples of nodes and their prio value
        @parallel - either: True or False.
                   If True - service group is a parallel service group.
                   If False - service group is a faillover service group
        """
        self.hagrp_add(group)
        self.hagrp_modify(group, "Parallel", str(int(parallel)))
        self._clustered_service_set_syslist(group, nodes_prio_tuples, parallel)

    def _clustered_service_set_syslist(self, group, nodes_prio_tuples,
                                       parallel):
        nodes_priorities = self._format_nodes_priorities(nodes_prio_tuples,
                                                         parallel)
        self.hagrp_add_in_system_list(group, nodes_priorities)

    def clustered_service_update_attributes(self, group, nodes_prio_tuples,
                                            parallel):
        """
        Add and set common VCS service group attributes: Parallel, SystemList
        @group - name of a service group,
        @nodes - list of systems this group can come online,
        @parallel - either: True or False.
                   If True - service group is a parallel service group.
                   If False - service group is a faillover service group
        """
        self.hagrp_modify(group, "Parallel", str(int(parallel)))
        self._clustered_service_set_syslist(group, nodes_prio_tuples,
                                            parallel)

    def cluster_app_agent_num_threads(self, app_agent_num_threads):
        mco_action = "cluster_app_agent_num_threads"

        args = {"app_agent_num_threads": app_agent_num_threads}

        result = self._call_mco(mco_action, args)
        return result["retcode"], result["out"], result["err"]

    def ensure_ipv6_nodad(self, group_name):
        """
        This method is used when a postonline trigger is added to a
        service in case the IP resource was previously deployed to
        ensure that the IPOption nodad is applied retrospectively
        """
        mco_action = "ensure_ipv6_nodad"

        args = {"group_name": group_name}

        result = self._call_mco(mco_action, args)
        return result["retcode"], result["out"], result["err"]

    def update_ip_resource(self, data_json, timeout):
        """
        This method is used when the IP resources on a network need to have
        its Address, NetMask or PrefixLen attribute updated
        """
        mco_action = "api_update_ip_resources_of_a_network"

        if timeout < MIN_UPDATE_IP_TIMEOUT:
            timeout = MIN_UPDATE_IP_TIMEOUT
        elif timeout > MAX_UPDATE_IP_TIMEOUT:
            timeout = MAX_UPDATE_IP_TIMEOUT

        result = self._call_mco(mco_action, {"data_json": data_json},
                                timeout, retries=0)
        return result["retcode"], result["out"], result["err"]

    def flush_resource(self):
        """
        This method is used to execute a command to change the state of
        a list of resources from stale back to valid.
        """
        mco_action = "flush_resource"

        args = {}

        result = self._call_mco(mco_action, args)
        return result["retcode"], result["out"], result["err"]

    def remove_standby_node(self, group_name, removed_node,
                            new_node):
        """
        This method is used to execute a command to change the state of
        a list of resources from stale back to valid.
        """
        mco_action = "remove_standby_node"

        args = {"group_name": group_name,
                "removed_node": removed_node,
                "new_node": new_node}
        result = self._call_mco(mco_action, args)
        return result["retcode"], result["out"], result["err"]

    def add_standby_node(self, group_name, new_node):
        """
        This method ...
        """
        mco_action = "add_standby_node"

        args = {"group_name": group_name,
                "new_node": new_node}
        result = self._call_mco(mco_action, args)
        return result["retcode"], result["out"], result["err"]

    def hagrp_switch_to_node(self, group_name, node):
        """
        This method ...
        """
        mco_action = "hagrp_switch_to_node"

        args = {"group_name": group_name,
                "node": node}
        result = self._call_mco(mco_action, args)
        return result["retcode"], result["out"], result["err"]

    def get_etc_llthosts(self):
        """
        This method executes a command to get the contents of
        the file /etc/llthosts
        """
        mco_action = "get_etc_llthosts"

        args = {}
        result = self._call_mco(mco_action, args)
        return result["retcode"], result["out"], result["err"]
