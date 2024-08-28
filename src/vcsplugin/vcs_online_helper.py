##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import time
from litp.core.litp_logging import LitpLogger
from litp.core.execution_manager import CallbackTask
from litp.core.execution_manager import CallbackExecutionException

from .vcs_base_helper import (
    VcsBaseHelper,
    is_clustered_service_redeploy_required,
    is_clustered_service_expansion,
    is_being_deactivated)
from .vcs_exceptions import VcsCmdApiException
from .vcs_utils import VcsUtils
from .vcs_utils import TimeoutParameters
from .vcs_utils import select_nodes_from_service

log = LitpLogger()


class VcsSGOnlineHelper(VcsBaseHelper):
    '''
    VcsSGOnlineHelper Class is responsible for bringing the
    VCS service groups online in a VCS cluster
    '''

    def _generate_online_task(self, cluster, service):
        """
        creates a CallbackTask for the given service
        :param cluster: query object representing the cluster
        :type  cluster: QueryItem
        :param service: query object representing the service
        :type  service: QueryItem
        :param runtime: query object representing the runtime
        :type  runtime: QueryItem
        """
        service_vpath = service.get_vpath()

        vcs_grp_name = self.get_group_name(service.item_id, cluster.item_id)

        task = CallbackTask(service,
                            'Bring VCS service group "{0}" online'.format(
                                vcs_grp_name),
                            self.plugin().callback_method,
                            callback_class=self.__class__.__name__,
                            callback_func="online_callback",
                            vcs_grp_name=vcs_grp_name,
                            service_vpath=service_vpath)

        task = VcsUtils().attach_child_items_to_task(task, service)
        return task

    def create_configuration(self, plugin_api_context, cluster, service):
        # pylint: disable=unused-argument
        pre_node_tasks = []
        post_node_tasks = []

        if service.is_for_removal() or is_being_deactivated(cluster, service)\
           or cluster.cs_initial_online == 'off':
            return pre_node_tasks, post_node_tasks

        # check only if new apps are added, subitems states of apps are
        # ignored as they are treated inside the responsible plugin and will
        # most probably be inside a lock/unlock pair
        initial_apps = [app for app in service.applications
                        if app.is_initial()]

        if (initial_apps
            or service.is_initial()
            or service.runtimes.has_initial_dependencies()
            or is_clustered_service_redeploy_required(service)
            or is_clustered_service_expansion(service)
            or not service.applied_properties_determinable
            ):
            post_node_tasks.append(
                self._generate_online_task(cluster, service))

        reduced_tasks = [task for task in post_node_tasks if task is not None]
        return pre_node_tasks, reduced_tasks

    def online_callback(self, callback_api, vcs_grp_name, service_vpath):
        '''
        Callback function for the tasks
        :param callback_api: access to security and execution manager
        :type  callback_api: class
        :param kwargs: arguments
        :type  kwargs: dict
        '''
        # callback_api is unused

        service = query_by_vpath(callback_api, service_vpath)

        self.nodes = select_nodes_from_service(service)

        self._bring_service_group_online(service, vcs_grp_name)

        timing_parameters = TimeoutParameters(
            max_wait=VcsUtils.get_service_online_time(service))
        log.trace.info('Waiting {time} seconds for on group "{group}" '
                'to come online'.format(
                    time=timing_parameters.max_wait,
                    group=vcs_grp_name))
        if not VcsUtils.wait_on_state(callback_api, self._check_group_online,
                timing_parameters, service, vcs_grp_name):
            raise CallbackExecutionException(
                'Clustered Service "{group}" has not come up within {time} '
                'seconds'.format(
                    group=vcs_grp_name,
                    time=timing_parameters.max_wait))

    def _check_group_online(self, service, group_name):
        """
        Gets the state of the service group and returns if it's online
        """
        grp_state = self.vcs_api.get_group_state(
                group_name=group_name,
                active_count=service.active,
                offline_count=service.standby
                )
        return grp_state == "ONLINE"

    def _bring_service_group_online(self, service, vcs_grp_name):
        '''
        Brings a serivce group online
        :param service_name: access to the vcs clustered service group name
        :type  service: string
        :param model: Dictionary of the vcs-cluster model items
        :type  model: dict
        '''

        cmd_timeout = service.online_timeout

        log.event.info("Attempting to bring Group %s online"\
                                     % (vcs_grp_name))

        #Check the group has resources first
        self.vcs_api.check_vcs_group_has_resources(vcs_grp_name)

        #verify main.cf is in a read only state
        self.vcs_api.check_main_cf_is_readonly()

        #verify the main.cf syntax is correct
        self.vcs_api.verify_main_cf()
        log.event.info("Vcsplugin : main.cf syntax is verified successfully.")

        self.check_for_pending_probes_on_service_group(vcs_grp_name,
                                                       cmd_timeout)

        self.vcs_api.bring_hagrp_online(vcs_grp_name)

    def check_for_pending_probes_on_service_group(
                                self, vcs_grp_name, cmd_timeout):
        '''Check to see if any probes are pending before bring group online'''
        start_time = time.time()
        while self.are_there_probes_pending():
            curr_time = time.time()
            if (curr_time - start_time) > float(cmd_timeout):
                err_msg = "Probes pending timeout on " + vcs_grp_name
                raise VcsCmdApiException(err_msg)
            time.sleep(1.0)

    def are_there_probes_pending(self):
        for node in self.nodes:
            self.vcs_api.set_node(node)
            res_val = self.vcs_api.probes_pending()
            if res_val != '0':
                return True

        return False


def query_by_vpath(callback_api, vpath):
    '''Allows to ask the model through the api for items given a vpath.
       NOTE: Can be deleted once core provides this functionality'''
    return callback_api.query_by_vpath(vpath)
