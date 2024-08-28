##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from litp.core.litp_logging import LitpLogger
from litp.core.execution_manager import CallbackTask
from litp.core.validators import ValidationError
from vcsplugin.vcs_base_helper import VcsBaseHelper, condense_name
from vcsplugin.legacy.vcs_mount_resource import get_mount_res_names
from vcsplugin.legacy.vcs_network_resource import get_ip_res_names


import os.path
from collections import defaultdict
from itertools import chain

log = LitpLogger()


class VcsApplicationLegacyResource(VcsBaseHelper):

    def validate_model(self, plugin_api_context):
        """
        Validates that clustered services do not attempt to run \
        the same service across the same node.

        e.g.
        services/cs1 runs httpd on node1 and node2
        and
        services/cs2 runs httpd on node2 and node3
        is not an allowed combination as node2 is included in both \
        clustered services

        :param plugin_api_context: An instance of PluginApiContext through \
                which validate_model can access the Deployment Model.
        :type plugin_api_context: litp.core.plugin_context_api.PluginApiContext

        :returns:   A list of :class:`litp.core.validators.ValidationError` \
                    objects for each problem found. An empty list means the \
                    model is valid for this plugin.
        :rtype: list
        """
        # Check that there are no overlapping services
        errors = []
        errors.extend(self._validate_for_duplicates(plugin_api_context))
        return errors

    def _validate_for_duplicates(self, plugin_api_context):
        """
        Checks for duplicate runtime services being run on the same nodes
        :param plugin_api_context: Plugin API context for querying the model
        :type  plugin_api_context: class
        """
        errors = []
        clusters = plugin_api_context.query("vcs-cluster")
        for cluster in clusters:
            runtime_to_nodes = defaultdict(list)
            for service in cluster.services:
                if service.is_for_removal():
                    continue
                nodes = set([node.hostname for node in service.nodes])
                base_services = service.query("service")
                for runtime in chain(service.runtimes, base_services):
                    if runtime.is_for_removal():
                        # Skip runtimes we expect to remove
                        continue
                    name = runtime.service_name
                    # Record a tuple of cluster-service id and its nodes
                    # so we can reference the id later
                    runtime_to_nodes[name].append((service.item_id, nodes))
            for rt_name, node_set in runtime_to_nodes.items():
                if len(node_set) == 1:
                    # The runtime is only referenced in one clustered service
                    continue
                for idx, (cs_name, nodes) in enumerate(node_set[:-1]):
                    for target_cs, target_nodes in node_set[idx + 1:]:
                        intersection = nodes & target_nodes
                        if intersection and target_cs != cs_name:
                            node_list = sorted(list(intersection))
                            msg = ("Cluster services %s and %s, on cluster "
                                   "%s, both attempt to start service %s "
                                   "on nodes: %s") % (cs_name, target_cs,
                                                      cluster.item_id,
                                                      rt_name,
                                                      ", ".join(node_list))
                            errors.append(ValidationError(
                                item_path=cluster.get_vpath(),
                                error_message=msg))
        return errors

    def create_configuration(self, plugin_api_context, cluster, service):
        # pylint: disable=unused-argument
        """
        Creates a list of tasks to add application resources to a service \
                group on a VCS cluster

        :param plugin_api_context: An instance of PluginApiContext through \
                which validate_model can access the Deployment Model.
        :type plugin_api_context: litp.core.plugin_context_api.PluginApiContext

        :returns: A list of :class:`litp.core.task.ConfigTask`, \
                :class:`litp.core.task.CallbackTask`, \
                :class:`litp.core.task.RemoteExecutionTask` or \
                :class:`litp.core.task.OrderedTaskList` objects \
                to be added to a new plan.
        :rtype: list
        """
        pre_node_tasks = []
        post_node_tasks = []
        for runtime in service.query("lsb-runtime"):
            if runtime.is_initial() or service.is_initial():
                post_node_tasks.append(
                    self._generate_app_task(cluster, service, runtime))
        return pre_node_tasks, post_node_tasks

    def _generate_app_task(self, cluster, service, runtime):
        """
        creates a CallbackTask for the given service
        :param cluster: query object representing the cluster
        :type  cluster: QueryItem
        :param service: query object representing the service
        :type  service: QueryItem
        :param runtime: query object representing the runtime
        :type  runtime: QueryItem
        """
        res_name = _get_app_res_name(cluster.item_id,
                                     service.name,
                                     runtime.item_id)
        vpaths = (cluster.get_vpath(),
                  service.get_vpath(),
                  runtime.get_vpath())
        vcs_grp_name = self.get_group_name(service.item_id,
                                            cluster.item_id)
        task = CallbackTask(runtime,
                            ('Create LSB application resource "{0}" for VCS '
                                'service group "{1}"').format(res_name,
                                                              vcs_grp_name),
                            self.plugin().callback_method,
                            callback_class=self.__class__.__name__,
                            callback_func="create_app_callback",
                            vpaths=vpaths)
        return task

    def create_app_callback(self, callback_api, vpaths):
        '''
        Callback function for the tasks
        :param callback_api: access to security and execution manager
        :type  callback_api: class
        :param vpaths: holds vpaths of cluster, service, runtime
        :type  kwargs: tuple
        '''
        cluster, service, runtime = [query_by_vpath(callback_api, vpath)
                                     for vpath in vpaths]

        res_name = _get_app_res_name(cluster.item_id, service.name,
                                         runtime.item_id)

        # Needed for _open/close_conf methods:
        self.nodes = [node.hostname for node in service.nodes]

        with self.vcs_api.readable_conf():
            self._create_app_resources(res_name, cluster,
                                       service, runtime)
            self._create_app_dependencies(res_name, cluster,
                                          service, runtime)
            self._create_mount_dependencies(res_name, cluster,
                                            service, runtime)

    def _create_app_resources(self, res_name, cluster, service, runtime):
        '''
        Callback function for the tasks
        :param res_name: Name of the App resource in VCS
        :type  res_name: string
        :param cluster: query object representing the cluster
        :type  cluster: QueryItem
        :param service: query object representing the service
        :type  service: QueryItem
        :param runtime: query object representing the runtime
        :type  runtime: QueryItem
        '''
        res_service_name = self.get_group_name(service.item_id,
                                                cluster.item_id)

        log.event.info(
            "VCS Creating App resource for {0}".format(res_service_name))

        wrapper_dir = "/usr/share/litp"

        log.event.info("Adding App resources")

        rt_svc_name = runtime.service_name
        # Get the (Start|Stop|Monitor)Program values second param is
        # the amount of time to wait before monitoring
        start_program = runtime.start_command or \
                       "%s %s 5" % (os.path.join(wrapper_dir, "vcs_lsb_start"),
                                     rt_svc_name)
        stop_program = runtime.stop_command or \
                        "%s %s 5" % (os.path.join(wrapper_dir, "vcs_lsb_stop"),
                                     rt_svc_name)

        if runtime.status_command:
            monitor_program = runtime.status_command
        elif runtime.item_type.item_type_id == "vm-service":
            monitor_program = "%s %s" % (os.path.join(
                wrapper_dir, "vcs_lsb_vm_status"), rt_svc_name)
        else:
            monitor_program = "%s %s" % (os.path.join(
                wrapper_dir, "vcs_lsb_status"), rt_svc_name)

        cleanup_program = runtime.cleanup_command
        user = runtime.user
        status_interval = runtime.status_interval
        status_timeout = runtime.status_timeout
        restart_limit = runtime.restart_limit
        startup_retry_limit = runtime.startup_retry_limit

        self._add_app_resource(res_name, res_service_name,
                               start_program, stop_program, monitor_program,
                               cleanup_program, user, status_interval,
                               status_timeout, restart_limit,
                               startup_retry_limit
                               )

    def _add_app_resource(self, res_name, service_name, start_program,
                          stop_program, monitor_program, cleanup_program,
                          user, status_interval, status_timeout,
                          restart_limit, startup_retry_limit):
        # Default the user to root if not set
        if not user:
            user = "root"

        self.vcs_api.hares_add(res_name, "Application", service_name)
        self.vcs_api.hares_modify(res_name, "Critical", "1")
        self.vcs_api.hares_modify(res_name, "User", user)
        self.vcs_api.hares_modify(res_name, "StartProgram",
                                  "'%s'" % start_program)
        self.vcs_api.hares_modify(res_name, "StopProgram",
                                  "'%s'" % stop_program)
        self.vcs_api.hares_modify(res_name, "MonitorProgram",
                                  "'%s'" % monitor_program)
        if status_interval is not None:
            self.vcs_api.hares_override_attribute(res_name, "MonitorInterval")
            self.vcs_api.hares_modify(res_name, "MonitorInterval",
                                      status_interval)
        if status_timeout is not None:
            self.vcs_api.hares_override_attribute(res_name, "MonitorTimeout")
            self.vcs_api.hares_modify(res_name, "MonitorTimeout",
                                      status_timeout)
        if restart_limit is not None:
            self.vcs_api.hares_override_attribute(res_name, "RestartLimit")
            self.vcs_api.hares_modify(res_name,
                                 "RestartLimit",
                                 "'%s'" % restart_limit)
        if startup_retry_limit is not None:
            self.vcs_api.hares_override_attribute(res_name, "OnlineRetryLimit")
            self.vcs_api.hares_modify(res_name,
                                 "OnlineRetryLimit",
                                 "'%s'" % startup_retry_limit)
        if cleanup_program:
            self.vcs_api.hares_modify(res_name, "CleanProgram", "'%s'" %
                    cleanup_program)
        self.vcs_api.hares_modify(res_name, "Enabled", "1")

    def _create_app_dependencies(self, res_name, cluster, service, runtime):
        # each of the ips in a runtime will be dependant on the app
        deps = []
        for ip in get_ip_res_names(runtime, service, cluster):
            deps.append((res_name, ip))

        for res_parent, res_child in deps:
            # "hares -link res_parent res_child"
            self.vcs_api.hares_link(res_parent, res_child)

    def _create_mount_dependencies(self, res_name, cluster, service, runtime):
        deps = get_mount_res_names(cluster, service, runtime)
        for mount_res_name in deps:
            self.vcs_api.hares_link(res_name, mount_res_name)


def query_by_vpath(callback_api, vpath):
    '''Allows to ask the model through the api for items given a vpath.
       NOTE: Can be deleted once core provides this functionality'''
    return callback_api.query_by_vpath(vpath)


def _get_app_res_name(cluster_id, sg_name, rt_name):
    '''
    Return resource app name with format
    Res_App_{cluster-item-id}_{clustered-service-name}_{runtime-name}
    '''
    # Res_App_<cluster_id>_<clustered-service-name>_<runtime-name>
    return condense_name("Res_App_{0}_{1}_{2}".\
                         format(cluster_id, sg_name, rt_name))
