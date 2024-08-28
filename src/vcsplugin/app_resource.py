##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from collections import defaultdict
import os.path

from litp.plan_types.deployment_plan import deployment_plan_tags
from litp.core.litp_logging import LitpLogger
from litp.core.execution_manager import CallbackTask, PlanStoppedException
from litp.core.validators import ValidationError

from vcsplugin.vcs_base_helper import (VcsBaseHelper,
                                       get_updated_properties,
                                       is_clustered_service_redeploy_required,
                                       is_failover_to_parallel,
                                       is_clustered_service_node_count_updated,
                                       is_being_deactivated,
                                       is_serv_grp_allowed_multi_apps)
from vcsplugin.network_resource import IPResources
from vcsplugin.vcs_utils import (format_list,
                                 select_nodes_from_service,
                                 is_os_reinstall_on_peer_nodes)
from vcsplugin.vcs_constants import PLAN_STOPPED_MESSAGE

log = LitpLogger()


APP_TASK_DESCRIPTION = ('Create application resource "{0}" for VCS '
                        'service group "{1}"')
APP_UPDATE_DESCRIPTION = ('Update application resource "{0}" for VCS '
                        'service group "{1}". Properties: {2}')
DEP_LIST_WITHOUT_SERVICE_ID = ('The "dependency_list" property cannot be set '
                               'without the "service_id" property being set.')
LINK_TASK_DESCRIPTION = ('Link IP resources to application resource "{0}" '
                         'for VCS service group "{1}"')
WRAPPER_PATH = "/usr/share/litp"


class ApplicationResource(VcsBaseHelper):
    def validate_model(self, plugin_api_context):
        """
        Calls the various validation methods on the model.
        Return a list of errors.
        """
        validators = (
            self._validate_ha_service_config,
            self._validate_failover_apps_all_have_ha_service_configs,
            self._validate_ha_service_configs_have_service_id_defined,
            self._validate_for_duplicate_apps_in_same_cs,
            self._validate_ha_service_configs_reference_extant_app,
            self._validate_service_dependency_items_exist,
            self._validate_service_dependency_items_not_repeating,
            self._validate_parallel_services_dont_specify_dependencies,
            self._validate_against_service_configs_depending_on_self,
            self._validate_against_cyclic_dependency_lists,
            self._validate_against_dependency_list_without_service_id,
            self._validate_update_failover_parallel,
            self._validate_update_parallel_failover,
            self._validate_updated_properties)

        errors = []
        for service in self.services_not_for_removal(plugin_api_context):
            for validator in validators:
                errors.extend(validator(service))
        return errors

    def _validate_ha_service_config(self, service):
        """
        Checks that maximum 1 ha-service-config is defined per service
        :param plugin_api_context: Plugin API context for querying the model
        :type  plugin_api_context: class
        """
        errors = []
        cfgs = service.query("ha-service-config")
        if not is_serv_grp_allowed_multi_apps(service) and len(cfgs) > 1:
            msg = ('Number of ha-service-config items defined for '
                   'vcs-clustered-service "{0}" exceeds maximum '
                   'number of 1'.format(service.name))
            errors.append(ValidationError(
                    item_path=service.get_vpath(),
                    error_message=msg))
        return errors

    def _validate_for_duplicate_apps_in_same_cs(self, service):
        errors = []
        if is_serv_grp_allowed_multi_apps(service):
            app_count = defaultdict(list)
            for app in service.applications:
                # Build duplicates
                app_count[app.service_name].append(app.item_id)
            for app_name, app_item_ids in app_count.items():
                if len(app_item_ids) > 1:
                    msg = ('Clustered service "{0}" attempts to start '
                           'service "{1}" in multiple service items {2}'
                          ).format(service.name, app_name,
                                   ", ".join(['"{0}"'.format(item_id) for
                                              item_id in app_item_ids]))
                    errors.append(ValidationError(
                        item_path=service.vpath,
                        error_message=msg))
        return errors

    def _validate_failover_apps_all_have_ha_service_configs(self, service):
        errors = []
        for app in service.applications:
            app_id = app.item_id
            configs = service.ha_configs.query("ha-service-config",
                                                service_id=app_id)
            if (not configs
                    and is_serv_grp_allowed_multi_apps(service)
                    and len(service.applications) > 1):
                msg = ('No ha-service-config item exists for '
                       'application "{0}"'.format(app_id))
                errors.append(ValidationError(
                    item_path=service.vpath,
                    error_message=msg))
            if len(configs) > 1:
                for config in configs:
                    msg = ('Too many ha-service-config items for '
                           'application "{0}"'.format(app_id))
                    errors.append(ValidationError(
                        item_path=config.vpath,
                        error_message=msg))
        return errors

    def _validate_ha_service_configs_reference_extant_app(self, service):
        errors = []
        if len(service.applications) > 0:
            app_ids = set(_get_all_app_ids(service))
            for cfg in service.ha_configs.query("ha-service-config"):
                if cfg.service_id and cfg.service_id not in app_ids:
                    msg = ('ha-service-config references a service, '
                           '"{0}", that does not exist in '
                           'clustered-service "{1}"'
                           ).format(cfg.service_id, service.name)
                    errors.append(ValidationError(
                        item_path=cfg.vpath,
                        error_message=msg))
        return errors

    def _validate_ha_service_configs_have_service_id_defined(self, service):
        errors = []
        if (is_serv_grp_allowed_multi_apps(service) and
                                                len(service.applications) > 1):
            for cfg in service.ha_configs.query("ha-service-config"):
                if cfg.service_id:
                    continue
                # Clustered services
                msg = ('The "service_id" property must be set for the '
                       '"ha-service-config" item if vcs-clustered service '
                       'contains more than one service')
                errors.append(ValidationError(
                    item_path=cfg.vpath,
                    error_message=msg))
        return errors

    def _validate_service_dependency_items_exist(self, service):
        """
        Checks that ha-service-config items that use dependency_list to specify
        service startup order actually reference existing services in the
        vcs-clustered service.
        :param plugin_api_context: Plugin API context for querying the model
        :type  plugin_api_context: class
        """
        errors = []
        if is_serv_grp_allowed_multi_apps(service):
            app_ids = set(_get_all_app_ids(service))
            for cfg in service.ha_configs.query("ha-service-config"):
                if not cfg.dependency_list:
                    continue
                for target_id in set(cfg.dependency_list.split(",")):
                    if target_id in app_ids:
                        continue
                    msg = ('ha-service-config dependency_list references '
                           'a service item_id, "{0}", that does not '
                           'exist'.format(target_id))
                    errors.append(ValidationError(
                        item_path=cfg.vpath,
                        error_message=msg))
        return errors

    def _validate_service_dependency_items_not_repeating(self, service):
        """
        Checks that ha-service-config items that use dependency_list to specify
        service startup order do not repeat the services.
        :param plugin_api_context: Plugin API context for querying the model
        :type  plugin_api_context: class
        """
        errors = []
        if is_serv_grp_allowed_multi_apps(service):
            for cfg in service.ha_configs.query("ha-service-config"):
                if not cfg.dependency_list:
                    continue
                dependency_list = cfg.dependency_list.split(",")
                if len(set(dependency_list)) == len(dependency_list):
                    continue
                repeatings = set([target_id for target_id in
                                  dependency_list
                                  if dependency_list.count(target_id) > 1])
                msg = ('ha-service-config dependency_list repeats '
                       'service item_id: "{0}"'
                       .format(", ".join(repeatings)))
                errors.append(ValidationError(
                    item_path=cfg.vpath,
                    error_message=msg))
        return errors

    def _validate_parallel_services_dont_specify_dependencies(self, service):
        """
        Checks that ha-service-config items in a parallel service group
        do not try to specify startup dependencies
        :param plugin_api_context: Plugin API context for querying the model
        :type  plugin_api_context: class
        """
        errors = []
        if not is_serv_grp_allowed_multi_apps(service):
            for cfg in service.ha_configs.query("ha-service-config"):
                if not cfg.dependency_list:
                    continue
                msg = ('A dependency_list property can only be specified '
                       'for the ha-service-config item in a failover or a '
                       'one node parallel vcs-clustered-service.')
                errors.append(ValidationError(
                    item_path=cfg.vpath,
                    error_message=msg))
                break
        return errors

    def _validate_against_service_configs_depending_on_self(self, service):
        """
        Checks that ha-service-config items with dependency_lists do not
        attempt to set a startup dependency for a service on itself
        :param plugin_api_context: Plugin API context for querying the model
        :type  plugin_api_context: class
        """
        errors = []
        if is_serv_grp_allowed_multi_apps(service):
            for cfg in service.ha_configs.query("ha-service-config"):
                if not cfg.service_id or not cfg.dependency_list:
                    continue
                if cfg.service_id not in cfg.dependency_list.split(","):
                    continue
                msg = ('ha-service-config for service "{0}" references '
                       'itself as a dependency'.format(cfg.service_id))
                errors.append(ValidationError(
                    item_path=cfg.vpath,
                    error_message=msg))
        return errors

    def _validate_against_dependency_list_without_service_id(self, service):
        """
        Check against a dependency_list being present without a service_id
        in the ha-service-config item
        """
        errors = []
        configs = service.ha_configs.query("ha-service-config")
        for config in configs:
            if config.dependency_list and not config.service_id:
                errors.append(ValidationError(
                    item_path=config.vpath,
                    error_message=DEP_LIST_WITHOUT_SERVICE_ID))
        return errors

    def _validate_against_cyclic_dependency_lists(self, service):
        """
        Checks that multi-application service groups do not attempt to specify
        cyclic startup dependency chains.
        :param plugin_api_context: Plugin API context for querying the model
        :type  plugin_api_context: class
        """
        errors = []
        cyclic_dependencies = get_cyclic_dependencies(service)
        if (is_serv_grp_allowed_multi_apps(service)
                and len(service.applications) > 1
                and cyclic_dependencies):
            msg = ('A circular dependency has been detected between '
                   'the following services: {0}. Check the '
                   '"dependency_list" property of the corresponding '
                   'ha-service-config item '
                   'to resolve the issue.'.format(format_list(
                        service_id for service_id in cyclic_dependencies)))
            errors.append(ValidationError(
                item_path=service.vpath,
                error_message=msg))
        return errors

    def _validate_updated_properties(self, service):
        """
        Checks that when updating the properties for the vcs resource, it
        allows only certain properties. This is to cover the cases when the
        property is marked as a rest updateable, but the plugin does not
        support its updating.
        :param plugin_api_context: Plugin API context for querying the model
        :type  plugin_api_context: class
        """
        errors = []
        if service.is_updated():
            properties = ('name',)
            errors.extend(_check_updated_properties_on_item(properties,
                                                            service))
        for app in service.applications:
            # the ha-service-config also needs to be checked
            if not (app.is_updated() or app.is_applied()):
                continue
            if app.is_updated():
                cluster = service.get_cluster()
                if is_os_reinstall_on_peer_nodes(cluster):
                    properties = ('service_name',)
                else:
                    properties = ('start_command', 'stop_command',
                                  'status_command', 'service_name')
                errors.extend(_check_updated_properties_on_item(
                                                            properties,
                                                            app))
        return errors

    def _validate_update_failover_parallel(self, service):
        """
        Checks if is an update from failover to parallel and the number of the
        nodes is changed
        """
        errors = []
        msg = ("Reconfigure from failover to parallel"
               " expects the same node list")
        if all((is_failover_to_parallel(service),
                service.active != '2',
                service.standby == '0')):
            errors.append(ValidationError(
                item_path=service.get_vpath(),
                error_message=msg))
        return errors

    def _validate_update_parallel_failover(self, service):
        """
        Checks if is an update from parallel to failover
        """
        errors = []
        msg = ("Reconfiguration of a clustered-service from"
               " parallel to failover is not supported")
        if (is_failover_to_parallel(service) and
                service.standby == '1'):
            errors.append(ValidationError(
                        item_path=service.get_vpath(),
                        error_message=msg))
        return errors

    def create_configuration(self, plugin_api_context, cluster, service):
        # pylint: disable=unused-argument
        """
        Creates a list of tasks to add application resources to a service
                group on a VCS cluster

        :param plugin_api_context: An instance of PluginApiContext through
                which validate_model can access the Deployment Model.
        :type plugin_api_context: litp.core.plugin_context_api.PluginApiContext

        :returns: Two lists of :class:`litp.core.task.CallbackTask`.
                First one contains tasks, that should be executed on
                pre-node lock phase. Second list contains tasks for
                post-node lock phase.
        :rtype: tuple
        """
        pre_node_tasks = []
        post_node_tasks = []
        vip_items = []
        vips = self._get_initial_vips(service)
        node_count_changed = is_clustered_service_node_count_updated(service)
        ordered_apps = self._order_applications_by_dependency(service)
        for app in ordered_apps:
            if any((app.is_initial(),
                    service.is_initial(),
                    is_clustered_service_redeploy_required(service))):
                app_name, grp_name, vpaths = self._get_app_parameters(app,
                                                                      cluster,
                                                                      service)
                task = CallbackTask(app,
                    APP_TASK_DESCRIPTION.format(app_name, grp_name),
                    self.plugin().callback_method,
                    callback_class=self.__class__.__name__,
                    callback_func="cb_create_app",
                    vpaths=vpaths
                )
                self._update_model_items(task, service, app)
                post_node_tasks.append(task)
                continue
            elif (not self._get_dependency_list(app, service) and
                  not node_count_changed and vips):
                app_name, grp_name, vpaths = self._get_app_parameters(app,
                                                                      cluster,
                                                                      service)
                task = CallbackTask(vips[0],
                    LINK_TASK_DESCRIPTION.format(app_name, grp_name),
                    self.plugin().callback_method,
                    callback_class=self.__class__.__name__,
                    callback_func="cb_link_vips_to_app",
                    vpaths=vpaths,
                    tag_name=deployment_plan_tags.PRE_NODE_CLUSTER_TAG
                )
                task.model_items.update(vips[1:])
                pre_node_tasks.append(task)
                vip_items.extend(vips)

            if (not service.is_for_removal() and
                not is_being_deactivated(cluster, service)):
                pre_node_tasks.extend(self._get_pre_node_lock_tasks(
                        cluster, service, app))

                post_node_tasks.extend(self._get_post_node_lock_tasks(
                    cluster, service, app))

        if pre_node_tasks and vip_items:
            online_task = self._generate_ensure_service_online_task(
                cluster, service, vip_items)

            online_task.requires.update(pre_node_tasks)
            pre_node_tasks.append(online_task)

        return pre_node_tasks, post_node_tasks

    def _generate_ensure_service_online_task(self, cluster, service, vips):
        service_vpath = service.get_vpath()

        vcs_grp_name = self.get_group_name(service.item_id, cluster.item_id)

        task = CallbackTask(vips[0],
                            'Ensure VCS service group "{0}" is '
                            'online'.format(vcs_grp_name),
                            self.plugin().callback_method,
                            callback_class='VcsSGOnlineHelper',
                            callback_func="online_callback",
                            vcs_grp_name=vcs_grp_name,
                            service_vpath=service_vpath)
        task.model_items.update(vips[1:])
        task.tag_name = deployment_plan_tags.PRE_NODE_CLUSTER_TAG
        return task

    def _get_pre_node_lock_tasks(self, cluster, service, app):
        """
        Returns tasks for pre-node lock phase of the plan.
        """
        pre_node_tasks = []
        updated_properties = (['offline_timeout', 'online_timeout']
                              if not service.applied_properties_determinable
                              else get_updated_properties(
                                                          ('offline_timeout',
                                                           'online_timeout'),
                                                          service))
        failed_update = (not service.applied_properties_determinable
                         and not service.is_initial())
        updated_commands = ['start_command', 'stop_command',
                                       'status_command']
        if is_os_reinstall_on_peer_nodes(cluster):
            updated_commands.append('cleanup_command')

        if any(((service.is_updated() and updated_properties),
                failed_update,
                self._ha_service_config_updated_or_init(service, app),
                get_updated_properties(
                    updated_commands,
                    app))):

            ha_service_config = get_ha_app_config(service, app)
            if ha_service_config:
                updated_properties.extend(get_updated_properties(
                    ('status_interval', 'status_timeout', 'restart_limit',
                     'startup_retry_limit', 'fault_on_monitor_timeouts',
                     'tolerance_limit', 'clean_timeout'),
                    ha_service_config))
            if app.is_updated():
                updated_properties.extend(get_updated_properties(
                    updated_commands, app))

            app_name, grp_name, vpaths = self._get_app_parameters(app,
                                                                  cluster,
                                                                  service)

            task = CallbackTask(app,
                APP_UPDATE_DESCRIPTION.format(app_name, grp_name,
                    format_list(updated_properties)),
                self.plugin().callback_method,
                callback_class=self.__class__.__name__,
                callback_func="cb_update_app_before_lock",
                vpaths=vpaths,
                tag_name=deployment_plan_tags.PRE_NODE_CLUSTER_TAG
            )
            task.model_items.add(service)
            pre_node_tasks.append(task)
        return pre_node_tasks

    def _get_post_node_lock_tasks(self, cluster, service, app):
        """
        Returns tasks for post-node lock phase of the plan.
        """
        post_node_tasks = []
        updated_properties = get_updated_properties(['cleanup_command'],
            app)
        if updated_properties and app.is_updated():
            app_name, grp_name, vpaths = self._get_app_parameters(app,
                                                                  cluster,
                                                                  service)
            task = CallbackTask(app,
                APP_UPDATE_DESCRIPTION.format(app_name, grp_name,
                    format_list(updated_properties)),
                self.plugin().callback_method,
                callback_class=self.__class__.__name__,
                callback_func="cb_update_app_after_lock",
                vpaths=vpaths
            )
            self._update_model_items(task, service, app)
            post_node_tasks.append(task)
        return post_node_tasks

    def _update_model_items(self, task, service, app):
        task.model_items.add(service)
        if self._ha_service_config_updated_or_init(service, app):
            ha_service_config = get_ha_app_config(service, app)
            task.model_items.add(ha_service_config)

    @staticmethod
    def _ha_service_config_updated_or_init(service, app):
        ha_service_config = get_ha_app_config(service, app)
        if ha_service_config:
            return (ha_service_config.is_updated() or
                    ha_service_config.is_initial())
        return False

    def _get_app_parameters(self, app, cluster, service):
        """
        Return application parameters that are used for the callback task.
        """
        app_name = self.get_app_res_name(cluster.item_id, service.name,
                                         app.item_id)
        grp_name = self.get_group_name(service.item_id, cluster.item_id)
        vpaths = (cluster.get_vpath(),
                  service.get_vpath(),
                  app.get_vpath())
        return (app_name, grp_name, vpaths)

    def _order_applications_by_dependency(self, service):
        """
        Sorts the application creation order by dependancy. I.e. it sorts them
        topologically.
        """
        unsorted_applications = dict(
            [(app.item_id, self._get_dependency_list(app, service))
             for app in service.applications])
        item_id_application = dict(
            (app.item_id, app) for app in service.applications)

        sorted_applications = []
        while unsorted_applications:
            for app_id, depencencies in unsorted_applications.items():
                for depencency in depencencies:
                    if depencency in unsorted_applications:
                        break
                else:
                    del unsorted_applications[app_id]
                    sorted_applications.append(item_id_application[app_id])

        return sorted_applications

    def _get_dependency_list(self, app, service):
        """
        Returns list of the app item_id dependencies if there are such,
        otherwise returns an empty list.
        """
        ha_service_configs = service.ha_configs.query('ha-service-config',
                                                      service_id=app.item_id)
        dependency_list = []
        if ha_service_configs:
            dep_list = ha_service_configs[0].dependency_list
            if dep_list is not None:
                dependency_list = dep_list.split(',')
        return dependency_list

    def _get_initial_vips(self, service):
        """
        Returns a list of vips in initial state
        """
        return [vip for vip in service.ipaddresses
                if vip.is_initial()]

    def cb_create_app(self, callback_api, vpaths):
        """
        Callback function for the tasks
        :param callback_api: access to security and execution manager
        :type  callback_api: class
        :param vpaths: holds vpaths of cluster, service, app
        :type  kwargs: tuple
        """
        res_name, cluster, service, app = self._get_appres_parameters(
            callback_api, vpaths)

        # Needed for _open/close_conf methods:
        self.nodes = select_nodes_from_service(service)
        with self.vcs_api.readable_conf():
            self._create_app_resources(res_name, cluster, service, app)
            self._create_app_dependencies(callback_api, res_name, cluster,
                                          service, app)

    def cb_link_vips_to_app(self, callback_api, vpaths):
        """
        Callback function create the dependencies between app and vips
        :param callback_api: access to security and execution manager
        :type  callback_api: class
        :param vpaths: holds vpaths of cluster, service, app
        :type  kwargs: tuple
        """
        res_name, cluster, service, app = self._get_appres_parameters(
            callback_api, vpaths)

        self.nodes = select_nodes_from_service(service)
        with self.vcs_api.readable_conf():
            self._create_app_dependencies(callback_api, res_name, cluster,
                                          service, app)

    def _create_app_resources(self, res_name, cluster, service, app):
        res_service_name = self.get_group_name(service.item_id,
                                               cluster.item_id)

        log.event.info(
            "VCS Creating App resource for {0}".format(res_service_name))

        svc_name = app.service_name
        # Get the (Start|Stop|Monitor)Program values second param is
        # the amount of time to wait before monitoring
        start_program = app.start_command or self._get_wrapper_command(
                                                        svc_name, "start")
        stop_program = app.stop_command or self._get_wrapper_command(
                                                        svc_name, "stop")
        if app.status_command:
            monitor_program = app.status_command
        elif app.item_type.item_type_id == "vm-service":
            monitor_program = self._get_wrapper_command(svc_name, "vm_status")
        else:
            monitor_program = self._get_wrapper_command(svc_name, "status")

        cleanup_program = app.cleanup_command

        app_online_timeout = service.online_timeout
        app_offline_timeout = getattr(service, 'offline_timeout', None)

        ha_app_config = get_ha_app_config(service, app)

        self._add_app_resource(res_name, res_service_name,
                               start_program, stop_program, monitor_program,
                               cleanup_program, app_online_timeout,
                               app_offline_timeout, ha_app_config)

    def _add_app_resource(self, res_name, service_name, start_program,
                          stop_program, monitor_program, cleanup_program,
                          app_online_timeout, app_offline_timeout,
                          ha_app_config):

        self.vcs_api.hares_add(res_name, "Application", service_name)
        self.vcs_api.hares_modify(res_name, "Critical", "1")

        self._modify_app_resource(res_name, ha_app_config, app_online_timeout,
                                  app_offline_timeout,
                                  start_command=start_program,
                                  stop_command=stop_program,
                                  monitor_program=monitor_program,
                                  cleanup_program=cleanup_program)

        self.vcs_api.hares_modify(res_name, "Enabled", "1")

    def _create_app_dependencies(self, callback_api, res_name, cluster,
                                 service, app):
        """
        Create dependencies if necessary from the single `app` on all `vips`
        in service. Create app interdependencies if defined.
        """
        dependency_list = None

        ha_app_config = get_ha_app_config(service, app)
        if ha_app_config:
            dependency_list = ha_app_config.dependency_list
            if dependency_list:
                for dependency in dependency_list.split(','):
                    if not callback_api.is_running():
                        raise PlanStoppedException(PLAN_STOPPED_MESSAGE)
                    app = service.applications.query('service',
                                                     item_id=dependency)[0]
                    app_res_name = self.get_app_res_name(cluster.item_id,
                                                         service.name,
                                                         app.item_id)
                    self.vcs_api.hares_link(res_name, app_res_name)

        if not dependency_list:
            ips_per_network = defaultdict(list)
            for ip in service.ipaddresses:
                ips_per_network[ip.network_name].append(ip)

            for ips in ips_per_network.values():
                ip_resources = IPResources(ips, cluster, service, None)

                for name in ip_resources.resource_names:
                    if not callback_api.is_running():
                        raise PlanStoppedException(PLAN_STOPPED_MESSAGE)
                    self.vcs_api.hares_link(parent=res_name, child=name)

    def cb_update_app_after_lock(self, callback_api, vpaths):
        """
        Callback function for update a resource
        :param callback_api: access to security and execution manager
        :type  callback_api: class
        :param vpaths: holds vpaths of cluster, service, app in that order
        :type  kwargs: tuple
        """
        res_name, cluster, service, app = self._get_appres_parameters(
            callback_api, vpaths)

        res_service_name = self.get_group_name(service.item_id,
                                               cluster.item_id)

        log.event.info(
            "VCS Updating App resource for {0}".format(res_service_name))

        cleanup_program = app.cleanup_command

        # Needed for _open/close_conf methods:
        self.nodes = select_nodes_from_service(service)
        with self.vcs_api.readable_conf():
            self._modify_app_resource(res_name,
                                      cleanup_program=cleanup_program)

    def cb_update_app_before_lock(self, callback_api, vpaths):
        """
        Callback function for update a resource
        :param callback_api: access to security and execution manager
        :type  callback_api: class
        :param vpaths: holds vpaths of cluster, service, app in that order
        :type  kwargs: tuple
        """
        res_name, cluster, service, app = self._get_appres_parameters(
            callback_api, vpaths)

        res_service_name = self.get_group_name(service.item_id,
                                               cluster.item_id)

        log.trace.info(
            "VCS Updating App resource for {0}".format(res_service_name))

        app_online_timeout = service.online_timeout
        app_offline_timeout = getattr(service, 'offline_timeout', None)

        ha_app_config = get_ha_app_config(service, app)

        # Needed for _open/close_conf methods:
        self.nodes = select_nodes_from_service(service)
        with self.vcs_api.readable_conf():
            if is_os_reinstall_on_peer_nodes(cluster):
                self._modify_app_resource(res_name, ha_app_config,
                                          app_online_timeout,
                                          app_offline_timeout,
                                          cleanup_program=app.cleanup_command,
                                          start_command=app.start_command,
                                          stop_command=app.stop_command,
                                          monitor_program=app.status_command)
            else:
                self._modify_app_resource(res_name, ha_app_config,
                                          app_online_timeout,
                                          app_offline_timeout,
                                          start_command=app.start_command,
                                          stop_command=app.stop_command,
                                          monitor_program=app.status_command)

    def _modify_app_resource(self, res_name, ha_app_config=None,
                             app_online_timeout=None, app_offline_timeout=None,
                             cleanup_program=None, **app_commands):

        properties = {}
        if ha_app_config:
            properties.update({
                'FaultOnMonitorTimeouts':
                    ha_app_config.fault_on_monitor_timeouts,
                'ToleranceLimit': ha_app_config.tolerance_limit,
                'CleanTimeout': ha_app_config.clean_timeout,
                'MonitorInterval': ha_app_config.status_interval,
                'MonitorTimeout': ha_app_config.status_timeout,
                'RestartLimit': ha_app_config.restart_limit,
                'OnlineRetryLimit': ha_app_config.startup_retry_limit})

        properties.update({'OnlineTimeout': app_online_timeout,
                           'OfflineTimeout': app_offline_timeout,
                           'StartProgram': app_commands.get('start_command',
                                                            None),
                           'StopProgram': app_commands.get('stop_command',
                                                           None),
                           'MonitorProgram': app_commands.get(
                               'monitor_program', None),
                           'CleanProgram': cleanup_program})

        log.trace.info("Update Resource {0}. Properties to update: "
                       "{1}".format(res_name, ', '.join(properties.keys())))
        self._assign_values(res_name, properties)

    def _assign_values(self, res_name, property_dictionary):
        """
        Assign values to the specific properties on the VCS resources.
        """

        for key, value in property_dictionary.items():
            if value is not None:
                self.vcs_api.hares_override_attribute(res_name, key)
                self.vcs_api.hares_modify(res_name, key, "'%s'" % value)

    def _get_appres_parameters(self, callback_api, vpaths):
        """
        Return parameters needed for application resource modification.
        :param callback_api: access to security and execution manager
        :type  callback_api: class
        :param vpaths: holds vpaths of cluster, service, app
        :type  kwargs: tuple
        """
        cluster, service, app = [self.query_by_vpath(callback_api, vpath)
                                 for vpath in vpaths]

        res_name = self.get_app_res_name(cluster.item_id, service.name,
                                         app.item_id)

        return (res_name, cluster, service, app)

    def _get_wrapper_command(self, service_name, cmd):
        cmds = {'start': 'vcs_lsb_start',
                'stop': 'vcs_lsb_stop',
                'status': 'vcs_lsb_status',
                'vm_status': 'vcs_lsb_vm_status',
               }
        cmd_path = os.path.join(WRAPPER_PATH, cmds[cmd])

        cmd_str = "{0} {1}".format(cmd_path, service_name)
        if 'status' not in cmd:
            # Add in the timeout as well
            cmd_str = "{0} {1}".format(cmd_str,
                    self._get_resource_check_delay())
        return cmd_str

    def _get_resource_check_delay(self):
        # Placeholder for when we query ha-config-base for this value
        return 5


def get_ha_app_config(service, app):
    """
    Return a single ha-service-config for the application in the vcs
    clustered service.
    :param service: query object representing the service
    :type  service: QueryItem
    :param app: query object represeting an app in the applications \
                collection of service
    :type app: QueryItem
    :returns: query object of ha-service-config item associated with the app \
                if found, or None
    :rtype: QueryItem
    """
    ha_service_params = service.ha_configs.query("ha-service-config")
    if len(ha_service_params) == 1 and \
       (ha_service_params[0].service_id is None or
        ha_service_params[0].service_id == app.item_id):
        ha_app_config = ha_service_params[0]
    else:
        ha_app_config = next((
            ha_config
            for ha_config in ha_service_params
            if ha_config.service_id == app.item_id), None)
    return ha_app_config


def _check_updated_properties(properties, item):
    """
    Return a list of updated properties from an interable of properties for
    the given item.
    """
    return [prop for prop in properties
            if item.applied_properties.get(prop) != getattr(item, prop)]


def _get_update_error_message(updated_properties):
    """
    Return an error message string for updated properties and normalize the
    names to add quotations.
    """
    updated_properties = ['"{0}"'.format(updated_property) for updated_property
                          in updated_properties]
    return ('The following propert{0} cannot be updated: {1}.'.format(
        'y' if len(updated_properties) == 1 else 'ies',
        ', '.join(updated_properties)))


def _check_updated_properties_on_item(properties, item):
    """
    Return a list of errors for properties that cannot be updated on each item.
    """
    errors = []
    updated_properties = _check_updated_properties(properties, item)
    if updated_properties:
        errors.append(ValidationError(
                      item_path=item.get_vpath(),
                      error_message=_get_update_error_message(
                                        updated_properties)))
    return errors


def get_cyclic_dependencies(clustered_service):
    """
    Topographic sort implementation that does not raise an exception when
    a cyclic dependency is encountered. Instead it returns a list of service
    item_ids that are in some way implicated in one or more cyclic
    dependencies.
    :param clustered-service: QueryItem representing a clustered-service
    :type  clustered-service: class
    """
    configs = clustered_service.query("ha-service-config")

    # We're in validation here, so we can't assume all data is correct when
    # this runs, so strip out anything that doesn't have a service_id
    valid_ids = set(_get_all_app_ids(clustered_service))
    configs = [config for config in configs if config.service_id
                                            and config.service_id in valid_ids]
    missing_ids = valid_ids - set([config.service_id for config in configs])

    dep_map = {}
    for config in configs:
        dependency_list = config.dependency_list or ""

        # Ignore the services that don't exist because there's other validation
        clean_dependency_list = set([service for service in
                                 set(dependency_list.split(","))
                                 if service in valid_ids]) - missing_ids

        dep_map[config.service_id] = clean_dependency_list
        # Ignore self-dependencies because there's other validation for this
        dep_map[config.service_id].discard(config.service_id)
        dep_map[config.service_id].discard("")

    while True:
        # leaves are anything without a dependency
        leaves = set(app_id for (app_id, deps) in dep_map.items() if not deps)
        if not leaves:
            # Either nothing left in dep_map or everything left has a
            # dependency
            break
        # trim leaves from dep_map keys AND from dependency_lists
        dep_map = dict(
                (app_id, (deps - leaves)) for (app_id, deps) in dep_map.items()
                    if app_id not in leaves)

    # If we still have something left we have cycles
    return dep_map.keys()


def _get_all_app_ids(clustered_service):
    app_ids = []
    for application in clustered_service.applications:
        app_ids.append(application.item_id)
    return app_ids
