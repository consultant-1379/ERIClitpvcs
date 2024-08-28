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
from litp.core.validators import ValidationError
from litp.core.execution_manager import (CallbackTask,
                                         CallbackExecutionException)
from litp.plan_types.deployment_plan import deployment_plan_tags

from .vcs_base_helper import (VcsBaseHelper,
                              condense_name,
                              property_updated,
                              same_list_different_order,
                              is_clustered_service_redeploy_required,
                              does_service_need_to_be_migrated,
                              is_serv_grp_allowed_multi_apps,
                              get_applied_nodes_in_cluster,
                              is_deactivating,
                              is_being_deactivated,
                              is_failover_standby_node_updated,
                              get_applied_node_list,
                              is_clustered_service_expansion,
                              is_clustered_service_contraction,
                              is_node_list_changed,
                              is_failover_to_parallel)

from .vcs_cmd_api import VcsRPC
from .vcs_utils import (VcsUtils, text_join, format_list, TimeoutParameters,
                        select_nodes_from_cluster, select_nodes_from_service,
                        is_os_reinstall_on_peer_nodes)
from .network_resource import vip_upd_standby_node
from .vcs_exceptions import VcsCmdApiException
from .vcs_constants import LOCK_FUDGE_FACTOR, OFFLINE_TIMEOUT

log = LitpLogger()

ERROR_DELETION_DEPENDENCY = ('The following clustered service dependencies '
                             'are marked for removal: "{0}". Update the '
                             '"dependency_list" property.')
ERROR_DELETION_INIT_DEPENDENCY = ('The following VCS clustered service initial'
                                  ' online dependencies are marked for '
                                  'removal: "{0}". Update the '
                                  '"initial_online_dependency_list" property.')
ERR_INVALID_NODE_LIST = ('Invalid node_list property "{0}". The node list can '
                         'be expanded or contracted, but replacing nodes is '
                         'not supported.')
ERR_NO_SG_CONTRACTION_WITH_VIPS = ('Removal of nodes from node_list of '
                                   'service containing VIPs is not supported.')
ERR_DEACTIVATES_SELF = ('deactivates property of a vcs-clustered-service '
                        'cannot reference itself.')
ERR_DEACTIVATES_NODE_OVERLAP = ('vcs-clustered-service "{0}" and the '
                    'vcs-clustered-service it is to deactivate, "{1}", cannot '
                    'be installed on the same node. Common nodes are "{2}"')
ERR_DEACTIVATES_DEPENDENCY = ('vcs-clustered-service "{0}" being deactivated '
                'by vcs-clustered-service "{1}" cannot be in dependency_list.')
ERR_DEACTIVATES_INIT_ONLINE_DEPENDENCY = ('vcs-clustered-service "{0}" being '
                                'deactivated by vcs-clustered-service "{1}" '
                                'cannot be in initial_online_dependency_list.')
ERR_DEACTIVATES_CRITICAL_SERVICE = ('critical_service property cannot '
                   'reference a vcs-clustered-service marked for deactivation')
ERR_DEACTIVATES_NOT_INITIAL = ('Cannot set deactivates property on a '
                         'vcs-clustered-service that is not in Initial state.')
ERR_DEACTIVATES_NOT_APPLIED_SERVICE = ('deactivates property cannot reference '
                       'a vcs-clustered-service that is not in Applied state.')
ERR_MULTIPLE_DEACTIVATIONS = ('Cannot deactivate more than one '
                           'vcs-clustered-service within the same vcs-cluster')
ERR_DEACTIVATED_INCORRECTLY_SET = ('deactivated property set to "true" on a '
                        'vcs-clustered-service that has not been deactivated.')
ERR_DEACTIVATES_UPDATE_INCOMPLETE = ('Cannot update deactivates property on a '
                      'vcs-clustered-service when deactivation is incomplete.')


class VcsServiceGroupHelper(VcsBaseHelper):
    '''
    VcsServiceGroupHelper Class is responsible for installing the
    VCS service groups in a VCS cluster
    '''

    def update_model(self, plugin_api_context):
        """
        Make any plugin specific updates to model items, before validation and
        create_configuration.
        :param plugin_api_context: access to the model manager

        Set the state of any service that has been deactivated to ForRemoval.
        If a service with deactivated=true is in in Initial state, it will be
        removed from the model.
        """
        services = plugin_api_context.query("vcs-clustered-service")
        for service in services:
            if service.applied_properties.get('deactivated') == 'true':
                log.trace.info('Setting deactivated vcs-clustered-service '
                '"{0}" to ForRemoval state.'.format(service.get_vpath()))
                plugin_api_context.remove_item(service.get_vpath())

    @staticmethod
    def _validate_nodes_in_cluster(cluster, clustered_service):
        """
        validates that the nodes in the clustered service are in the
        correct state
        :param cluster: cluster to be validated
        :type  cluster: class
        :param clustered_service: clustered service being checked
        :type  clustered_service: string
        """
        errors = []
        for node in clustered_service.nodes:
            if node.is_for_removal():
                err_msg = ("Node {0} not in cluster {1} as it is marked "
                           "for removal".format(node.item_id,
                                                cluster.item_id))
                log.trace.error(err_msg)
                errors.append(
                    ValidationError(item_path=clustered_service.get_vpath(),
                                    error_message=err_msg))
        return errors

    def _validate_unique_service_name(self, cluster, clustered_service):
        """
        validates the service name is unique by counting the occurances
        of name in the services of the cluster
        :param cluster: cluster to be validated
        :type  cluster: class
        :param clustered_service: clustered service being checked
        :type  clustered_service: string
        """
        errors = []
        names = [service.name for service in
                 self.services_not_for_removal_from_cluster(cluster)]
        no_of_name = names.count(clustered_service.name)
        if not no_of_name == 1:
            err_msg = 'There are {0} clustered services using the same ' \
            '"name" property as "{1}", this should be unique'.format(
                                                                    no_of_name,
                                                    clustered_service.name)
            log.trace.error(err_msg)
            errors.append(
                ValidationError(item_path=clustered_service.get_vpath(),
                                error_message=err_msg))
        return errors

    def _validate_active_standby(self, clustered_service):
        """
        validates that number of active and standby nodes is correct
        :param clustered_service: service defined within the cluster
        :type  clustered_service: class
        """
        errors = []
        num_active = int(clustered_service.active)
        num_standby = int(clustered_service.standby)
        if num_standby == 1:
            if not num_active == 1:
                err_msg = "Must have only 1 active if 1 standby"
                log.trace.error(err_msg)
                errors.append(ValidationError(
                    item_path=clustered_service.get_vpath(),
                    error_message=err_msg))
        elif not num_standby == 0:
            err_msg = "Must have only 0 or 1 standby nodes"
            log.trace.error(err_msg)
            errors.append(ValidationError(
                item_path=clustered_service.get_vpath(),
                error_message=err_msg))
        return errors

    def _validate_number_of_nodes(self, clustered_service):
        """
        validates that the total number of nodes in the clustered service
        is the sum of the number of active and standby nodes
        :param clustered_service: service defined within the cluster
        :type  clustered_service: class
        """
        errors = []
        total_active_and_standby = (int(clustered_service.active) +
                                    int(clustered_service.standby))
        number_of_nodes = len(clustered_service.node_list.split(','))
        if number_of_nodes != total_active_and_standby:
            err_msg = "Number of nodes must match active plus standby"
            log.trace.error(err_msg)
            errors.append(ValidationError(
                item_path=clustered_service.get_vpath(),
                error_message=err_msg))
        return errors

    def _get_app_list(self, clustered_service, app_type):
        app_list = []
        for app in clustered_service.query(app_type):
            if app.is_for_removal():
                continue
            app_list.append(app)
        return app_list

    def _is_clustered_service_dependency_list_updated(self, service):
        """
        Returns True if the service is in an updated state and the property
        "dependency_list" has changed.
        """
        return (service.is_updated() and
                    property_updated(service, 'dependency_list') and not
                    same_list_different_order(service, 'dependency_list'))

    def _is_clustered_service_initial_dependency_list_updated(self, service):
        """
        Returns True if the service is in an updated state and the property
        "initial_online_dependency_list" has changed.
        """
        return (
            service.is_updated() and
            property_updated(service, 'initial_online_dependency_list') and not
            same_list_different_order(service, 'initial_online_dependency_list'
                                      ))

    def _get_dep_list_and_app_dep_list(self, service):
        dep_list = service.dependency_list
        app_dep_list = service.applied_properties.get(
            'dependency_list', '')
        dep_list = '' if dep_list is None else dep_list

        return dep_list.split(','), app_dep_list.split(',')

    def _clustered_service_dependency_list_additions(self, service):
        """
        Returns a list of the added service group ids from the service
        "dependency_list"
        """
        dep_list, app_dep_list = self._get_dep_list_and_app_dep_list(service)
        return [dep for dep in dep_list if dep and dep not in app_dep_list]

    def _clustered_service_dependency_list_removals(self, service):
        """
        Returns a list of the removed service group ids from the service
        "dependency_list"
        """
        dep_list, app_dep_list = self._get_dep_list_and_app_dep_list(service)
        return [dep for dep in app_dep_list if dep and dep not in dep_list]

    def _is_clustered_service_dependency_list_updated_add(self, service):
        added_deps = self._clustered_service_dependency_list_additions(service)
        return (self._is_clustered_service_dependency_list_updated(service)
                and bool(added_deps))

    def _is_clustered_service_dependency_list_updated_remove(self, service):
        removed_deps = self._clustered_service_dependency_list_removals(
            service)
        return (self._is_clustered_service_dependency_list_updated(service)
                and bool(removed_deps))

    def _validate_number_of_runtime(self, clustered_service):
        """
        validates that a vcs-cluster-service can only have
        one lsb_runtime, or one service in a parallel service group,
        or up to ten services in a failover service group
        :param clustered_service: service defined within the cluster
        :type  clustered_service: class
        """
        errors = []
        num_lsb_runtimes_allowed = 1
        num_services_allowed = 1
        if is_serv_grp_allowed_multi_apps(clustered_service):
            num_services_allowed = 10

        #Ensure not more than one lsb-runtime per cluster service
        lsb_list = self._get_app_list(clustered_service, "lsb-runtime")
        if len(lsb_list) > num_lsb_runtimes_allowed:
            err_msg = "Number of lsb-runtimes per vcs-clustered-service"\
            " must be 1"
            log.trace.error(err_msg)
            errors.append(ValidationError(
                item_path=clustered_service.get_vpath(),
                error_message=err_msg))

        # Ensure not more than one service per parallel cluster service
        # or 10 services in a failover cluster service
        service_list = self._get_app_list(clustered_service, "service")
        if len(service_list) > num_services_allowed:
            err_msg = ("Multiple services are only supported in a failover "
                       "or a one node parallel vcs-clustered-service.")
            if is_serv_grp_allowed_multi_apps(clustered_service):
                err_msg = ('Number of services in vcs-clustered-service '
                           '"{0}" exceeds maximum number of {1}'
                           .format(clustered_service.name,
                                   num_services_allowed))
            log.trace.error(err_msg)
            errors.append(ValidationError(
                item_path=clustered_service.get_vpath(),
                error_message=err_msg))

        #Ensure no mixing of service/runtime is allowed
        if lsb_list and service_list:
            err_msg = ('service and lsb-runtime items may not both be used '
                       'in the same vcs-clustered-service')
            errors.append(ValidationError(
                item_path=clustered_service.get_vpath(),
                error_message=err_msg))

        # Ensure clustered-service is not empty
        if (not lsb_list) and (not service_list):
            err_msg = 'No service or lsb-runtime items found'
            log.trace.error(err_msg)
            errors.append(ValidationError(
                item_path=clustered_service.get_vpath(),
                error_message=err_msg))
        return errors

    def _validate_dependencies_node_list(self, cluster, clustered_service):
        '''
        Method to validate that (if clustered_service is parallel) that each of
        the dependencies in dependency_list (if also parallel) are running on
        nodes that this clustered service intends to run on.
        Note: this is due to a service group dependency limitation in VCS
        '''
        errors = []
        if clustered_service.standby != "0":
            return []

        service_dependencies = clustered_service.dependency_list
        if service_dependencies:
            for dep in service_dependencies.split(","):
                services = [s for s in cluster.services if s.item_id == dep]
                if services:
                    service = services[0]  # item_id will be unique
                    if service.standby != "0":
                        continue

                    for node in clustered_service.node_list.split(','):
                        if node not in service.node_list.split(','):
                            err_msg = ('The node_list for dependency "{0}" '
                                'does not contain node "{1}" which is part of '
                                'the node_list for "{2}". This is required if '
                                'both the service and the dependency are in '
                                'parallel'.format(dep, node,
                                    clustered_service.item_id))
                            errors.append(ValidationError(
                                item_path=clustered_service.get_vpath(),
                                error_message=err_msg))

        return errors

    def _validate_dependency_not_one_node(self, cluster, clustered_service):
        '''
        Method to validate that there is no dependency on a one node
        vcs-clustered-service. Dependency on a one node vcs clustered service
        can cause issues when unlocking the node. The only exception is
        another one node vcs-clustered-service with the same node_list.
        '''
        errors = []

        service_dependencies = clustered_service.dependency_list
        if service_dependencies:
            for dep in service_dependencies.split(","):
                services = [s for s in
                            self.services_not_for_removal_from_cluster(cluster)
                            if s.item_id == dep]
                if services:
                    service = services[0]  # item_id will be unique

                    if service.active == "1" and service.standby == "0":
                        if (set(clustered_service.node_list) !=
                            set(service.node_list)):
                            err_msg = ('The dependency "{0}" is a one node '
                                       'vcs-clustered-service. Only a one node'
                                       ' vcs-clustered-service with the same '
                                       'node_list can depend on a one node '
                                       'vcs-clustered-service.'.format(dep))
                            errors.append(ValidationError(
                                item_path=clustered_service.get_vpath(),
                                error_message=err_msg))

        return errors

    def _validate_init_deps_no_depend_itself(self, cluster):
        """
        Validation to ensure no cluster service has initial online dependencies
        on itself, that all vcs-clustered-services in
        initial_online_dependency_list exist
        """
        errors = []

        all_services = []
        for service in cluster.services:
            all_services.append(service.item_id)
            if service.initial_online_dependency_list:
                if service.item_id in service.initial_online_dependency_list\
                        .split(','):
                    errors.append(ValidationError(
                        service.get_vpath(),
                        error_message='Service can not have an initial online'
                                      ' dependency on itself. Please ensure '
                                      '"initial_online_dependency_list" '
                                      'property is correct'))

        for service in cluster.services:
            if service.initial_online_dependency_list:
                for dep in service.initial_online_dependency_list.split(','):
                    if dep not in all_services:
                        errors.append(ValidationError(
                            service.get_vpath(),
                            error_message='The dependency "{0}" in '
                                          '"initial_online_dependency_list"'
                                          ' does not exist.'.format(dep)))

        return errors

    def _get_circular_deps_and_level_count(self, dependency_tree):
        """
        Method to return a list of any circular dependencies from the given
        dependency tree, and also the dependencies level count
        :param dependency_tree: (dictionary) the dependencies a sg has.
        :return:(tuple) The circular dependencies (list), the level count (int)
        """
        level_counter = 0

        all_sgs = []
        # If a service depends on itself, remove from tree, caught by others
        for sg, sg_deps in dependency_tree.items():
            all_sgs.append(sg)
            if sg in sg_deps:
                sg_deps.remove(sg)

        # If the dependency does not exist, remove from tree, caught by others
        for sg_deps in dependency_tree.values():
            non_exists = [sg_dep for sg_dep in sg_deps if
                          sg_dep not in all_sgs]
            for non_exist in non_exists:
                sg_deps.remove(non_exist)

        while dependency_tree:
            to_remove = [k for k, v in dependency_tree.iteritems() if not v]

            if not to_remove:
                return ([service_id for service_id in dependency_tree.keys()],
                        level_counter)

            # Prune leaf nodes by looking for nodes with no leaves
            for node, node_leaves in dependency_tree.items():
                if node in to_remove and not dependency_tree[node]:
                    del dependency_tree[node]
                else:
                    # Delete the relevent node_leaves from the node
                    dependency_tree[node] = set(node_leaves).difference(
                        to_remove)
            level_counter += 1

        return [], level_counter

    def _validate_dependency_list(self, cluster):
        '''
        Method to perform two validations on the dependency_list:
        1) Check for circular dependencies
        2) Check that the dependency list is not more than 5 levels deep
        Both validations are done in this method as the same tree pruning
        is the same for both validations
        '''
        MAXIMUM_DEPENDENCY_DEPTH = 5

        dependency_tree = VcsUtils().get_dependency_tree(cluster.services)

        circular_deps, level_counter = \
            self._get_circular_deps_and_level_count(dependency_tree)

        if circular_deps:
            err_msg = ('A circular dependency has been detected between the '
                       'following clustered-services: {0}. Check the '
                       '"dependency_list" property of each clustered-service '
                       'item to resolve the issue.'.format(format_list(
                       [dep for dep in circular_deps])))
            return [ValidationError(item_path=cluster.get_vpath(),
                                    error_message=err_msg)]

        if level_counter > MAXIMUM_DEPENDENCY_DEPTH:
            err_msg = ('The dependency tree depth for the vcs clustered '
                       'services for this cluster is "{0}". The maximum '
                       'dependency depth supported is "{1}".').format(
                level_counter, MAXIMUM_DEPENDENCY_DEPTH)
            return [ValidationError(item_path=cluster.get_vpath(),
                                    error_message=err_msg)]

        errors = []

        errors.extend(self._validate_update_dependency_list(cluster))

        return errors

    def _validate_initial_online_dependency_list(self, cluster):
        """
        Validation to ensure there is no circular dependencies within the
        initial_online_dependency_list for the cluster services
        """
        dependency_tree = VcsUtils().get_dependency_tree_initial_deps(
                                                            cluster.services)

        circular_deps, _ = self._get_circular_deps_and_level_count(
            dependency_tree)

        if circular_deps:
            err_msg = ('A circular dependency has been detected between the '
                       'following clustered-services: {0}. Check the '
                       '"initial_online_dependency_list" property of each '
                       'clustered-service item to resolve the issue.'.format(
                       format_list([dep for dep in circular_deps])))
            return [ValidationError(item_path=cluster.get_vpath(),
                                    error_message=err_msg)]

        return []

    def _validate_combined_dep_list_and_init_deps(self, cluster):
        """
        Method to perform validations that the combined dependency_list and
        initial_online_dependency_list do not contain a circular dependency
        """
        dependency_tree = VcsUtils().get_dependency_tree(
            cluster.services, include_initial_deps=True)

        circular_deps, _ = self._get_circular_deps_and_level_count(
            dependency_tree)

        if circular_deps:
            err_msg = ('A circular dependency has been detected between the '
                       'following vcs-clustered-services: {0}. Check the '
                       '"initial_online_dependency_list" and the '
                       '"dependency_list" properties of each clustered-service'
                       ' item to resolve the issue.'.format(
                       format_list([dep for dep in circular_deps])))
            return [ValidationError(item_path=cluster.get_vpath(),
                                    error_message=err_msg)]

        return []

    def _validate_dependency_not_in_both(self, cluster):
        """
        Method to perform validation that the same vcs-clustered-service
        cannot be referenced in both initial_online_dependency_list and the
        dependency_list properties.
        """

        errors = []

        for service in cluster.services:
            if service.dependency_list and \
               service.initial_online_dependency_list:
                for dep in service.initial_online_dependency_list.split(','):
                    if dep in service.dependency_list.split(','):
                        errors.append(ValidationError(service.get_vpath(),
                            error_message=(
                                'The dependency "{0}" is in both '
                                '"dependency_list" and '
                                '"initial_online_dependency_list". The same '
                                'vcs-clustered-service cannot be referenced in'
                                ' both the "initial_online_dependency_list" '
                                'and the "dependency_list" property.'.format(
                                dep))))

        return errors

    def _get_service_for_deactivation(self, cluster, new_service,
                                      check_is_deployed=True):
        """
        Return service to be deactivated by new_service, if it is a current
        deactivation, that is the service to be deactivated exists in the
        cluster. Also, the state of the service may be checked depending on
        the check_is_deployed parameter.
        Return None if no such service exists,
        """
        def is_deployed(service):
            return service.is_applied() or service.is_updated()

        old_service = None
        if new_service.deactivates:
            if check_is_deployed:
                old_service = next((service for service in cluster.services
                                if service.item_id == new_service.deactivates
                                and is_deployed(service)), None)
            else:
                old_service = next((service for service in cluster.services
                                if service.item_id == new_service.deactivates),
                              None)
        return old_service

    def _validate_update_dependency_list(self, cluster):
        """
        Validate that the dependency_list update contains no errors
        One check is done:
        - check that there is no dependency on an initial service group.
          Exception to this is that a dependency by an applied service on an
          initial service that is deactivating another service is allowed.
        """
        errors = []
        for service in self.services_not_for_removal_from_cluster(cluster):
            if self._is_clustered_service_dependency_list_updated(service):
                dep_list = service.dependency_list
                dep_list = '' if dep_list is None else dep_list

                for dep in dep_list.split(','):
                    dep_services = [s for s in cluster.services
                                    if s.item_id == dep]
                    if dep_services:
                        dep_service = dep_services[0]
                        if (dep_service.is_initial()
                            and not is_deactivating(cluster, dep_service)):
                            msg = ('An applied vcs-clustered-service cannot '
                                'be updated to depend on a '
                                'vcs-clustered-service "{0}" in Initial state'.
                                    format(dep_service.item_id))
                            errors.append(ValidationError(
                                item_path=service.vpath,
                                error_message=msg))
        return errors

    def _validate_deletion_dependency(self, cluster):
        '''
        Validates that no service which is not marked for removal has a
        dependant service which is being removed
        :param cluster: cluster to be validated
        :type  cluster: class
        '''
        def get_clustered_service_from_item_id(services, item_id):
            return next((service for service in services
                         if service.item_id == item_id), None)

        def get_removed_deps(cluster, dep_list):
            removed_deps = []
            for dep_id in dep_list:
                dep_cs = get_clustered_service_from_item_id(
                    cluster.services, dep_id)
                if dep_cs and dep_cs.is_for_removal():
                    removed_deps.append(dep_id)
            return removed_deps

        errors = []
        dependency_tree = VcsUtils().get_dependency_tree(cluster.services)

        # Prune leaf nodes by looking for nodes with no leaves
        for cs_id, dep_list in dependency_tree.items():
            clustered_service = get_clustered_service_from_item_id(
                cluster.services, cs_id)
            if not clustered_service.is_for_removal():
                removed_deps = get_removed_deps(cluster, dep_list)
                if removed_deps:
                    errors.append(ValidationError(
                            item_path=clustered_service.get_vpath(),
                            error_message=ERROR_DELETION_DEPENDENCY.format(
                                 text_join(removed_deps))))
        return errors

    def _validate_deletion_initial_dependency(self, cluster):
        """
        Validates that no service which is not marked for removal has an
        initial online dependant service which is being removed
        :param cluster: cluster to be validated
        :type  cluster: object
        """
        def get_clustered_service_from_item_id(services, item_id):
            return next((service for service in services
                         if service.item_id == item_id), None)

        def get_removed_deps(cluster, dep_list):
            removed_deps = []
            for dep_id in dep_list:
                dep_cs = get_clustered_service_from_item_id(
                    cluster.services, dep_id)
                if dep_cs and dep_cs.is_for_removal():
                    removed_deps.append(dep_id)
            return removed_deps

        errors = []
        dependency_tree = VcsUtils().get_dependency_tree_initial_deps(
            cluster.services)

        # Prune leaf nodes by looking for nodes with no leaves
        for cs_id, dep_list in dependency_tree.items():
            clustered_service = get_clustered_service_from_item_id(
                cluster.services, cs_id)
            if not clustered_service.is_for_removal():
                removed_deps = get_removed_deps(cluster, dep_list)
                if removed_deps:
                    errors.append(ValidationError(
                        item_path=clustered_service.get_vpath(),
                        error_message=ERROR_DELETION_INIT_DEPENDENCY.format(
                            text_join(removed_deps))))
        return errors

    def _validate_cluster_service_id_no_dash_underscore(self, cluster,
                                                        clustered_service):
        """
        validates the "item_id" property of a clustered service.
        can not exist two item with similar "item_id" property, using
        "-" instead of "_", because is part of the VCS_group_name
        :param cluster: cluster to be validated
        :type  cluster: class
        :param clustered_service: clustered service being checked
        :type  clustered_service: class
        """
        errors = []

        service_condensed_name = condense_name(clustered_service.item_id)
        repeated_services = [
                        s.vpath
                        for s in
                        self.services_not_for_removal_from_cluster(cluster)
                        if condense_name(s.item_id) == service_condensed_name
                        and clustered_service.item_id != s.item_id]

        if repeated_services:
            err_msg = ('The model item_id "{0}" is incompatible with the '
                       'model item_id in "{1}" because "-" and "_" are '
                       'interchangeable.'.format(clustered_service.item_id,
                       '", "'.join(repeated_services)))
            log.trace.error(err_msg)
            errors.append(
                ValidationError(item_path=clustered_service.get_vpath(),
                                error_message=err_msg))
        return errors

    def _validate_network_name_no_dash_underscore(self, clustered_service):
        """
        validates the "network_name" property of a ipaddress.
        can not exist two item with similar "name" property, using
        "-" instead of "_", because is part of the VCS_group_name
        :param cluster: cluster to be validated
        :type  cluster: class
        :param clustered_service: clustered service being checked
        :type  clustered_service: class
        """
        errors = []
        ipaddresses = self._get_ipaddresses(clustered_service)

        for ipaddress in ipaddresses:
            ipaddress_name = condense_name(ipaddress.network_name)
            repeated_names = [
                    (ip.network_name + ' (' + ip.vpath + ')')
                    for ip in ipaddresses
                    if condense_name(ip.network_name) == ipaddress_name
                    and ipaddress.network_name != ip.network_name]

            if repeated_names:
                err_msg = ('The "network_name" "{0}" is incompatible '
                           'with the "network_name" "{1}" because "-",'
                           ' "_" and "." are interchangeable in this '
                           'property.'.format(ipaddress.network_name,
                                        '", "'.join(repeated_names)))
                log.trace.error(err_msg)
                errors.append(
                    ValidationError(item_path=ipaddress.get_vpath(),
                            error_message=err_msg))
        return errors

    def _validate_fs_item_id_no_dash_underscore(self, clustered_service):
        """
        validates the "item_id" property of a filesystem.
        can not exist two item with similar "item_id" property, using
        "-" instead of "_", because is part of the VCS_group_name
        :param cluster: cluster to be validated
        :type  cluster: class
        :param clustered_service: clustered service being checked
        :type  clustered_service: class
        """
        errors = []
        filesystems = self._get_filesystems(clustered_service)
        for fs in filesystems:
            fs_name = condense_name(fs.item_id)
            repeated_item_ids = [f.vpath for f in filesystems
                                 if condense_name(f.item_id) == fs_name
                                 and f.item_id != fs.item_id]

            if repeated_item_ids:
                err_msg = ('The model item_id "{0}" is incompatible with '
                           'the model item_id in "{1}" because "-" and'
                           ' "_" are interchangeable.'.format(fs.item_id,
                           '", "'.join(repeated_item_ids)))
                log.trace.error(err_msg)
                errors.append(
                    ValidationError(item_path=fs.get_vpath(),
                            error_message=err_msg))
        return errors

    def _get_ipaddresses(self, service):
        ipaddresses = []
        for runtime in service.query('lsb-runtime'):
            for ipaddress in runtime.ipaddresses:
                ipaddresses.append(ipaddress)
        for ipaddress in service.ipaddresses:
            ipaddresses.append(ipaddress)
        return ipaddresses

    def _get_filesystems(self, service):
        filesystems = []
        for runtime in service.query('lsb-runtime'):
            for filesystem in runtime.filesystems:
                filesystems.append(filesystem)
        for filesystem in service.filesystems:
            filesystems.append(filesystem)
        return filesystems

    def _validate_clustered_service(self, cluster, clustered_service):
        """
        performs validation on the clustered service
        :param cluster: cluster defined within the model
        :type  cluster: class
        :param clustered_service: service defined within the cluster
        :type  clustered_service: class
        """
        errors = []

        if clustered_service.is_for_removal():
            errors.extend(self._validate_update_deactivates_before_completed(
                                                   cluster, clustered_service))
            return errors

        errors.extend(self._validate_active_standby(clustered_service))
        errors.extend(self._validate_number_of_nodes(clustered_service))
        errors.extend(self._validate_unique_service_name(cluster,
                                                         clustered_service))
        errors.extend(self._validate_nodes_in_cluster(cluster,
                                                      clustered_service))
        errors.extend(self._validate_number_of_runtime(clustered_service))
        one_node_errors = self._validate_dependency_not_one_node(cluster,
                                                            clustered_service)
        errors.extend(one_node_errors)
        errors.extend(self._validate_cluster_service_id_no_dash_underscore(
            cluster, clustered_service))
        errors.extend(self._validate_fs_item_id_no_dash_underscore(
            clustered_service))
        errors.extend(self._validate_network_name_no_dash_underscore(
            clustered_service))
        # If the one node validation is triggered, don't test for dependencies
        # node_list as there will be two similar validation error messages
        if not one_node_errors:
            errors.extend(self._validate_dependencies_node_list(cluster,
                                                            clustered_service))
        errors.extend(self._validate_can_have_update(clustered_service))
        errors.extend(self._validate_against_contraction_with_vips(
                                                            clustered_service))
        errors.extend(self._validate_critical_service_cant_migrate(cluster,
                                                            clustered_service))
        errors.extend(self._validate_deactivates(cluster, clustered_service))

        return errors

    def _validate_deactivates(self, cluster, service):
        errors = []

        errors.extend(self._validate_deactivated_set(service))
        if not service.deactivates:
            return errors

        errors.extend(self._validate_deactivates_self(service))
        errors.extend(self._validate_deactivates_critical_service(cluster,
                                                                  service))
        errors.extend(self._validate_deactivation_node_overlap(cluster,
                                                               service))
        errors.extend(self._validate_deactivation_dependency(cluster, service))
        errors.extend(self._validate_deactivating_srv_not_initial(service))
        errors.extend(self._validate_deactivates_applied_srv(cluster, service))
        return errors

    def _validate_deactivates_self(self, service):
        """
        Validate that a clustered service is not set to deactivate itself.
        """
        errors = []
        if service.deactivates == service.item_id:
            errors.append(ValidationError(item_path=service.get_vpath(),
                                          error_message=ERR_DEACTIVATES_SELF))
        return errors

    def _validate_deactivates_critical_service(self, cluster, service):
        """
        Validate that a clustered service is not set to deactivate the critical
        service in the cluster.
        This method assumes there is only one critical service in a cluster
        """
        errors = []
        if service.deactivates == cluster.critical_service:
            errors.append(ValidationError(item_path=cluster.get_vpath(),
                            error_message=ERR_DEACTIVATES_CRITICAL_SERVICE))
        return errors

    def _validate_deactivation_node_overlap(self, cluster, service):
        """
        Validate that there is no overlap in the node list of the service for
        deactivation and the deactivating service.
        """
        errors = []
        service_for_deact = self._get_service_for_deactivation(cluster,
                                                               service)
        if service_for_deact:
            new_nodes = service.node_list.split(',')
            old_nodes = service_for_deact.node_list.split(',')
            common_nodes = set(new_nodes) & set(old_nodes)
            if common_nodes:
                err_msg = ERR_DEACTIVATES_NODE_OVERLAP.format(service.item_id,
                                service.deactivates, ', '.join(common_nodes))
                errors.append(ValidationError(item_path=service.get_vpath(),
                                              error_message=err_msg))
        return errors

    def _validate_deactivation_dependency(self, cluster, clustered_service):
        """
        Validate that there are no dependencies existing on a clustered service
        to be deactivated.
        """
        errors = []
        service_for_deact = self._get_service_for_deactivation(cluster,
                                                             clustered_service)
        if service_for_deact:
            for dep_service in (service for service in cluster.services
                                if service.dependency_list
                                and service_for_deact.item_id in
                                    service.dependency_list.split(',')):
                err_msg = ERR_DEACTIVATES_DEPENDENCY.format(
                          service_for_deact.item_id, clustered_service.item_id)
                errors.append(ValidationError(
                                        item_path=dep_service.get_vpath(),
                                        error_message=err_msg))

            for dep_service in (service for service in cluster.services
                                if service.initial_online_dependency_list
                                and service_for_deact.item_id in
                            service.initial_online_dependency_list.split(',')):
                err_msg = ERR_DEACTIVATES_INIT_ONLINE_DEPENDENCY.format(
                          service_for_deact.item_id, clustered_service.item_id)
                errors.append(ValidationError(
                                        item_path=dep_service.get_vpath(),
                                        error_message=err_msg))
        return errors

    def _validate_deactivating_srv_not_initial(self, service):
        """
        Validate that an applied service activates property cannot be
        updated.
        """
        errors = []
        if (not service.is_initial() and
            property_updated(service, 'deactivates')):
            errors.append(ValidationError(item_path=service.get_vpath(),
                                error_message=ERR_DEACTIVATES_NOT_INITIAL))
        return errors

    def _validate_deactivates_applied_srv(self, cluster, service):
        """
        Validate that the service to be deactivated is in applied state. This
        check only applies to the service itself, not to it's descendant items.
        """
        errors = []

        service_for_deact = self._get_service_for_deactivation(cluster,
                                              service, check_is_deployed=False)

        # Return no error if service for deact does not exist or if it has
        # already been deactivated and is in state ForRemoval.
        if (not service_for_deact
                or service_for_deact.applied_properties.get('deactivated')
                                                                    == 'true'):
            return errors

        if not service_for_deact.is_applied():
            errors.append(ValidationError(item_path=service.get_vpath(),
                            error_message=ERR_DEACTIVATES_NOT_APPLIED_SERVICE))
        return errors

    def _validate_update_deactivates_before_completed(self, cluster, service):
        """
        Validates that a vcs-clustered-service deactivates property has not
        been updated before the deactivation is completed.
        If there is a service with deactivated set in applied properties then
        there should be a deactivating service that is either in Applied state
        or in Initial with apd false. This is true because the deactivation
        task is done with the tasks for deactivating service.
        """
        errors = []
        if service.applied_properties.get('deactivated') == 'true':
            deactivating_serv = next((serv for serv in cluster.services
                             if serv.deactivates == service.item_id
                             and (serv.is_applied() or
                                  (serv.is_initial() and
                                   not serv.applied_properties_determinable))),
                                None)
            if not deactivating_serv:
                errors.append(ValidationError(item_path=service.get_vpath(),
                              error_message=ERR_DEACTIVATES_UPDATE_INCOMPLETE))
        return errors

    def _validate_deactivated_set(self, service):
        """
        Validates that a vcs-clustered-service deactivated flag has not been
        set by CLI.
        """
        errors = []
        if (service.deactivated == 'true' and
            service.applied_properties.get('deactivated') != 'true'):
            errors.append(ValidationError(item_path=service.get_vpath(),
                                error_message=ERR_DEACTIVATED_INCORRECTLY_SET))
        return errors

    def _validate_against_contraction_with_vips(self, clustered_service):
        """
        Validates that a vcs-clustered-service with vips is not being
        contracted, as this is not currently supported.
        :type  clustered_service: class
        """
        errors = []
        if clustered_service.is_updated():
            if (is_clustered_service_contraction(clustered_service) and
                    len(clustered_service.ipaddresses) > 0):
                errors.append(ValidationError(
                    item_path=clustered_service.get_vpath(),
                    error_message=ERR_NO_SG_CONTRACTION_WITH_VIPS))
        return errors

    def _validate_can_have_update(self, clustered_service):
        """
        performs validation against there is no lsb-runtimes on the cluster
        :param clustered_service: clustered service defined within the model
        :type  clustered_service: class
        """
        errors = []
        err_msg = ("Can not update a vcs-clustered-service that contains "
                   "lsb-runtimes")
        if (clustered_service.is_updated() and
            self._get_app_list(clustered_service, "lsb-runtime")):
            errors.append(ValidationError(
                item_path=clustered_service.get_vpath(),
                error_message=err_msg))

        return errors

    def _validate_one_deactivation(self, cluster):
        """
        Validate that there is only one service deactivion in the cluster.
        """
        errors = []
        deactivations = [service for service in cluster.services
                         if service.deactivates]
        cs_ids = [cs.item_id for cs in cluster.services
                  if not cs.is_for_removal()]
        deact_of_svc_in_model = [s for s in deactivations
                                 if s.deactivates in cs_ids]
        if len(deact_of_svc_in_model) > 1:
            err_msg = ERR_MULTIPLE_DEACTIVATIONS
            for service in deact_of_svc_in_model:
                errors.append(ValidationError(item_path=service.get_vpath(),
                                              error_message=err_msg))
        return errors

    def _validate_cluster(self, cluster):
        """
        performs validation on the cluster
        :param cluster: cluster defined within the model
        :type  cluster: class
        """
        errors = []
        errors.extend(self._validate_dependency_list(cluster))
        errors.extend(self._validate_deletion_dependency(cluster))
        errors.extend(self._validate_init_deps_no_depend_itself(cluster))
        errors.extend(self._validate_deletion_initial_dependency(cluster))
        errors.extend(self._validate_initial_online_dependency_list(cluster))
        errors.extend(self._validate_dependency_not_in_both(cluster))
        errors.extend(self._validate_one_deactivation(cluster))

        if not errors:
            # Only return combined error if no individual to avoid duplicates
            errors.extend(self._validate_combined_dep_list_and_init_deps(
                cluster))

        for clustered_service in cluster.services:
            errors.extend(self._validate_clustered_service(cluster,
                clustered_service))

        return errors

    def validate_model(self, plugin_api_context):
        """
        performs validation on the model
        :param plugin_api_context: access to the model manager
        :type  plugin_api_context: class
        """
        errors = []
        clusters = plugin_api_context.query("vcs-cluster")
        errs_list = [self._validate_cluster(cluster)
                     for cluster in clusters
                     ]
        for errs in errs_list:
            errors.extend(errs)
        return errors

    def _validate_critical_service_cant_migrate(self, cluster,
                                                clustered_service):
        """
        Validates that a critical service cannot migrate from existing nodes
        to a complete set of new nodes.
        :param cluster: cluster defined within the model
        :type  cluster: class
        :param clustered_service: service defined within the cluster
        :type  clustered_service: class
        """
        errors = []
        err_msg = ("Migration of a critical service {0} is not supported"
                                    .format(clustered_service.item_id))
        if clustered_service.item_id == cluster.critical_service:
            if is_node_list_changed(clustered_service):
                errors.append(ValidationError(
                                item_path=clustered_service.vpath,
                                error_message=err_msg))

        return errors

    def _generate_remove_incomplete_service_task(self, service,
                                                 cluster):
        """
        creates a CallbackTask for the given service
        :param service: clustered service
        :type  service: class
        :param model: Dictionary containing mode;
        :type  model: dict
        """
        service_name = self.get_group_name(service.item_id, cluster.item_id)
        task = CallbackTask(service,
                            'Remove VCS service'
                            ' group "{0}"'.format(
                                service_name
                            ),
                            self.plugin().callback_method,
                            callback_class=self.__class__.__name__,
                            callback_func="remove_incomplete_service_callback",
                            service_vpath=service.get_vpath(),
                            cluster_vpath=cluster.get_vpath())
        return task

    def _generate_install_task(self, service, cluster_item_id, cluster_vpath):
        """
        creates a CallbackTask for the given service
        :param service: clustered service
        :type  service: class
        :param model: Dictionary containing mode;
        :type  model: dict
        """
        service_name = self.get_group_name(service.item_id, cluster_item_id)
        state_name = 'Create' if service.is_initial() else 'Restore'
        task = CallbackTask(service,
                            '{0} VCS service group "{1}"'.format(
                                state_name,
                                service_name
                            ),
                            self.plugin().callback_method,
                            callback_class=self.__class__.__name__,
                            callback_func="install_callback",
                            service_vpath=service.get_vpath(),
                            cluster_item_id=cluster_item_id,
                            cluster_vpath=cluster_vpath)

        task = VcsUtils().attach_child_items_to_task(task, service)
        return task

    def _generate_update_task(self, service, cluster_item_id):
        """
        Creates a callback task to add nodes to the given service
        :param service: clustered service
        :type  service: class
        :param cluster_item_id: Item id of cluster containing the service
        :type  cluster_item_id: string
        """
        vcs_group_name = self.get_group_name(service.item_id, cluster_item_id)
        added_nodes = format_list(
                                self.added_node_hostnames(service))

        task = CallbackTask(service,
                            'Update VCS service group "{0}" to add node(s) {1}'
                                .format(vcs_group_name, added_nodes),
                            self.plugin().callback_method,
                            callback_class=self.__class__.__name__,
                            callback_func="update_callback",
                            service_vpath=service.get_vpath(),
                            cluster_item_id=cluster_item_id)
        return task

    def _generate_contraction_task(self, service, cluster_item_id):
        """
        Creates a callback task to remove nodes from the given service
        :param service: clustered service
        :type  service: class
        :param cluster_item_id: Item id of cluster containing the service
        :type  cluster_item_id: string
        """
        vcs_group_name = self.get_group_name(service.item_id, cluster_item_id)
        removed_nodes = format_list(
                            self.removed_node_hostnames(service))

        task = CallbackTask(service,
                            'Update VCS service group "{0}" to remove node(s) '
                            '{1}'.format(vcs_group_name, removed_nodes),
                            self.plugin().callback_method,
                            callback_class=self.__class__.__name__,
                            callback_func="contraction_callback",
                            service_vpath=service.get_vpath(),
                            cluster_item_id=cluster_item_id,
                            tag_name=deployment_plan_tags.PRE_NODE_CLUSTER_TAG)
        return task

    def _generate_update_dependencies_task(self, service, cluster_item_id):
        """
        creates a CallbackTask for the given service to updated SG requires
        :param service: clustered service
        :type  service: class
        :param cluster_item_id: Item id of cluster containing the service
        :type  cluster_item_id: string
        """
        service_group_name = self.get_group_name(service.item_id,
                                                 cluster_item_id)
        task = CallbackTask(service,
                            ('Update VCS service group "{0}" to add '
                             'dependencies'.format(service_group_name)),
                            self.plugin().callback_method,
                            callback_class=self.__class__.__name__,
                            callback_func="update_dependencies_callback",
                            service_vpath=service.get_vpath(),
                            cluster_item_id=cluster_item_id,
                            service_group_name=service_group_name)
        return task

    def _generate_update_remove_dependencies_task(self, service,
                                                   cluster_item_id):
        """
        creates a CallbackTask for the given service to updated SG requires
        :param service: clustered service
        :type  service: class
        :param cluster_item_id: Item id of cluster containing the service
        :type  cluster_item_id: string
        """
        service_group_name = self.get_group_name(service.item_id,
                                                 cluster_item_id)

        tag_name = deployment_plan_tags.PRE_NODE_CLUSTER_TAG
        task = CallbackTask(service,
                        ('Update VCS service group "{0}" to remove '
                         'dependencies'.format(service_group_name)),
                        self.plugin().callback_method,
                        callback_class=self.__class__.__name__,
                        callback_func="update_remove_dependencies_callback",
                        service_vpath=service.get_vpath(),
                        cluster_item_id=cluster_item_id,
                        service_group_name=service_group_name,
                        tag_name=tag_name)
        return task

    def update_init_deps_callback(self, callback_api):
        """
        This is a dummy task in order ensure that the given item is marked as
        applied. Updating the initial dependencies will have no effect on an
        applied vcs-cluster-service
        """
        pass

    def _generate_update_init_deps_task(self, service, cluster_item_id):
        """
        creates a CallbackTask for the given service to updated SG requires
        :param service: clustered service
        :type  service: object
        """
        service_group_name = self.get_group_name(service.item_id,
                                                 cluster_item_id)
        task = CallbackTask(service,
                            ('Update initial dependencies on VCS service group'
                             ' "{0}"'.format(service_group_name)),
                            self.plugin().callback_method,
                            callback_class=self.__class__.__name__,
                            callback_func="update_init_deps_callback")
        return task

    def _generate_remove_task(self, service, cluster):
        """
        creates a delete CallbackTask for a given service
        :param service: clustered service being deleted
        :type  service: class
        :param cluster_item_id: Item id of the cluster, used for service name
        :type  cluster_item_id: string
        """
        service_name = self.get_group_name(service.item_id, cluster.item_id)

        task = CallbackTask(service,
                            'Remove VCS service group "{0}"'.format(
                                 service_name),
                            self.plugin().callback_method,
                            callback_class=self.__class__.__name__,
                            callback_func="delete_callback",
                            service_vpath=service.get_vpath(),
                            cluster_vpath=cluster.get_vpath(),
                            tag_name=deployment_plan_tags.PRE_NODE_CLUSTER_TAG)

        return task

    def _generate_deactivate_task(self, service, cluster):
        """
        creates a delete CallbackTask for a given service
        :param service: clustered service being deleted
        :type  service: class
        :param cluster_item_id: Item id of the cluster, used for service name
        :type  cluster_item_id: string
        """
        service_name = self.get_group_name(service.item_id, cluster.item_id)

        task = CallbackTask(service,
                            'Deactivate VCS service group "{0}"'.format(
                                service_name),
                            self.plugin().callback_method,
                            callback_class=self.__class__.__name__,
                            callback_func="delete_callback",
                            service_vpath=service.get_vpath(),
                            cluster_vpath=cluster.get_vpath(),
                            tag_name=deployment_plan_tags.CLUSTER_TAG)

        if (cluster.is_updated() and
                property_updated(cluster, 'critical_service') and
                cluster.applied_properties.get('critical_service') ==
                service.item_id):
            task.model_items.add(cluster)

        return task

    def _generate_remove_standby_node_task(self, service, cluster):
        """
        creates a delete CallbackTask for a given service
        :param service: clustered service being updated
        :type  service: class
        :param cluster_item_id: Item id of the cluster
        :type  cluster_item_id: string
        """
        service_name = self.get_group_name(service.item_id, cluster.item_id)
        applied_node_list = set(get_applied_node_list(service))
        node_list = set(service.node_list.split(','))
        removed_id = applied_node_list.difference(node_list)
        removed = [node for node in cluster.nodes
                   if node.item_id in removed_id][0]
        description = ('Remove standby node "{0}" from clustered '
                       'service "{1}"'.format(removed.hostname,
                                              service_name))
        callback = "_remove_standby_node"
        task = CallbackTask(service,
                            description,
                            self.plugin().callback_method,
                            callback_class=self.__class__.__name__,
                            callback_func=callback,
                            service_vpath=service.get_vpath(),
                            cluster_vpath=cluster.get_vpath())
        return task

    def _generate_add_new_standby_node(self, service, cluster):
        """
        creates a delete CallbackTask for a given service
        :param service: clustered service being updated
        :type  service: class
        :param cluster_item_id: Item id of the cluster
        :type  cluster_item_id: string
        """
        service_name = self.get_group_name(service.item_id, cluster.item_id)

        callback = "_add_standby_node_cb"
        nodes = set(service.node_list.split(','))
        new_node_item_id = list(nodes.difference(
                set(get_applied_node_list(service))))[0]
        new_node = [n for n in cluster.nodes
                    if n.item_id == new_node_item_id][0]
        task = CallbackTask(service,
                            'Add new standby node "{0}" to service '
                            'group "{1}"'.format(new_node.hostname,
                                                 service_name),
                            self.plugin().callback_method,
                            callback_class=self.__class__.__name__,
                            callback_func=callback,
                            service_vpath=service.get_vpath(),
                            cluster_vpath=cluster.get_vpath())
        return task

    def create_configuration(self, plugin_api_context, cluster, service):
        # pylint: disable=unused-argument
        pre_node_tasks = []
        post_node_tasks = []
        if service.is_for_removal() or \
           is_being_deactivated(cluster, service):
            return pre_node_tasks, post_node_tasks

        if is_failover_standby_node_updated(cluster, service):
            task = self._generate_add_new_standby_node(service, cluster)
            post_node_tasks.append(task)

        if (is_clustered_service_redeploy_required(service) and
            not is_failover_standby_node_updated(cluster, service)):
            task = []
            task = self._generate_remove_incomplete_service_task(service,
                                                        cluster)
            if does_service_need_to_be_migrated(service):
                task.tag_name = deployment_plan_tags.PRE_NODE_CLUSTER_TAG
                pre_node_tasks.append(task)
            else:
                post_node_tasks.append(task)

        if (service.is_initial() or
           is_clustered_service_redeploy_required(service)
           or not service.applied_properties_determinable):
            post_node_tasks.append(
                self._generate_install_task(service, cluster.item_id,
                                            cluster.get_vpath()))

        # Service group expansion
        elif is_clustered_service_expansion(service):
            post_node_tasks.append(
                self._generate_update_task(service, cluster.item_id))

        if self._is_clustered_service_dependency_list_updated_add(service):
            post_node_tasks.append(self._generate_update_dependencies_task(
                service, cluster.item_id))

        if self._is_clustered_service_initial_dependency_list_updated(service):
            post_node_tasks.append(self._generate_update_init_deps_task(
                service, cluster.item_id))

        if service.deactivates:
            service_for_deactivation = self._get_service_for_deactivation(
                                                             cluster, service)
            if (service_for_deactivation and
                    not service_for_deactivation.deactivated == 'true'):
                post_node_tasks.append(self._generate_deactivate_task(
                                    service_for_deactivation, cluster))

        return pre_node_tasks, post_node_tasks

    def delete_configuration(self, plugin_api_context, cluster, service):
        # pylint: disable=unused-argument
        tasks = []

        if is_failover_standby_node_updated(cluster, service):
            task = self._generate_remove_standby_node_task(service,
                                                           cluster)
            task.tag_name = deployment_plan_tags.PRE_NODE_CLUSTER_TAG
            tasks.append(task)

        if is_clustered_service_redeploy_required(service):
            return tasks

        if self._is_clustered_service_dependency_list_updated_remove(service):
            tasks.append(
                self._generate_update_remove_dependencies_task(service,
                                                              cluster.item_id))

        if not cluster.is_for_removal():
            if service.is_for_removal() and not service.deactivated == 'true':
                tasks.append(self._generate_remove_task(service, cluster))
            # Service group contraction
            # This code lives here as we need the contraction
            # tasks generated before the node lock.
            elif is_clustered_service_contraction(service):
                tasks.append(
                    self._generate_contraction_task(service,
                                                    cluster.item_id))

        return tasks

    def _get_sg_from_item_id(self, callback_api, service, dep):
        dep_service_vpath = service.get_vpath().rsplit('/', 1)[0] + '/' + dep
        return self.query_by_vpath(callback_api, dep_service_vpath)

    def _get_ordered_hostnames(self, service, applied=False):
        if applied:
            nodes_item_ids = service.applied_properties['node_list'].split(',')
        else:
            nodes_item_ids = service.node_list.split(',')
        # this will hold a list of nodes hostnames, in order that is specified
        #  in service.node_list
        ordered_hostnames = []

        for item_id in nodes_item_ids:
            for node in service.nodes:
                if node.item_id == item_id:
                    ordered_hostnames.append(node.hostname)
        return ordered_hostnames

    def _clustered_service_set_depends(self, callback_api, service,
                                       cluster_vpath):

        cluster = self.query_by_vpath(callback_api, cluster_vpath)
        grp_name = self.get_group_name(service.item_id, cluster.item_id)
        for srv in cluster.services:
            if srv.dependency_list is None or srv == service or \
                    srv.is_initial() or \
                    srv.is_for_removal() or \
                    is_being_deactivated(cluster, srv) or \
                    is_clustered_service_redeploy_required(srv):
                continue

            if service.item_id in srv.dependency_list.split(","):
                srv_name = self.get_group_name(srv.item_id, cluster.item_id)
                if srv.standby == "0" and service.standby == "0":
                    # If both services are in Parallel, use "local"
                    self.vcs_api.hagrp_link(srv_name, grp_name, "online",
                                            "local", "soft")
                else:
                    self.vcs_api.hagrp_link(srv_name, grp_name, "online",
                                            "global", "soft")

    def _get_service_dependencies(self, service):
        """
        Return the service group dependencies that the need to be created
        """
        if service.is_updated() and service.dependency_list:
            applied_deps = service.applied_properties.get('dependency_list')
            if applied_deps is None:
                return service.dependency_list

            if applied_deps != service.dependency_list:
                new_dependencies = [dep for dep in service.dependency_list.
                    split(",") if dep not in applied_deps.split(",")]
                return ','.join(new_dependencies)

        return service.dependency_list

    def _clustered_service_set_dependencies(self, callback_api, service,
                                            service_name, cluster_item_id):
        """
        Create the required dependencies using the VCS hagrp link command
        """
        service_dependencies = self._get_service_dependencies(service)
        if service_dependencies:
            for dep in service_dependencies.split(","):
                grp_name = self.get_group_name(dep, cluster_item_id)
                dep_service = self._get_sg_from_item_id(callback_api, service,
                                                        dep)

                if service.standby == "0" and dep_service.standby == "0":
                    # If both services are in Parallel, use "local"
                    log.trace.info("Ensuring service group {0} locally "
                        "depends on service group {1}".format(service_name,
                                                              grp_name))
                    self.vcs_api.hagrp_link(service_name, grp_name,
                                            "online", "local", "soft")
                else:
                    log.trace.info("Ensuring service group {0} globally "
                        "depends on service group {1}".format(service_name,
                                                              grp_name))
                    self.vcs_api.hagrp_link(service_name, grp_name,
                                            "online", "global", "soft")

    def _clustered_service_remove_dependencies(self, service, service_name,
                                               cluster_item_id):
        removed_deps = self._clustered_service_dependency_list_removals(
            service)
        for dep in removed_deps:
            grp_name = self.get_group_name(dep, cluster_item_id)

            log.trace.info("Ensuring service group {0} does not depend on "
                           "service group {1}".format(service_name, grp_name))
            self.vcs_api.hagrp_unlink(service_name, grp_name)

    def remove_incomplete_service_callback(self, callback_api,
                                           service_vpath, cluster_vpath):
        """
        """
        service = self.query_by_vpath(callback_api, service_vpath)
        cluster = self.query_by_vpath(callback_api, cluster_vpath)
        service_name = self.get_group_name(service.item_id, cluster.item_id)
        # Needed for parent class.
        if service.is_initial() or is_os_reinstall_on_peer_nodes(cluster):
            self.nodes = select_nodes_from_service(service)
        else:
            applied_nodes = get_applied_nodes_in_cluster(cluster)
            self.nodes = [node.hostname for node in applied_nodes]

        self._remove_if_service_group_exist_in_cluster(callback_api,
                                                       service_name,
                                                       service)

    def install_callback(self, callback_api, service_vpath, cluster_item_id,
                         cluster_vpath):
        '''
        Callback function for the tasks
        :param callback_api: access to security and execution manager
        :type  callback_api: class
        :param kwargs: arguments
        :type  kwargs: dict
        '''
        service = self.query_by_vpath(callback_api, service_vpath)
        # Needed for parent class.
        self.nodes = select_nodes_from_service(service)

        ordered_hostnames = self._get_ordered_hostnames(service)
        ordered_hnames_tuple = tuple(enumerate(ordered_hostnames))

        cluster = service.get_cluster()
        service_name = self.get_group_name(service.item_id, cluster_item_id)
        if ((not service.applied_properties_determinable and
                service.is_initial() and
                not is_os_reinstall_on_peer_nodes(cluster)) or
            (is_failover_to_parallel(service) and
             not is_node_list_changed(service) and
             is_os_reinstall_on_peer_nodes(cluster))):
            self._remove_if_service_group_exist_in_cluster(callback_api,
                                                           service_name,
                                                           service)

        log.event.info("VCS Install service {0}".format(service.get_vpath()))

        parallel = True if service.standby == "0" else False
        with self.vcs_api.readable_conf():
            self.vcs_api._clustered_service_set_attributes(
                service_name, ordered_hnames_tuple, parallel)
            self.vcs_api.hagrp_add_in_auto_start_list(service_name,
                                      " ".join(ordered_hostnames))
            self._clustered_service_set_dependencies(
                callback_api, service, service_name, cluster_item_id)
            if is_clustered_service_redeploy_required(service):
                self._clustered_service_set_depends(callback_api,
                                                    service,
                                                    cluster_vpath)

    def update_callback(self, callback_api, service_vpath, cluster_item_id):
        '''
        Callback function for the tasks
        :param callback_api: access to security and execution manager
        :type  callback_api: class
        :param service_vpath: location in model of service
        :type  service_vpath: string
        :param cluster_item_id: item_id of cluster
        :type  cluster_item_id: string
        '''
        service = self.query_by_vpath(callback_api, service_vpath)
        # Needed for using the VCS cmd api, see `VcsBaseHelper`.
        self.nodes = select_nodes_from_service(service)
        added_hostnames = self.added_node_hostnames(service)

        added_hn_prio_tuples = tuple(enumerate(added_hostnames))

        service_name = self.get_group_name(service.item_id, cluster_item_id)

        log.event.info("VCS update service {0} to add node(s) {1}".format(
                     service.get_vpath(), format_list(added_hostnames)))

        parallel = service.standby == "0"
        with self.vcs_api.readable_conf():
            self.vcs_api._clustered_service_set_syslist(service_name,
                                                        added_hn_prio_tuples,
                                                        parallel)
            self.vcs_api.hagrp_add_in_auto_start_list(
                service_name, " ".join(added_hostnames))

    def contraction_callback(self, callback_api, service_vpath,
                                                              cluster_item_id):
        '''
        Callback function for the task to reduce service group node_list
        :param callback_api: access to security and execution manager
        :type  callback_api: class
        :param service_vpath: vpath of the vcs-clustered-service
        :type  service_vpath: string
        :param cluster_item_id: item_id of cluster
        :type  cluster_item_id: string
        '''
        service = self.query_by_vpath(callback_api, service_vpath)
        # Needed for using the VCS cmd api, see `VcsBaseHelper`.
        self.nodes = select_nodes_from_service(service)

        removed_hostnames = self.removed_node_hostnames(service)

        vcs_group_name = self.get_group_name(service.item_id, cluster_item_id)

        log.event.info("VCS update service {0} to remove node(s) {1}".format
                     (service.get_vpath(), format_list(removed_hostnames)))

        with self.vcs_api.readable_conf():
            for node in removed_hostnames:
                self.vcs_api.hagrp_offline(vcs_group_name, node, forced=True)
                self.vcs_api.check_hagrp_isoffline(callback_api,
                                                   vcs_group_name,
                     int(getattr(service, "offline_timeout",
                                 OFFLINE_TIMEOUT)) * 2,
                     node, expect_faulted=True)
            self.vcs_api.hagrp_delete_in_system_list(
                vcs_group_name, " ".join(removed_hostnames))

    def delete_callback(self, callback_api, service_vpath, cluster_vpath):
        '''
        Callback function for the delete task
        :param callback_api: access to security and execution manager
        :type  callback_api: class
        :param service_vpath: vpath in the model for the service to be deleted
        :type  service_vpath: string
        :param cluster_vpath: vpath in the model for the cluster
        :type  cluster_vpath: string
        '''
        service = self.query_by_vpath(callback_api, service_vpath)
        cluster = self.query_by_vpath(callback_api, cluster_vpath)
        # Needed for parent class.
        self.nodes = select_nodes_from_cluster(cluster)

        service_name = self.get_group_name(service.item_id, cluster.item_id)

        log.event.info("VCS Delete service {0}".format(service.get_vpath()))

        with self.vcs_api.readable_conf():
            self.vcs_api.hagrp_offline(service_name)
            self.vcs_api.check_hagrp_isoffline(
                callback_api,
                service_name,
                int(getattr(service, "offline_timeout", OFFLINE_TIMEOUT)) * 3,
                expect_faulted=True)
            self.vcs_api.hagrp_unlink_all(service_name)
            self.vcs_api.hagrp_remove(service_name)

        if not service.is_for_removal():
            service.deactivated = 'true'

    def update_dependencies_callback(self, callback_api, service_vpath,
                                     cluster_item_id, service_group_name):
        """
        Callback function to update the dependencies of given Service Group
        from the dependency_list property
        :param callback_api: access to execution manager
        :type  callback_api: class
        :param service_vpath: location in model of service
        :type  service_vpath: string
        :param cluster_item_id: item_id of cluster
        :type  cluster_item_id: string
        :param service_group_name: VCS service group name
        :type  service_group_name: string
        """
        service = self.query_by_vpath(callback_api, service_vpath)
        # Needed for using the VCS cmd api, see `VcsBaseHelper`.
        self.nodes = select_nodes_from_service(service)

        log.event.info('Updating VCS service group dependencies on service'
            ' "{0}"'.format(service_group_name))

        with self.vcs_api.readable_conf():
            self._clustered_service_set_dependencies(callback_api,
                                                     service,
                                                     service_group_name,
                                                     cluster_item_id)

    def update_remove_dependencies_callback(self, callback_api, service_vpath,
                                         cluster_item_id, service_group_name):
        """
        Callback function to update the dependencies of given Service Group
        from the dependency_list property
        :param callback_api: access to execution manager
        :type  callback_api: class
        :param service_vpath: location in model of service
        :type  service_vpath: string
        :param cluster_item_id: item_id of cluster
        :type  cluster_item_id: string
        :param service_group_name: VCS service group name
        :type  service_group_name: string
        """
        service = self.query_by_vpath(callback_api, service_vpath)
        # Needed for using the VCS cmd api, see `VcsBaseHelper`,
        self.nodes = select_nodes_from_service(service)

        log.event.info('Updating VCS service group dependencies on service'
            ' "{0}" to remove dependencies'.format(service_group_name))

        with self.vcs_api.readable_conf():
            self._clustered_service_remove_dependencies(service,
                                                        service_group_name,
                                                        cluster_item_id)

    def _remove_if_service_group_exist_in_cluster(self, callback_api,
                                                  service_name, service):
        service_group_list = self.vcs_api.hagrp_list()
        if service_name in service_group_list:
            log.trace.info("Service Group {0} already exists in {1}, so "
                           " removing service group from cluster service"
                                .format(service_name, service.get_cluster()))
            with self.vcs_api.readable_conf():
                self.vcs_api.hagrp_offline(service_name)
                self.vcs_api.check_hagrp_isoffline(
                    callback_api,
                    service_name,
                    int(getattr(service, "offline_timeout",
                                OFFLINE_TIMEOUT)) * 2,
                    expect_faulted=False)
                self.vcs_api.hagrp_unlink_all(service_name)
                self.vcs_api.hagrp_remove(service_name)

    def _remove_standby_node(self, callback_api, service_vpath,
                             cluster_vpath):
        """
        Callback function to ensure a failover service is active on one node
        and to remove the standby from the SystemList
        :param callback_api: access to execution manager
        :type  callback_api: class
        :param service_vpath: location in model of service
        :type  service_vpath: string
        :param cluster_vpath: location in model of cluster
        :type  cluster_vpath: string
        """
        cluster = self.query_by_vpath(callback_api, cluster_vpath)
        service = self.query_by_vpath(callback_api, service_vpath)

        self.nodes = select_nodes_from_service(service)
        service_name = self.get_group_name(service.item_id, cluster.item_id)
        applied_nodes = set(get_applied_node_list(service))
        nodes = set(service.node_list.split(','))
        retained_item_id = list(applied_nodes.intersection(nodes))[0]
        removed_item_id = list(applied_nodes.difference(nodes))[0]
        new_node_item_id = list(nodes.difference(applied_nodes))[0]
        retained_node = [node for node in cluster.nodes
                         if node.item_id == retained_item_id][0]
        removed_node = [n for n in cluster.nodes
                        if n.item_id == removed_item_id][0]
        new_node = [n for n in cluster.nodes
                    if n.item_id == new_node_item_id][0]
        grp_state_on_nodes = self._get_group_state_on_nodes(
            group_name=service_name)

        if removed_node.hostname not in grp_state_on_nodes:
            log.trace.info('Attempt to remove node {node} that has '
                           'already been removed. Skipping task'.format(
                node=removed_node))
            return

        self._switch_failover_service_if_required(callback_api,
                                                  service_vpath,
                                                  cluster_vpath,
                                                  retained_node.hostname)
        with self.vcs_api.readable_conf():
            self.vcs_api.remove_standby_node(service_name,
                                             removed_node.hostname,
                                             new_node.hostname)

    def _switch_failover_service_if_required(self, callback_api, service_vpath,
                                             cluster_vpath, node):
        cluster = self.query_by_vpath(callback_api, cluster_vpath)
        service = self.query_by_vpath(callback_api, service_vpath)
        self.nodes = select_nodes_from_cluster(cluster)
        service_name = self.get_group_name(service.item_id, cluster.item_id)
        with self.vcs_api.readable_conf():
            grp_state_on_nodes = self._get_group_state_on_nodes(
                group_name=service_name)
            if node not in grp_state_on_nodes:
                err_msg = ('Attempting to switch group {group} to node '
                           '{node} failed. Node is not '
                           'available'.format(node=node, group=service_name))
                log.trace.error(err_msg)
                raise CallbackExecutionException(err_msg)
            if len(grp_state_on_nodes) > 1:
                self.vcs_api.hagrp_modify(service_name, "AutoFailOver", "0")
                self.vcs_api.hagrp_switch_to_node(service_name, node)
                timing_parameters = TimeoutParameters(
                    max_wait=(int(getattr(service, "offline_timeout",
                              OFFLINE_TIMEOUT)) +
                              VcsUtils.get_service_online_time(service) +
                              LOCK_FUDGE_FACTOR))
                log.trace.info('Waiting {time} seconds for on group "{group}" '
                               'to come online'.format(
                        time=timing_parameters.max_wait,
                        group=service_name))
                if not VcsUtils.wait_on_state(
                    callback_api, self._check_group_status_on_node,
                    timing_parameters, service_name, node):
                    raise CallbackExecutionException(
                        'Clustered Service "{group}" has not come up within '
                        '{time} seconds'.format(
                            group=service_name,
                            time=timing_parameters.max_wait))

    def _check_group_status_on_node(self, group_name, node):
        """
        Gets the state of the service group and returns if it's online
        of faulted
        """
        grp_state_on_nodes = self._get_group_state_on_nodes(
            group_name=group_name)
        return (grp_state_on_nodes[node] != "|OFFLINE|")

    def _add_standby_node_cb(self, callback_api, service_vpath,
                             cluster_vpath):
        """
        Callback function to ensure a failover service is active on one node
        and to remove the standby from the SystemList
        :param callback_api: access to execution manager
        :type  callback_api: class
        :param service_vpath: location in model of service
        :type  service_vpath: string
        :param cluster_vpath: location in model of cluster
        :type  cluster_vpath: string
        """
        cluster = self.query_by_vpath(callback_api, cluster_vpath)
        service = self.query_by_vpath(callback_api, service_vpath)
        self.nodes = select_nodes_from_service(service)
        service_name = self.get_group_name(service.item_id, cluster.item_id)
        applied_nodes = set(get_applied_node_list(service))
        nodes = set(service.node_list.split(','))
        new_node_item_id = list(nodes.difference(applied_nodes))[0]
        new_node = [n for n in cluster.nodes
                    if n.item_id == new_node_item_id][0]
        with self.vcs_api.readable_conf():
            self.vcs_api.add_standby_node(service_name, new_node.hostname)
            vip_upd_standby_node(callback_api, self.vcs_api, service, cluster)
            timing_parameters = TimeoutParameters(
                max_wait=VcsUtils.get_service_online_time(service))
            if not VcsUtils.wait_on_state(callback_api,
                                          self._check_group_ready,
                                          timing_parameters, service_name,
                                          new_node.hostname):
                raise CallbackExecutionException(
                    'Clustered Service "{group}" has not come up within '
                    '{time} seconds on the new standby node'.format(
                        group=service_name,
                        time=timing_parameters.max_wait))

    def _check_group_ready(self, group_name, node):
        vcs_rpc = VcsRPC(node)
        try:
            ret, _, _ = vcs_rpc.check_ok_to_online(group_name, node)
            if ret != 0:
                return False
            grp_state_on_nodes = self._get_group_state_on_nodes(
                group_name=group_name)
            return "|ONLINE|" in grp_state_on_nodes.values()
        except VcsCmdApiException:
            return False

    def _get_group_state_on_nodes(self, group_name):
        grp_state_on_nodes = self.vcs_api.get_group_state_on_nodes(
                group_name=group_name)
        return dict([node_state.split(":")
                     for node_state in grp_state_on_nodes.split(",")])
