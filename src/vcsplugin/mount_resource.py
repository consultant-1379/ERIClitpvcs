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
import itertools
import os.path

from litp.core.litp_logging import LitpLogger
from litp.core.execution_manager import CallbackTask
from litp.core.validators import ValidationError

from .vcs_base_helper import (condense_name,
                              VcsBaseHelper,
                              is_clustered_service_redeploy_required,
                              is_being_deactivated,
                              is_service_deactivation_pair)

from .vcs_utils import (select_nodes_from_cluster,
                        select_nodes_from_service,
                        is_os_reinstall_on_peer_nodes)

#from vcsplugin.vcs_utils import VcsUtils

log = LitpLogger()

VX_DISK_PATH = "/dev/vx/dsk"
VXVM_VOLUME_DRIVER = "vxvm"
SFHA_CLUSTER_TYPE = "sfha"
FSCK_OPT = "%-y"


class MountResource(VcsBaseHelper):

    def validate_model(self, plugin_api_context):
        """
        Calls the various validation methods on the model.
        Return a list of errors.
        """
        validators = (
            self._validate_filesystem_properties,
        )
        validators_clusters = (
            self._validate_fs_linked_only_in_sfha_clusters,
        )
        validators_sfha_clusters = (
            self._validate_mount_res_inherits_from_cluster_storage,
            self._validate_all_dg_filesystems_mounted,
            self._validate_no_duplicate_mount_points_in_sfha_cluster,
        )
        validators_sfha_services = (
            self._validate_mount_res_only_in_failover_service,
            self._validate_fs_is_unique_in_each_service,
            self._validate_filesystem_has_mount_point,
            self._validate_filesystem_mount_point_not_updated,
            self._validate_dg_unique_per_service,
            self._validate_heterogeneous_dg_per_service,
            self._validate_no_lsb_runtime,
        )

        clusters = plugin_api_context.query("vcs-cluster")
        sfha_clusters = self.sfha_clusters(plugin_api_context)
        sfha_services = [service for service in
                         self.services_not_for_removal(plugin_api_context,
                                                       cluster_type='sfha')]

        errors = []
        for validator in validators:
            errors.extend(validator(plugin_api_context))
        for validator in validators_clusters:
            errors.extend(validator(clusters))
        for validator in validators_sfha_clusters:
            errors.extend(validator(sfha_clusters))
        for validator in validators_sfha_services:
            errors.extend(validator(sfha_services))
        return errors

    def create_configuration(self, plugin_api_context, cluster, service):
        # pylint: disable=unused-argument
        """
        Create the tasks needed for VxVM creation.
        """
        pre_node_tasks = []
        post_node_tasks = []
        apps = get_apps(service)
        for filesystem in service.filesystems:
            if (filesystem.is_initial() or
            is_clustered_service_redeploy_required(service)):
                diskgroup_name = self.get_diskgroup_name(filesystem)
                post_node_tasks += self.create_diskgroup_tasks(
                    cluster, service, apps, filesystem, diskgroup_name)
        if not is_clustered_service_redeploy_required(service):
            for task in post_node_tasks:
                # Set dependencies so volmgr VxVM task run first
                task.requires = set([cluster.storage_profile])
        return pre_node_tasks, post_node_tasks

    def get_diskgroup_name(self, filesystem):
        """
        Return the diskgroup name for the volume.
        """
        dg = self._get_dg(filesystem)
        return dg.volume_group_name

    def create_diskgroup_tasks(self, cluster, service, apps, filesystem,
                               diskgroup_name):
        """
        Return the task required for creating each diskgroup.
        """
        return [
            self._generate_deport_task(cluster, filesystem, diskgroup_name,
                                       service),
            self._generate_dskgrp_res_task(
                cluster, service, apps, filesystem, diskgroup_name),
            self._generate_mount_res_task(
                cluster, service, apps, filesystem, diskgroup_name)]

    def _get_app_id_from_list(self, service, apps):
        """
        Return the item id of the first application in the list. If the number
        of applications in the service is more than one, return an empty string
        because we will not use it in the naming scheme of the dskgrp and the
        mount vcs resources.
        """
        app_id = apps[0].item_id
        if len(service.applications) > 1:
            app_id = ''
        return app_id

    def _generate_dskgrp_res_task(self, cluster, service, apps,
                                  filesystem, diskgroup_name):
        app_id = self._get_app_id_from_list(service, apps)
        res_name = get_disk_group_res_name(
            cluster.item_id, service.item_id, app_id, filesystem.item_id)
        vcs_grp_name = self.get_group_name(service.item_id, cluster.item_id)

        return CallbackTask(
            filesystem,
            'Create VxVM disk group resource "{0}" for VCS service group '
            '"{1}"'.format(res_name, vcs_grp_name),
            self.plugin().callback_method,
            callback_class=self.__class__.__name__,
            callback_func="cb_create_diskgroup",
            res_name=res_name,
            sg_name=vcs_grp_name,
            vx_dg_name=diskgroup_name,
            service_vpath=service.get_vpath())

    def _generate_deport_task(self, cluster, filesystem, diskgroup_name,
                              service):
        vcs_grp_name = self.get_group_name(service.item_id, cluster.item_id)
        return CallbackTask(
            filesystem,
            'Deport VxVM disk group "{0}" for VCS service group '
            '"{1}"'.format(diskgroup_name, vcs_grp_name),
            self.plugin().callback_method,
            callback_class=self.__class__.__name__,
            callback_func="cb_deport_diskgroup",
            vx_dg_name=diskgroup_name,
            service_vpath=service.get_vpath()
        )

    def cb_deport_diskgroup(self, callback_api, vx_dg_name, service_vpath):
        service = self.query_by_vpath(callback_api, service_vpath)
        cluster = service.get_cluster()
        self.nodes = select_nodes_from_cluster(cluster)
        if is_os_reinstall_on_peer_nodes(cluster) \
                and service.applied_properties:
            service_nodes = select_nodes_from_service(service)
            self.nodes = [node for node in self.nodes if node not in
                          service_nodes]
        for node in self.nodes:
            self.vcs_api.set_node(node)
            output = self.vcs_api.get_diskgroup_mounted_status(vx_dg_name)
            if output:
                self.vcs_api.deport_disk_group(vx_dg_name)
                break

    def cb_create_diskgroup(self, callback_api, res_name, sg_name,
                            vx_dg_name, service_vpath):
        service = self.query_by_vpath(callback_api, service_vpath)
        self.nodes = select_nodes_from_service(service)
        with self.vcs_api.readable_conf():
            _add_disk_group_resource(self.vcs_api, res_name,
                                     sg_name, vx_dg_name)

    def _generate_mount_res_task(self, cluster, service, apps, fs, dg_name):
        app_id = self._get_app_id_from_list(service, apps)
        res_name = get_mount_res_name(cluster.item_id, service.item_id, app_id,
                                      fs.item_id)
        dg_res_name = get_disk_group_res_name(cluster.item_id, service.item_id,
                                              app_id, fs.item_id)
        vcs_grp_name = self.get_group_name(service.item_id, cluster.item_id)
        app_res_names = [self.get_app_res_name(cluster.item_id, service.name,
                                               app.item_id) for app in apps]
        mount_pt = fs.mount_point
        vol_name = _get_source_item_id(fs)
        return CallbackTask(
            fs,
            'Create VxVM mount resource "{0}" for VCS service group '
            '"{1}"'.format(res_name, vcs_grp_name),
            self.plugin().callback_method,
            callback_class=self.__class__.__name__,
            callback_func="cb_create_mount",
            res_name=res_name,
            sg_name=vcs_grp_name,
            mount_point=mount_pt,
            vx_dg_name=dg_name,
            vx_vol_name=vol_name,
            vcs_dg_res_name=dg_res_name,
            app_res_names=app_res_names,
            service_vpath=service.get_vpath())

    def cb_create_mount(self, callback_api, res_name, sg_name, mount_point,
                        vx_dg_name, vx_vol_name, vcs_dg_res_name,
                        app_res_names, service_vpath):
        block_dev = os.path.join(VX_DISK_PATH, vx_dg_name, vx_vol_name)
        service = self.query_by_vpath(callback_api, service_vpath)
        fs_type = _find_fs_item_in_service(service, vx_vol_name).type
        self.nodes = select_nodes_from_service(service)
        with self.vcs_api.readable_conf():
            _add_mount_resource(self.vcs_api, res_name, sg_name, mount_point,
                                block_dev, fs_type, FSCK_OPT, vcs_dg_res_name,
                                app_res_names)

    def _validate_mount_res_inherits_from_cluster_storage(
            self, clusters):
        return itertools.chain(*[
            self._check_fs_in_cluster_storage(cluster)
            for cluster in clusters])

    def _check_fs_in_cluster_storage(self, cluster):
        fs_vpaths = self.get_fs_vpaths(cluster)
        errors = []
        for cs in self.services_not_for_removal_from_cluster(cluster):
            for fs in cs.filesystems:
                if fs.get_source().get_vpath() not in fs_vpaths:
                    err_msg = (
                        "File systems under clustered services must be "
                        "inherited from \"{0}\" with volume drive of "
                        "vxvm type".format(
                            cluster.storage_profile.get_vpath()))
                    errors.append(ValidationError(
                        item_path=fs.get_vpath(),
                        error_message=err_msg))
        return errors

    def get_fs_vpaths(self, cluster):
        file_system_vpaths = set()
        for storage_profile in cluster.storage_profile:
            if storage_profile.volume_driver == VXVM_VOLUME_DRIVER:
                for volume_group in storage_profile.volume_groups:
                    for file_system in volume_group.file_systems:
                        file_system_vpaths.add(file_system.get_vpath())
        return file_system_vpaths

    def _validate_mount_res_only_in_failover_service(self, services):
        errors = []
        # Return validation errors only for sfha clusters
        for service in services:
            if not _is_service_failover(service):
                for fs in service.filesystems:
                    err_msg = ("File systems must not be referenced under "
                               "non-failover vcs-clustered-services")
                    errors.append(ValidationError(
                        item_path=fs.get_vpath(),
                        error_message=err_msg))
        return errors

    def _validate_fs_linked_only_in_sfha_clusters(self, clusters):
        errors = []
        for cluster in clusters:
            if cluster.cluster_type != SFHA_CLUSTER_TYPE:
                for service in (
                        self.services_not_for_removal_from_cluster(cluster)):
                    for fs in service.filesystems:
                        err_msg = ("File systems may only be referenced in "
                                   "SFHA-enabled VCS clusters.")
                        errors.append(ValidationError(
                            item_path=fs.get_vpath(),
                            error_message=err_msg))
        return errors

    def _validate_dg_unique_per_service(self, services):
        """
        Validates that no diskgroup has filesystems used by multiple
        services.
        """
        diskgroups_services = defaultdict(list)
        for service in services:
            for filesystem in get_service_filesystems(service):
                if filesystem.is_for_removal():
                    # Skip validation if we're removing the fs
                    continue
                diskgroup = self._get_dg(filesystem)
                diskgroups_services[diskgroup.get_vpath()].append(service)

        errors = []
        for dg_vpath, services in diskgroups_services.items():
            if len(services) == 1 or is_service_deactivation_pair(services):
                continue
            message = ("Filesystem from volume-group %s is inherited "
                       "on more than one service.")
            errors.append(ValidationError(
                item_path=dg_vpath,
                error_message=message % dg_vpath))
        return errors

    def _validate_heterogeneous_dg_per_service(self, services):
        """
        Validate that each filesystem of a service belongs to a different
        diskgroup.
        """
        errors = []
        error_message = ("vcs-clustered-service contains more than one "
                         "filesystem from diskgroup: %s.")
        for service in services:
            dg_counter = defaultdict(int)
            for filesystem in get_service_filesystems(service):
                if filesystem.is_for_removal():
                    # Skip validation if we're removing the fs
                    continue
                dg_counter[self._get_dg(filesystem).get_vpath()] += 1
            for dg_vpath, count in dg_counter.items():
                if count > 1:
                    msg = error_message % (dg_vpath)
                    errors.append(ValidationError(
                        item_path=service.get_vpath(),
                        error_message=msg))
        return errors

    def _validate_all_dg_filesystems_mounted(self, clusters):
        """
        Validate that disk groups do not include filesystems which are not
        mounted.
        """
        errors = []
        err_msg = "Filesystem {0} is not used in any vcs-clustered-service"
        for cluster in clusters:
            profile_filesystems = set()
            sg_filesystems = set()
            for fs in get_cluster_storage_profile_filesystems(cluster):
                if not fs.is_for_removal():
                    profile_filesystems.add(fs.vpath)
            for service in self.services_not_for_removal_from_cluster(cluster):
                for filesystem in get_service_filesystems(service):
                    if (not filesystem.is_for_removal()
                            and not is_being_deactivated(cluster, service)):
                        sg_filesystems.add(filesystem.get_source().vpath)
            for filesystem in profile_filesystems - sg_filesystems:
                error_msg = err_msg.format(filesystem)
                errors.append(ValidationError(
                        item_path=filesystem,
                        error_message=error_msg))
        return errors

    def _get_dg(self, filesystem):
        diskgroup = filesystem.get_source()
        while diskgroup.get_source():
            diskgroup = diskgroup.get_source()
        return diskgroup.parent.parent

    def _validate_fs_is_unique_in_each_service(self, services):
        errors = []
        fs_in_cs = defaultdict(list)
        for service in services:
            for fs in get_service_filesystems(service):
                if fs.is_for_removal():
                    # Skip validation if we're removing the fs
                    continue
                fs_src = fs.get_source()
                fs_in_cs[fs_src.get_vpath()].append(service)

        # Don't allow a filesystem to be associated with more than one
        # clustered-service
        for fs, cs_list in fs_in_cs.items():
            if len(cs_list) > 1:
                if is_service_deactivation_pair(cs_list):
                    continue
                for cs in cs_list:
                    err_msg = ("VxVM file systems must not be referenced by "
                               "more than one vcs-clustered-service")
                    errors.append(ValidationError(
                        item_path=cs.get_vpath(),
                        error_message=err_msg))
        return errors

    def _validate_no_lsb_runtime(self, services):
        errors = []
        for service in services:
            if get_apps(service):
                continue
            for fs in service.filesystems:
                err_msg = ("Filesystems may not be referenced under {0} "
                           "without a corresponding service in {1}."
                           "".format(service.filesystems.get_vpath(),
                               service.applications.get_vpath()))
                errors.append(ValidationError(
                    item_path=fs.get_vpath(),
                    error_message=err_msg))
        return errors

    def _validate_filesystem_has_mount_point(self, services):
        errors = []
        for service in services:
            for filesystem in service.filesystems:
                if filesystem.mount_point:
                    continue
                err_msg = ("VxVM file systems must have the "
                           "'mount_point' property set")
                errors.append(ValidationError(
                    item_path=filesystem.get_vpath(),
                    error_message=err_msg))
        return errors

    def _validate_filesystem_mount_point_not_updated(self, services):
        errors = []
        for service in services:
            for filesystem in service.filesystems:
                if filesystem.is_initial():
                    continue
                applied_mp = filesystem.applied_properties.get('mount_point')
                if filesystem.mount_point != applied_mp and \
                not service.applied_properties_determinable:
                    err_msg = ("Update of mount_point property is not "
                               "supported")
                    errors.append(ValidationError(
                            item_path=filesystem.get_vpath(),
                            error_message=err_msg))
        return errors

    def _validate_no_duplicate_mount_points_in_sfha_cluster(self,
            sfha_clusters):
        errors = []
        for cluster in sfha_clusters:
            mount_point_to_nodes = defaultdict(list)
            for service in cluster.services:
                if not _is_service_failover(service):
                    continue
                if service.is_for_removal():
                    continue
                for fs in service.filesystems:
                    if not fs.mount_point:
                        # other validation will catch empty mount points
                        continue
                    mount_point_to_nodes[fs.mount_point].append(tuple(
                            [fs, set([node.hostname
                                        for node in service.nodes])]))

            for mount_point, node_set_list in mount_point_to_nodes.items():
                if len(node_set_list) == 1:
                    continue
                # Now get intersections of node_lists
                vpath_to_nodes = defaultdict(set)
                for idx, (fs, nodes) in enumerate(node_set_list[:-1]):
                    for other_fs, other_nodes in node_set_list[idx + 1:]:
                        # Build the total intersection to find the
                        # total set of nodes this fs conflicts with
                        intersection = nodes & other_nodes

                        # Update vpath-to-node map of both vpaths
                        vpath_to_nodes[fs.vpath] |= intersection
                        vpath_to_nodes[other_fs.vpath] |= intersection
                # Now emit validationErrors for each fs
                for (fs_vpath, intersection) in vpath_to_nodes.items():
                    if not intersection:
                        continue
                    msg = ('File-system mount_point "{0}" is not unique on '
                          'nodes: "{1}"').format(mount_point, ", ".join(
                               sorted(list(intersection))))
                    errors.append(ValidationError(item_path=fs_vpath,
                                                  error_message=msg))

        return errors

    def _validate_filesystem_properties(self, plugin_api_context):
        """
        Validate that no properties of the child filesystem differ
        from the parent item.
        """
        filesystems = self._parent_child_filesystems(plugin_api_context)
        return list(itertools.chain(*[
            self._compare_filesystem_properties(parent, child)
            for parent, child in filesystems]))

    def _parent_child_filesystems(self, plugin_api_context):
        """
        yield two tuples containing: (parent_filesystem, child_filesystem)
        for each vxvm filesystem inherited to a service.
        """
        for service in self.services_not_for_removal(plugin_api_context,
                                                    cluster_type='sfha'):
            for filesystem in get_service_filesystems(service):
                yield (filesystem.get_source(), filesystem)

    def _compare_filesystem_properties(self, parent, child):
        """
        Compare two filesystem items, return a list of `ValidationError`s
        for each property that differs from the child to the parent.
        """
        errors = []
        err_msg = ('You cannot change the properties of a file-system '
                'inherited under a vcs-clustered-service. Please update the '
                'file-system at {vpath}')
        if any(dict_compare(parent.properties, child.properties)):
            errors.append(ValidationError(
                item_path=child.get_vpath(),
                error_message=err_msg.format(vpath=parent.get_vpath())
                )
            )
        return errors


def get_service_filesystems(service):
    """
    Return the relevant collection of filesystems depending on whether
    an 'lsb-runtime' or a 'service' is created
    """
    for runtime in service.runtimes:
        return runtime.filesystems
    return service.filesystems


def dict_compare(parent, child):
    """
    Compare two dictionaries and yield the keys which contain different
    values.
    """
    for key, value in parent.iteritems():
        if child.get(key) != value:
            yield key


def get_cluster_storage_profile_filesystems(cluster):
    return cluster.storage_profile.query('file-system')


def get_apps(service):
    # The fs mount should be ensured only for the top level apps that have no
    # dependencies. It is covered by validation that at least one is without
    # the dependency_list if the ha-service-config is provided.
    ha_configs = [ha_config for ha_config
                  in service.ha_configs.query("ha-service-config")
                  if ha_config.dependency_list is None]
    apps = []
    if len(ha_configs) > 1:
        app_ids = [ha_config.service_id for ha_config in ha_configs]
        apps = [app for app in service.applications if app.item_id in app_ids]
    elif len(ha_configs) == 1:
        # it might not have a service_id
        app_id = getattr(ha_configs[0], 'service_id', None)
        if app_id is not None:
            apps = [app for app in service.applications
                    if app.item_id == app_id]
        else:
            # if it has no service_id, there is only one app
            apps = [app for app in service.applications]
    else:
        apps = [app for app in service.applications]
    return apps


def _find_fs_item_in_service(service, vx_vol_name):
    for fs in service.filesystems:
        if _get_source_item_id(fs) == vx_vol_name:
            return fs


def get_mount_res_names(cluster, service, app):
    # Used by vcs_app_resource.py to establish VCS resource links between the
    # app and the mount resources
    return [
        get_mount_res_name(
            cluster.item_id, service.item_id, app.item_id, fs.item_id)
        for fs in service.filesystems]


def _get_source_item_id(item):
    """
    Return the `item_id` of the `item`s source.
    """
    item_source = item.get_source()
    return item_source.item_id


def _is_service_failover(service):
    return int(service.active) == 1 and int(service.standby) == 1


def get_disk_group_res_name(cluster_item_id, cs_item_id, svc_item_id,
                            fs_item_id):
    """
    Return resource app name with format
    Res_DG_<cluster_item_id>_<cs_item_id>_<rt_item_id>_<fs_item_id>
    """
    if svc_item_id:
        return condense_name("Res_DG_{0}_{1}_{2}_{3}".format(cluster_item_id,
                             cs_item_id, svc_item_id, fs_item_id))
    return condense_name("Res_DG_{0}_{1}_{2}".format(cluster_item_id,
                         cs_item_id, fs_item_id))


def get_mount_res_name(cluster_item_id, cs_item_id, svc_item_id, fs_item_id):
    """
    Return resource app name with format
    Res_Mnt_<cluster_item_id>_<cs_item_id>_<rt_item_id>_<fs_item_id>
    """
    if svc_item_id:
        return condense_name("Res_Mnt_{0}_{1}_{2}_{3}".format(cluster_item_id,
                             cs_item_id, svc_item_id, fs_item_id))
    return condense_name("Res_Mnt_{0}_{1}_{2}".format(cluster_item_id,
                         cs_item_id, fs_item_id))


def _add_mount_resource(vcs_api, res_name, sg_name, mount_path, block_dev_path,
                        fs_type, fsck_opt, vcs_dg_res_name, app_res_names):
    """
    Calls the VCS commands needed to create a VCS Mount Resource
    """
    # hares -add VersantMount1 Mount ServiceGroupName
    vcs_api.hares_add(res_name, "Mount", sg_name)
    # hares -modify VersantMount1 Critical 1
    vcs_api.hares_modify(res_name, "Critical", "1")
    # hares -modify VersantMount1 MountPoint /VersantDB
    vcs_api.hares_modify(res_name, "MountPoint", mount_path)
    # hares -modify VersantMount1 CreateMntPt 2
    vcs_api.hares_modify(res_name, "CreateMntPt", "2")
    # hares -modify VersantMount1 BlockDevice /dev/vx/dsk/PocDG_1/PocVolume1
    vcs_api.hares_modify(res_name, "BlockDevice", block_dev_path)
    # hares -modify VersantMount1 FSType vxfs
    vcs_api.hares_modify(res_name, "FSType", fs_type)
    # hares -modify VersantMount1 FsckOpt %-y
    vcs_api.hares_modify(res_name, "FsckOpt", fsck_opt)
    # hares -modify VersantMount1 Enabled 1
    vcs_api.hares_modify(res_name, "Enabled", "1")
    # hares -link VersantMount1 VersantVol1
    vcs_api.hares_link(res_name, vcs_dg_res_name)
    for app_res_name in app_res_names:
        # hares -link VerantApp1 VersantMount1
        vcs_api.hares_link(app_res_name, res_name)


def _add_disk_group_resource(vcs_api, res_name, sg_name, vx_dg_name):
    """
    Calls the VCS commands needed to create a VCS Disk Group Resource
    """
    # hares -add VerstantDg1  DiskGroup ServiceGroupName
    vcs_api.hares_add(res_name, "DiskGroup", sg_name)
    # hares -modify VersantDg1 Critical 1
    vcs_api.hares_modify(res_name, "Critical", "1")
    # hares -modify VersantDg1 Volume versant_filesystem
    vcs_api.hares_modify(res_name, "DiskGroup", vx_dg_name)
    # hares -modify VersantDg1 Enabled 1
    vcs_api.hares_modify(res_name, "Enabled", "1")
