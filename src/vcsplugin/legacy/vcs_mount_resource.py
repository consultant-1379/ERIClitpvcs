##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import itertools
import os.path

from litp.core.litp_logging import LitpLogger
from litp.core.execution_manager import CallbackTask
from litp.core.validators import ValidationError

from vcsplugin.vcs_base_helper import VcsBaseHelper, condense_name


log = LitpLogger()

VX_DISK_PATH = "/dev/vx/dsk"
VXVM_VOLUME_DRIVER = "vxvm"
SFHA_CLUSTER_TYPE = "sfha"
FSCK_OPT = "%-y"


class VcsMountLegacyResource(VcsBaseHelper):

    def validate_model(self, plugin_api_context):
        """
        Calls the various validation methods on the model.
        Return a list of errors.
        """
        validators = (
            self._validate_mount_res_inherits_from_cluster_storage,
            self._validate_fs_linked_only_in_sfha_clusters,
            self._validate_mount_res_only_in_failover_service,
            self._validate_filesystem_has_mount_point,
            self._validate_filesystem_properties,
        )

        return list(itertools.chain(*[
            validator(plugin_api_context)
            for validator in validators]))

    def create_configuration(self, plugin_api_context, cluster, service):
        # pylint: disable=unused-argument
        """
        Create the tasks needed for VxVM creation.
        """
        pre_node_tasks = []
        post_node_tasks = []
        for runtime in service.runtimes:
            for filesystem in runtime.filesystems:
                if filesystem.is_initial():
                    volume_name = _get_source_item_id(filesystem)
                    diskgroup_name = self.get_diskgroup_name(filesystem)

                    post_node_tasks += self.create_diskgroup_tasks(
                        cluster, service, runtime, filesystem, diskgroup_name,
                        volume_name)
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

    def create_diskgroup_tasks(self, cluster, service, runtime, filesystem,
                               diskgroup_name, volume_name):
        # pylint: disable=unused-argument
        """
        Return the task required for creating each diskgroup.
        """
        return [
            self._generate_dskgrp_res_task(
                cluster, service, runtime, filesystem, diskgroup_name),
            self._generate_mount_res_task(
                cluster, service, runtime, filesystem, diskgroup_name)]

    def _generate_dskgrp_res_task(self, cluster, service, runtime,
                                  filesystem, diskgroup_name):
        res_name = get_disk_group_res_name(
            cluster.item_id, service.item_id, runtime.item_id,
            filesystem.item_id)
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

    def cb_create_diskgroup(self, callback_api, res_name, sg_name,
                            vx_dg_name, service_vpath):
        service = self.query_by_vpath(callback_api, service_vpath)
        self.nodes = [node.hostname for node in service.nodes]
        with self.vcs_api.readable_conf():
            _add_disk_group_resource(self.vcs_api, res_name,
                                     sg_name, vx_dg_name)

    def _generate_mount_res_task(self, cluster, service, runtime, fs, dg_name):
        res_name = get_mount_res_name(cluster.item_id, service.item_id,
                                      runtime.item_id, fs.item_id)
        dg_res_name = get_disk_group_res_name(cluster.item_id, service.item_id,
                                           runtime.item_id, fs.item_id)
        vcs_grp_name = self.get_group_name(service.item_id, cluster.item_id)
        mount_pt = fs.mount_point
        vol_name = _get_source_item_id(fs)
        return CallbackTask(
            fs,
            'Create LSB VxVM mount resource "{0}" for VCS service group '
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
            service_vpath=service.get_vpath())

    def cb_create_mount(self, callback_api, res_name, sg_name, mount_point,
                        vx_dg_name, vx_vol_name, vcs_dg_res_name,
                        service_vpath):
        block_dev = os.path.join(VX_DISK_PATH, vx_dg_name, vx_vol_name)
        service = self.query_by_vpath(callback_api, service_vpath)
        fs_type = _find_fs_item_in_service(service, vx_vol_name).type
        self.nodes = [node.hostname for node in service.nodes]
        with self.vcs_api.readable_conf():
            _add_mount_resource(self.vcs_api, res_name, sg_name, mount_point,
                                block_dev, fs_type, FSCK_OPT, vcs_dg_res_name)

    def _validate_mount_res_inherits_from_cluster_storage(
            self, plugin_api_context):
        clusters = self.sfha_clusters(plugin_api_context)
        return itertools.chain(*[
            self._check_fs_in_cluster_storage(cluster)
            for cluster in clusters])

    def _check_fs_in_cluster_storage(self, cluster):
        fs_vpaths = self.get_fs_vpaths(cluster)
        errors = []
        for service in cluster.services:
            if service.is_for_removal():
                continue
            for fs in service.query("file-system"):
                if fs.get_source().get_vpath() not in fs_vpaths:
                    err_msg = (
                        "File systems under clustered services must "
                        "be inherited from {0} with volume drive of "
                        "vxvm type"
                        .format(cluster.storage_profile.get_vpath()))
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

    def _validate_mount_res_only_in_failover_service(self, plugin_api_context):
        errors = []
        # Return validation errors only for sfha clusters
        for service in self.services_not_for_removal(plugin_api_context,
                                                     cluster_type="sfha"):
            if not _is_service_failover(service):
                for fs in service.runtimes.query("file-system"):
                    err_msg = ("File systems must not be referenced under "
                               "non-failover clustered-services")
                    errors.append(ValidationError(
                        item_path=fs.get_vpath(),
                        error_message=err_msg))
        return errors

    def _validate_fs_linked_only_in_sfha_clusters(self, plugin_api_context):
        errors = []
        clusters = plugin_api_context.query("vcs-cluster")
        for cluster in clusters:
            if cluster.cluster_type != SFHA_CLUSTER_TYPE:
                for service in cluster.services:
                    if service.is_for_removal():
                        continue
                    for rt in service.query("lsb-runtime"):
                        for fs in rt.filesystems:
                            err_msg = ("File systems may only be referenced "
                                       "in SFHA-enabled VCS clusters.")
                            errors.append(ValidationError(
                                item_path=fs.get_vpath(),
                                error_message=err_msg))
        return errors

    def _get_dg(self, filesystem):
        diskgroup = filesystem.get_source()
        while diskgroup.get_source():
            diskgroup = diskgroup.get_source()
        return diskgroup.parent.parent

    def _validate_filesystem_has_mount_point(self, plugin_api_context):
        errors = []
        for service in self.services_not_for_removal(plugin_api_context,
                                                      cluster_type='sfha'):
            for filesystem in service.runtimes.query('file-system'):
                if not filesystem.mount_point:
                    err_msg = ("VxVM file systems must have the "
                               "'mount_point' property set")
                    errors.append(ValidationError(
                        item_path=filesystem.get_vpath(),
                        error_message=err_msg))
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
        for each vxvm filesystem inherited to a runtime.
        """
        for service in self.services_not_for_removal(plugin_api_context,
                                                     cluster_type='sfha'):
            for filesystem in service.runtimes.query('file-system'):
                yield (filesystem.get_source(), filesystem)

    def _compare_filesystem_properties(self, parent, child):
        """
        Compare two filesystem items, return a list of `ValidationError`s
        for each property that differs from the child to the parent.
        """
        errors = []
        for property_ in dict_compare(parent.properties, child.properties):
            errors.append(ValidationError(
                item_path=child.get_vpath(),
                error_message='Property "%s" changed from parent item.' %
                property_))
        return errors


def dict_compare(parent, child):
    """
    Compare two dictionaries and yield the keys which contain different
    values.
    """
    for key, value in parent.iteritems():
        if child.get(key) != value:
            yield key


def _find_fs_item_in_service(service, vx_vol_name):
    for rt in service.runtimes:
        for fs in rt.filesystems:
            if _get_source_item_id(fs) == vx_vol_name:
                return fs


def get_mount_res_names(cluster, service, runtime):
    # Used by vcs_app_resource.py to establish VCS resource links between the
    # app and the mount resources
    return [
        get_mount_res_name(
            cluster.item_id, service.item_id, runtime.item_id, fs.item_id)
        for fs in runtime.filesystems]


def _get_source_item_id(item):
    """
    Return the `item_id` of the `item`s source.
    """
    item_source = item.get_source()
    return item_source.item_id


def _is_service_failover(service):
    return int(service.active) == 1 and int(service.standby) == 1


def get_disk_group_res_name(cluster_item_id, cs_item_id, rt_item_id,
                            fs_item_id):
    """
    Return resource app name with format
    Res_DG_<cluster_item_id>_<cs_item_id>_<rt_item_id>_<fs_item_id>
    """
    return condense_name("Res_DG_{0}_{1}_{2}_{3}".format(cluster_item_id,
                         cs_item_id, rt_item_id, fs_item_id))


def get_mount_res_name(cluster_item_id, cs_item_id, rt_item_id, fs_item_id):
    """
    Return resource app name with format
    Res_Mnt_<cluster_item_id>_<cs_item_id>_<rt_item_id>_<fs_item_id>
    """
    return condense_name("Res_Mnt_{0}_{1}_{2}_{3}".format(cluster_item_id,
                         cs_item_id, rt_item_id, fs_item_id))


def _add_mount_resource(vcs_api, res_name, sg_name, mount_path, block_dev_path,
                        fs_type, fsck_opt, vcs_dg_res_name):
    """
    Calls the VCS commands needed to create a VCS Mount Resource
    """
    # hares -add VersantMount1 Mount ServiceGroupName
    vcs_api.hares_add(res_name, "Mount", sg_name)
    # hares -modify VersantMount1 Critical 1
    vcs_api.hares_modify(res_name, "Critical", "1")
    # hares -modify VersantMount1 MountPoint /VersantDB
    vcs_api.hares_modify(res_name, "MountPoint", mount_path)
    # hares -modify VersantMount1 CreateMntPt 1
    vcs_api.hares_modify(res_name, "CreateMntPt", "1")
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
