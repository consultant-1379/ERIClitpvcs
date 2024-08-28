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
from litp.core.execution_manager import (CallbackTask,
                                         CallbackExecutionException)
from litp.core.validators import ValidationError

from .vcs_cmd_api import VcsRPC
from .vcs_exceptions import VcsCmdApiException, VCSRuntimeException
from .vcs_utils import VcsUtils, TimeoutParameters
from .vcs_base_helper import (VcsBaseHelper, updated_properties)


log = LitpLogger()

TIMEOUT_FOR_STOP_ALL_NODES = 60 * 30


class VcsIOFencingHelper(VcsBaseHelper):

    def _validate_uuids(self, api, errors, clusters):
        """
        Validate that uuids of fencing disks are unique
        """
        # validate fencing disks are unique between clusters
        fenc_uuids = dict()
        for cluster in clusters:
            fenc_disks = [disk for disk in cluster.fencing_disks if disk.uuid]
            for disk in fenc_disks:
                fenc_uuids.setdefault(disk.uuid, []).append(
                    (disk.get_vpath(), cluster.item_id))

        for disk_uuid, info in fenc_uuids.iteritems():
            if len(info) > 1:
                for disk_vpath, _ in info:
                    for other_disk_vpath, other_cluster in info:  # eww
                        if other_disk_vpath != disk_vpath:
                            errors.append(
                                ValidationError(
                                    item_path=disk_vpath,
                                    error_message=(
                                        "Duplicate disk UUID detected: '{0}'. "
                                        "Fencing disk with the same UUID "
                                        "already defined under "
                                        "cluster: '{1}'".format(
                                            disk_uuid,
                                            other_cluster))))

        #validate fencing disks uuids are unique between all disks
        all_disks = [disk for disk in api.query("disk") if disk.uuid]
        all_uuids = [disk.uuid for disk in api.query("disk") if disk.uuid]
        fenc_disks, fenc_disks_uuids = [], []
        for cluster in clusters:
            for disk in cluster.fencing_disks:
                if disk.uuid:
                    fenc_disks.append(disk)
                    fenc_disks_uuids.append(disk.uuid)
        for disk in fenc_disks:
            if disk.uuid in all_uuids:
                all_disks.remove(disk)

        for disk in all_disks:
            if disk.uuid in fenc_disks_uuids:
                errors.append(ValidationError(
                    item_path=disk.get_vpath(),
                    error_message="Duplicate disk UUID detected: "
                                  " '{0}'. Disk '{1}' has the same "
                                  "disk UUID.".format(disk.uuid, disk.name)
                ))

    def _validate_bootable_disks(self, errors, clusters):
        for cluster in clusters:
            disks = [disk for disk in cluster.fencing_disks]
            for disk in disks:
                if disk.bootable == 'true':
                    errors.append(ValidationError(
                        item_path=disk.get_vpath(),
                        error_message="Fencing disk: '{0}' can't be defined "
                                      "as a bootable device".format(disk.name))
                    )

    def _validate_no_disk_updated(self, errors, clusters):
        """
        Validate that after the fencing disk has been applied that there are
        no properties updated
        """
        updatable = ['uuid', 'storage_container']
        err_msg = 'Fencing disk: "{0}" Only the UUID and storage_container '\
                  'of the Fencing disk can be updated when it is in an ' \
                  '"Applied" state'

        for cluster in clusters:
            for disk in cluster.fencing_disks:
                if disk.is_updated():
                    for prop in updated_properties(disk):
                        if prop not in updatable:
                            errors.append(ValidationError(
                                item_path=disk.get_vpath(),
                                error_message=err_msg.format(disk.name)))

    def validate_model(self, plugin_api_context):
        """
        performs validation on the model
        :param plugin_api_context: access to the model manager
        :type  plugin_api_context: class
        """
        errors = []
        clusters = plugin_api_context.query("vcs-cluster")

        self._validate_uuids(plugin_api_context, errors, clusters)
        self._validate_bootable_disks(errors, clusters)
        self._validate_no_disk_updated(errors, clusters)

        for cluster in clusters:
            disks = [disk for disk in cluster.fencing_disks]
            number_of_disks = len(disks)
            if number_of_disks not in (0, 3):
                errors.append(ValidationError(
                        item_path=cluster.get_vpath(),
                        error_message="Wrong number of fencing disks. "
                                      "There should be 3 or 0 disks defined "
                                      "for VCS cluster.")
                        )
            # Fencing disks can't be added to a non-initial cluster
            if not cluster.is_initial() and cluster.fencing_disks.\
                has_initial_dependencies():
                errors.append(ValidationError(
                        item_path=cluster.get_vpath(),
                        error_message="Fencing disks may not be added to an "
                                      "existing cluster")
                        )
            if number_of_disks == 3 and cluster.cluster_type != 'sfha':
                errors.append(ValidationError(
                        item_path=cluster.get_vpath(),
                        error_message="Wrong cluster type. When using I/O "
                                      "fencing, the cluster type must be "
                                      "'sfha' and not '{0}'".format(
                                      cluster.cluster_type))
                        )

        return errors

    def create_configuration(self, plugin_api_context, cluster):
        # pylint: disable=unused-argument
        post_node_tasks = []
        nodes = [node.hostname for node in cluster.nodes
                 if not node.is_for_removal()]
        nodes_initial = [node.hostname for node in cluster.nodes
                         if node.is_initial()]
        fencing_disks = [fencing_disk for fencing_disk in
                         cluster.fencing_disks]

        cluster_expansion = self.is_cluster_expansion(cluster)

        if fencing_disks and (cluster.is_initial() or nodes_initial or
                              not cluster.applied_properties_determinable):
            if not cluster_expansion:
                # In the case of cluster expansion and fencing disks, then the
                # configuration of fencing is handled in ConfigTasks
                task = CallbackTask(
                    cluster,
                    'Configure VCS to use VX fencing on cluster "{0}"'.format(
                        cluster.item_id),
                    self.plugin().callback_method,
                    callback_class=self.__class__.__name__,
                    callback_func="vx_io_fencing",
                    nodes=nodes,
                    cluster_name=cluster.item_id)
                task.requires.add(cluster.fencing_disks)
                post_node_tasks.append(task)

                task = CallbackTask(
                    cluster,
                    'Check VCS engine is running on cluster "{0}"'.format(
                        cluster.item_id),
                    self.plugin().callback_method,
                    callback_class='VcsCluster',
                    callback_func="vcs_poll_callback",
                    nodes=nodes)
                task.requires.add(cluster.fencing_disks)
                post_node_tasks.append(task)

            task = CallbackTask(
                cluster,
                'Check VX fencing is configured on cluster "{0}"'.format(
                    cluster.item_id),
                self.plugin().callback_method,
                callback_class=self.__class__.__name__,
                callback_func="vx_verify_io_fencing",
                nodes=nodes)
            task.requires.add(cluster.fencing_disks)
            post_node_tasks.append(task)

        return [], post_node_tasks

    def vx_io_fencing(self, callback_api, nodes, cluster_name):
        # This check is here to see if fencing is already installed.
        # If so, we don't need to restart vcs on the nodes.
        if self.io_fencing_is_already_installed(callback_api, nodes):
            return
        # pylint: disable=unused-argument
        self.nodes = nodes
        for node in nodes:
            log.event.info('Starting Vx Fencing on node "{0}"'.format(
                node))
            self.vcs_api.set_node(node)
            self.vcs_api.start_vx_fencing()

        for node in nodes:
            log.event.info('Editing main.cf to use fencing on node "{0}"'
                           .format(node))
            self.vcs_api.set_node(node)
            self.vcs_api.edit_maincf_use_fence(cluster_name)

        for node in nodes:
            log.event.info('Verifying main.cf on node "{0}"'.format(node))
            self.vcs_api.set_node(node)
            self.vcs_api.verify_main_cf()

        for node in nodes:
            log.event.info('Ensure that haconf is read-only on node "{0}"'
                           .format(node))
            self.vcs_api.set_node(node)
            self.vcs_api.haconf("dump", read_only="True")

        log.event.info('Stopping VCS on all nodes')
        self.vcs_api.stop_vcs()

        timing_parameters = TimeoutParameters(
            max_wait=TIMEOUT_FOR_STOP_ALL_NODES)
        if not VcsUtils.wait_on_state(callback_api, self._check_stopped_nodes,
                                      timing_parameters, nodes):
            raise CallbackExecutionException(
                'Waiting for "{max_wait}" seconds but not succeed '
                'to stop all nodes'.format(
                    max_wait=timing_parameters.max_wait))

        log.event.info("Successfully stopped VCS on all nodes")

        for node in nodes:
            log.event.info('Starting VCS on node "{0}"'.format(node))
            self.vcs_api.set_node(node)
            self.vcs_api.start_vcs()

    def _check_stopped_nodes(self, nodes):
        """ Return True if all nodes are stopped """
        for node in nodes:
            vcs_rpc = VcsRPC(node)
            try:
                ret, out, err = vcs_rpc.cluster_stopped()
                if ret != 0:
                    log.event.debug('VCS is not stopped on node "{0}", '
                        'error: "{1}", output: "{2}"'.format(node, err, out))
                    return False
            except VcsCmdApiException as ex:
                log.event.debug('VCS is not stopped on node "{0}", error: '
                    '"{1}"'.format(node, ex))
                return False
        return True

    def verify_vxfen_admin(self):
        return_string_vxfen_admin = self.vcs_api.vxfen_admin()
        log.event.debug('Return string verify_vxfen_admin: {0}'.format(
            return_string_vxfen_admin))
        lines = [line.replace(' ', '') for line\
            in return_string_vxfen_admin.split("\n")]

        if 'FencingMode:SCSI3' not in lines:
            err_msg = 'The Fencing mode configuration was not set up '\
            'correctly. "Fencing Mode: SCSI3" is not visible in the output of'\
            ' "vxfenadm -d"'
            raise VCSRuntimeException(err_msg)

        if 'FencingSCSI3DiskPolicy:dmp' not in lines:
            err_msg = 'The Fencing mode configuration was not set up '\
            'correctly. "Fencing SCSI3 Disk Policy: dmp" is not visible in '\
            'the output of "vxfenadm -d"'
            raise VCSRuntimeException(err_msg)

    def verify_vxfen_config(self):
        return_string_vxfen_config = self.vcs_api.vxfen_config()
        log.event.debug('Return string verify_vxfen_config: {0}'.format(
            return_string_vxfen_config))
        lines = [line.replace(' ', '') for line\
            in return_string_vxfen_config.split("\n")]

        if 'Count:3' not in lines:
            err_msg = 'The Fencing mode configuration was not set up '\
            'correctly. "Count: 3" is not visible in the output of'\
            ' "vxfenconfig -l"'
            raise VCSRuntimeException(err_msg)

    def vx_verify_io_fencing(self, callback_api, nodes):
        # pylint: disable=unused-argument
        """
        In order to verify Vx Fencing, two checks are run:
        1) "vxfenadm -d" configuration should be correct
        2) "vxfenconfig -l" the number ofdisks specified in the plan should be
           included in the I/O fencing configuration.
        """
        self.nodes = nodes
        self.vcs_api.set_node(self.nodes[0])
        self.verify_vxfen_admin()
        self.verify_vxfen_config()

    def io_fencing_is_already_installed(self, callback_api, nodes):
        try:
            self.vx_verify_io_fencing(callback_api, nodes)
            return True
        except (CallbackExecutionException, VcsCmdApiException,
                VCSRuntimeException):
            return False
