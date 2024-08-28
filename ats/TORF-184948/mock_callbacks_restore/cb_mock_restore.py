import mock
from litp.core.plugin import Plugin
from litp.core.litp_logging import LitpLogger
log = LitpLogger()

import vcsplugin.vcs_sg_helper

try:
    setattr(vcsplugin.vcs_sg_helper.VcsServiceGroupHelper, "_generate_remove_standby_node_task",
            vcsplugin.vcs_sg_helper.VcsServiceGroupHelper.gen_remove_standby_task_holder)
    setattr(vcsplugin.vcs_sg_helper.VcsServiceGroupHelper, "_generate_add_new_standby_node",
            vcsplugin.vcs_sg_helper.VcsServiceGroupHelper.gen_add_standby_task_holder)
    setattr(vcsplugin.vcs_cluster.VcsCluster, "_create_vcs_poll_task",
            vcsplugin.vcs_cluster.VcsCluster.create_vcs_poll_task_holder)
except:
    import traceback
    traceback.print_exc()

class MockRestorePlugin(Plugin):
    pass

