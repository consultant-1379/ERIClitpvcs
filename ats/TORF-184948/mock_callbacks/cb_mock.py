import mock
from litp.core.plugin import Plugin
from litp.core.litp_logging import LitpLogger
log = LitpLogger()

from litp.core.execution_manager import CallbackTask
import vcsplugin.vcs_sg_helper

def mock_remove_callback(self, callback_api, *args, **kwargs):
    pass

def mock_add_callback(self, callback_api, *args, **kwargs):
    pass

def mock_check_vcs_callback(self, callback_api, *args, **kwargs):
    pass


def gen_remove_mock(self, service, cluster):
    service_vpath = service.get_vpath()
    vcs_grp_name = self.get_group_name(service.item_id, cluster.item_id)
    description = ('Remove standby node from clustered '
                   'service "{0}"'.format(vcs_grp_name))
    task = CallbackTask(service,
                        description,
                        self.plugin().mock_remove_callback,
                        callback_class="MockPlugin",
                        callback_func="mock_remove_callback")
    return task

def gen_add_mock(self, service, cluster):
    service_vpath = service.get_vpath()
    vcs_grp_name = self.get_group_name(service.item_id, cluster.item_id)
    description = ('Add standby node to clustered '
                   'service "{0}"'.format(vcs_grp_name))
    task = CallbackTask(service,
                        description,
                        self.plugin().mock_add_callback,
                        callback_class="MockPlugin",
                        callback_func="mock_add_callback")
    return task

def gen_check_vcs_mock(self, nodes, cluster):
    cluster_vpath = cluster.get_vpath()
    description = ('Check VCS engine is running on cluster "{0}"'.format(
                   cluster.item_id))
    task = CallbackTask(cluster,
                        description,
                        self.plugin().mock_check_vcs_callback,
                        callback_class="MockPlugin",
                        callback_func="mock_check_vcs_callback")
    return task

try:
    setattr(vcsplugin.vcs_sg_helper.VcsServiceGroupHelper, "gen_remove_standby_task_holder",
            vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._generate_remove_standby_node_task)
    setattr(vcsplugin.vcs_sg_helper.VcsServiceGroupHelper, "_generate_remove_standby_node_task", gen_remove_mock)
    setattr(vcsplugin.vcs_sg_helper.VcsServiceGroupHelper, "gen_add_standby_task_holder",
            vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._generate_add_new_standby_node)
    setattr(vcsplugin.vcs_sg_helper.VcsServiceGroupHelper, "_generate_add_new_standby_node", gen_add_mock)
    setattr(vcsplugin.vcs_cluster.VcsCluster, "create_vcs_poll_task_holder",
            vcsplugin.vcs_cluster.VcsCluster._create_vcs_poll_task)
    setattr(vcsplugin.vcs_cluster.VcsCluster, "_create_vcs_poll_task", gen_check_vcs_mock)
    setattr(vcsplugin.vcs_plugin.VcsPlugin, "mock_remove_callback", mock_remove_callback)
    setattr(vcsplugin.vcs_plugin.VcsPlugin, "mock_add_callback", mock_add_callback)
    setattr(vcsplugin.vcs_plugin.VcsPlugin, "mock_check_vcs_callback", mock_check_vcs_callback)
except:
    import traceback
    traceback.print_exc()

class MockPlugin(Plugin):
    def mock_remove_callback(self, api):
        pass

    def mock_add_callback(self, api):
        pass

