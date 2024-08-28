import mock
from litp.core.plugin import Plugin
from litp.core.litp_logging import LitpLogger
log = LitpLogger()

from litp.core.execution_manager import CallbackTask
import vcsplugin.vcs_online_helper

def mock_online_callback(self, callback_api, *args, **kwargs):
    pass


def gen_online_mock(self, cluster, service):
    service_vpath = service.get_vpath()

    vcs_grp_name = self.get_group_name(service.item_id, cluster.item_id)

    task = CallbackTask(service,
                        'Bring VCS service group "{0}" online'.format(
                            vcs_grp_name),
                        self.plugin().mock_online_callback,
                        callback_class="OnlineMockPlugin",
                        callback_func="mock_online_callback")
    return task

try:
    setattr(vcsplugin.vcs_online_helper.VcsSGOnlineHelper, "gen_online_task_holder",
            vcsplugin.vcs_online_helper.VcsSGOnlineHelper._generate_online_task)
    setattr(vcsplugin.vcs_online_helper.VcsSGOnlineHelper, "_generate_online_task", gen_online_mock)
    setattr(vcsplugin.vcs_plugin.VcsPlugin, "mock_online_callback", mock_online_callback)
except:
    import traceback
    traceback.print_exc()

class OnlineMockPlugin(Plugin):
    def mock_online_callback(self, api):
        pass
