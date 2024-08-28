import mock
from litp.core.plugin import Plugin
from litp.core.litp_logging import LitpLogger
log = LitpLogger()

import vcsplugin.vcs_online_helper

try:
    setattr(vcsplugin.vcs_online_helper.VcsSGOnlineHelper, "_generate_online_task",
            vcsplugin.vcs_online_helper.VcsSGOnlineHelper.gen_online_task_holder)
except:
    import traceback
    traceback.print_exc()

class OnlineMockRestorePlugin(Plugin):
    pass
