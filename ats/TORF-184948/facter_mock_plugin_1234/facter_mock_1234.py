from litp.core.plugin import Plugin
import vcsplugin.vcs_cluster

def mock_get_etc_llthosts(self):
    return (0, '0 mn4\n1 mn3\n2 mn2\n3 mn1', '')

try:
  setattr(vcsplugin.vcs_cluster.VcsCmdApi, "get_etc_llthosts", mock_get_etc_llthosts)
except:
    import traceback
    traceback.print_exc()

class FacterMockPlugin(Plugin):
    pass
