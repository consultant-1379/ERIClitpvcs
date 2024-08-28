from litp.core.plugin import Plugin
import vcsplugin.vcs_cluster

def mock_get_etc_llthosts(self):
    return (0, '1 mn1\n0 mn2', '')

try:
  setattr(vcsplugin.vcs_cluster.VcsCmdApi, "get_etc_llthosts", mock_get_etc_llthosts)
except:
    import traceback
    traceback.print_exc()

class Torf389839PatchMcoAgent(Plugin):
    def create_configuration(self, plugin_api_context):
        return []
