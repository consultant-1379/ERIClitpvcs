##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from litp.core.plugin import Plugin
from litp.core.execution_manager import CallbackTask
import vcsplugin.vcs_sg_helper
from vcsplugin.vcs_plugin import VcsPlugin

def gen_deactivate_task_mock(self, service, cluster_item_id):
    """
    Method to repolace the actual VcsServiceGroupHelper(VcsPlugin
    generate_deactivate_task method. Calls the original method and sets the
    deactivated property to true.
    The deactivated property is actually set in the callback method, so this
    is to replicate that in ATs (where callback methods are not executed)
    """
    helper = vcsplugin.vcs_sg_helper.VcsServiceGroupHelper(VcsPlugin)
    task = vcsplugin.vcs_sg_helper.VcsServiceGroupHelper.gen_deactivate_task_holder(helper, service, cluster_item_id)
    service.deactivated = 'true'
    return task

try:
    # set place holder for original VcsServiceGroupHelper._generate_deactivate_task
    setattr(vcsplugin.vcs_sg_helper.VcsServiceGroupHelper, "gen_deactivate_task_holder",
            vcsplugin.vcs_sg_helper.VcsServiceGroupHelper._generate_deactivate_task)
    # set VcsServiceGroupHelper._generate_deactivate_task to point to gen_deactivate_task_mock
    setattr(vcsplugin.vcs_sg_helper.VcsServiceGroupHelper, "_generate_deactivate_task",
            gen_deactivate_task_mock)
except:
    import traceback
    traceback.print_exc()

class SetDeactivated(Plugin):
   pass
