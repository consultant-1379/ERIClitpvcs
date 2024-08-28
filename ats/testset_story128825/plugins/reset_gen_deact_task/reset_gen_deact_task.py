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
import vcsplugin.vcs_sg_helper
from vcsplugin.vcs_plugin import VcsPlugin

try:
    # Reset VcsServiceGroupHelper._generate_deactivate_task to point to actual
    # method which is pointed to by gen_deactivate_task_holder
    setattr(vcsplugin.vcs_sg_helper.VcsServiceGroupHelper, "_generate_deactivate_task",
            vcsplugin.vcs_sg_helper.VcsServiceGroupHelper.gen_deactivate_task_holder)
except:
    import traceback
    traceback.print_exc()

class ResetGenDeactivateTask(Plugin):
   pass
