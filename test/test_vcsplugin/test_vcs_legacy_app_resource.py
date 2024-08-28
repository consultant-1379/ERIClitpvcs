##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from vcsplugin.vcs_plugin import VcsPlugin
from base_vcs_integration import VCSIntegrationBase
from vcsplugin.legacy.vcs_app_resource import VcsApplicationLegacyResource
import mock


class TestVCSPluginIntegration(VCSIntegrationBase):

    def setUp(self):
        super(TestVCSPluginIntegration, self).setUp()

    def test_app_resource(self):
        self.setup_model()
        ips = self._add_service_to_model(1, no_of_ips=2)
        vcs_app_helper = VcsApplicationLegacyResource(VcsPlugin)
        vcs_app_helper._vcs_api = mock.Mock()
        vcs_app_helper._vcs_api.readable_conf = mock.MagicMock()

        pre_tasks = []
        post_tasks = []
        for cluster in self.context_api.query('vcs-cluster'):
            for service in cluster.services:
                service_pre_tasks, service_post_tasks = vcs_app_helper.create_configuration(
                    self.context_api, cluster, service)
                pre_tasks.extend(service_pre_tasks)
                post_tasks.extend(service_post_tasks)
                task = post_tasks[0]
                vcs_app_helper.create_app_callback(
                    self.callback_api,
                    vpaths=task.kwargs['vpaths'])
