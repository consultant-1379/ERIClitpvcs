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
from litp.core.task import CallbackTask
from litp.core.extension import ModelExtension
from litp.core.model_type import ItemType


class TestExtension(ModelExtension):
    def define_item_types(self):
        return [
            ItemType(
                "mock-service",
                extend_item="service",
            )
        ]

class TestPlugin(Plugin):

    def validate_model(self, plugin_api_context):
        return []

    def create_configuration(self, plugin_api_context):
        tasks = []
        clusters = plugin_api_context.query('vcs-cluster')
        for cluster in clusters:
            for node in cluster.nodes:
                for svc in node.query("mock-service"):
                    tasks.append(CallbackTask(svc,
                        "Mock service task on node {0}".format(node.hostname),
                        self.mock_task,
                        service_name=svc.service_name))
        return tasks

    def mock_task(self, callback_api, service_name):
        return
