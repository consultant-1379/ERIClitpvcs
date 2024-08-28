import unittest
import mock
from vcsplugin.vcs_cluster import VcsCluster
from vcsplugin.vcs_sg_helper import VcsServiceGroupHelper
from vcsplugin.vcs_exceptions import VCSRuntimeException
from vcsplugin.vcs_plugin import VcsPlugin
from litp.core.execution_manager import CallbackExecutionException

def globals_side_effect():
    d = {"VcsCluster": mock.Mock().__class__,
         "VcsServiceGroupHelper": mock.Mock().__class__}
    return d

def val_model_no_errs_side_effect(plugin_api_context):
    errs = ["err", "err2"]
    return errs

def cre_conf_no_tasks_side_effect(plugin_api_context):
    tasks = ["t"]
    return tasks

def callback_side_effect(callback_api, *args, **kwargs):
    pass

def cre_class_mock(cl):
    mo = mock.Mock()
    mo.validate_model =\
        mock.Mock(side_effect=val_model_no_errs_side_effect)
    mo.create_configuration =\
        mock.Mock(side_effect=cre_conf_no_tasks_side_effect)
    mo.install_callback =\
        mock.Mock(side_effect=callback_side_effect)
    return mo

class TestVcsPlugin(unittest.TestCase):

    def setUp(self):
        pass

    @mock.patch('vcsplugin.vcs_plugin.VcsPlugin._create_class',
                mock.Mock(side_effect=cre_class_mock))
    def test_vcs_cluster(self):
        plugin_api_context_mock = mock.Mock(['query'])
        plugin_api_context_mock.query.return_value = []

        p = VcsPlugin()

        errs = p.validate_model(plugin_api_context_mock)
        t = p.create_configuration(plugin_api_context_mock)

        p.callback_method(None,
                          callback_class="VcsCluster",
                          callback_func="install_callback",
                          node="mn1")

        self.assertRaises(VCSRuntimeException,
                          p.callback_method, None,
                          callback_class=None,
                          callback_func="install_callback",
                          node="mn1")

        self.assertRaises(VCSRuntimeException,
                          p.callback_method, None,
                          callback_class="VcsCluster",
                          callback_func=None,
                          node="mn1")

        self.assertRaises(VCSRuntimeException,
                          p.callback_method, None,
                          callback_class="NotVcsCluster",
                          callback_func="install_callback",
                          node="mn1")
