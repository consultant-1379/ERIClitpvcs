##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import ConfigParser
import unittest
import os
from StringIO import StringIO

from vcsplugin import vcs_config
from vcsplugin.vcs_exceptions import VCSConfigException

vcs_rpms_conf_path = os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'vcsplugin')

class TestVCSConfig(unittest.TestCase):
    def setUp(self):
        self.vcsconfig = vcs_config.VCSConfig()

    def test_read_config(self):
        vcs_rpms = self.vcsconfig.read_plugin_config("vcs", "rpms")
        self.assertEquals(vcs_rpms,
                          'VRTSveki VRTSperl VRTSvlic VRTSspt VRTSllt VRTSgab '
                          'VRTSvxfen VRTSamf VRTSpython VRTSvcs VRTSvcsag '
                          'VRTSvcsea VRTSsfmh VRTSvbs VRTSvcswiz VRTSsfcpi')

        self.assertEquals(16, len(vcs_rpms.split()))
        self.assertRaises(VCSConfigException,
                        self.vcsconfig.read_plugin_config, "vcs", "blabla")

        sfha_rpms = self.vcsconfig.read_plugin_config("sfha", "rpms")
        self.assertEquals(sfha_rpms,
                          'VRTSveki VRTSperl VRTSvlic VRTSspt VRTSvxvm '
                          'VRTSaslapm VRTSvxfs VRTSfssdk VRTSllt '
                          'VRTSgab VRTSvxfen VRTSamf VRTSpython VRTSvcs '
                          'VRTSvcsag VRTSvcsea VRTSdbed VRTSodm VRTSsfmh '
                          'VRTSvbs VRTSvcswiz VRTSsfcpi VRTSglm VRTScavf '
                          'VRTSgms')

        self.assertEquals(25, len(sfha_rpms.split()))
        self.assertRaises(VCSConfigException,
                          self.vcsconfig.read_plugin_config, "sfha", "blabla")

    def test_vcs_config(self):
        self.assertRaises(VCSConfigException, vcs_config.VCSConfig, "file_not_exist")

    def test_vcs_config_empty_entry(self):
        vcs_empty_conf = 'vcs_empty.pyc'
        with open(vcs_rpms_conf_path + '/' + vcs_empty_conf , 'w') as f1:
            f1.write('[vcs]\n')
            f1.write('val1=Val1_nonempty\n')
            f1.write('valempty=\n')
            f1.write('val2=Val2_nonempty\n')

        self.vcsconfig_empty = vcs_config.VCSConfig(vcs_empty_conf)
        self.assertRaises(VCSConfigException,
                                self.vcsconfig_empty.read_plugin_config, "vcs", "valempty")
