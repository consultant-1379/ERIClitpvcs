##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import ConfigParser
import os

from litp.core.litp_logging import LitpLogger
from vcsplugin.vcs_exceptions import VCSConfigException

log = LitpLogger()


class VCSConfig(object):
    '''
    Read configuration VCS file and offers
    wrapper read_plugin_config function
    '''

    def __init__(self, config_file=None):
        '''
        Creates the config object

        :param config_file: Path to the configuration file
        :type config_file: string
        '''
        if config_file is None:
            config_file = "vcs_rpms.conf"
        self.config_file = config_file
        self.config = ConfigParser.ConfigParser()

        # config.read doesn't raise an exception when it fails,
        # so need to check return type is not of len zero
        log.trace.debug(os.path.dirname(__file__))
        dataset = self.config.read(os.path.join(os.path.dirname(__file__),
                                                self.config_file))
        if len(dataset) == 0:
            log.trace.error("Failed to open %s" % self.config_file)
            raise VCSConfigException("VCSConfig failed to init")

    def read_plugin_config(self, section, option):
        """
        Read an option from the current config file.
        Raise an exception if it fails

        :param section: Section to read from the config file
        :type section: string
        :param option: Option to read from the config file
        :type option: string
        """
        try:
            value = self.config.get(section, option)
            if len(value) == 0:
                log.trace.error("Unable to read option {0} from section {1}"
                                  "of VCS plugin config file".format(section,
                                                                option))
                raise VCSConfigException("Failed to read plugin config")
        except ConfigParser.Error as error:
            # log.trace.exception("%s : read_config exception: %s"
            #% (self.component, error))
            log.trace.error("Exception Error {0} happened while reading"
                            " option {0} from section {1} of VCS"
                            " plugin config file".format(
                                                  error,
                                                  section,
                                                  option)
                            )
            raise VCSConfigException("Failed to read plugin config")
        return value
