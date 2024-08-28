##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import logging
import logging.handlers

# Formatting Definitions
VCS_API_LOG_TAG = "vcs_cmd_api"
VCS_SYSLOG_FORMAT = "[%(levelname)s](%(thread)d) {0}: %(message)s"

SYSLOG_LINUX_SOCKET = "/dev/log"

class NullHandler(logging.Handler):
    """
    Does not emit any output.
    logging.NullHandler was only introduced on Python 2.7
    """
    def emit(self, record): pass


class VcsApiLogger(object):
    """
    Offer a basic logger to be used by vcs_cmd_api's.
    """
    @staticmethod
    def get_syslog_format(log_tag):
        if log_tag:
            log_tag = "{0}->{1}".format(VCS_API_LOG_TAG, log_tag)

        return VCS_SYSLOG_FORMAT.format(log_tag)

    @staticmethod
    def get_handler(log_tag, log_level):
        try:
            log_tag = VcsApiLogger.get_syslog_format(log_tag)
            handler = logging.handlers.SysLogHandler(SYSLOG_LINUX_SOCKET,
                                        logging.handlers.SysLogHandler.LOG_USER)
            handler.setFormatter(logging.Formatter(log_tag))
            handler.setLevel(log_level)
        except:
            handler = NullHandler()

        return handler

    @staticmethod
    def get_logger(log_tag="VcsApiLogger", log_level=logging.INFO):
        """
        Returns a new logger instance to be used by VCS API's
        :param verbose: boolean True, if to activate verbose logging
        :return: logger instance
        """
        root_logger = logging.getLogger()
        root_logger.addHandler(VcsApiLogger.get_handler(log_tag, log_level))
        root_logger.setLevel(logging.NOTSET)

        return root_logger
