#! /usr/bin/env python

##############################################################################
# COPYRIGHT Ericsson AB 2015
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

"""
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!
!! THIS UTITITY MUST ONLY BE USED AS DOCUMENTED AND UPON LITP SUPPORT REQUEST!
!!
!! PLEASE, CHECK DOCUMENTATION BEFORE YOU RUN THIS UITILITY.
!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
"""

import os
import sys
import shutil
import socket
import argparse
import functools
import subprocess
import logging
import logging.handlers

# =========================================================
# LITP imports
# =========================================================
sys.path.append('/opt/ericsson/nms/litp')
from litp.core.rpc_commands import PuppetCatalogRunProcessor

# =========================================================
# Globals
# =========================================================
# External Commands
MCO = '/usr/bin/mco'

# Others
UTILITY_VERBOSE_LEVEL = logging.DEBUG
UTILITY_NAME = os.path.basename(__file__)
UTILITY_BACKUP_DIR = '/var/opt/ericsson'
VCS_TEMPLATES_DIR = '/opt/ericsson/nms/litp/etc/puppet/modules/vcs/templates'
GABTAB_CONTENT_TEMPLATE = '/sbin/gabconfig -c -n<%= {vcs_seed_threshold} %>\n'

# The modeled vcs_seed_threshold value is completely
# ignored. The new value is calculated using number
# of hostnames in the 'hostnames' hash created
# by the VCS Plugin Configure task as this must
# reflect the modeled number of nodes in the cluster.
# As this script is expected to used when on site is
# gone, there will be only half of the original
# (currently modeled) number of nodes, so the
# original internal formula is adapted to account
# for it: (N/2)/2 + 1
VCS_SEED_THRESHOLD_FORMULA = 'Integer(@hostnames.length/4) + 1'


# =========================================================
# Exceptions
# =========================================================
class NoUserConfirmationException(SystemExit):
    exit_code = 1


class InvalidUsageException(SystemExit):
    exit_code = 2


class FailToProcessRequestException(SystemExit):
    exit_code = 3


class FailToExecuteCommandException(SystemExit):
    exit_code = 4


class InterruptedByTheUserException(SystemExit):
    exit_code = 5


# =========================================================
# Decorators
# =========================================================
def keyboard_interruptable(callback=None):
    """
    Decorator to care about CTRL-C keyboard interruption by
    the user.
    :param callback: The callback function to call, can be None.
    """
    def actual_decorator(interruptable_method):
        """
        Decorator
        :param interruptable_method: Method to wrap
        :return:
        """
        @functools.wraps(interruptable_method)
        def wrapper(self, *args, **kwargs):
            """
            Wrapper
            :param args: args
            :param kwargs: kwargs
            :return:
            """
            try:
                return interruptable_method(self, *args, **kwargs)
            except KeyboardInterrupt:
                try:
                    if callback:
                        callback(self)
                finally:
                    raise InterruptedByTheUserException()

        return wrapper

    return actual_decorator


# =========================================================
# Logging Helper Classes
# =========================================================
class ConsoleFormatter(logging.Formatter):

    def format(self, record):
        """
        Formats the output message, based on its level.
        :param record: operand to string to be formatted
        :return: formatted message
        """
        if record.levelno == logging.INFO:
            self._fmt = '==> %(message)s'
        else:
            self._fmt = '==> %(levelname)s: %(message)s'

        return logging.Formatter.format(self, record)


class SetGabTabLogger(object):

    SYSLOG_FORMAT = '[%(levelname)s] {0}: %(message)s'.format(UTILITY_NAME)

    @staticmethod
    def get_logger(verbose):
        """
        Attachs and configure LITP loggers.
        :param verbose: boolean True, if to activate verbose logging
        :return: 'litp.trace' logger instance
        """
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(ConsoleFormatter())
        console.setLevel(logging.INFO)

        syslog = logging.handlers.SysLogHandler('/dev/log',
                                    logging.handlers.SysLogHandler.LOG_USER)
        syslog.setFormatter(logging.Formatter(SetGabTabLogger.SYSLOG_FORMAT))
        if verbose:
            syslog.setLevel(UTILITY_VERBOSE_LEVEL)
        else:
            syslog.setLevel(logging.INFO)

        root_logger = logging.getLogger()
        root_logger.addHandler(syslog)
        root_logger.setLevel(logging.NOTSET)

        litp_logger = logging.getLogger('litp')
        litp_logger.propagate = False
        litp_logger.addHandler(syslog)
        litp_logger.setLevel(logging.NOTSET)

        litp_trace_logger = logging.getLogger('litp.trace')
        litp_trace_logger.propagate = True
        litp_trace_logger.addHandler(console)
        litp_trace_logger.setLevel(logging.NOTSET)

        return litp_trace_logger


# =========================================================
# SetGabTab Class
# =========================================================
class SetGabtab(object):

    EXPECTED_CONFIRMATION = 'YeS'
    CONFIRMATION_PROMPT = 'Enter [{0}] to confirm request to: '.format(
                                            EXPECTED_CONFIRMATION)

    BACKUP_FILE = '{0}/gabtab.erb.bk'.format(UTILITY_BACKUP_DIR)
    GABTAB_TEMPLATE_FILE = '{0}/gabtab.erb'.format(VCS_TEMPLATES_DIR)
    GABTAB_CONTENT = GABTAB_CONTENT_TEMPLATE.format(\
                        vcs_seed_threshold=VCS_SEED_THRESHOLD_FORMULA)

    def __init__(self, logger, undo):
        """
        Initializes instance
        :param logger: logger to be used.
        :param undo: boolean True, if to issue the undo operation
                             False, otherwise.
        """
        self.logger = logger
        self.undo = undo

    def _process_request_interrupted(self):
        """
        Callback to treat user CTRL-C interruption
        during request processing.
        """
        self.logger.warning('Execution interrupted (CTRL-C) by the user!')

    @keyboard_interruptable(callback=_process_request_interrupted)
    def process_request(self):
        """
        Entry-point to process the user's requested operation.
        """
        self._validate_request()
        self._request_user_confirmation()
        self._execute_request()
        self._sync_puppet_catalog()

    def _backup_file_found(self):
        """
        Verify the existence of the backup file
        :return: boolean, True is exists, False otherwise
        """
        return os.path.isfile(self.BACKUP_FILE)

    def _validate_request(self):
        """
        Validate user's request
        """
        error_msg = None

        if self._backup_file_found():
            if not self.undo:
                error_msg = 'It seems {0} has already been applied! ' \
                        'Undo it first.'.format(UTILITY_NAME)
        else:
            if self.undo:
                error_msg = 'It seems {0} has NOT been applied previously! ' \
                        'Nothing to undo.'.format(UTILITY_NAME)

        if error_msg:
            self.logger.error(error_msg)
            raise InvalidUsageException()

    def _get_user_input(self):
        """
        Get User input.
        :return: string input by the user
        """
        return raw_input()

    def _request_user_confirmation(self):
        """
        Request user confirmation to any operation being requested.
        """
        if self.undo:
            operation = 'Undo'
        else:
            operation = 'Apply'

        self.logger.info(self.CONFIRMATION_PROMPT + operation)
        user_answer = self._get_user_input()
        self.logger.info('Your answer was: {0}'.format(user_answer))
        if user_answer != self.EXPECTED_CONFIRMATION:
            self.logger.info('Request NOT confirmed. Aborting execution!')
            raise NoUserConfirmationException()

    def _execute_request(self):
        """
        Executes the user requested operation based
        on the undo attribute.
        """
        if self.undo:
            self._undo_set_gabtab()
        else:
            self._set_gabtab()

    def _get_running_nodes(self):
        """
        Get nodes known by MCollective as being running.
        :return: list(str)
        """
        hosts = self._exec_command([MCO, 'find']).split()
        ms = socket.gethostname()
        if ms in hosts:
            hosts.remove(ms)
        return hosts

    def _sync_puppet_catalog(self):
        """
        Synchronize Puppet catalog by requesting
        to be restored when this scripts is issued with undo.
        """
        puppet = PuppetCatalogRunProcessor()
        catalog = puppet.update_config_version()
        puppet.trigger_and_wait(catalog, self._get_running_nodes())

    def _copy_file(self, source, dest):
        """
        Copy source file into dest file.
        copy2 tries to preserve metadata as 'cp -p'.
        :param source: source file
        :param dest: destination file
        """
        try:
            shutil.copy2(source, dest)
        except IOError as e:
            msg = 'Unable to copy file {0} to {1}!'.format(source, dest)
            self._log_error(msg, e)
            raise FailToProcessRequestException()

    def _remove_file(self, target):
        """
        Delete file from filesystem.
        :param target: target file
        """
        try:
            os.remove(target)
        except IOError as e:
            msg = 'Unable to remove file {0}!'.format(target)
            self._log_error(msg, e)
            raise FailToProcessRequestException()

    def _backup_gabtab_template(self):
        """
        Backup the gabtab puppet template to allow it
        to be restored when this scripts is issued with undo.
        """
        self._copy_file(self.GABTAB_TEMPLATE_FILE, self.BACKUP_FILE)

    def _restore_gabtab_template(self):
        """
        Restore the backup of the gabtab puppet template
        created by this script over the modified one.
        """
        self._copy_file(self.BACKUP_FILE, self.GABTAB_TEMPLATE_FILE)
        self._remove_file(self.BACKUP_FILE)

    def _modify_gabtab_template(self):
        """
        Modify gabtab template with the expected VCS
        gaconfig command to set seeding threshold.
        The content for the new gabtab Puppet template
        is provided by: SetGabtab.GABTAB_CONTENT
        """
        with open(self.GABTAB_TEMPLATE_FILE, 'w') as template:
            template.write(self.GABTAB_CONTENT)

    def _set_gabtab(self):
        """
        Force the a new value to be used for vcs_seed_threshold outside
        of the normal LITP configuration.
        """
        self._backup_gabtab_template()
        self._modify_gabtab_template()

    def _undo_set_gabtab(self):
        """
        Undo all the modifications applied by this script.
        """
        self._restore_gabtab_template()

    def _is_executable(self, file_path):
        """
        Check if a file is executable.
        :param filepath: path to the file to be checked
        :return: boolean indicating if the file is executable or not
        """
        return os.path.isfile(file_path) and os.access(file_path, os.X_OK)

    def _exec_command(self, command):
        """
        Handles the execution of an external command.
        :param command: command to execute
        """
        try:
            self.logger.debug('Execute command: {0}'.format(command))

            p = subprocess.Popen(command,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            stdout = p.communicate()[0].strip()
            if p.returncode != 0:
                raise IOError(p.returncode, stdout, command)

            return stdout

        except IOError as e:
            msg = 'Failed to execute command: {0}. ErrorCode: {1}'.format(
                                                         command, e.errno)
            self._log_error(msg, e)
            raise FailToExecuteCommandException()

    def _log_error(self, message, exception):
        self.logger.exception(message)
        for line in exception.strerror.splitlines():
            self.logger.exception(line)


# =============================================================================
# Entry-Point Helper Class
# =============================================================================
class EntryPoint(object):

    @staticmethod
    def _create_parser(utility_name):
        """
        Create a parser to check the input arguements
        :returns: Instance of ArgumentParser
        """
        desc = 'Utility to force vcs_seed_threshold without change the model.'
        parser = argparse.ArgumentParser(prog=utility_name, description=desc)

        parser.add_argument('-v', '--verbose', dest='verbose',
                            action='store_true',
                            help='verbose Syslog logging. ' \
                                 'No effect on Console.')

        parser.add_argument('-u', '--undo', dest='undo', action='store_true',
                            help='undo all the effects of this utility.')

        return parser

    @staticmethod
    def main(args):
        """
        Main application function
        :param args: arguments to be processed
        """
        parser = EntryPoint._create_parser(args[0])
        parsed_args = parser.parse_args(args[1:])
        logger = SetGabTabLogger.get_logger(parsed_args.verbose)

        logger.info('Executing: {0}'.format(' '.join(args)))
        if not os.path.exists(UTILITY_BACKUP_DIR):
            logger.info('Directory {0} not found, creating!'.format(
                                                UTILITY_BACKUP_DIR))
            os.makedirs(UTILITY_BACKUP_DIR, 0755)

        set_gabtab = SetGabtab(logger, parsed_args.undo)
        set_gabtab.process_request()
        logger.info('Gabtab successfully changed.')


# =============================================================================
# ENTRY-POINT
# =============================================================================
if __name__ == '__main__':
    EntryPoint.main(sys.argv)
