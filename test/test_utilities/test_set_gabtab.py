##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import mock
import unittest
import sys
import logging

from utilities import set_gabtab
from utilities.set_gabtab import InterruptedByTheUserException

COMMON_LOGGING_LEVELS = (
    logging.CRITICAL,
    logging.ERROR,
    logging.WARNING,
    logging.INFO,
    logging.DEBUG,
    logging.NOTSET
)

#################################
# TODO: 1. Refactory to use decoration for setgabtab_mock on all methods
#       2. IOError appropriate mocking
#       3. Check number of mock_calls
#       4. Validate raising other IO Exceptions
#       5. Define tests own constants instead of using
#          set_gabtab.py ones
#       6. Check for no return methods too
#       7. Tests for TestSetGabTab_EntryPoint
#       8. Tests for Keyboard Interruption

class TestSetGabTab_ConsoleFormatter(unittest.TestCase):

    @mock.patch('logging.Formatter.format')
    def _check_format_result(self, level, expected_format, format_mock):
        format_mock.side_effect = lambda _self, _record: (_self, _record)
        formatter = set_gabtab.ConsoleFormatter()
        record = mock.MagicMock(levelno = level)

        #--- Test Target
        _self, _record = formatter.format(record)

        self.assertEqual(formatter, _self)
        self.assertEqual(record, _record)
        self.assertEqual(expected_format, formatter._fmt)

    def test_format(self):
        for level in COMMON_LOGGING_LEVELS:
            if level == logging.INFO:
                expected_format = '==> %(message)s'
            else:
                expected_format = '==> %(levelname)s: %(message)s'
            self._check_format_result(level, expected_format)


class TestSetGabTab_SetGabTabLogger(unittest.TestCase):

    @mock.patch('utilities.set_gabtab.logging')
    @mock.patch('utilities.set_gabtab.ConsoleFormatter')
    def _check_get_logger_internals(self, verbose, expected_console_formatter,
                                                   logging_mock):
        # Console Handler
        expected_console_formatter.return_value = expected_console_formatter
        expected_console_handler = mock.MagicMock(
                stream=sys.stderr,
                level=logging_mock.INFO,
                formatter=expected_console_formatter)

        # Syslog Handler
        expected_syslog_formatter = mock.MagicMock(
                format=set_gabtab.SetGabTabLogger.SYSLOG_FORMAT)
        expected_syslog_handler = mock.MagicMock(
                address=('/dev/log'),
                facility=logging_mock.handlers.SysLogHandler.LOG_USER,
                level=set_gabtab.UTILITY_VERBOSE_LEVEL if verbose else
                                                            logging_mock.INFO,
                formatter=expected_syslog_formatter)

        # root Logger
        expected_root_logger = mock.MagicMock()
        expected_root_logger.configure_mock(
                name='',
                handler=expected_syslog_handler,
                level=logging_mock.NOTSET)

        # litp Logger
        expected_litp_logger = mock.MagicMock()
        expected_litp_logger.configure_mock(
                name='litp',
                propagate=False,
                handler=expected_syslog_handler,
                level=logging_mock.NOTSET)

        # litp.trace Logger
        expected_litp_trace_logger = mock.MagicMock()
        expected_litp_trace_logger.configure_mock(
                name='litp.trace',
                propagate=True,
                handler=expected_console_handler,
                level=logging_mock.NOTSET)

        logging_mock.StreamHandler.return_value = expected_console_handler
        logging_mock.Formatter.return_value = expected_syslog_formatter
        logging_mock.handlers.SysLogHandler.return_value = \
                                                    expected_syslog_handler
        logging_mock.getLogger.side_effect = [expected_root_logger,
                                              expected_litp_logger,
                                              expected_litp_trace_logger]

        #--- Test Target
        logger = set_gabtab.SetGabTabLogger.get_logger(verbose)

        # Check return
        logging_mock.assertEqual(expected_litp_trace_logger, logger)

        # Check ConsoleFormatter calls
        expected_calls = [
            mock.call.ConsoleFormatter()]
        expected_console_formatter.assert_has_calls(expected_calls)

        # Check Console Handler calls
        expected_calls = [
            mock.call.setFormatter(expected_console_handler.formatter),
            mock.call.setLevel(expected_console_handler.level)]
        expected_console_handler.assert_has_calls(expected_calls)

        # Check Syslog Handler calls
        expected_calls = [
            mock.call.setFormatter(expected_syslog_handler.formatter),
            mock.call.setLevel(expected_syslog_handler.level)]
        expected_syslog_handler.assert_has_calls(expected_calls)

        # Check Logging calls
        expected_calls = [
            mock.call.StreamHandler(expected_console_handler.stream),
            mock.call.handlers.SysLogHandler(expected_syslog_handler.address,
                                        expected_syslog_handler.facility),
            mock.call.Formatter(expected_syslog_formatter.format),
            mock.call.getLogger(),
            mock.call.getLogger(expected_litp_logger.name),
            mock.call.getLogger(expected_litp_trace_logger.name)]
        logging_mock.assert_has_calls(expected_calls)

    def test_get_logger(self):

        self._check_get_logger_internals(True)
        self._check_get_logger_internals(False)


class TestSetGabTab_SetGabtab(unittest.TestCase):

    def _attach_method(self, mock_instance, method_name, method):
        def _method(*args, **kwargs):
            return method(mock_instance, *args, **kwargs)
        setattr(mock_instance, method_name, _method)

    def _wrap_methods(self, mock_instance, *methods_name):
        for method_name in methods_name:
            method = getattr(set_gabtab.SetGabtab, method_name)
            self._attach_method(mock_instance, method_name, method)

    def test_process_request_interrupted(self):
        setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
        self._wrap_methods(setgabtab_mock, '_process_request_interrupted')
        setgabtab_mock.configure_mock(
            logger=mock.MagicMock())
        setgabtab_mock._process_request_interrupted()
        warning_msg='Execution interrupted (CTRL-C) by the user!'
        expected_calls = [
            mock.call.logger.warning(warning_msg)]
        setgabtab_mock.assert_has_calls(expected_calls)

    def test_process_request(self):
        setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
        self._wrap_methods(setgabtab_mock, 'process_request')
        setgabtab_mock.process_request()
        expected_calls = [
            mock.call._validate_request(),
            mock.call._request_user_confirmation(),
            mock.call._execute_request(),
            mock.call._sync_puppet_catalog()]
        setgabtab_mock.assert_has_calls(expected_calls)

    def test_process_request_interrupt_exception(self):
        def side_effect():
            raise KeyboardInterrupt()
        setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
        self._wrap_methods(setgabtab_mock, 'process_request')
        setgabtab_mock._validate_request.side_effect = side_effect
        self.assertRaises(InterruptedByTheUserException,
                          setgabtab_mock.process_request)
        expected_calls = [
            mock.call._validate_request()]
        setgabtab_mock.assert_has_calls(expected_calls)

    def test_backup_file_found(self):

        @mock.patch('os.path.isfile')
        def _check_backup_file_found(backup_file_exists, isfile_mock):
            setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
            setgabtab_mock.configure_mock(
                BACKUP_FILE=set_gabtab.SetGabtab.BACKUP_FILE)
            self._wrap_methods(setgabtab_mock, '_backup_file_found')
            isfile_mock.return_value = backup_file_exists
            result = setgabtab_mock._backup_file_found()
            self.assertEqual(backup_file_exists, result)
            expected_calls = [
                mock.call.logger.error(set_gabtab.SetGabtab.BACKUP_FILE)]
            isfile_mock.assert_has_calls(expected_calls)

        # Backup does not exist
        _check_backup_file_found(False)

        # Backup exists
        _check_backup_file_found(True)

    def test_validate_request(self):

        def _check_validate_request(backup_file_exists, undo, error_msg):
            setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
            setgabtab_mock.configure_mock(
                _backup_file_found=\
                    mock.MagicMock(return_value=backup_file_exists),
                undo=undo,
                logger=mock.MagicMock())
            self._wrap_methods(setgabtab_mock, '_validate_request')

            if error_msg:
                self.assertRaises(set_gabtab.InvalidUsageException,
                                  setgabtab_mock._validate_request)
                expected_calls = [
                    mock.call._backup_file_found(),
                    mock.call.logger.error(error_msg)]
                setgabtab_mock.assert_has_calls(expected_calls)
            else:
                setgabtab_mock._validate_request()
                expected_calls = [
                    mock.call._backup_file_found()]
                setgabtab_mock.assert_has_calls(expected_calls)

        # Backup exists is False and undo is False
        _check_validate_request(False, False, None)

        # Backup exists is False and undo is True
        error_msg = 'It seems {0} has NOT been applied previously! ' \
                    'Nothing to undo.'.format(set_gabtab.UTILITY_NAME)
        _check_validate_request(False, True, error_msg)

        # Backup exists is True and undo is False
        error_msg = 'It seems {0} has already been applied! ' \
                    'Undo it first.'.format(set_gabtab.UTILITY_NAME)
        _check_validate_request(True, False, error_msg)

        # Backup exists is True and undo is True
        _check_validate_request(True, True, None)

    def test_request_user_confirmation(self):

        def _check_request_user_confirmation(undo, user_answer):
            setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
            setgabtab_mock.configure_mock(
                EXPECTED_CONFIRMATION=\
                    set_gabtab.SetGabtab.EXPECTED_CONFIRMATION,
                CONFIRMATION_PROMPT=\
                    set_gabtab.SetGabtab.CONFIRMATION_PROMPT,
                undo=undo,
                logger=mock.MagicMock())
            setgabtab_mock._get_user_input.return_value = user_answer
            self._wrap_methods(setgabtab_mock, '_request_user_confirmation')

            if undo:
                operation = 'Undo'
            else:
                operation = 'Apply'

            if user_answer == set_gabtab.SetGabtab.EXPECTED_CONFIRMATION:
                setgabtab_mock._request_user_confirmation()
                expected_calls = [
                    mock.call.logger.info(
                        set_gabtab.SetGabtab.CONFIRMATION_PROMPT + operation),
                    mock.call._get_user_input(),
                    mock.call.logger.info('Your answer was: {0}'.format(
                        user_answer))]
                setgabtab_mock.assert_has_calls(expected_calls)
            else:
                self.assertRaises(set_gabtab.NoUserConfirmationException,
                                  setgabtab_mock._request_user_confirmation)
                expected_calls = [
                    mock.call.logger.info(
                        set_gabtab.SetGabtab.CONFIRMATION_PROMPT + operation),
                    mock.call._get_user_input(),
                    mock.call.logger.info(
                        'Your answer was: {0}'.format(user_answer)),
                    mock.call.logger.info(
                        'Request NOT confirmed. Aborting execution!')]
                setgabtab_mock.assert_has_calls(expected_calls)

        # Undo False and User answer 'no'
        _check_request_user_confirmation(False, 'no')

        # Undo False and User answer 'YeS'
        _check_request_user_confirmation(False, 'YeS')

        # Undo True and User answer 'no'
        _check_request_user_confirmation(True, 'no')

        # Undo True and User answer 'Yes'
        _check_request_user_confirmation(True, 'YeS')

    def test_execute_request(self):

        def _check_request_user_confirmation(undo):
            setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
            setgabtab_mock.configure_mock(
                undo=undo)
            self._wrap_methods(setgabtab_mock, '_execute_request')

            setgabtab_mock._execute_request()
            if undo:
                expected_calls = [
                    mock.call._undo_set_gabtab()]
            else:
                expected_calls = [
                    mock.call._set_gabtab()]

            setgabtab_mock.assert_has_calls(expected_calls)
        _check_request_user_confirmation(True)
        _check_request_user_confirmation(False)

    def test_get_running_nodes(self):

        @mock.patch('socket.gethostname')
        def _check_get_running_nodes(hosts, ms_hostname, gethostname_mock):
            setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
            setgabtab_mock._exec_command.return_value = hosts
            self._wrap_methods(setgabtab_mock, '_get_running_nodes')
            gethostname_mock.return_value = ms_hostname

            result = setgabtab_mock._get_running_nodes()
            expected_calls = [
                mock.call._exec_command([set_gabtab.MCO, 'find'])]
            setgabtab_mock.assert_has_calls(expected_calls)
            hosts_minus_ms = set(hosts.split()) - set([ms_hostname])
            self.assertTrue(hosts_minus_ms == set(result))

        _check_get_running_nodes("n1 n2", 'ms')
        _check_get_running_nodes("ms n1 n2", 'ms')

    @mock.patch('utilities.set_gabtab.PuppetCatalogRunProcessor')
    def test_sync_puppet_catalog(self, processor_mock):
        setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
        self._wrap_methods(setgabtab_mock, '_sync_puppet_catalog')
        processor_mock.return_value = processor_mock

        setgabtab_mock._sync_puppet_catalog()
        expected_calls = [
            mock.call._get_running_nodes()]
        setgabtab_mock.assert_has_calls(expected_calls)

        expected_calls = [
            mock.call(),
            mock.call.update_config_version(),
            mock.call.trigger_and_wait(
                processor_mock.update_config_version(),
                setgabtab_mock._get_running_nodes())]
        processor_mock.assert_has_calls(expected_calls)

    def test_copy_file(self):

        @mock.patch('shutil.copy2')
        def _check_copy_file(raise_exception, copy2_mock):
            setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
            self._wrap_methods(setgabtab_mock, '_copy_file')
            source = 'file_source'
            destination = 'file_destination'

            if raise_exception:
                copy2_mock.side_effect = IOError()
                self.assertRaises(set_gabtab.FailToProcessRequestException,
                    setgabtab_mock._copy_file, source, destination)
                expected_calls = [
                    mock.call._log_error(
                        'Unable to copy file {0} to {1}!'.format(
                            source, destination),
                        copy2_mock.side_effect)]
                setgabtab_mock.assert_has_calls(expected_calls)
            else:
                setgabtab_mock._copy_file(source, destination)

            expected_calls = [
                mock.call(source, destination)]
            copy2_mock.assert_has_calls(expected_calls)

        # Check without rasing IOError
        _check_copy_file(False)

        # Check with rasing IOError
        _check_copy_file(True)

    def test_remove_file(self):

        @mock.patch('os.remove')
        def _check_remove_file(raise_exception, remove_mock):
            setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
            self._wrap_methods(setgabtab_mock, '_remove_file')
            target = 'target_file'

            if raise_exception:
                remove_mock.side_effect = IOError()
                self.assertRaises(set_gabtab.FailToProcessRequestException,
                    setgabtab_mock._remove_file, target)
                expected_calls = [
                    mock.call._log_error(
                        'Unable to remove file {0}!'.format(target),
                        remove_mock.side_effect)]
                setgabtab_mock.assert_has_calls(expected_calls)
            else:
                setgabtab_mock._remove_file(target)

            expected_calls = [
                mock.call(target)]
            remove_mock.assert_has_calls(expected_calls)

        # Check without rasing IOError
        _check_remove_file(False)

        # Check with rasing IOError
        _check_remove_file(True)

    def test_backup_gabtab_template(self):
        setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
        self._wrap_methods(setgabtab_mock, '_backup_gabtab_template')
        setgabtab_mock.configure_mock(
            GABTAB_TEMPLATE_FILE=\
                set_gabtab.SetGabtab.GABTAB_TEMPLATE_FILE,
            BACKUP_FILE=\
                set_gabtab.SetGabtab.BACKUP_FILE)
        setgabtab_mock._backup_gabtab_template()
        expected_calls = [
            mock.call._copy_file(
                setgabtab_mock.GABTAB_TEMPLATE_FILE,
                setgabtab_mock.BACKUP_FILE)]
        setgabtab_mock.assert_has_calls(expected_calls)

    def test_restore_gabtab_template(self):
        setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
        self._wrap_methods(setgabtab_mock, '_restore_gabtab_template')
        setgabtab_mock.configure_mock(
            GABTAB_TEMPLATE_FILE=\
                set_gabtab.SetGabtab.GABTAB_TEMPLATE_FILE,
            BACKUP_FILE=\
                set_gabtab.SetGabtab.BACKUP_FILE)
        setgabtab_mock._restore_gabtab_template()
        expected_calls = [
            mock.call._copy_file(
                setgabtab_mock.BACKUP_FILE,
                setgabtab_mock.GABTAB_TEMPLATE_FILE),
            mock.call._remove_file(
                setgabtab_mock.BACKUP_FILE)]
        setgabtab_mock.assert_has_calls(expected_calls)


    @mock.patch('__builtin__.open')
    def test_modify_gabtab_template(self, open_mock):
        setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
        self._wrap_methods(setgabtab_mock, '_modify_gabtab_template')
        setgabtab_mock.configure_mock(
            GABTAB_TEMPLATE_FILE=\
                set_gabtab.SetGabtab.GABTAB_TEMPLATE_FILE,
            GABTAB_CONTENT=\
                set_gabtab.SetGabtab.GABTAB_CONTENT)
        setgabtab_mock._modify_gabtab_template()
        expected_calls = [
            mock.call(setgabtab_mock.GABTAB_TEMPLATE_FILE, 'w'),
            mock.call().__enter__(),
            mock.call().__enter__().write(setgabtab_mock.GABTAB_CONTENT),
            mock.call().__exit__(None, None, None)]
        open_mock.assert_has_calls(expected_calls)

    def test_set_gabtab(self):
        setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
        self._wrap_methods(setgabtab_mock, '_set_gabtab')
        setgabtab_mock._set_gabtab()
        expected_calls = [
            mock.call._backup_gabtab_template(),
            mock.call._modify_gabtab_template()]
        setgabtab_mock.assert_has_calls(expected_calls)

    def test_undo_set_gabtab(self):
        setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
        self._wrap_methods(setgabtab_mock, '_undo_set_gabtab')
        setgabtab_mock._undo_set_gabtab()
        expected_calls = [
            mock.call._restore_gabtab_template()]
        setgabtab_mock.assert_has_calls(expected_calls)

    def test_is_executable(self):

        @mock.patch('os.access')
        @mock.patch('os.path.isfile')
        def _check_is_executable(isfile_return, access_return,
                                 isfile_mock, access_mock):
            setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
            self._wrap_methods(setgabtab_mock, '_is_executable')
            isfile_mock.return_value = isfile_return
            access_mock.return_value = access_return
            file_path = 'foo'
            result = setgabtab_mock._is_executable(file_path)
            expected_calls = [
                mock.call(file_path)]
            isfile_mock.assert_has_calls(expected_calls)
            if isfile_return:
                expected_calls = [
                    mock.call(file_path, set_gabtab.os.X_OK)]
                access_mock.assert_has_calls(expected_calls)
            self.assertEqual(isfile_return and access_return, result)

        # Check isfile False and access X_OK False
        _check_is_executable(False, False)

        # Check isfile False and access X_OK True
        _check_is_executable(False, True)

        # Check isfile True and access X_OK False
        _check_is_executable(True, False)

        # Check isfile True and access X_OK True
        _check_is_executable(True, True)

    def test_exec_command(self):

        @mock.patch('subprocess.Popen')
        def _check_exec_command(returncode, popen_mock):
            setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
            self._wrap_methods(setgabtab_mock, '_exec_command')
            setgabtab_mock.configure_mock(
                logger=mock.MagicMock())
            command = '/bin/run/foo_bar'
            command_output = 'foo bar'
            popen_mock.return_value = mock.MagicMock(
                returncode=returncode,
                communicate=mock.MagicMock(return_value=[command_output]))

            if returncode == 0:
                result = setgabtab_mock._exec_command(command)
                self.assertEqual(command_output, result)
            else:
                self.assertRaises(set_gabtab.FailToExecuteCommandException,
                                  setgabtab_mock._exec_command, command)

            expected_calls = [
                mock.call(command,
                          stdout=set_gabtab.subprocess.PIPE,
                          stderr=set_gabtab.subprocess.STDOUT)]
            popen_mock.assert_has_calls(expected_calls)

            expected_calls = [
                mock.call.logger.debug('Execute command: {0}'.format(command))]
            setgabtab_mock.assert_has_calls(expected_calls)

        # Check command execution successfull
        _check_exec_command(0)

        # Check command execution failed
        _check_exec_command(1)

    def test_log_error(self):
        setgabtab_mock = mock.MagicMock(spec=set_gabtab.SetGabtab)
        self._wrap_methods(setgabtab_mock, '_log_error')
        setgabtab_mock.configure_mock(
            logger=mock.MagicMock())
        message = 'Test foo:'
        strerror = ['line1', 'line2', 'line3']
        exception_mock = mock.MagicMock(
            strerror='\n'.join(strerror))
        setgabtab_mock._log_error(message, exception_mock)
        expected_calls = [
            mock.call.logger.exception(message),
            mock.call.logger.exception(strerror[0]),
            mock.call.logger.exception(strerror[1]),
            mock.call.logger.exception(strerror[2])]
        setgabtab_mock.assert_has_calls(expected_calls)


class TestSetGabTab_EntryPoint(unittest.TestCase):

    def test_create_parser(self):
        parser = set_gabtab.EntryPoint._create_parser("set_gabtab")
        parsed_args = parser.parse_args(["--undo"])
        self.assertTrue(parsed_args.undo)
        self.assertFalse(parsed_args.verbose)

    @mock.patch('utilities.set_gabtab.SetGabTabLogger')
    @mock.patch('utilities.set_gabtab.SetGabtab')
    @mock.patch('os.makedirs')
    @mock.patch('os.path.exists')
    def test_main(self, mock_os_exists, mock_makedirs,
                  mock_gabtab, mock_gabtab_logger):
        logger = mock.Mock()
        mock_process_request = mock.Mock()
        mock_gabtab.return_value = mock_gabtab
        mock_gabtab.process_request = mock_process_request
        mock_gabtab_logger.return_value = mock_gabtab_logger
        mock_gabtab_logger.get_logger.return_value = logger
        mock_os_exists.return_value = False
        set_gabtab.EntryPoint.main(["set_gabtab", "-v"])
        expected_calls = [
            mock.call.get_logger(True),
            mock.call.get_logger().info('Executing: set_gabtab -v'),
            mock.call.get_logger().info('Directory /var/opt/ericsson '
                                        'not found, creating!'),
            mock.call.get_logger().info('Gabtab successfully changed.')]
        mock_gabtab_logger.assert_has_calls(expected_calls)
        mock_makedirs.assert_has_calls([mock.call('/var/opt/ericsson', 0755)])
        mock_os_exists.assert_has_calls([mock.call('/var/opt/ericsson')])
        mock_gabtab.assert_has_calls([mock.call(logger, False)])
        mock_process_request.assert_called_once_with()
