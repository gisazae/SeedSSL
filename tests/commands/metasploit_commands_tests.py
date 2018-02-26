import random
import socket
import unittest

import mock
from click.testing import CliRunner

from semillero_seguridadssl.commands.metasploit_commands import *
from semillero_seguridadssl.modules.metasploit_wrapper import ClientNotAvailableException
from tests.helpers import generateString


class MetasploitCommandsTestCases(unittest.TestCase):
    @mock.patch('semillero_seguridadssl.commands.metasploit_commands.MetasploitClient', autospec=True)
    def setUp(self, mock_client):
        self.runner = CliRunner()
        self.mock_client = mock_client
        MetasploitCommands.msfClient = mock_client


class LoginTestCase(MetasploitCommandsTestCases):
    def setUp(self):
        super(LoginTestCase, self).setUp()
        self.login_params = {
            'username': 'admin',
            'password': '123456',
            'server': 'localhost',
            'port': '55553',
            'ssl': False
        }

    def test_try_login_without_credentials(self):
        result = self.runner.invoke(MetasploitCommands.login)
        self.assertEqual(result.exit_code, 2)

    def test_login_with_credentials(self):
        self.login_params['port'] = None
        self.login_params['server'] = None

        self.runner.invoke(MetasploitCommands.login, [
            self.login_params['password'],
            '-u', self.login_params['username']
        ])

        self.mock_client.login.assert_called_with(**self.login_params)

    def test_login_without_password(self):
        result = self.runner.invoke(MetasploitCommands.login, ['-u', self.login_params['username']])
        self.assertEqual(result.exit_code, 2)

    def test_login_only_with_password(self):
        result = self.runner.invoke(MetasploitCommands.login, [self.login_params['password']])

        self.assertEqual(result.exit_code, 0)
        self.assertNotEqual(result.output, '')

    def test_login_with_credentials_and_host_parameters(self):
        result = self.runner.invoke(MetasploitCommands.login, [
            self.login_params['password'],
            '-u', self.login_params['username'],
            '-s', self.login_params['server'],
            '-p', self.login_params['port']
        ])

        self.assertEqual(result.exit_code, 0)
        self.mock_client.login.assert_called_with(**self.login_params)
        self.assertNotEqual(result.output, '')

    def test_login_without_ssl_option(self):
        for param in self.login_params:
            self.login_params[param] = None if param != 'password' else self.login_params[param]
        self.login_params['ssl'] = False

        result = self.runner.invoke(MetasploitCommands.login, [self.login_params['password'], '--no-ssl'])

        self.assertEqual(result.exit_code, 0)
        self.mock_client.login.assert_called_with(**self.login_params)
        self.assertNotEqual(result.output, '')

    def test_login_with_ssl_option(self):
        for param in self.login_params:
            self.login_params[param] = None if param != 'password' else self.login_params[param]
        self.login_params['ssl'] = True

        result = self.runner.invoke(MetasploitCommands.login, [self.login_params['password'], '--ssl'])

        self.mock_client.login.assert_called_with(**self.login_params)
        self.assertNotEqual(result.output, '')

    def test_connection_refused(self):
        self.mock_client.login.side_effect = socket.error()
        result = self.runner.invoke(MetasploitCommands.login, [self.login_params['password']])
        self.assertIn('Verify msf server connection settings.', result.output)


class ExploitsTestCase(MetasploitCommandsTestCases):
    def setUp(self):
        super(ExploitsTestCase, self).setUp()
        self.exploits = [generateString(10) for _ in range(5)]
        self.exploit_options = {generateString(5): generateString(4) for _ in range(4)}

    def test_try_get_exploits_list_without_being_logged_in(self):
        self.mock_client.getExploits.side_effect = ClientNotAvailableException()
        result = self.runner.invoke(ExploitCommands.list)
        self.assertIn('First, log into metasploit server.', result.output)

    def test_get_exploits_list(self):
        self.mock_client.getExploits.return_value = self.exploits
        result = self.runner.invoke(ExploitCommands.list)
        self.assertIn('\n'.join(self.exploits), result.output)

    def test_try_use_exploit_without_being_logged_in(self):
        self.mock_client.useExploit.side_effect = ClientNotAvailableException()
        exploit = random.choice(self.exploits)

        result = self.runner.invoke(ExploitCommands.use, [exploit])

        self.assertIn('First, log into metasploit server.', result.output)

    def test_use_valid_exploit(self):
        exploit = random.choice(self.exploits)
        self.runner.invoke(ExploitCommands.use, [exploit])
        self.mock_client.useExploit.assert_called_with(exploit)

    def test_use_invalid_exploit(self):
        message = generateString(10)
        self.mock_client.useExploit.side_effect = NameError(message)
        exploit = generateString(5)

        result = self.runner.invoke(ExploitCommands.use, [exploit])

        self.assertEqual(result.output, message + '\n')

    def test_get_all_exploit_options(self):
        self.mock_client.getExploitOptions.return_value = self.exploit_options
        result = self.runner.invoke(ExploitCommands.options)
        self.assertIn(str(self.exploit_options), result.output)

    def test_get_multiple_exploit_options(self):
        options = [
            random.choice(self.exploit_options.keys()),
            random.choice(self.exploit_options.keys())
        ]
        self.runner.invoke(ExploitCommands.options, ['-op', options[0], '-op', options[1]])
        self.mock_client.getExploitOptions.assert_called_with(*options)

    def test_get_multiple_exploit_options_with_one_invalid_format_option(self):
        options = [
            random.choice(self.exploit_options.keys()),
            random.choice(self.exploit_options.keys())
        ]
        invalidOption = '='.join((options[0], self.exploit_options[options[0]]))

        self.runner.invoke(ExploitCommands.options, ['-op', invalidOption, '-op', options[1]])

        self.mock_client.getExploitOptions.assert_called_with(options[1])

    def test_set_multiple_exploit_options(self):
        options = ['='.join((optionName, self.exploit_options[optionName]))
                   for optionName in self.exploit_options]
        command_args = ['--modify']
        [command_args.extend(['-op', option]) for option in options]

        self.runner.invoke(ExploitCommands.options, command_args)

        self.mock_client.setExploitOptions.assert_called_with(**self.exploit_options)

    def test_set_multiple_exploit_options_with_one_invalid_format_option(self):
        validOptionName = random.choice(self.exploit_options.keys())
        validOption = '='.join((validOptionName, self.exploit_options[validOptionName]))
        invalidOption = random.choice(self.exploit_options.keys())

        self.runner.invoke(ExploitCommands.options, ['--modify', '-op', validOption, '-op', invalidOption])

        self.mock_client.setExploitOptions.assert_called_with(
            **{validOptionName: self.exploit_options[validOptionName]})

    def test_execute_exploit_without_payload_and_payload_flag(self):
        self.runner.invoke(ExploitCommands.execute)
        self.mock_client.executeExploit.assert_called_with(False)

    def test_execute_exploit_without_payload_and_with_payload_flag(self):
        self.runner.invoke(ExploitCommands.execute, ['--payload'])
        self.mock_client.executeExploit.assert_called_with(True)


class PayloadsTestCase(MetasploitCommandsTestCases):
    def setUp(self):
        super(PayloadsTestCase, self).setUp()
        self.payloads = [generateString(10) for _ in range(4)]
        self.payload_options = {generateString(5): generateString(4) for _ in range(3)}

    def test_get_exploit_payloads(self):
        self.mock_client.getExploitPayloads.return_value = self.payloads
        result = self.runner.invoke(ExploitCommands.payloads)
        self.assertIn(str(self.payloads), result.output)

    def test_try_use_payload_without_being_logged_in(self):
        self.mock_client.usePayload.side_effect = ClientNotAvailableException()
        payload = random.choice(self.payloads)

        result = self.runner.invoke(PayloadCommands.use, [payload])

        self.assertIn('First, log into metasploit server.', result.output)

    def test_use_valid_payload(self):
        payload = random.choice(self.payloads)
        self.runner.invoke(PayloadCommands.use, [payload])
        self.mock_client.usePayload.assert_called_with(payload)

    def test_use_invalid_payload(self):
        message = generateString(10)
        self.mock_client.usePayload.side_effect = NameError(message)
        payload = generateString(5)

        result = self.runner.invoke(PayloadCommands.use, [payload])

        self.assertEqual(result.output, message + '\n')

    def test_get_all_payload_options(self):
        self.mock_client.getPayloadOptions.return_value = self.payload_options
        result = self.runner.invoke(PayloadCommands.options)
        self.assertIn(str(self.payload_options), result.output)

    def test_get_multiple_payload_options(self):
        options = [
            random.choice(self.payload_options.keys()),
            random.choice(self.payload_options.keys())
        ]
        self.runner.invoke(PayloadCommands.options, ['-op', options[0], '-op', options[1]])
        self.mock_client.getPayloadOptions.assert_called_with(*options)

    def test_get_multiple_payload_options_with_one_invalid_format_option(self):
        options = [
            random.choice(self.payload_options.keys()),
            random.choice(self.payload_options.keys())
        ]
        invalidOption = '='.join((options[0], self.payload_options[options[0]]))

        self.runner.invoke(PayloadCommands.options, ['-op', invalidOption, '-op', options[1]])

        self.mock_client.getPayloadOptions.assert_called_with(options[1])

    def test_set_multiple_payload_options(self):
        options = ['='.join((optionName, self.payload_options[optionName]))
                   for optionName in self.payload_options]
        command_args = ['--modify']
        [command_args.extend(['-op', option]) for option in options]

        self.runner.invoke(PayloadCommands.options, command_args)

        self.mock_client.setPayloadOptions.assert_called_with(**self.payload_options)

    def test_set_multiple_payload_options_with_one_invalid_format_option(self):
        validOptionName = random.choice(self.payload_options.keys())
        validOption = '='.join((validOptionName, self.payload_options[validOptionName]))
        invalidOption = random.choice(self.payload_options.keys())

        self.runner.invoke(PayloadCommands.options, ['--modify', '-op', validOption, '-op', invalidOption])

        self.mock_client.setPayloadOptions.assert_called_with(
            **{validOptionName: self.payload_options[validOptionName]})

    def test_execute_exploit_with_payload_option(self):
        self.runner.invoke(ExploitCommands.execute, ['--payload'])
        self.mock_client.executeExploit.assert_called_with(True)


class SessionsTestCase(MetasploitCommandsTestCases):
    def setUp(self):
        super(SessionsTestCase, self).setUp()
        self.sessions = {i: {generateString(4): generateString(4)} for i in range(3)}
        self.mock_client.getActiveSessions.return_value = self.sessions

    def test_get_active_sessions_list(self):
        result = self.runner.invoke(MetasploitCommands.sessions, ['--list'])
        self.assertIn(str(self.sessions), result.output)

    def test_get_interpreter_from_active_session(self):
        sessionId = random.choice(self.sessions.keys())
        self.runner.invoke(MetasploitCommands.sessions, ['--interact', sessionId])
        self.mock_client.getActiveSession.assert_called_once_with(sessionId)

    def test_try_get_shell_from_non_existing_session(self):
        self.mock_client.getActiveSession.side_effect = KeyError
        sessionId = random.choice(self.sessions.keys()) + 10

        result = self.runner.invoke(MetasploitCommands.sessions, ['--interact', sessionId])

        self.assertIn('Session does not exist', result.output, result.exit_code or result.exit_code)
