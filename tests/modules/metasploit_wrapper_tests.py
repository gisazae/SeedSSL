import random
import unittest

import mock
from mock import patch

from semillero_seguridadssl.modules.metasploit_wrapper import *
from tests.helpers import generateString


class MetasploitClientTestCases(unittest.TestCase):
    def setUp(self):
        self._client = MetasploitClient()


class LoginTestCase(MetasploitClientTestCases):
    def setUp(self):
        super(LoginTestCase, self).setUp()
        self.login_params = {
            'username': 'admin',
            'password': '123456',
            'server': 'localhost',
            'port': '55553',
            'ssl': False
        }

    @mock.patch('semillero_seguridadssl.modules.metasploit_wrapper.MsfRpcClient', autospec=True)
    def test_login_with_empty_password(self, mock_client):
        mock_client.side_effect = Exception('')
        self.login_params['password'] = ''
        self.login_params['username'] = 'msf'

        with self.assertRaises(Exception):
            self._client.login(**self.login_params)

    @mock.patch('semillero_seguridadssl.modules.metasploit_wrapper.MsfRpcClient', autospec=True)
    def test_login_without_username(self, mock_client):
        self._client.login(**{k: self.login_params[k] for k in self.login_params if k != 'username'})
        self.login_params['username'] = 'msf'
        mock_client.assert_called_with(**self.login_params)

    @mock.patch('semillero_seguridadssl.modules.metasploit_wrapper.MsfRpcClient', autospec=True)
    def test_login_with_ssl_option(self, mock_client):
        self.login_params['ssl'] = True
        self._client.login(**self.login_params)
        mock_client.assert_called_with(**self.login_params)

    @mock.patch('semillero_seguridadssl.modules.metasploit_wrapper.MsfRpcClient', autospec=True)
    def test_login_with_credentials_and_host_parameters(self, mock_client):
        self._client.login(**self.login_params)
        mock_client.assert_called_with(**self.login_params)


class ExploitsTestCase(MetasploitClientTestCases):
    @mock.patch('semillero_seguridadssl.modules.metasploit_wrapper.MsfRpcClient', autospec=True)
    def setUp(self, mock_client):
        super(ExploitsTestCase, self).setUp()
        self.exploits = [generateString(10) for _ in range(5)]
        self.exploit_options = {generateString(5): generateString(4) for _ in range(4)}
        self._client.msfClient = mock_client
        self._client.msfClient.modules.exploits = self.exploits

    def test_try_get_exploits_list_without_being_logged_in(self):
        self._client.msfClient = None

        with self.assertRaises(ClientNotAvailableException):
            self._client.getExploits()

    def test_get_exploits_list(self):
        exploits = self._client.getExploits()
        self.assertIsInstance(exploits, list)

    def test_try_use_exploit_without_being_logged_in(self):
        self._client.msfClient = None

        with self.assertRaises(ClientNotAvailableException):
            exploitName = random.choice(self.exploits)
            self._client.useExploit(exploitName)

    @mock.patch('metasploit.msfrpc.ExploitModule', autospec=True)
    def test_use_exploit(self, stub_exploit):
        with patch.object(self._client.msfClient.modules, 'use', autospec=True) as mock_use:
            mock_use.return_value = stub_exploit
            exploitName = random.choice(self.exploits)

            self._client.useExploit(exploitName)

            self.assertIsNotNone(self._client.exploit)
        mock_use.assert_called_with('exploit', exploitName)

    def test_use_invalid_exploit(self):
        self._client.msfClient.modules.use.side_effect = MsfRpcError('')
        exploitName = generateString(6)

        self.assertNotIn(exploitName, self.exploits)
        with self.assertRaises(NameError):
            self._client.useExploit(exploitName)

    def test_get_exploit_options_without_select_an_exploit(self):
        with self.assertRaises(ModuleNotSelectedException):
            self._client.getExploitOptions()

    @mock.patch('metasploit.msfrpc.ExploitModule', autospec=True)
    def test_get_all_exploit_options(self, stub_exploit):
        self.__initExploitOptionsKeys(stub_exploit)
        options = self._client.getExploitOptions()
        self.assertItemsEqual(options.keys(), self.exploit_options.keys())

    @mock.patch('metasploit.msfrpc.ExploitModule', autospec=True)
    def test_get_an_invalid_exploit_option(self, stub_exploit):
        self.__initExploitOptionsKeys(stub_exploit)
        optionSelected = generateString(5)

        options = self._client.getExploitOptions(optionSelected)

        self.assertEquals(len(options), 0)

    @mock.patch('metasploit.msfrpc.ExploitModule', autospec=True)
    def test_get_a_valid_exploit_option(self, stub_exploit):
        self.__initExploitOptions(stub_exploit)
        optionSelected = random.choice(self.exploit_options.keys())

        options = self._client.getExploitOptions(optionSelected)

        self.assertEquals(options[optionSelected], self.exploit_options[optionSelected])

    @mock.patch('metasploit.msfrpc.ExploitModule', autospec=True)
    def test_set_valid_exploit_option(self, stub_exploit):
        self.__initExploitOptions(stub_exploit)
        self.assertEquals(stub_exploit._options, self.exploit_options)
        key = random.choice(self.exploit_options.keys())

        self._client.setExploitOptions(**{key: generateString(4)})

        self.assertNotEquals(stub_exploit._options, self.exploit_options)

    @mock.patch('metasploit.msfrpc.ExploitModule', autospec=True)
    def test_set_invalid_exploit_option(self, mock_exploit):
        self.__initExploitOptions(mock_exploit)
        options = self.exploit_options.copy()
        options['INVALID_KEY'] = ''

        self._client.setExploitOptions(**options)

        self.assertEquals(mock_exploit._options, self.exploit_options)

    @mock.patch('metasploit.msfrpc.ExploitModule', autospec=True)
    def test_execute_exploit_without_payload_and_with_use_payload_flag(self, mock_exploit):
        self._client.exploit = mock_exploit
        self._client.executeExploit(True)
        mock_exploit.execute.assert_called_with()

    @mock.patch('metasploit.msfrpc.ExploitModule', autospec=True)
    def test_execute_exploit_without_payload_and_use_payload_flag(self, mock_exploit):
        self._client.exploit = mock_exploit
        self._client.executeExploit()
        mock_exploit.execute.assert_called_with()

    def __initExploitOptionsKeys(self, fake_exploit):
        fake_exploit.options = self.exploit_options.keys()
        self._client.exploit = fake_exploit

    def __initExploitOptions(self, fake_exploit):
        def getItem(item):
            return fake_exploit._options[item]

        def setItem(key, value):
            fake_exploit._options[key] = value

        fake_exploit._options = self.exploit_options.copy()
        self.__initExploitOptionsKeys(fake_exploit)
        fake_exploit.__getitem__.side_effect = getItem
        fake_exploit.__setitem__.side_effect = setItem
        for option in self.exploit_options:
            fake_exploit[option] = self.exploit_options[option]


class PayloadsTestCase(MetasploitClientTestCases):
    @mock.patch('semillero_seguridadssl.modules.metasploit_wrapper.MsfRpcClient', autospec=True)
    def setUp(self, mock_client):
        super(PayloadsTestCase, self).setUp()
        self.payloads = [generateString(10) for _ in range(4)]
        self.payload_options = {generateString(5): generateString(4) for _ in range(3)}
        self._client.msfClient = mock_client

    @mock.patch('metasploit.msfrpc.ExploitModule', autospec=True)
    def test_get_exploit_payloads(self, stub_exploit):
        stub_exploit.payloads = self.payloads
        self._client.exploit = stub_exploit

        payloads = self._client.getExploitPayloads()

        self.assertListEqual(payloads, self.payloads)

    def test_try_use_payload_without_being_logged_in(self):
        self._client.msfClient = None

        with self.assertRaises(ClientNotAvailableException):
            payload = random.choice(self.payloads)
            self._client.usePayload(payload)

    def test_use_payload(self):
        with patch.object(self._client.msfClient.modules, 'use', autospec=True) as mock_use:
            payload = random.choice(self.payloads)

            self._client.usePayload(payload)

            self.assertIsNotNone(self._client.payload)
        mock_use.assert_called_with('payload', payload)

    @mock.patch('semillero_seguridadssl.modules.metasploit_wrapper.MsfRpcClient', autospec=True)
    def test_use_invalid_payload(self, mock_client):
        self._client.msfClient.modules.use.side_effect = MsfRpcError('')
        payload = generateString(6)

        self.assertNotIn(payload, self.payloads)
        with self.assertRaises(NameError):
            self._client.useExploit(payload)
            mock_client.modules.use.assert_called_with('payload', payload)

    def test_get_payload_options_without_select_a_payload(self):
        with self.assertRaises(ModuleNotSelectedException):
            self._client.getPayloadOptions()

    @mock.patch('metasploit.msfrpc.PayloadModule', autospec=True)
    def test_get_all_payload_options(self, stub_payload):
        self.__initPayloadOptionsKeys(stub_payload)
        options = self._client.getPayloadOptions()
        self.assertItemsEqual(options.keys(), self.payload_options.keys())

    @mock.patch('metasploit.msfrpc.PayloadModule', autospec=True)
    def test_get_an_invalid_payload_option(self, stub_payload):
        self.__initPayloadOptionsKeys(stub_payload)
        optionSelected = generateString(6)

        options = self._client.getPayloadOptions(optionSelected)

        self.assertEquals(len(options), 0)

    @mock.patch('metasploit.msfrpc.PayloadModule', autospec=True)
    def test_get_a_valid_payload_option(self, stub_payload):
        self.__initPayloadtOptions(stub_payload)
        optionSelected = random.choice(self.payload_options.keys())

        options = self._client.getPayloadOptions(optionSelected)

        self.assertEquals(options[optionSelected], self.payload_options[optionSelected])

    @mock.patch('metasploit.msfrpc.PayloadModule', autospec=True)
    def test_set_valid_payload_option(self, stub_payload):
        self.__initPayloadtOptions(stub_payload)
        self.assertEquals(stub_payload._options, self.payload_options)
        key = random.choice(self.payload_options.keys())

        self._client.setPayloadOptions(**{key: generateString(4)})

        self.assertNotEquals(stub_payload._options, self.payload_options)

    @mock.patch('metasploit.msfrpc.PayloadModule', autospec=True)
    def test_set_invalid_payload_option(self, mock_payload):
        self.__initPayloadtOptions(mock_payload)
        options = self.payload_options.copy()
        options['INVALID_KEY'] = ''

        self._client.setPayloadOptions(**options)

        self.assertEquals(mock_payload._options, self.payload_options)

    @mock.patch('metasploit.msfrpc.PayloadModule', autospec=True)
    @mock.patch('metasploit.msfrpc.ExploitModule', autospec=True)
    def test_execute_exploit_with_payload_and_use_payload_flag(self, mock_exploit, stub_payload):
        self._client.exploit = mock_exploit
        self._client.payload = stub_payload

        self._client.executeExploit(True)

        mock_exploit.execute.assert_called_with(payload=stub_payload)

    @mock.patch('metasploit.msfrpc.PayloadModule', autospec=True)
    @mock.patch('metasploit.msfrpc.ExploitModule', autospec=True)
    def test_execute_exploit_with_payload_and_without_use_payload_flag(self, mock_exploit, stub_payload):
        self._client.exploit = mock_exploit
        self._client.payload = stub_payload

        self._client.executeExploit()

        mock_exploit.execute.assert_called_with()

    def __initPayloadOptionsKeys(self, fake_payload):
        fake_payload.options = self.payload_options.keys()
        self._client.payload = fake_payload

    def __initPayloadtOptions(self, fake_payload):
        def getItem(item):
            return fake_payload._options[item]

        def setItem(key, value):
            fake_payload._options[key] = value

        fake_payload._options = self.payload_options.copy()
        self.__initPayloadOptionsKeys(fake_payload)
        fake_payload.__getitem__.side_effect = getItem
        fake_payload.__setitem__.side_effect = setItem
        for option in self.payload_options:
            fake_payload[option] = self.payload_options[option]


class SessionsTestCase(MetasploitClientTestCases):
    @mock.patch('metasploit.msfrpc.SessionManager', autospec=True)
    @mock.patch('semillero_seguridadssl.modules.metasploit_wrapper.MsfRpcClient', autospec=True)
    def setUp(self, mock_client, stub_session):
        super(SessionsTestCase, self).setUp()
        self.sessions = {i: {} for i in range(2)}
        stub_session.list = self.sessions
        self._client.msfClient = mock_client
        self._client.msfClient.sessions = stub_session

    def test_get_active_sessions_list(self):
        sessions = self._client.getActiveSessions()
        self.assertEqual(sessions, self.sessions)

    def test_try_get_shell_from_non_existing_session(self):
        self._client.msfClient.sessions.session.side_effect = KeyError()
        sessionId = random.choice(self.sessions.keys()) + 10

        with (self.assertRaises(KeyError)):
            self._client.getActiveSession(sessionId)

            self._client.msfClient.sessions.session.assert_called_with(sessionId)

    @mock.patch('semillero_seguridadssl.modules.metasploit_wrapper.SessionInterpreter', autospec=True)
    @mock.patch('metasploit.msfrpc.MsfSession', autospec=True)
    def test_get_shell_from_active_session(self, stub_session, mock_session_interpreter):
        self._client.msfClient.sessions.session.return_value = stub_session
        sessionId = random.choice(self.sessions.keys())

        self._client.getActiveSession(sessionId)

        self._client.msfClient.sessions.session.assert_called_with(sessionId)

    @mock.patch('semillero_seguridadssl.modules.metasploit_wrapper.SessionInterpreter', autospec=True)
    @mock.patch('metasploit.msfrpc.MsfSession', autospec=True)
    def test_create_session_interpreter(self, stub_session, mock_session_interpreter):
        self._client.msfClient.sessions.session.return_value = stub_session
        sessionId = random.choice(self.sessions.keys())

        self._client.getActiveSession(sessionId)

        mock_session_interpreter.assert_called_with(stub_session)


class SessionInterpreterTestCase(unittest.TestCase):
    @mock.patch('metasploit.msfrpc.ShellSession', autospec=True)
    def test_cmdloop_interaction(self, mock_session):
        sessionInterpreter = SessionInterpreter(mock_session)

        sessionInterpreter.default('ls')

        mock_session.write.assert_called_with('ls\n')
        assert mock_session.read.called
