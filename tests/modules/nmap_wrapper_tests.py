import unittest

import mock

from semillero_seguridadssl.modules.nmap_wrapper import *
from tests.helpers import generateIP, randomPort, generateString


class NmapScanManagerTestCases(unittest.TestCase):
    @mock.patch('semillero_seguridadssl.modules.nmap_wrapper.nmap.PortScanner', autospec=True)
    def setUp(self, mock_port_scanner):
        mock_port_scanner.return_value = mock_port_scanner
        self.mock_port_scanner = mock_port_scanner
        self.scanManager = NmapScanManager()
        self.address = generateIP()


class NmapScanManagerAddHostTestCase(NmapScanManagerTestCases):
    def test_add_empty_host_ip(self):
        self.scanManager.addHost('')
        hosts = self.scanManager.hosts

        self.assertEqual(len(hosts), 0)

    def test_add_host_ip(self):
        host = self.scanManager.addHost(self.address)

        self.assertEqual(len(self.scanManager.hosts), 1)
        self.assertIsInstance(host, Host)
        self.assertEqual(host.ip, self.address)

    def test_add_host_with_valid_ports_range(self):
        firstPort = randomPort(max=90)
        lastPort = randomPort(91, 100)

        host = self.scanManager.addHost(self.address, firstPort, lastPort)

        hosts = self.scanManager.hosts
        self.assertEqual(len(hosts), 1)
        self.assertEqual(host.ip, self.address)
        self.assertEqual(host.ports, '{}-{}'.format(firstPort, lastPort))

    def test_add_host_with_ports_range_inverted(self):
        firstPort = randomPort(90, 100)
        lastPort = randomPort(80, 89)

        with self.assertRaises(PortRangeBackwardException):
            self.scanManager.addHost(self.address, firstPort, lastPort)

    def test_add_host_with_first_port(self):
        firstPort = randomPort()

        host = self.scanManager.addHost(self.address, firstPort)

        self.assertIsInstance(host, Host)
        self.assertEqual(host.ip, self.address)
        self.assertEqual(host.ports, str(firstPort))

    def test_add_host_with_last_port(self):
        host = self.scanManager.addHost(self.address, lastPort=randomPort())

        self.assertIsInstance(host, Host)
        self.assertEqual(host.ip, self.address)
        self.assertEqual(host.ports, None)


class NmapScanManagerScanHostTestCase(NmapScanManagerTestCases):
    def setUp(self):
        super(NmapScanManagerScanHostTestCase, self).setUp()
        self.port = randomPort()
        self.stub_result = {
            'nmap': {
                'scaninfo': {
                    'tcp': {
                        'services': str(self.port)
                    }
                }
            }
        }

    def test_scan_host_without_host_and_ports(self):
        with self.assertRaises(NoHostsToScanException):
            self.scanManager.scanHost(len(self.scanManager.hosts) - 1)

    def test_scan_host_without_ports(self):
        self.mock_port_scanner.scan.return_value = self.stub_result

        host = self.scanManager.addHost(self.address)

        self.assertIsNone(host.results)
        result = self.scanManager.scanHost(len(self.scanManager.hosts) - 1)
        self.assertIsNotNone(host.results)
        self.assertIsNone(result['nmap']['scaninfo'].get('error'))

    def test_scan_host_with_port(self):
        self.mock_port_scanner.scan.return_value = self.stub_result

        host = self.scanManager.addHost(self.address, firstPort=self.port)

        self.assertIsNone(host.results)
        result = self.scanManager.scanHost(len(self.scanManager.hosts) - 1)
        self.assertIsNotNone(host.results)
        self.assertEqual(result['nmap']['scaninfo']['tcp']['services'], str(self.port))


class NmapCommandsAddScriptTestCase(NmapScanManagerTestCases):
    def test_add_script(self):
        script = generateString(5)
        self.scanManager.addScript(script)
        self.assertIn(script, self.scanManager.scripts)

    def test_add_script_with_arguments(self):
        script = generateString(5)
        params = [generateString(3) for _ in range(2)]
        self.scanManager.addScript(script, *params)
        scriptExpected = script + " --script-args '{}'".format(' '.join(params))
        self.assertIn(scriptExpected, self.scanManager.scripts)


class NmapScanManagerListHostResultsTestCase(NmapScanManagerTestCases):
    def setUp(self):
        super(NmapScanManagerListHostResultsTestCase, self).setUp()
        self.results = []

    def test_list_hosts_results_without_host_ids(self):
        self.__addHost(self.address, randomPort())
        results = self.scanManager.getHostResults(False)
        self.assertEqual(len(results), 0)

    def test_list_hosts_results_with_host_ids(self):
        self.__addHost(self.address, randomPort())

        results = self.scanManager.getHostResults(False, 0)

        self.assertEqual(len(results), 1)
        self.assertEqual(results, self.results)

    def test_list_hosts_results_all_host_set_to_true(self):
        self.__addHost(generateIP(), randomPort())
        self.__addHost(generateIP(), randomPort())
        results = self.scanManager.getHostResults(True)
        self.assertEqual(len(results), 2)
        self.assertEqual(results, self.results)

    def test_list_hosts_results_with_invalid_host_id(self):
        with self.assertRaises(IndexError):
            self.scanManager.getHostResults(False, 0)

    def __addHost(self, address, firstPort=None):
        host = self.scanManager.addHost(address, firstPort)
        self.scanManager.scanHost(len(self.scanManager.hosts) - 1)
        self.results.append(host.results)
