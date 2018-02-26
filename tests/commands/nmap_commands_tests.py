import random
import unittest

import mock
from click.testing import CliRunner

from semillero_seguridadssl.commands.nmap_commands import *
from semillero_seguridadssl.modules.nmap_wrapper import Host, NoHostsToScanException, PortRangeBackwardException
from tests.helpers import generateIP, randomPort, generateString


class NmapCommandsTetsCases(unittest.TestCase):
    @mock.patch('semillero_seguridadssl.modules.nmap_wrapper.NmapScanManager', autospec=True)
    def setUp(self, mock_scan_manager):
        self.runner = CliRunner()
        self.mock_scan_manager = mock_scan_manager
        NmapCommands.scanManager = mock_scan_manager


class NmapCommandsAddHostTestCase(NmapCommandsTetsCases):
    def setUp(self):
        super(NmapCommandsAddHostTestCase, self).setUp()
        self.address = generateIP()

    def test_add_host_without_options(self):
        hostId = random.randint(0, 3)
        stub_host = Host(hostId, self.address, None)
        self.mock_scan_manager.addHost.return_value = stub_host

        result = self.runner.invoke(NmapCommands.add_host, [self.address])

        self.assertEqual(result.output, 'Added: Id: {}\n{}\n'.format(hostId, self.address))

    def test_add_host_with_first_port_option(self):
        hostId = random.randint(0, 3)
        firstPort = randomPort()
        stub_host = Host(hostId, self.address, str(firstPort))
        self.mock_scan_manager.addHost.return_value = stub_host

        result = self.runner.invoke(NmapCommands.add_host, [self.address, '-fp', firstPort])

        self.assertEqual(result.output, 'Added: Id: {}\n{}:{}\n'.format(hostId, self.address, firstPort))

    def test_add_host_with_last_port_option(self):
        hostId = random.randint(0, 3)
        lastPort = randomPort()
        stub_host = Host(hostId, self.address, None)
        self.mock_scan_manager.addHost.return_value = stub_host

        result = self.runner.invoke(NmapCommands.add_host, [self.address, '-lp', lastPort])

        self.assertEqual(result.output, 'Added: Id: {}\n{}\n'.format(hostId, self.address))

    def test_add_host_with_port_options(self):
        hostId = random.randint(0, 3)
        firstPort = randomPort(max=90)
        lastPort = randomPort(91, 100)
        ports = '{}-{}'.format(firstPort, lastPort)
        stub_host = Host(hostId, self.address, ports)
        self.mock_scan_manager.addHost.return_value = stub_host

        result = self.runner.invoke(NmapCommands.add_host, [self.address, '-fp', firstPort,
                                                            '-lp', lastPort])

        self.assertEqual(result.output, 'Added: Id: {}\n{}:{}\n'.format(hostId, self.address, ports))

    def test_add_host_with_invalid_port_options(self):
        firstPort = randomPort(max=90)
        lastPort = randomPort(91, 100)
        self.mock_scan_manager.addHost.side_effect = PortRangeBackwardException()

        result = self.runner.invoke(NmapCommands.add_host, [self.address, '-fp', lastPort,
                                                            '-lp', firstPort])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.output, 'First port must be lower than last port\n')


class NmapCommandsScanHostTestCase(NmapCommandsTetsCases):
    def test_scan_host_without_hosts_to_scan(self):
        self.mock_scan_manager.scanHost.side_effect = NoHostsToScanException()
        result = self.runner.invoke(NmapCommands.scan_host)
        self.assertEqual(result.output, "Add hosts first\n")

    def test_scan_host_without_host_id(self):
        self.runner.invoke(NmapCommands.scan_host)
        self.mock_scan_manager.scanHost.assert_called_with(-1)

    def test_scan_host_with_host_id(self):
        hostId = random.randint(0, 3)
        self.runner.invoke(NmapCommands.scan_host, [str(hostId)])
        self.mock_scan_manager.scanHost.assert_called_with(hostId)


class NmapCommandsListHostsTestCase(NmapCommandsTetsCases):
    def setUp(self):
        super(NmapCommandsListHostsTestCase, self).setUp()
        self.address = generateIP()

    def test_list_hosts_with_no_hosts(self):
        self.mock_scan_manager.getHosts.return_value = []
        result = self.runner.invoke(NmapCommands.list_hosts)
        self.assertEqual(result.output, '')

    def test_list_hosts_with_one_host(self):
        hosts = [Host(i, generateIP(), '{}-{}'.format(randomPort(max=90), randomPort(91, 100)))
                 for i in range(2)]
        listResult = '\n'.join([str(host) for host in hosts])
        self.mock_scan_manager.getHosts.return_value = hosts

        result = self.runner.invoke(NmapCommands.list_hosts)

        self.assertEqual(result.output, listResult + '\n')


class NmapCommandsAddScriptTestCase(NmapCommandsTetsCases):
    def test_add_script(self):
        script = generateString(5)
        result = self.runner.invoke(NmapCommands.add_script, [script])
        self.assertEqual(result.output, 'Script added: {}\n'.format(script))

    def test_add_script_with_arguments(self):
        script = generateString(5)
        params = [generateString(3) for _ in range(2)]
        result = self.runner.invoke(NmapCommands.add_script, [script,
                                                              '-p', params[0],
                                                              '-p', params[1]])
        self.assertIn('With params: {}\n'.format(' '.join(params)), result.output)


class NmapCommandsListHostResultsTestCase(NmapCommandsTetsCases):
    def setUp(self):
        super(NmapCommandsListHostResultsTestCase, self).setUp()
        self.address = generateIP()
        self.hosts = [Host(i, generateIP(), '{}-{}'.format(randomPort(max=90), randomPort(91, 100)))
                      for i in range(2)]

    def test_list_hosts_results_without_parameters(self):
        for host in self.hosts:
            host.results = {
                'nmap': {
                    'scaninfo': {
                        'tcp': {
                            'services': host.ports
                        }
                    }
                }
            }
        hostResults = [host.results for host in self.hosts]
        self.mock_scan_manager.getHostResults.return_value = hostResults

        result = self.runner.invoke(NmapCommands.show_host_results)

        self.assertEqual(result.output, str(hostResults) + '\n')

    def test_list_hosts_results_with_host_ids(self):
        hostId = random.randint(0, len(self.hosts) - 1)
        self.runner.invoke(NmapCommands.show_host_results, ['-h', hostId])
        self.mock_scan_manager.getHostResults.assert_called_with(False, hostId)

    def test_list_hosts_results_all_host_set_to_true(self):
        self.runner.invoke(NmapCommands.show_host_results, ['--all-hosts'])
        self.mock_scan_manager.getHostResults.assert_called_with(True, -1)

    def test_list_hosts_results_with_invalid_host_id(self):
        amount = len(self.hosts)
        self.mock_scan_manager.getHostResults.side_effect = IndexError

        result = self.runner.invoke(NmapCommands.show_host_results, ['-h', random.randint(amount, amount + 2)])

        self.assertEqual(result.output, 'Invalid host id\n')
