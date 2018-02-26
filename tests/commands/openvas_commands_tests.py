import random
import unittest

import mock
from click.testing import CliRunner

from semillero_seguridadssl.commands.openvas_commands import *
from semillero_seguridadssl.modules.openvas_wrapper import OpenvasClient
from tests.helpers import generateId, generateIP, generateString


class OpenvasCommandsTestsCases(unittest.TestCase):
    @mock.patch('semillero_seguridadssl.commands.openvas_commands.OpenvasClient', autospec=True)
    def setUp(self, mock_client):
        self.runner = CliRunner()
        self.mock_client = mock_client
        OpenvasCommands.client = mock_client


class SetCredentialsTestCase(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()
        self.login_params = {
            'host': generateIP(),
            'username': generateString(5),
            'password': generateString(6)
        }
        OpenvasCommands.client = OpenvasClient()

    def test_set_password(self):
        result = self.runner.invoke(OpenvasCommands.credentials, ['-p', self.login_params['password']])
        self.assertIn('Ok', result.output, result.exception or result.exit_code)

    def test_set_username(self):
        result = self.runner.invoke(OpenvasCommands.credentials, ['-u', self.login_params['username']])
        self.assertIn('Ok', result.output, result.exception or result.exit_code)

    def test_set_host(self):
        result = self.runner.invoke(OpenvasCommands.credentials, ['-h', self.login_params['host']])
        self.assertIn('Ok', result.output, result.exception or result.exit_code)


class ScansTestCase(OpenvasCommandsTestsCases):
    def setUp(self):
        super(ScansTestCase, self).setUp()
        self.configs = {generateString(5): generateId() for _ in range(4)}

    def test_list_scan_configurations(self):
        self.mock_client.listScanConfigs.return_value = self.configs.keys()
        result = self.runner.invoke(OpenvasCommands.scan, ['--configs'])
        self.assertIn(str(self.configs.keys()), result.output, result.exception or result.exit_code)

    def test_add_target(self):
        host = generateIP()
        self.runner.invoke(OpenvasCommands.targets, ['--create', host])
        self.mock_client.addTarget.assert_called_with(host)

    def test_list_targets(self):
        targets = [generateIP() for _ in range(3)]
        self.mock_client.listTargets.return_value = targets

        result = self.runner.invoke(OpenvasCommands.targets)

        self.assertEqual(result.output, str(targets) + '\n', result.exception or result.exit_code)

    def test_run_scan(self):
        target = random.randint(0, 5)
        self.runner.invoke(OpenvasCommands.scan, input=str(target) + "\n")
        self.mock_client.scan.assert_called_with(target=target, configName=None)

    def test_run_scan_with_configuration(self):
        configs = self.configs.keys()
        self.mock_client.listScanConfigs.return_value = configs
        target = random.randint(0, 5)
        scanConfig = random.randint(0, len(configs) - 1)

        self.runner.invoke(OpenvasCommands.scan, ['--with-config'], '\n'.join((str(target), str(scanConfig))))

        self.mock_client.scan.assert_called_with(target=target, configName=configs[scanConfig])

    def test_list_tasks(self):
        tasks = [
            {'id': generateId(),
             'name': 'Scan of IP' + generateIP(),
             'progress': 'Running: {}%'.format(random.randrange(0, 100)),
             'status': generateString(5)}
            for _ in range(2)
        ]
        resultExpected = '\n\n'.join([
            "{0}.\nScan ID: {1}\nScan progress: {2}".format(
                task['name'],
                task['id'],
                task['progress']
            )
            for task in tasks
        ]) + '\n\n'
        self.mock_client.listTasks.return_value = tasks

        result = self.runner.invoke(OpenvasCommands.tasks)

        self.assertEqual(resultExpected, result.output, result.exception or result.exit_code)

    def test_list_tasks_with_a_task_done(self):
        tasks = [
            {'id': generateId(),
             'name': 'Scan of IP' + generateIP(),
             'progress': '-1',
             'status': generateString(5)}
            for _ in range(2)
        ]
        resultExpected = '\n\n'.join([
            "{0}.\nScan ID: {1}\nScan progress: {2}".format(
                task['name'],
                task['id'],
                task['progress']
            )
            for task in tasks
        ]) + '\n\n'
        self.mock_client.listTasks.return_value = tasks

        result = self.runner.invoke(OpenvasCommands.tasks)

        self.assertEqual(resultExpected, result.output)


class ReportsTestCase(OpenvasCommandsTestsCases):
    def setUp(self):
        super(ReportsTestCase, self).setUp()
        self.formats = [generateString(10) for _ in range(5)]
        self.reports = [generateString(10) for _ in range(5)]

    def test_list_report_formats(self):
        self.mock_client.listReportFormats.return_value = self.formats
        result = self.runner.invoke(OpenvasCommands.reports, ['--formats'])
        self.assertIn(str(self.formats), result.output)

    def test_list_reports(self):
        self.mock_client.listReports.return_value = self.reports
        result = self.runner.invoke(OpenvasCommands.reports)
        self.assertIn(str(self.reports), result.output)

    def test_download_report(self):
        self.mock_client.listReportFormats.return_value = self.formats
        self.mock_client.listReports.return_value = self.reports
        reportIndex = random.randint(0, len(self.reports) - 1)
        formatIndex = random.randint(0, len(self.formats) - 1)
        path = generateString(5)

        self.runner.invoke(OpenvasCommands.reports, ['--download'],
                           '\n'.join((str(formatIndex), str(reportIndex), path)))

        self.mock_client.downloadReport.assert_called_with(reportIndex, formatIndex, path)

    def test_try_download_report_without_reports(self):
        self.mock_client.listReports.return_value = []
        result = self.runner.invoke(OpenvasCommands.reports, ['--download'])
        self.assertEqual('No reports available.\n', result.output)

    def test_reports_command_without_passing_an_option(self):
        self.runner.invoke(OpenvasCommands.reports)
        self.assertTrue(self.mock_client.listReports.called)
