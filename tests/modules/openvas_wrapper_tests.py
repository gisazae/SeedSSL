import random
import unittest

import mock
from mock import mock_open, patch
from pyvas import Client

from semillero_seguridadssl.modules.openvas_wrapper import *
from tests.helpers import *


class OpenvasClientTestCases(unittest.TestCase):
    @mock.patch('semillero_seguridadssl.modules.openvas_wrapper.Client', autospec=True)
    def setUp(self, mock_client):
        self._client = OpenvasClient()
        self._client.openvasClient = mock_client


class ScansTestCase(OpenvasClientTestCases):
    def setUp(self):
        super(ScansTestCase, self).setUp()
        self.stub_configs = [{'name': generateString(6), '@id': generateId()}
                             for _ in range(4)] + [{'name': 'Host Discovery', '@id': generateId()}]
        self.config_names = [config['name'] for config in self.stub_configs]
        self.targets = [
            {'name': generateString(5),
             'hosts': generateIP(),
             '@id': generateId()}
            for _ in range(3)
        ]

    def test_list_scan_configurations(self):
        self._client.openvasClient.list_configs.return_value = self.stub_configs

        configurations = self._client.listScanConfigs()

        assert self._client.openvasClient.list_configs.called
        self.assertItemsEqual(self.config_names, configurations)

    def test_add_target(self):
        host = generateIP()
        create_target_result = {'@id': generateId()}
        result_expected = {
            'hosts': host,
            '@id': create_target_result['@id']
        }
        self._client.openvasClient.create_target.return_value = create_target_result

        self._client.addTarget(host)

        self._client.openvasClient.create_target.assert_called_with(host, host)
        self.assertIn(result_expected, self._client.targets)

    def test_list_targets(self):
        self._client.openvasClient.list_targets.return_value = self.targets
        result_expected = [target['hosts'] for target in self.targets]

        result = self._client.listTargets()

        self.assertEqual(result, result_expected)

    def test_start_a_task_when_scan_is_called_if_no_errors_raise(self):
        task = {'@id': generateId()}
        target = random.randrange(0, len(self.targets) - 1)
        self._client.configs = self.stub_configs
        self._client.targets = self.targets
        self._client.openvasClient.create_task.return_value = task

        self._client.scan(target)

        self._client.openvasClient.start_task.assert_called_with(task['@id'])

    def test_run_a_scan_with_a_config(self):
        configName = random.choice(self.config_names)
        configId = [config['@id'] for config in self.stub_configs if config['name'] == configName][0]
        target = random.randrange(0, len(self.targets) - 1)
        name = 'Scan of IP ' + self.targets[target]['hosts']
        self._client.configs = self.stub_configs
        self._client.targets = self.targets

        self._client.scan(target, configName)

        self._client.openvasClient.create_task.assert_called_with(name, configId, self.targets[target]['@id'])

    def test_run_a_scan_with_an_invalid_config(self):
        configName = random.choice(self.config_names)
        configName = generateString(6)
        target = random.randrange(0, len(self.targets))
        self._client.configs = self.stub_configs
        self._client.targets = self.targets

        with self.assertRaises(ValueError):
            self._client.scan(target, configName)

    def test_run_a_scan_without_a_config(self):
        configName = 'Host Discovery'
        configId = [config['@id'] for config in self.stub_configs if config['name'] == configName][0]
        target = random.randrange(0, len(self.targets) - 1)
        name = 'Scan of IP ' + self.targets[target]['hosts']
        self._client.configs = self.stub_configs
        self._client.targets = self.targets

        self._client.scan(target)

        self._client.openvasClient.create_task.assert_called_with(name, configId, self.targets[target]['@id'])

    def test_try_run_a_scan_null_config(self):
        configId = [config['@id'] for config in self.stub_configs if config['name'] == 'Host Discovery'][0]
        target = random.randrange(0, len(self.targets) - 1)
        name = 'Scan of IP ' + self.targets[target]['hosts']
        self._client.configs = self.stub_configs
        self._client.targets = self.targets

        self._client.scan(target, None)

        self._client.openvasClient.create_task.assert_called_with(name, configId, self.targets[target]['@id'])

    def test_list_tasks(self):
        task_name = 'Scan of IP' + generateIP()
        tasks = [{
            '@id': generateId(),
            'name': task_name,
            'progress': str(random.randrange(0, 100)),
            'status': 'Running'
        }]
        resultExpected = [{
            'name': task_name,
            'id': tasks[0]['@id'],
            'progress': '{}: {}%'.format(tasks[0]['status'], tasks[0]['progress'])
        }]
        self._client.openvasClient.list_tasks.return_value = tasks

        result = self._client.listTasks()

        self.assertAlmostEqual(result, resultExpected)

    def test_list_tasks_when_progress_answer_is_a_dictionary(self):
        task_name = 'Scan of IP' + generateIP()
        tasks = [{
            '@id': generateId(),
            'name': task_name,
            'progress': {'#text': str(random.randrange(0, 100))},
            'status': 'Running'
        }]
        resultExpected = [{
            'name': task_name,
            'id': tasks[0]['@id'],
            'progress': '{}: {}%'.format(tasks[0]['status'], tasks[0]['progress']['#text'])
        }]
        self._client.openvasClient.list_tasks.return_value = tasks

        result = self._client.listTasks()

        self.assertAlmostEqual(result, resultExpected)

    def test_list_tasks_with_a_task_done(self):
        task_name = 'Scan of IP' + generateIP()
        tasks = [{
            '@id': generateId(),
            'name': task_name,
            'progress': '-1',
            'status': 'Done'
        }]
        resultExpected = [{
            'name': task_name,
            'id': tasks[0]['@id'],
            'progress': tasks[0]['status']
        }]
        self._client.openvasClient.list_tasks.return_value = tasks

        result = self._client.listTasks()

        self.assertAlmostEqual(result, resultExpected)


class ContestManagerConnectionTestCase(OpenvasClientTestCases):
    @mock.patch('semillero_seguridadssl.modules.openvas_wrapper.Client', autospec=True)
    def test_set_client_before_open_connection(self, mock_client):
        mock_client.__enter__ = Client.__enter__
        mock_client.__exit__ = Client.__exit__
        mock_client.return_value = mock_client
        self._client.openvasClient = None

        self._client.listTasks()

        self.assertIsNotNone(self._client.openvasClient)
        assert mock_client.open.called
        assert mock_client.close.called

    def test_execute_command_with_context_manager(self):
        self._client.openvasClient.__enter__ = Client.__enter__
        self._client.openvasClient.__exit__ = Client.__exit__

        self._client.listTasks()

        assert self._client.openvasClient.open.called
        assert self._client.openvasClient.close.called


class ReportsTestCase(OpenvasClientTestCases):
    def setUp(self):
        super(ReportsTestCase, self).setUp()
        self.host = generateIP()
        self.stub_formats = [
            {'name': generateString(6),
             '@id': generateId(),
             'extension': generateString(3),
             'summary': generateString(10)}
            for _ in range(4)
        ]
        self.stub_reports = [
            {'task': {'name': generateString(6)},
             '@id': generateId(),
             'creation_time': generateString(10)}
            for _ in range(3)
        ]

        self._client.openvasClient.list_report_formats.return_value = self.stub_formats
        self._client.openvasClient.list_reports.return_value = self.stub_reports

    def test_list_report_formats(self):
        resultsExpected = ['{}: {}'.format(format['name'], format['summary'])
                           for format in self.stub_formats]
        results = self._client.listReportFormats()
        self.assertEqual(results, resultsExpected)

    def test_list_report(self):
        resultsExpected = ['Task {}, created at {}'.format(report['task']['name'], report['creation_time'])
                           for report in self.stub_reports]
        results = self._client.listReports()
        self.assertEqual(results, resultsExpected)

    def test_download_report(self):
        report = generateString(20)
        reportIndex = random.randint(0, len(self.stub_reports) - 1)
        reportId = self.stub_reports[reportIndex]['@id']
        formatIndex = random.randint(0, len(self.stub_formats) - 1)
        formatId = self.stub_formats[formatIndex]['@id']
        extension = self.stub_formats[formatIndex]['extension']
        fileName = generateString(5)
        path = '.'.join((fileName, extension))
        self._client.reports = self.stub_reports
        self._client.formats = self.stub_formats
        self._client.openvasClient.download_report.return_value = report

        with patch('__builtin__.open', new_callable=mock_open()) as open:
            with open(path) as mock_file:
                self._client.downloadReport(reportIndex, formatIndex, fileName)

                self._client.openvasClient.download_report.assert_called_with(reportId, formatId)
                open.assert_called_with(path, 'w')
                mock_file.write.assert_called_with(report)


class SetCredentialsTestCase(OpenvasClientTestCases):
    def setUp(self):
        self._client = OpenvasClient()

    @mock.patch('semillero_seguridadssl.modules.openvas_wrapper.Client', autospec=True)
    def test_set_host_with_openvas_client(self, mock_client):
        self._client.openvasClient = mock_client
        host = generateIP()

        self._client.setHost(host)

        self.assertEqual(self._client.host, host)
        self.assertEqual(mock_client.host, host)

    @mock.patch('semillero_seguridadssl.modules.openvas_wrapper.Client', autospec=True)
    def test_set_username_with_openvas_client(self, mock_client):
        self._client.openvasClient = mock_client
        username = generateString(5)

        self._client.setUsername(username)

        self.assertEqual(self._client.username, username)
        self.assertEqual(mock_client.username, username)

    @mock.patch('semillero_seguridadssl.modules.openvas_wrapper.Client', autospec=True)
    def test_set_password_with_openvas_client(self, mock_client):
        self._client.openvasClient = mock_client
        password = generateString(6)

        self._client.setPassword(password)

        self.assertEqual(self._client.password, password)
        self.assertEqual(mock_client.password, password)

    def test_set_host_without_openvas_client(self):
        host = generateIP()

        self._client.setHost(host)

        self.assertIsNone(self._client.openvasClient)
        self.assertEqual(self._client.host, host)

    def test_set_username_without_openvas_client(self):
        username = generateString(5)

        self._client.setUsername(username)

        self.assertIsNone(self._client.openvasClient)
        self.assertEqual(self._client.username, username)

    def test_set_password_without_openvas_client(self):
        password = generateString(6)

        self._client.setPassword(password)

        self.assertIsNone(self._client.openvasClient)
        self.assertEqual(self._client.password, password)
