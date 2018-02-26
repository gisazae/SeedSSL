__all__ = [
    'OpenvasClient',
]

from functools import wraps

from pyvas import Client


class OpenvasClient:
    def __init__(self):
        self.openvasClient = None
        self.host = '127.0.0.1'
        self.username = ''
        self.password = ''
        self.configs = []
        self.targets = []
        self.formats = []
        self.reports = []

    def open_connection_before_execute(command):
        @wraps(command)
        def open_connection(self, *args, **kwargs):
            if not self.openvasClient:
                self.openvasClient = Client(self.host, self.username, self.password)
            with self.openvasClient:
                result = command(self, *args, **kwargs)
            return result

        return open_connection

    @open_connection_before_execute
    def listScanConfigs(self):
        self.__updateConfigs()
        return [config['name'] for config in self.configs]

    def __updateConfigs(self):
        openvas_configs = self.openvasClient.list_configs()
        self.configs = [{key: openvas_config[key] for key in openvas_config if key == 'name' or key == '@id'}
                        for openvas_config in openvas_configs]

    @open_connection_before_execute
    def addTarget(self, host):
        result = self.openvasClient.create_target(host, host)
        self.targets.append({'hosts': host, '@id': result['@id']})

    @open_connection_before_execute
    def listTargets(self):
        self.__updateTargets()
        return [target['hosts'] for target in self.targets]

    def __updateTargets(self):
        openvas_targets = self.openvasClient.list_targets()
        self.targets = [{key: openvas_target[key] for key in openvas_target if key == 'hosts' or key == '@id'}
                        for openvas_target in openvas_targets]

    @open_connection_before_execute
    def scan(self, target, configName=None):
        host = self.targets[target]['hosts']
        targetId = self.targets[target]['@id']
        if configName is None:
            configName = 'Host Discovery'

        configId = None
        for config in self.configs:
            if config['name'] == configName:
                configId = config['@id']
                break

        if not configId:
            raise ValueError('Config name not found')

        task = self.openvasClient.create_task('Scan of IP ' + host, configId, targetId)
        self.openvasClient.start_task(task['@id'])

    @open_connection_before_execute
    def listTasks(self):
        openvasTasks = self.openvasClient.list_tasks()
        tasks = []

        for task in openvasTasks:
            tasks.append({
                'name': task['name'],
                'id': task['@id'],
                'progress': self.__getTaskStatus(task)
            })

        return tasks

    def __getTaskStatus(self, task):
        if task['progress'] == '-1':
            taskStatus = task['status']
        else:
            progress = task['progress']
            progress = progress if isinstance(progress, str) else progress['#text']
            taskStatus = '{}: {}%'.format(task['status'], progress)
        return taskStatus

    @open_connection_before_execute
    def listReportFormats(self):
        self.formats = self.openvasClient.list_report_formats()
        return ['{}: {}'.format(format['name'], format['summary']) for format in self.formats]

    @open_connection_before_execute
    def listReports(self):
        self.reports = self.openvasClient.list_reports()
        return ['Task {}, created at {}'.format(report['task']['name'], report['creation_time'])
                for report in self.reports]

    @open_connection_before_execute
    def downloadReport(self, reportIndex, formatIndex, path):
        report = self.openvasClient.download_report(
            self.reports[reportIndex]['@id'],
            self.formats[formatIndex]['@id'])
        extension = self.formats[formatIndex]['extension']
        with open('.'.join((path, extension)), 'w') as file:
            file.write(report)

    def setHost(self, host):
        self.host = host
        if self.openvasClient:
            self.openvasClient.host = host

    def setUsername(self, username):
        self.username = username
        if self.openvasClient:
            self.openvasClient.username = username

    def setPassword(self, password):
        self.password = password
        if self.openvasClient:
            self.openvasClient.password = password
