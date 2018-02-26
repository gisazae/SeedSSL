__all__ = [
    'OpenvasCommands',
]

import os

import click

from semillero_seguridadssl.modules.openvas_wrapper import *


class OpenvasCommands:
    client = OpenvasClient()

    @click.group(options_metavar='OPTIONS')
    def openvas():
        """Commands to interact with openvas services."""

    @openvas.command(short_help='Set credentials', options_metavar='OPTIONS')
    @click.option('-h', 'host', metavar='IP', help='Set Greenbone IP server to connect to.')
    @click.option('-u', 'username', metavar='username', help='Set username in Greenbone server.')
    @click.option('-p', 'password', metavar='password', help='Set password in Greenbone server.')
    def credentials(password, username, host):
        """Set different credentials values."""
        if password:
            OpenvasCommands.client.setPassword(password)
        if username:
            OpenvasCommands.client.setUsername(username)
        if host:
            OpenvasCommands.client.setHost(host)
        click.echo('Ok')

    @openvas.command(short_help='List configurations and run scans', options_metavar='OPTIONS')
    @click.option('--configs', 'list_flag', is_flag=True, help='List the configurations available to scan.')
    @click.option('--with-config', 'with_config', is_flag=True, help=('Allows you to choose a configuration '
                                                                      'before running the scan.'))
    def scan(with_config, list_flag):
        """Run a new scan. With --configs option, list the configurations available to scan."""
        if list_flag:
            click.echo(OpenvasCommands.client.listScanConfigs())
        else:
            targets = OpenvasCommands.client.listTargets()
            for i, target in enumerate(targets):
                click.echo('{} -> {}'.format(i, target))
            target = click.prompt('Choose the target to scan', type=click.INT)
            config = None
            if with_config:
                configs = OpenvasCommands.client.listScanConfigs()
                for i, config in enumerate(configs):
                    click.echo('{} -> {}'.format(i, config))
                config = click.prompt('Choose the configuration to use', type=click.INT)
            args = {
                'target': target,
                'configName': configs[config] if with_config else config
            }
            OpenvasCommands.client.scan(**args)

    @openvas.command(short_help='List and create targets', options_metavar='OPTIONS')
    @click.option('--create', 'host', metavar='IP', help='Creates a new target.')
    def targets(host):
        """List the targets available. With --create option, create a new target."""
        if host:
            OpenvasCommands.client.addTarget(host)
            click.echo('Ok')
        else:
            click.echo(OpenvasCommands.client.listTargets())

    @openvas.command(short_help='List tasks', options_metavar='OPTIONS')
    def tasks():
        """List tasks and their current status."""
        tasks = OpenvasCommands.client.listTasks()
        for task in tasks:
            click.echo("{0}.\nScan ID: {1}\nScan progress: {2}\n".format(
                task['name'],
                task['id'],
                task['progress']
            ))

    @openvas.command(short_help='List reports and formats', options_metavar='OPTIONS')
    @click.option('--formats', 'formats_flag', is_flag=True)
    @click.option('--download', 'download_flag', is_flag=True)
    def reports(download_flag, formats_flag):
        """List the reports available. With the --formats options list the formats available. When used with
        --download option you will be prompted for information to download a desired report."""
        if download_flag:
            reports = OpenvasCommands.client.listReports()
            if len(reports) == 0:
                click.echo('No reports available.')
            else:
                formats = OpenvasCommands.client.listReportFormats()
                for i, format in enumerate(formats):
                    click.echo('{} -> {}'.format(i, format))
                formatIndex = click.prompt('Choose the format to save', type=click.INT)
                for i, report in enumerate(reports):
                    click.echo('{} -> {}'.format(i, report))
                reportIndex = click.prompt('Choose the report to save', type=click.INT)
                path = click.prompt('Enter file name in which to save the report',
                                    default='/'.join((os.environ['HOME'], 'report')))
                OpenvasCommands.client.downloadReport(reportIndex, formatIndex, path)
        else:
            if formats_flag:
                click.echo_via_pager(OpenvasCommands.client.listReportFormats())
            click.echo_via_pager(OpenvasCommands.client.listReports())
