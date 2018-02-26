__all__ = [
    'NmapCommands',
]

import os

import click

from semillero_seguridadssl.modules.nmap_wrapper import *


class NmapCommands:
    scanManager = NmapScanManager()

    @click.group(options_metavar='OPTIONS')
    def nmap():
        """Commands to interact with the nmap tool."""

    @nmap.command(short_help='Add a host to scan', options_metavar='OPTIONS')
    @click.argument('host_ip', 'IP', required=True, metavar='IP')
    @click.option('-fp', '--first-port', 'firstPort', type=click.INT, metavar='port',
                  help='Single port to scan or first port of a range if passed with -lp option.')
    @click.option('-lp', '--last-port', 'lastPort', type=click.INT, metavar='port',
                  help='Last port to scan of a range. Need to be passed with -fp option.')
    def add_host(host_ip, firstPort, lastPort):
        """Add a host to be scanned. A range of ports can be given to reduce the scanning."""
        try:
            host = NmapCommands.scanManager.addHost(host_ip, firstPort, lastPort)
            click.echo('Added: {0}'.format(str(host)))
        except PortRangeBackwardException:
            click.echo('First port must be lower than last port')

    @nmap.command(short_help='Runs a new scan', options_metavar='OPTIONS')
    @click.argument('host_id', 'ID', metavar='ID', default=-1, type=click.INT)
    def scan_host(host_id):
        """Runs a new scan to the given host ID."""
        try:
            results = NmapCommands.scanManager.scanHost(host_id)
            click.echo(results)
        except NoHostsToScanException:
            click.echo('Add hosts first')

    @nmap.command(short_help='List hosts', options_metavar='OPTIONS')
    def list_hosts():
        """List the hosts previously added."""
        hosts = NmapCommands.scanManager.getHosts()
        for host in hosts:
            click.echo(str(host))

    @nmap.command(short_help='Display results information', options_metavar='OPTIONS')
    @click.option('-h', 'hostIds', multiple=True, type=click.INT, default=(-1,), metavar='id',
                  help="The host id of scanned host. Can be passed multiple times like '-h 0 -h 1'.")
    @click.option('--all-hosts', 'allHosts', is_flag=True, help='Show all the results.')
    def show_host_results(allHosts, hostIds):
        """Display the results of the host IDs scanned. When the --all-hosts is given, shows all the results."""
        try:
            results = NmapCommands.scanManager.getHostResults(allHosts, *hostIds)
            click.echo(results)
        except IndexError:
            click.echo('Invalid host id')

    @nmap.command(short_help='Add nmap script', options_metavar='OPTIONS')
    @click.argument('script')
    @click.option('-p', 'params', multiple=True, metavar='name=value',
                  help='Parameter of the nmap script chosen.')
    def add_script(script, params):
        """Add a nmap script from the nmap script engine to be used."""
        NmapCommands.scanManager.addScript(script, *params)
        click.echo('Script added: ' + script)
        if params:
            click.echo('With params: ' + ' '.join(params))

    @nmap.command(short_help='List nmap scripts', options_metavar='OPTIONS')
    def list_scripts():
        """List the scripts from the nmap script engine available."""
        os.system("ls /usr/share/nmap/scripts/*.nse")
