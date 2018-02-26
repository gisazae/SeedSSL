__all__ = [
    'MetasploitCommands',
    'ExploitCommands',
    'PayloadCommands',
]

import socket
from functools import wraps

import click

from semillero_seguridadssl.modules.metasploit_wrapper import *


def execute_if_exists_client(command):
    @wraps(command)
    def validate_client(*args, **kwargs):
        try:
            return command(*args, **kwargs)
        except ClientNotAvailableException:
            click.echo('First, log into metasploit server.')

    return validate_client


def execute_if_module_selected(moduleType):
    def wrap_command(command):
        @wraps(command)
        def execute_module(*args, **kwargs):
            try:
                return command(*args, **kwargs)
            except ModuleNotSelectedException:
                click.echo('{0} not selected.'.format(moduleType))

        return execute_module

    return wrap_command


class MetasploitCommands:
    msfClient = MetasploitClient()

    @click.group(options_metavar='OPTIONS')
    def metasploit():
        """Commands to interact with the metasploit framework."""

    @metasploit.command(short_help='Log into metasploit server', options_metavar='OPTIONS')
    @click.argument('password')
    @click.option('-u', 'username', metavar='username',
                  help='Username used to authenticate to msfrpcd (default: msf)')
    @click.option('-s', 'server', metavar='IP',
                  help='Remote server IP address hosting msfrpcd (default: 127.0.0.1)')
    @click.option('-p', 'port', metavar='port',
                  help='Remote msfrpcd port to connect to (default: 55553)')
    @click.option('--ssl/--no-ssl', default=False, help='Enable ssl connection.')
    def login(**kwargs):
        """Log into metasploit server. A msfrpcd must be active to interact with the framework."""
        try:
            MetasploitCommands.msfClient.login(**kwargs)
            click.echo('Logged in')
        except socket.error as ser:
            click.echo('Verify msf server connection settings.')

    @metasploit.command(short_help='Display information about sessions', options_metavar='OPTIONS')
    @click.option('-l', '--list', 'list_flag', is_flag=True, help='List all active sessions.')
    @click.option('-i', '--interact', 'session_id', default=None, type=click.INT,
                  metavar='ID', help='Interact with the given session.')
    def sessions(session_id, list_flag):
        """List active sessions and interact with them."""
        if list_flag:
            click.echo(MetasploitCommands.msfClient.getActiveSessions())
        elif session_id is not None:
            try:
                MetasploitCommands.msfClient.getActiveSession(session_id)
            except KeyError:
                click.echo('Session does not exist')


class ExploitCommands:
    @click.group(options_metavar='OPTIONS')
    def exploit():
        """Commands to list, use and configure exploits from metasploit framework."""

    @exploit.command(short_help='List exploits', options_metavar='OPTIONS')
    @execute_if_exists_client
    def list():
        """List metasploit exploits available."""
        exploits = "\n".join(MetasploitCommands.msfClient.getExploits())
        click.echo_via_pager(exploits)

    @exploit.command(short_help='Choose exploit', options_metavar='OPTIONS')
    @click.argument('exploit')
    @execute_if_exists_client
    def use(exploit):
        """Choose exploit to use."""
        try:
            MetasploitCommands.msfClient.useExploit(exploit)
        except NameError as ner:
            click.echo(ner.message)

    @exploit.command(short_help='Interact with exploit options', options_metavar='OPTIONS')
    @click.option('--modify', is_flag=True, help='Use this option to set the exploit option value.')
    @click.option('-op', 'optionsReceived', multiple=True, metavar='option | --modify -op option=value',
                  help=('Use this option to get the value of exploit options. When used with --modify option, '
                        'set the exploit option value.'))
    @execute_if_module_selected('exploit')
    def options(optionsReceived, modify):
        """Display and modify information about exploit options."""
        if modify:
            options = {}
            for optionReceived in optionsReceived:
                if '=' in optionReceived:
                    option, value = optionReceived.split('=')
                    options[option] = value
            MetasploitCommands.msfClient.setExploitOptions(**options)
        else:
            options = [optionReceived for optionReceived in optionsReceived
                       if '=' not in optionReceived]
            click.echo(MetasploitCommands.msfClient.getExploitOptions(*options))

    @exploit.command(short_help='List compatible payloads', options_metavar='OPTIONS')
    @execute_if_module_selected('exploit')
    def payloads():
        """List the payloads than can be used with the exploit selected."""
        click.echo(MetasploitCommands.msfClient.getExploitPayloads())

    @exploit.command(short_help='Execute exploit', options_metavar='OPTIONS')
    @click.option('--payload', 'usePayload', is_flag=True,
                  help='Execute with a payload.')
    @execute_if_module_selected('exploit')
    def execute(usePayload):
        """Execute the exploit selected and configured. When used with --payload option,
        the exploit is executed with the selected payload, if any."""
        try:
            click.echo(MetasploitCommands.msfClient.executeExploit(usePayload))
        except ValueError:
            click.echo('Invalid payload')
        except TypeError as ter:
            click.echo(ter.message)


class PayloadCommands:
    @click.group(options_metavar='OPTIONS')
    def payload():
        """Commands to list, use and configure payloads from metasploit framework"""

    @payload.command(short_help='Choose payload', options_metavar='OPTIONS')
    @click.argument('payload')
    @execute_if_exists_client
    def use(payload):
        """Choose payload to use."""
        try:
            MetasploitCommands.msfClient.usePayload(payload)
        except NameError as ner:
            click.echo(ner.message)

    @payload.command(short_help='Interact with exploit options', options_metavar='OPTIONS')
    @click.option('--modify', is_flag=True, help='Use this option to set the payload option value.')
    @click.option('-op', 'optionsReceived', multiple=True, metavar='option | --modify -op option=value',
                  help=('Use this option to get the value of payload options. When used with --modify option, '
                        'set the payload option value.'))
    @execute_if_module_selected('payload')
    def options(optionsReceived, modify):
        """Display and modify information about payload options."""
        if modify:
            options = {}
            for optionReceived in optionsReceived:
                if '=' in optionReceived:
                    option, value = optionReceived.split('=')
                    options[option] = value
            MetasploitCommands.msfClient.setPayloadOptions(**options)
        else:
            options = [optionReceived for optionReceived in optionsReceived
                       if '=' not in optionReceived]
            click.echo(
                MetasploitCommands.msfClient.getPayloadOptions(*options))
