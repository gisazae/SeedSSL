__all__ = [
    'MetasploitClient',
    'ModuleNotSelectedException',
    'ClientNotAvailableException',
    'MsfRpcError',
    'SessionInterpreter'
]

import cmd
from functools import wraps

from metasploit.msfrpc import MsfRpcClient, MsfRpcError


class ModuleNotSelectedException(Exception):
    pass


class ClientNotAvailableException(Exception):
    pass


class MetasploitClient:
    def __init__(self):
        self.msfClient = None
        self.exploit = None
        self.payload = None
        self.session = None

    def execute_if_exists_client(command):
        @wraps(command)
        def validate_client(self, *args, **kwargs):
            if not self.msfClient:
                raise ClientNotAvailableException()
            return command(self, *args, **kwargs)

        return validate_client

    def execute_if_module_selected(moduleType):
        def wrap_command(command):
            @wraps(command)
            def check_module(self, *args, **kwargs):
                modules = {
                    'exploit': self.exploit,
                    'payload': self.payload
                }
                if not modules[moduleType]:
                    raise ModuleNotSelectedException()
                return command(self, *args, **kwargs)

            return check_module

        return wrap_command

    def login(self, password, port=None, server=None, username=None, ssl=None):
        self.msfClient = MsfRpcClient(
            password,
            username=username or 'msf',
            port=port or '55553-55559',
            server=server or '127.0.0.1',
            ssl=ssl or False,
        )

    @execute_if_exists_client
    def getExploits(self):
        return self.msfClient.modules.exploits

    @execute_if_exists_client
    def useExploit(self, exploitName):
        self.exploit = self.__useModule('exploit', exploitName)

    @execute_if_module_selected('exploit')
    def getExploitOptions(self, *options):
        return self.__getModuleOptions(self.exploit, *options)

    @execute_if_module_selected('exploit')
    def setExploitOptions(self, **options):
        self.__setModuleOptions(self.exploit, **options)

    @execute_if_module_selected('exploit')
    def getExploitPayloads(self):
        return self.exploit.payloads

    @execute_if_exists_client
    def usePayload(self, payloadName):
        self.payload = self.__useModule('payload', payloadName)

    @execute_if_module_selected('payload')
    def getPayloadOptions(self, *options):
        return self.__getModuleOptions(self.payload, *options)

    @execute_if_module_selected('payload')
    def setPayloadOptions(self, **options):
        self.__setModuleOptions(self.payload, **options)

    @execute_if_module_selected('exploit')
    def executeExploit(self, usePayload=False):
        if usePayload and self.payload:
            result = self.exploit.execute(payload=self.payload)
        else:
            result = self.exploit.execute()
        return result

    def getActiveSessions(self):
        return self.msfClient.sessions.list

    def getActiveSession(self, sessionId):
        self.session = self.msfClient.sessions.session(sessionId)
        SessionInterpreter(self.session).cmdloop()

    def __useModule(self, moduleType, moduleName):
        try:
            return self.msfClient.modules.use(moduleType, moduleName)
        except MsfRpcError:
            raise NameError('Invalid {0}.'.format(moduleType))

    def __getModuleOptions(self, msf_module, *options):
        if options:
            return {option: msf_module[option] for option in msf_module.options
                    if option in options}
        else:
            return {option: msf_module[option] for option in msf_module.options}

    def __setModuleOptions(self, msf_module, **options):
        if options:
            for option in options:
                if option in msf_module.options:
                    msf_module[option] = options[option]


class SessionInterpreter(cmd.Cmd):
    def __init__(self, session):
        cmd.Cmd.__init__(self)
        self.prompt = '>> '
        self.intro = 'Session interpreter ready'
        self.session = session

    def default(self, line):
        self.session.write(line + '\n')
        print(self.session.read())
