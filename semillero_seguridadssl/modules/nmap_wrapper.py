__all__ = [
    'Host',
    'NmapScanManager',
    'PortRangeBackwardException',
    'NoHostsToScanException',
]

import nmap


class PortRangeBackwardException(Exception):
    pass


class NoHostsToScanException(Exception):
    pass


class Host:
    def __init__(self, id, ip, ports=None):
        self.id = id
        self.ip = ip
        self.ports = ports
        self.results = None

    def __str__(self):
        host = 'Id: {0}\n{1}'.format(self.id, self.ip)
        if self.ports:
            host += ':{0}'.format(self.ports)
        return host


class NmapScanManager:
    def __init__(self):
        self.__hosts = []
        self.__scanner = nmap.PortScanner()
        self.__scripts = []

    def addHost(self, hostIp, firstPort=None, lastPort=None):
        if hostIp:
            hostId = len(self.__hosts)
            ports = self.__getPortsFormatted(firstPort, lastPort)
            host = Host(hostId, hostIp, ports)
            self.__hosts.append(host)
            return host

    def __getPortsFormatted(self, firstPort, lastPort):
        ports = None
        if firstPort and lastPort:
            if firstPort > lastPort:
                raise PortRangeBackwardException()
            ports = '{0}-{1}'.format(firstPort, lastPort)
        elif firstPort:
            ports = str(firstPort)
        return ports

    def scanHost(self, host_id):
        if not self.__hosts:
            raise NoHostsToScanException()
        host = self.__hosts[host_id]
        if not host.results:
            if self.__getScriptsFormatted():
                host.results = self.__scanner.scan(host.ip, host.ports, '-sV --script ' + self.__getScriptsFormatted())
            else:
                host.results = self.__scanner.scan(host.ip, host.ports)
        return host.results

    def getHosts(self):
        return self.__hosts

    def getHostResults(self, allHosts, *hostIds):
        results = []
        if allHosts:
            for host in self.__hosts:
                results.append(host.results)
        else:
            for hostId in hostIds:
                results.append(self.__hosts[hostId].results)
        return results

    def addScript(self, script, *params):
        if params:
            script += " --script-args '{}'".format(' '.join(params))
        self.__scripts.append(script)

    def getScripts(self):
        return self.__scripts

    def __getScriptsFormatted(self):
        scripts = ''
        if self.__scripts:
            for script in self.__scripts:
                scripts += str(script) + ','
            scripts = scripts[:-1]
        return scripts

    hosts = property(getHosts)
    scripts = property(getScripts)
