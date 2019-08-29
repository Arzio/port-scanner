import sys
import re
import datetime
import socket
from json import JSONEncoder
from enum import Enum

def help() -> None:
    raise NotImplementedError

class ConnectionMethod(Enum):
    TCP = 'TCP'
    UDP = 'UDP'

class ArgumentParser:
    def __init__(self, dict: dict = None):
        if dict == None:
            self.min = self.max = self.ip = None
            self.udp = self.tcp = self.json = False

            for arg_index in range(len(sys.argv)):
                arg = sys.argv[arg_index]

                if arg in ('-h', '-H', '--help'):
                    help()
                    exit(0)

                elif arg in ('-f', '-F', '--from'):
                    self.min = int(sys.argv[arg_index + 1])

                elif arg in ('-t', '-T', '--to'):
                    self.max = int(sys.argv[arg_index + 1])

                elif arg == '--udp':
                    self.udp = True

                elif arg == '--tcp':
                    self.tcp = True

                elif arg == '--json':
                    self.json = True

                elif re.match(r"^(\d{1,3}\.){3}\d{1,3}$", arg):
                    self.ip = arg
        
        else:
            self.min = int(dict['min'])
            self.max = int(dict['max'])
            self.ip = str(dict['ip'])
            self.udp = bool(dict['udp'])
            self.tcp = bool(dict['tcp'])
            self.json = True

    def has_valid_args(self) -> bool:
        return None not in (self.min, self.max, self.ip) and (self.tcp or self.udp)
    
    def has_allowed_port_range(self) -> bool:
        return self.min >= 1 and self.max <= (2**16 - 1) and self.min <= self.max

class PortScanner:
    def __init__(self, ip: str, ports: tuple):
        self.ip = ip
        self.ports = ports

    # TODO: Create threads for every port scan
    def scan(self, method: ConnectionMethod) -> None:
        print('Scanning {} ports at {}'.format(method.value, self.ip))
        start = datetime.datetime.now()

        for port in self.ports:
            if method == ConnectionMethod.TCP:
                self.__tcp_scan__(port, True)
            
            elif method == ConnectionMethod.UDP:
                self.__udp_scan__(port, True)

        time_taken = (datetime.datetime.now() - start).total_seconds()
        print('{} scanning finished, it took {} seconds'.format(method.value, time_taken))
        
    def scan_to_list(self, method: ConnectionMethod) -> list:
        open_ports = list()

        for port in self.ports:
            if method == ConnectionMethod.TCP:
                if self.__tcp_scan__(port, False):
                    open_ports.append(port)
            
            elif method == ConnectionMethod.UDP:
                if self.__udp_scan__(port, False):
                    open_ports.append(port)
        
        return open_ports

    def __tcp_scan__(self, port: int, show_info: bool) -> bool:
        con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        con.settimeout(0.1)
        dest = (self.ip, port)

        if con.connect_ex(dest) == 0:
            if show_info:
                print('TCP port {} is open!'.format(port))

            con.close()
            return True
        
        else:
            con.close()
            return False
    
    # TODO: UDP scan
    def __udp_scan__(self, port: int, show_info: bool) -> int:
        raise NotImplementedError

# TODO: Implement observer design pattern
def main() -> None:
    arg_parser = ArgumentParser()

    if not arg_parser.has_valid_args():
        print('Invalid args')
        exit(1)

    if not arg_parser.has_allowed_port_range():
        print('Range not allowed')
        exit(1)
    
    ps = PortScanner(arg_parser.ip, range(arg_parser.min, arg_parser.max + 1))

    if arg_parser.json:
        tcp_ports = list()
        udp_ports = list()

        if arg_parser.tcp:
            tcp_ports = ps.scan_to_list(ConnectionMethod.TCP)
        
        if arg_parser.udp:
            udp_ports = ps.scan_to_list(ConnectionMethod.UDP)

        json_object = JSONEncoder().encode({'tcp': tcp_ports, 'udp': udp_ports})
        print(json_object)

    else:
        if arg_parser.tcp:
            ps.scan(ConnectionMethod.TCP)
        
        if arg_parser.udp:
            ps.scan(ConnectionMethod.UDP)

if __name__ == '__main__':
    main()