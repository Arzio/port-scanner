import sys
import re
import datetime
import socket
from enum import Enum

def help():
    raise NotImplementedError

class ScanStatus:
    def __init__(self):
        self.open_ports = list()
        self.closed_ports = list()

    def __init__(self, open_ports: list, closed_ports: list):
        self.open_ports = open_ports
        self.closed_ports = closed_ports

class ArgumentParser:
    def __init__(self):
        self.min = self.max = self.ip = None
        self.udp = self.tcp = False
        
        for arg_index in range(len(sys.argv)):
            arg = sys.argv[arg_index]

            if arg in ("-h", "-H", "--help"):
                help()
                exit()

            elif arg in ("-f", "-F", "--from"):
                self.min = int(sys.argv[arg_index + 1])

            elif arg in ("-t", "-T", "--to"):
                self.max = int(sys.argv[arg_index + 1])

            elif arg == "--udp":
                self.udp = True

            elif arg == "--tcp":
                self.tcp = True

            elif re.match(r"^(\d{1,3}\.){3}\d{1,3}$", arg):
                self.ip = arg

    def has_valid_args(self):
        return None not in (self.min, self.max, self.ip) and (self.tcp or self.udp)
    
    def has_allowed_port_range(self):
        return self.min >= 1 or self.max <= (2**16 - 1)

class ConnectionMethod(Enum):
    TCP = "TCP"
    UDP = "UDP"

class PortScanner:
    def __init__(self, ip: str, ports: tuple):
        self.ip = ip
        self.ports = ports

    # TODO: Create threads for every port scan
    def scan(self, method: ConnectionMethod):
        print("Scanning {} ports at {}".format(method.value, self.ip))
        start = datetime.datetime.now()

        for port in self.ports:
            if method == ConnectionMethod.TCP:
                self.__tcp_scan__(port)
            
            elif method == ConnectionMethod.UDP:
                self.__udp_scan__(port)

        time_taken = (datetime.datetime.now() - start).total_seconds()
        print("{} scanning finished, it took {} seconds".format(method.value, time_taken))

    def __tcp_scan__(self, port: int):
        con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        con.settimeout(0.1)
        dest = (self.ip, port)

        if con.connect_ex(dest) == 0:
            print("TCP port {} is open!".format(port))
        
        con.close()
    
    # TODO: UDP scan
    def __udp_scan__(self, port: int):
        raise NotImplementedError
        ''' con = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        con.settimeout(0.1)
        dest = (self.ip, port)

        try:
            con.sendto(".".encode(), dest)
            data, server = con.recvfrom(255)

        except socket.timeout as e:
            print(e)

        finally:
            con.close() '''

# TODO: Implement observer design pattern
def main():
    arg_parser = ArgumentParser()

    if not arg_parser.has_valid_args():
        print("Invalid args")
        exit()

    if not arg_parser.has_allowed_port_range():
        print("Range not allowed")
        exit()
    
    ps = PortScanner(arg_parser.ip, tuple(range(arg_parser.min, arg_parser.max + 1)))

    if arg_parser.tcp:
        ps.scan(ConnectionMethod.TCP)
    
    if arg_parser.udp:
        ps.scan(ConnectionMethod.UDP)

if __name__ == "__main__":
    main()