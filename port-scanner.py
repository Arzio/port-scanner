import sys
import re
import datetime
import socket
from enum import Enum

class ConnectionMethod(Enum):
    TCP = 1,
    UDP = 2

def help():
    raise NotImplementedError

def port_scan(ip: str, min: int, max: int, method: ConnectionMethod):
    if method == ConnectionMethod.TCP:
        name = "TCP"
    elif method == ConnectionMethod.UDP:
        name = "UDP"

    print("Scanning {} ports at {}".format(name, ip))
    start = datetime.datetime.now()
    
    for port in range(min, max + 1):
        if method == ConnectionMethod.TCP:
            con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        elif method == ConnectionMethod.UDP:
            con = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        dest = (ip, port)

        if con.connect_ex(dest) == 0:
            print("{} port {} is open!".format(name, port))

        con.close()

    time_taken = (datetime.datetime.now() - start).total_seconds()
    print("{} scanning finished, it took {} seconds".format(name, time_taken))

def main():
    min = max = ip = None
    udp = tcp = False

    for arg_index in range(len(sys.argv)):
        arg = sys.argv[arg_index]

        if arg in ("-h", "--help"):
            help()
            exit()

        elif arg in ("-f", "--from"):
            min = int(sys.argv[arg_index + 1])

        elif arg in ("-t", "--to"):
            max = int(sys.argv[arg_index + 1])

        elif arg == "--udp":
            udp = True
        
        elif arg == "--tcp":
            tcp = True
        
        elif re.match(r"^(\d{1,3}\.){3}\d{1,3}$", arg):
            ip = arg

    if None in (min, max, ip) and (tcp == False and udp == False):
        print("Invalid args")
        exit()

    if min < 1 or max > (2**16 - 1):
        print("Range not allowed")
        exit()

    if tcp == True:
        port_scan(ip, min, max, ConnectionMethod.TCP)

    if udp == True:
        port_scan(ip, min, max, ConnectionMethod.UDP)

if __name__ == "__main__":
    main()