import re
import sys

from src.core import ScanMethod


def help_message():
    print(
        'A simple TCP and UDP port scanner'
        '\n\n'
        'Usage: portscanner.py [args]'
        '\n\n'
        'Required args:'
        '\n'
        '\t--ip: Represents a IP which will be targeted. e.g. "--ip 127.0.0.1"'
        '\n'
        '\t--ports: Represents a group of TCP/UDP ports whose will be scanned.'
        ' It must have one group of ports (TCP or UDP). '
        ' However, you can use this arg twice to declare TCP and UDP ports.'
        ' Groups are structured sequentially by one initial letter (T or U), colon'
        ' and a set of numbers joint by comma. e.g. "--ports T:22,80,443,8080"'
        '\n\n'
        'Optional args:'
        '\n'
        '\t--help: Shows that message'
        '\n'
        '\t--json: Converts the output of the scan into a JSON body'
        '\n'
        '\t--threads: Imply a number of thread workers that will be created for the scan.'
        ' The default value is the number of processor\'s cores. e.g --threads 4'
        '\n\n'
        'Example of usage: portscanner.py --ip 8.8.8.8 --ports T:22,80,443 --ports U:22,80,443'
    )
    exit()


class ArgumentParser:

    def __init__(self):
        self.ip = ''
        self.methods_ports = dict()
        self.json = False
        self.threads = None

        for arg_index in range(len(sys.argv)):
            arg = sys.argv[arg_index]

            if arg == '--help':
                help_message()

            elif arg == '--ip':
                if self.ip != '':
                    print('Only one IP is allowed')
                    exit(1)

                supposed_ip = sys.argv[arg_index + 1]

                if re.match(r'^[0-2]?[0-9]?[1-9](\.[0-2]?[0-9]?[0-9]){3}$', supposed_ip):
                    self.ip = supposed_ip

            elif arg == '--json':
                if self.json:
                    print('JSON argument already given')
                    exit(1)

                self.json = True

            elif arg == '--ports':
                supposed_ports = str(sys.argv[arg_index + 1])

                if re.match(r'^T:(\d{1,5},)*\d{1,5}((?!.)+)$', supposed_ports):
                    if ScanMethod.TCP in self.methods_ports and len(self.methods_ports[ScanMethod.TCP]) > 0:
                        print('TCP ports already given')
                        exit(1)

                    self.methods_ports[ScanMethod.TCP] = list(map(int, supposed_ports.replace('T:', '').split(',')))

                elif re.match(r'^U:(\d{1,5},)*\d{1,5}((?!.)+)$', supposed_ports):
                    if ScanMethod.UDP in self.methods_ports and len(self.methods_ports[ScanMethod.UDP]) > 0:
                        print('UDP ports already given')
                        exit(1)

                    self.methods_ports[ScanMethod.UDP] = list(map(int, supposed_ports.replace('U:', '').split(',')))

                else:
                    print('Ports incorrectly given')
                    exit(1)

            elif arg == '--threads':
                if self.threads is not None:
                    print('Number of threads already defined')
                    exit(1)

                self.threads = int(sys.argv[arg_index + 1])

    def has_valid_args(self) -> bool:
        return self.ip != '' and self.__has_allowed_ports()

    def __has_allowed_ports(self) -> bool:
        for key in self.methods_ports:
            if len(self.methods_ports[key]) <= 0:
                return False

            for port in self.methods_ports[key]:
                if port <= 0 or port >= 2 ** 16:
                    return False

        return len(self.methods_ports) > 0
