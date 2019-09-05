import sys
import re
import datetime
import socket
from json import JSONEncoder
from enum import Enum

def help() -> None:
    '''
    Função que exibirá um informativo de como usar a ferramenta, junto de seus argumentos
    '''
    raise NotImplementedError

class ConnectionMethod(Enum):
    '''
    Enum que representa os tipos de protocolos/métodos para fazer scan em portas
    '''
    TCP = 'TCP'
    UDP = 'UDP'

class ScanResult:
    ''' 
    Classe que receberá informações do scan de um certo ip numa certa porta, como:
    - Protocolo/método usado para scannear
    - Se estava aberta ou não
    '''
    def __init__(self, method: ConnectionMethod, ip: str, port: int):
        self.method = method
        self.ip = ip
        self.port = port
        self.open: bool = None
    
    def __str__(self):
        return "{}\t{}\t{}\t{}".format(self.method.value, self.ip, self.port, self.open)

class ArgumentParser:
    '''
    Classe que cuidará de analisar os argumentos recebidos por linha de comando referentes, talvez
    necessários, para a execução da ferramenta.

    Ao ser instânciada, o construtor olhará os argv's (através do sys) buscando por strings nas condicionais
    
    Ex: "python portscanner.py --help" fará com que o código execute a função help()

    Ex: "python portscanner.py -f 200 -t 300 8.8.8.8 --tcp" fará com que o código saiba que
    o range de ports é [200; 300], o IP a ser scanneado é 8.8.8.8 e deverá ser feito um scan TCP

    Note que dá para fazer um scan TCP e/ou UDP, além de receber um JSON como output da ferramenta
    e que min, max, ip, (tcp || udp) são argumentos requeridos para a ferramenta funcionar

    '''

    def __init__(self):
        '''
        Construtor que verifica os argumentos relacionados à ferramenta vindo da linha de comando
        '''
        self.min: int = None
        self.max: int = None
        self.ip: str = None
        self.udp = self.tcp = self.json = False

        for arg_index in range(len(sys.argv)):
            arg = sys.argv[arg_index]

            if arg in ('-h', '-H', '--help'):
                help()
                exit()

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

            # Isso é um RegEx para verificar se o argumento de IP está mesmo no padrão de um IP
            elif re.match(r"^(\d{1,3}\.){3}\d{1,3}$", arg):
                self.ip = arg

    def has_valid_args(self) -> bool:
        return None not in (self.min, self.max, self.ip) and (self.tcp or self.udp)
    
    def has_allowed_port_range(self) -> bool:
        return self.min <= self.max and self.min >= 1 and self.max <= (2**16 - 1)

class PortScanner:
    def __init__(self, ip: str, ports: tuple):
        self.ip = ip
        self.ports = ports

    def __tcp_scan__(self, port: int) -> ScanResult:
        con = socket.socket()
        con.settimeout(0.5)
        dest = (self.ip, port)
        scan_result = ScanResult(ConnectionMethod.TCP, self.ip, port)

        if con.connect_ex(dest) == 0:
            scan_result.open = True
        
        else:
            scan_result.open = False

        con.close()

        return scan_result
    
    # TODO: UDP scan
    def __udp_scan__(self, port: int) -> ScanResult:
        raise NotImplementedError
        con = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        con.settimeout(0.5)
        dest = (self.ip, port)
        scan_result = ScanResult(ConnectionMethod.UDP, self.ip, port)

        # Scan algorithm

        con.close()

        return scan_result


    # TODO: Create threads for every port scan
    def scan(self, method: ConnectionMethod) -> None:
        print("METHOD\tIP\t\tPORT\tOPEN")

        for port in self.ports:
            if method == ConnectionMethod.TCP:
                scan_result = self.__tcp_scan__(port)
            
            elif method == ConnectionMethod.UDP:
                scan_result = self.__udp_scan__(port)
            
            print(scan_result)
        
    def scan_to_list(self, method: ConnectionMethod) -> list:
        scan_results = list()

        for port in self.ports:
            if method == ConnectionMethod.TCP:
                scan_result = self.__tcp_scan__(port)
            
            elif method == ConnectionMethod.UDP:
                scan_result = self.__udp_scan__(port)
            
            scan_results.append(scan_result)
        
        return scan_results

# TODO: Implement observer design pattern
def main() -> None:
    arg_parser = ArgumentParser()

    if not arg_parser.has_valid_args():
        print('Invalid args')
        exit(1)

    if not arg_parser.has_allowed_port_range():
        print('Range not allowed')
        exit(2)
    
    ps = PortScanner(arg_parser.ip, range(arg_parser.min, arg_parser.max + 1))

    if arg_parser.json:
        results = list()

        if arg_parser.tcp:
            results.append(ps.scan_to_list(ConnectionMethod.TCP))
        
        if arg_parser.udp:
            results.append(ps.scan_to_list(ConnectionMethod.UDP))

        # FIXME: ScanResult isn't serializable
        json_object = JSONEncoder().encode(results)
        print(json_object)

    else:
        if arg_parser.tcp:
            ps.scan(ConnectionMethod.TCP)
        
        if arg_parser.udp:
            ps.scan(ConnectionMethod.UDP)

if __name__ == '__main__':
    main()