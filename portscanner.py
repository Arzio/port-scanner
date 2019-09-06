import sys
import re
import datetime
import socket
import json
from enum import Enum

def help() -> None:
    '''
    Função que exibirá um informativo de como usar a ferramenta, junto de seus argumentos
    '''
    raise NotImplementedError

class ConnectionMethod(Enum):
    '''
    Enum (classe com constantes que, por debaixo dos panos, são enumeradas) que representa 
    os tipos de protocolos/métodos para fazer scan em portas
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
    
    def __str__(self) -> str:
        '''
        Método que será chamado ao transformar o objeto em string, como em "print(obj)"

        TL;DR: um toString()
        '''
        return "{}\t{}\t{}\t{}".format(self.method.value, self.ip, self.port, self.open)
    
    def __dict__(self) -> dict:
        return { 'method': self.method.value, 'ip': self.ip, 'port': self.port, 'open': self.open }

class ArgumentParser:
    '''
    Classe que cuidará de analisar os argumentos recebidos por linha de comando referentes, talvez
    necessários, para a execução da ferramenta.

    Ao ser instânciada, o construtor olhará os argv's (através do sys) buscando por strings nas condicionais
    
    Ex: "python portscanner.py --help" fará com que o código execute a função help()

    Ex: "python portscanner.py -f 200 -t 300 8.8.8.8 --tcp" fará com que o código saiba que
    o range de ports é [200; 300], o IP a ser scanneado é 8.8.8.8 e deverá ser feito um scan TCP

    Note que dá para fazer um scan TCP e/ou UDP, além de receber um JSON como output da ferramenta
    '''

    def __init__(self):
        '''
        Construtor que verifica os argumentos relacionados à ferramenta vindo da linha de comando
        '''
        self.min = 0
        self.max = 0
        self.ip = ''
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
            # Mais sobre RegEx: https://dev.to/catherinecodes/a-regex-cheatsheet-for-all-those-regex-haters-and-lovers--2cj1

            elif re.match(r"^[0-2]?[0-9]?[1-9](\.[0-2]?[0-9]?[0-9]){3}$", arg):
                self.ip = arg

    def has_valid_args(self) -> bool:
        '''
        Verifica se há argumentos preenchidos para que a ferramenta execute

        min, max, ip, tcp e/ou udp são argumentos requeridos para a ferramenta funcionar
        '''
        return 0 not in (self.min, self.max) and self.ip != '' and (self.tcp or self.udp)
    
    def has_allowed_port_range(self) -> bool:
        '''
        Verifica se o range de portas TCP/UDP é valido (visto que há portas de 1 até 2^16 - 1)
        '''
        return self.min <= self.max and self.min >= 1 and self.max <= (2**16 - 1)

class PortScanner:
    '''
    Classe que se responsabilizará por fazer os scans

    Precisa do ip do destino e uma coleção de portas a se fazer o scan
    '''

    def __init__(self, ip: str, ports: tuple):
        self.ip = ip
        self.ports = ports

    def __tcp_scan(self, port: int) -> ScanResult:
        '''
        Método privado (que somente a classe e seus objetos conhecem) para fazer o scan por TCP

        Cria um socket, e tenta conectar com o destino (ip e porta) em 500ms. Retorna um ScanResult com
        as informações do scan, sendo que o atributo open será True caso o socket consiga conexão, False 
        em qualquer outro caso
        '''
        con = socket.socket()
        con.settimeout(1)
        dest = (self.ip, port)
        scan_result = ScanResult(ConnectionMethod.TCP, self.ip, port)

        if con.connect_ex(dest) == 0:
            scan_result.open = True
        
        else:
            scan_result.open = False

        con.close()

        return scan_result
    
    def __udp_scan(self, port: int) -> ScanResult:
        '''
        Método privado (que somente a classe e seus objetos conhecem) para fazer o scan por UDP
        '''
        con = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        con.settimeout(1)
        dest = (self.ip, port)
        scan_result = ScanResult(ConnectionMethod.UDP, self.ip, port)

        try:
            con.sendto(bytes(0), dest)
            data, addr = con.recvfrom(1024)
            scan_result.open = True

        except socket.timeout:
            scan_result.open = False
        
        con.close()

        return scan_result


    # TODO: Create threads for every port scan
    def scan(self, method: ConnectionMethod) -> None:
        '''
        Realiza o scan baseado no protocolo/método escolhido e nas portas do objeto
        
        Exibe os ScanResult como output de texto plano
        '''
        print("METHOD\tIP\t\tPORT\tOPEN")

        for port in self.ports:
            if method == ConnectionMethod.TCP:
                scan_result = self.__tcp_scan(port)
            
            elif method == ConnectionMethod.UDP:
                scan_result = self.__udp_scan(port)
            
            print(scan_result)
        
    def scan_to_list(self, method: ConnectionMethod) -> list:
        '''
        Realiza o scan baseado no protocolo/método escolhido e nas portas do objeto
        
        Retorna uma lista de ScanResult
        '''
        scan_results = list()

        for port in self.ports:
            if method == ConnectionMethod.TCP:
                scan_result = self.__tcp_scan(port)
            
            elif method == ConnectionMethod.UDP:
                scan_result = self.__udp_scan(port)
            
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
            results.extend(ps.scan_to_list(ConnectionMethod.TCP))
        
        if arg_parser.udp:
            results.extend(ps.scan_to_list(ConnectionMethod.UDP))

        json_object = json.dumps(results, default = lambda sr: sr.__dict__(), indent = 4)
        print(json_object)

    else:
        if arg_parser.tcp:
            ps.scan(ConnectionMethod.TCP)
        
        if arg_parser.udp:
            ps.scan(ConnectionMethod.UDP)

if __name__ == '__main__':
    try:
        main()
    
    except KeyboardInterrupt:
        exit()