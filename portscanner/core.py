import socket
from enum import Enum


class ConnectionMethod(Enum):
    """
    Enum (classe com constantes que, por debaixo dos panos, são enumeradas) que representa
    os tipos de protocolos/métodos para fazer scan em portas
    """

    TCP = 'TCP'
    UDP = 'UDP'


class ScanResult:
    """
    Classe que receberá informações do scan de um certo ip numa certa porta, como:
    - Protocolo/método usado para scannear
    - Se estava aberta ou não
    """

    def __init__(self, method: ConnectionMethod, ip: str, port: int):
        self.method = method
        self.ip = ip
        self.port = port
        self.open = False

    def __str__(self) -> str:
        """
        Método que será chamado ao transformar o objeto em string, como em "print(obj)"

        TL;DR: um toString() do Java, por exemplo
        """
        return "{}\t{}\t{}\t{}".format(self.method.value, self.ip, self.port, self.open)

    def __dict__(self) -> dict:
        return {'method': self.method.value, 'ip': self.ip, 'port': self.port, 'open': self.open}


class ScanController:
    """
    Classe que se responsabilizará por fazer os scans

    Precisa do ip do destino e uma coleção de portas a se fazer o scan
    """

    def __init__(self, ip: str, ports: tuple):
        self.ip = ip
        self.ports = ports

    def __tcp_scan(self, port: int) -> ScanResult:
        """
        Método privado (que somente a classe e seus objetos conhecem) para fazer o scan por TCP

        Cria um socket, e tenta conectar com o destino (ip e porta) em 1s. Retorna um ScanResult com
        as informações do scan, sendo que o atributo open será True caso o socket consiga conexão, False
        em qualquer outro caso
        """
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
        """
        Método privado (que somente a classe e seus objetos conhecem) para fazer o scan por UDP

        Cria um socket, e tenta enviar e receber algo pelo destino (ip e porta) em 1s. Retorna um ScanResult com
        as informações do scan, sendo que o atributo open será True caso o socket consiga receber alguma informação, False no caso
        de timeout
        """
        con = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        con.settimeout(1)
        dest = (self.ip, port)
        scan_result = ScanResult(ConnectionMethod.UDP, self.ip, port)

        try:
            con.sendto(bytes(0), dest)
            con.recvfrom(1024)
            scan_result.open = True

        except socket.timeout:
            scan_result.open = False

        con.close()

        return scan_result

    # TODO: Create threads for every port scan
    '''
    See:
    https://diogommartins.wordpress.com/2017/04/07/concorrencia-e-paralelismo-threads-multiplos-processos-e-asyncio-parte-1/
    https://diogommartins.wordpress.com/2017/04/22/concorrencia-e-paralelismo-threads-multiplos-processos-e-asyncio-parte-2/
    '''
    def scan(self, method: ConnectionMethod) -> None:
        """
        Realiza o scan baseado no protocolo/método escolhido e nas portas do objeto

        Exibe os ScanResult como output de texto plano
        """
        for port in self.ports:
            if method == ConnectionMethod.TCP:
                scan_result = self.__tcp_scan(port)

            else:
                scan_result = self.__udp_scan(port)

            print(scan_result)

    def scan_to_list(self, method: ConnectionMethod) -> list:
        """
        Realiza o scan baseado no protocolo/método escolhido e nas portas do objeto

        Retorna uma lista de ScanResult
        """
        scan_results = list()

        for port in self.ports:
            if method == ConnectionMethod.TCP:
                scan_result = self.__tcp_scan(port)

            else:
                scan_result = self.__udp_scan(port)

            scan_results.append(scan_result)

        return scan_results
