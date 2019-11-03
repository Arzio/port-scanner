import socket
from enum import Enum
from multiprocessing.dummy import Pool as ThreadPool


class ConnectionMethod(Enum):
    """
    Enum (classe com constantes que, por debaixo dos panos, são enumeradas) que representa
    os tipos de protocolos/métodos para fazer scan em portas
    """
    TCP = 'TCP'


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

    def tcp_scan(self, port: int) -> ScanResult:
        """
        Método para fazer o scan por TCP

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

        con.close()

        return scan_result

    def print_scan_result(self, port: int):
        scan_result = self.tcp_scan(port)
        print(scan_result)

    def scan(self, threads_number: int) -> None:
        """
        Realiza o scan baseado nas portas do objeto através de thread workers

        Exibe os ScanResult como output de texto plano
        """
        pool = ThreadPool(threads_number)
        pool.map(self.print_scan_result, self.ports)

    def scan_to_list(self, threads_number: int) -> list:
        """
        Realiza o scan baseado nas portas do objeto através de thread workers

        Retorna uma lista de ScanResult
        """
        pool = ThreadPool(threads_number)
        results = pool.map(self.tcp_scan, self.ports)

        return results
