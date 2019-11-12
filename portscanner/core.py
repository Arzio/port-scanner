import socket
import errno
from enum import Enum
from multiprocessing.dummy import Pool as ThreadPool


class ScanMethod(Enum):
    """
    Enum que indica os métodos de análise suportados pelo programa
    """
    TCP_CON = 'Conn'

class ConnectionStatus(Enum):
    """
    Enum que indica o status de análise de cada porta TCP
    """
    OPEN = 'Open'
    CLOSED = 'Closed'
    FILTERED = 'Filtered'


class ScanResult:
    """
    Classe que receberá informações do scan de um certo ip numa certa porta, como:
    - Método usado para scannear
    - Se estava aberta, fechada ou filtrada
    """

    def __init__(self, method: ScanMethod,  ip: str, port: int):
        self.method = method
        self.ip = ip
        self.port = port
        self.status = ConnectionStatus.CLOSED

    def __str__(self) -> str:
        """
        Método que será chamado ao transformar o objeto em string, como em "print(obj)"

        TL;DR: um toString() do Java, por exemplo
        """
        return "{}\t{}\t{}\t{}".format(self.method.value, self.ip, self.port, self.status.value)

    def __dict__(self) -> dict:
        return {'method': self.method.value, 'ip': self.ip, 'port': self.port, 'status': self.status.value}


class ScanController:
    """
    Classe que se responsabilizará por fazer os scans

    Precisa do ip do destino e uma coleção de portas a se fazer o scan
    """

    def __init__(self, ip: str, ports: tuple):
        self.ip = ip
        self.ports = ports

    def __tcp_conn_scan(self, port: int) -> ScanResult:
        """
        Método para fazer o scan por TCP connect

        Cria um socket, e tenta conectar com o destino (ip e porta) em 1s. Retorna um ScanResult com
        as informações do scan, sendo que o atributo status será OPEN caso o socket consiga conexão, CLOSED
        caso a conexão seja rejeitada, e FILTERED caso não haja resposta do target
        """
        con = socket.socket()
        con.settimeout(1)
        dest = (self.ip, port)
        scan_result = ScanResult(ScanMethod.TCP_CON, self.ip, port)

        con_result = con.connect_ex(dest)
        con.close()

        if con_result == 0:
            scan_result.status = ConnectionStatus.OPEN
        
        elif con_result == errno.ECONNRESET or con_result == errno.ECONNREFUSED or con_result == errno.ECONNABORTED:
            scan_result.status = ConnectionStatus.CLOSED
        
        else:
            scan_result.status = ConnectionStatus.FILTERED

        return scan_result

    def __print_scan_result(self, port: int) -> None:
        scan_result = self.__tcp_conn_scan(port)
        print(scan_result)

    def scan(self, threads_number: int) -> None:
        """
        Realiza o scan baseado nas portas do objeto através de thread workers

        Exibe os ScanResult como output de texto plano
        """
        pool = ThreadPool(threads_number)
        pool.map(self.__print_scan_result, self.ports)

    def scan_to_list(self, threads_number: int) -> list:
        """
        Realiza o scan baseado nas portas do objeto através de thread workers

        Retorna uma lista de ScanResult
        """
        pool = ThreadPool(threads_number)
        results = pool.map(self.__tcp_conn_scan, self.ports)

        return results
