import socket
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, wait


class ScanMethod(Enum):
    """
    Enum que indica os métodos de análise suportados pelo programa
    """

    TCP = 'TCP'
    UDP = 'UDP'


class ScanStatus(Enum):
    """
    Enum que indica o status de análise de cada porta TCP
    """

    OPEN = 'Open'
    CLOSED = 'Closed'
    FILTERED = 'Filtered'
    OPEN_FILTERED = 'Open | Filtered'
    CLOSED_FILTERED = 'Closed | Filtered'


class ScanTarget:
    """
    Classe que representa o IP do alvo, os métodos de scan a serem usados e as portas para cada método
    """

    def __init__(self, ip: str, methods_ports: dict):
        self.ip = ip
        self.methods_ports = methods_ports


class ScanResult:
    """
    Classe que receberá informações do scan de um certo ip numa certa porta, como:
    - Método usado para scannear
    - Se estava aberta e/ou fechada e/ou filtrada
    """

    def __init__(self, method: ScanMethod, ip: str, port: int):
        self.method = method
        self.ip = ip
        self.port = port
        self.status = None

    def __str__(self) -> str:
        """
        Método que será chamado ao transformar o objeto em string, como em "print(obj)"
        :return: Uma string representando o objeto
        """
        return "{}\t{}\t{}\t{}".format(self.method.value, self.ip, self.port, self.status.value)

    def __dict__(self) -> dict:
        """
        Converte o objeto em dicionário
        :return: Um dicionário representando o objeto
        """
        return {'method': self.method.value, 'ip': self.ip, 'port': self.port, 'status': self.status.value}


class ScanController:
    """
    Classe que se responsabilizará por fazer os scans
    Precisa do scan target para realizar os scans
    """

    def __init__(self, scan_target: ScanTarget):
        self.scan_target = scan_target

    def __tcp_scan(self, port: int) -> ScanResult:
        """
        Método para fazer o scan por conexão TCP
        Cria um socket e tenta se conectar com o destino (ip e porta) em 500ms. O status será OPEN caso o socket consiga
        criar uma conexão com sucesso, CLOSED caso a conexão seja rejeitada, e FILTERED caso não haja resposta do target
        :param port: A porta a ser scanneada
        :return: O resultado do scan
        """
        con = socket.socket()
        con.settimeout(0.5)
        dest = (self.scan_target.ip, port)
        scan_result = ScanResult(ScanMethod.TCP, self.scan_target.ip, port)

        try:
            con.connect(dest)
            scan_result.status = ScanStatus.OPEN

        except socket.timeout:
            scan_result.status = ScanStatus.FILTERED

        except socket.error:
            scan_result.status = ScanStatus.CLOSED

        finally:
            con.close()

        return scan_result

    def __udp_scan(self, port: int) -> ScanResult:
        """
        Método para fazer o scan por UDP
        Cria um socket UDP e tenta enviar um pacote vazio e receber um outro pacote do destino (ip e porta) em 500ms.
        O status será OPEN se o socket receber um pacote com sucesso (muito difícil, ainda mais enviando pacote vazio),
        OPEN_FILTERED se não houver nenhuma resposta até o timeout ou CLOSED_FILTERED caso haja um erro (a implementação
        não permite receber um código ICMP, então não há como garantir se a porta está fechada ou filtrada)
        :param port: A porta ser scanneada
        :return: O resultado do scan
        """
        con = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        con.settimeout(0.5)
        dest = (self.scan_target.ip, port)
        scan_result = ScanResult(ScanMethod.UDP, self.scan_target.ip, port)

        try:
            con.connect(dest)
            con.send(bytes(0))
            con.recv(1024)
            scan_result.status = ScanStatus.OPEN

        except socket.timeout:
            scan_result.status = ScanStatus.OPEN_FILTERED

        except socket.error:
            scan_result.status = ScanStatus.CLOSED_FILTERED

        finally:
            con.close()

        return scan_result

    def __print_tcp_scan(self, port: int) -> None:
        """
        Imprime o resultado do scan TCP
        :param port: A porta a ser scanneada
        """
        print(self.__tcp_scan(port))

    def __print_udp_scan(self, port: int) -> None:
        """
        Imprime o resultado do scan UDP
        :param port: A porta a ser scanneada
        """
        print(self.__udp_scan(port))

    def scan(self, threads_number: int) -> None:
        """
        Realiza o scan, exibindo os resultados em texto plano
        :param threads_number: Número de thread workers a ser criada pelo pool
        """
        with ThreadPoolExecutor(max_workers=threads_number) as executor:
            if ScanMethod.TCP in self.scan_target.methods_ports:
                wait([executor.submit(self.__print_tcp_scan, p) for p in self.scan_target.methods_ports[ScanMethod.TCP]])

            if ScanMethod.UDP in self.scan_target.methods_ports:
                wait([executor.submit(self.__print_udp_scan, p) for p in self.scan_target.methods_ports[ScanMethod.UDP]])

    def scan_to_list(self, threads_number: int) -> list:
        """
        Realiza o scan, jogando os resultados para uma lista a parte
        :param threads_number: Número de thread workers a ser criada pelo pool
        :return: Uma lista com os resultados do scan
        """
        results = list()

        with ThreadPoolExecutor(max_workers=threads_number) as executor:
            if ScanMethod.TCP in self.scan_target.methods_ports:
                results.extend(executor.map(self.__tcp_scan, self.scan_target.methods_ports[ScanMethod.TCP]))

            if ScanMethod.UDP in self.scan_target.methods_ports:
                results.extend(executor.map(self.__udp_scan, self.scan_target.methods_ports[ScanMethod.UDP]))

        return results
