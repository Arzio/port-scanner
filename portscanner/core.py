import socket
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, wait


class ScanMethod(Enum):

    TCP = 'TCP'
    UDP = 'UDP'


class ScanStatus(Enum):

    OPEN = 'Open'
    CLOSED = 'Closed'
    FILTERED = 'Filtered'
    OPEN_FILTERED = 'Open | Filtered'
    CLOSED_FILTERED = 'Closed | Filtered'


class ScanTarget:

    def __init__(self, ip: str, methods_ports: dict):
        self.ip = ip
        self.methods_ports = methods_ports


class ScanResult:

    def __init__(self, method: ScanMethod, ip: str, port: int):
        self.method = method
        self.ip = ip
        self.port = port
        self.status = None

    def __str__(self) -> str:
        return '{}\t{}\t{}'.format(self.method.value, self.port, self.status.value)

    def __dict__(self) -> dict:
        return {'method': self.method.value, 'ip': self.ip, 'port': self.port, 'status': self.status.value}


class ScanController:

    def __init__(self, scan_target: ScanTarget):
        self.scan_target = scan_target

    def __tcp_scan(self, port: int) -> ScanResult:
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

    def __print_tcp_scan(self, port: int):
        print(self.__tcp_scan(port))

    def __print_udp_scan(self, port: int):
        print(self.__udp_scan(port))

    def scan(self, threads_number: int):
        with ThreadPoolExecutor(max_workers=threads_number) as executor:
            if ScanMethod.TCP in self.scan_target.methods_ports:
                wait([executor.submit(self.__print_tcp_scan, p) for p in self.scan_target.methods_ports[ScanMethod.TCP]])

            if ScanMethod.UDP in self.scan_target.methods_ports:
                wait([executor.submit(self.__print_udp_scan, p) for p in self.scan_target.methods_ports[ScanMethod.UDP]])

    def scan_to_list(self, threads_number: int) -> list:
        results = list()

        with ThreadPoolExecutor(max_workers=threads_number) as executor:
            if ScanMethod.TCP in self.scan_target.methods_ports:
                results.extend(executor.map(self.__tcp_scan, self.scan_target.methods_ports[ScanMethod.TCP]))

            if ScanMethod.UDP in self.scan_target.methods_ports:
                results.extend(executor.map(self.__udp_scan, self.scan_target.methods_ports[ScanMethod.UDP]))

        return results
