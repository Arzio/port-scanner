from scan.connection_method import ConnectionMethod


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
        self.open: bool = False

    def __str__(self) -> str:
        """
        Método que será chamado ao transformar o objeto em string, como em "print(obj)"

        TL;DR: um toString()
        """
        return "{}\t{}\t{}\t{}".format(self.method.value, self.ip, self.port, self.open)

    def __dict__(self) -> dict:
        return {'method': self.method.value, 'ip': self.ip, 'port': self.port, 'open': self.open}
