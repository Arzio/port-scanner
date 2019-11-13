import re
import sys

from portscanner.core import ScanMethod


class ArgumentParser:
    """
    Classe que cuidará de analisar os argumentos recebidos por linha de comando referentes, talvez
    necessários, a execução da ferramenta

    Ao ser instanciada, o construtor olhará o argv (através do sys) buscando por argumentos válidos nas condicionais

    Ex: "portscanner.py --help" fará com que o código execute a função help()

    Ex: "portscanner.py --ip 8.8.8.8 --ports T:21,22,80,8080" fará com que o algoritmo saiba que
    o IP e portas a serem scanneadas é 8.8.8.8 e (21,22,80,8080), e a análise a ser feita é por TCP

    Note que dá para receber um JSON como output da ferramenta e definir o número de threads a serem criadas
    """

    def __init__(self):
        """
        Construtor que verifica os argumentos relacionados à ferramenta vindo da linha de comando
        """
        self.ip = ''
        self.methods_ports = dict()
        self.json = False
        self.threads = None

        for arg_index in range(len(sys.argv)):
            arg = sys.argv[arg_index]

            if arg == '--help':
                self.help_message()

            elif arg == '--ip':
                if self.ip != '':
                    print('Only one IP is allowed')
                    exit(1)

                supposed_ip = sys.argv[arg_index + 1]

                if re.match(r"^[0-2]?[0-9]?[1-9](\.[0-2]?[0-9]?[0-9]){3}$", supposed_ip):
                    self.ip = supposed_ip

            elif arg == '--json':
                if self.json:
                    print('JSON argument already given')
                    exit(1)

                self.json = True

            elif arg == '--ports':
                supposed_ports = str(sys.argv[arg_index + 1])

                if re.match(r"^T:(\d{1,5},)*\d{1,5}((?!.)+)$", supposed_ports):
                    if ScanMethod.TCP in self.methods_ports and len(self.methods_ports[ScanMethod.TCP]) > 0:
                        print('TCP ports already given')
                        exit(1)

                    self.methods_ports[ScanMethod.TCP] = list(map(int, supposed_ports.replace('T:', '').split(',')))

                elif re.match(r"^U:(\d{1,5},)*\d{1,5}((?!.)+)$", supposed_ports):
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

    def help_message(self) -> None:
        """
        Função que exibirá um informativo de como usar a ferramenta, junto de seus argumentos
        """
        print(
            'Um scanner de portas TCP/IP simples'
            '\n\n'
            'Uso: portscanner.py [argumentos]'
            '\n\n'
            'Argumentos obrigatórios:'
            '\n'
            '\t--ip: Representa o IP do host a ser analisado. É um argumento obrigatório. Ex: "--ip 127.0.0.1"'
            '\n'
            '\t--ports: Representa as portas a serem scanneadas.'
            ' Deve começar por T (portas TCP) ou U (portas UDP) e dois pontos, '
            'e as portas devem ser separadas por vírgula.'
            ' Deve-se declarar pelo menos uma vez. Ex: "--ports T:22,80,443,8080"'
            '\n\n'
            'Argumentos opcionais:'
            '\n'
            '\t--help: Exibe essa mensagem'
            '\n'
            '\t--json: Converte o output da aplicação num JSON.'
            '\n'
            '\t--threads: Indica o número de thread workers que devem criados para o scan. O quantidade padrão é'
            ' o número de núcleos da máquina. Ex: "--threads 4"'
            '\n\n'
            'Exemplo de uso da aplicação: portscanner.py --ip 8.8.8.8 --ports T:22,80,443'
        )
        exit()

    def has_valid_args(self) -> bool:
        """
        Verifica se há argumentos preenchidos para que a ferramenta execute

        ip e ports são argumentos requeridos para a ferramenta funcionar
        :return: Boolean do resultado
        """
        return self.ip != '' and self.__has_allowed_ports()

    def __has_allowed_ports(self) -> bool:
        """
        Verifica se existe métodos e portas a serem scanneadas, e se o range de portas TCP/IP é valido
        (visto que há portas TCP/IP de 1 até 2^16 - 1)
        :return: Boolean do resultado
        """
        for key in self.methods_ports:
            if len(self.methods_ports[key]) <= 0:
                return False

            for port in self.methods_ports[key]:
                if port <= 0 or port >= 2 ** 16:
                    return False

        return len(self.methods_ports) > 0
