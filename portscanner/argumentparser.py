import re
import sys
import os

from portscanner.core import ScanMethod


class ArgumentParser:
    """
    Classe que cuidará de analisar os argumentos recebidos por linha de comando referentes, talvez
    necessários, a execução da ferramenta.

    Ao ser instanciada, o construtor olhará o argv (através do sys) buscando por argumentos válidos nas condicionais

    Ex: "python portscanner.py --help" fará com que o código execute a função help()

    Ex: "python portscanner.py --ip 8.8.8.8 --ports 21,22,80,8080 --tcp" fará com que o algoritmo saiba que
    o IP e portas a serem scanneadas é 8.8.8.8 e (21,22,80,8080), e a análise a ser feita é por TCP

    Note que dá para receber um JSON como output da ferramenta
    """

    def __init__(self):
        """
        Construtor que verifica os argumentos relacionados à ferramenta vindo da linha de comando
        """
        self.ip = ''
        self.ports = list()
        self.json = False
        self.threads = os.cpu_count()
        self.methods = list()

        for arg_index in range(len(sys.argv)):
            arg = sys.argv[arg_index]

            if arg == '--help':
                self.help_message()

            elif arg == '--ip':
                supposed_ip = sys.argv[arg_index + 1]
                if re.match(r"^[0-2]?[0-9]?[1-9](\.[0-2]?[0-9]?[0-9]){3}$", supposed_ip):
                    self.ip = supposed_ip

            elif arg == '--json':
                self.json = True

            elif arg == '--ports' and len(self.ports) == 0:
                self.ports.extend(map(int, sys.argv[arg_index + 1].split(',')))

            elif arg == '--threads':
                self.threads = int(sys.argv[arg_index + 1])

            elif arg == '--tcp' and ScanMethod.TCP not in self.methods:
                self.methods.append(ScanMethod.TCP)

            elif arg == '--udp' and ScanMethod.UDP not in self.methods:
                self.methods.append(ScanMethod.UDP)

    def help_message(self) -> None:
        """
        Função que exibirá um informativo de como usar a ferramenta, junto de seus argumentos
        """
        print(
            'Um scanner de portas TCP/IP simples\n\n'
            'Uso: portscanner.py [argumentos]\n\n'
            'Argumentos obrigatórios:\n'
            '\t--ip: Representa o IP do host a ser analisado. É um argumento obrigatório. Ex: "--ip 127.0.0.1"\n'
            '\t--ports: As portas a serem scanneadas. Devem ser separadas por vírgula. '
            'É um argumento obrigatório. Ex: "--ports 21,22,80,8080"\n\n'
            '\tMétodos de scan: Indicam o(s) método(s) a ser(em) usado(s) no scan. Pelo menos um é obrigatório.\n'
            '\t\t--tcp: Executa a análise TCP por conexão.\n'
            '\t\t--udp: Executa a análise UDP.\n\n'
            'Argumentos opcionais:\n'
            '\t--help: Exibe essa mensagem\n'
            '\t--json: Converte o output da aplicação num JSON.\n'
            '\t--threads: Indica o número de thread workers que devem criados para o scan. O número padrão é '
            'a quantidade de núcleos lógicos e físicos do sistema. Ex: "--threads 4"\n\n'
            'Exemplo de uso da aplicação: portscanner.py --ip 8.8.8.8 --ports 21,22,80,8080 --tcp'
        )
        exit()

    def has_valid_args(self) -> bool:
        """
        Verifica se há argumentos preenchidos para que a ferramenta execute

        ports, ip e methods são argumentos requeridos para a ferramenta funcionar
        :return: Boolean do resultado
        """
        return self.ports and self.ip != '' and self.methods

    def has_allowed_ports(self) -> bool:
        """
        Verifica se o range de portas TCP/IP é valido (visto que há portas de 1 até 2^16 - 1)
        :return: Boolean do resultado
        """
        for port in self.ports:
            if port <= 0 or port >= 2 ** 16:
                return False

        return self.ports and True
