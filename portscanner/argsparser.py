import re
import sys


def help_message() -> None:
    """
    Função que exibirá um informativo de como usar a ferramenta, junto de seus argumentos
    """
    print(
        'Um analisador de portas TCP\n\n'
        'Uso: portscanner.py [opções]\n\n'
        'Opções:\n'
        '\t--help: Exibe essa mensagem\n'
        '\t--ip: Representa o IP do host a ser analisado. É um argumento obrigatório.\n'
        '\t--ports: As portas a serem scanneadas. Devem ser separadas por vírgula. '
        'É um argumento obrigatório. Ex: "21,22,80,8080"\n'
        '\t--json: Converte o output da aplicação num JSON.\n\n'
        '\t--threads: Indica o número de thread workers que devem criados para o scan. O padrão é quatro.'
        'Exemplo de uso da aplicação: portscanner.py --ip 8.8.8.8 --ports 21,22,80,8080'
    )

    exit()


class ArgsParser:
    """
    Classe que cuidará de analisar os argumentos recebidos por linha de comando referentes, talvez
    necessários, para a execução da ferramenta.

    Ao ser instânciada, o construtor olhará os argv's (através do sys) buscando por strings nas condicionais

    Ex: "python portscanner.py --help" fará com que o código execute a função help()

    Ex: "python portscanner.py --ip 8.8.8.8 --ports 21,22,80,8080" fará com que o algoritmo saiba que
    o IP e portas a serem scanneadas é 8.8.8.8 e (21,22,80,8080)

    Note que dá para receber um JSON como output da ferramenta
    """

    def __init__(self):
        """
        Construtor que verifica os argumentos relacionados à ferramenta vindo da linha de comando
        """
        self.ip = ''
        self.ports = ()
        self.json = False
        self.threads = 4

        for arg_index in range(len(sys.argv)):
            arg = sys.argv[arg_index]

            if arg == '--help':
                help_message()

            elif arg == '--ip':
                supposed_ip = sys.argv[arg_index + 1]
                if re.match(r"^[0-2]?[0-9]?[1-9](\.[0-2]?[0-9]?[0-9]){3}$", supposed_ip):
                    self.ip = supposed_ip

            elif arg == '--json':
                self.json = True

            elif arg == '--ports':
                self.ports = tuple(map(int, sys.argv[arg_index + 1].split(',')))

            elif arg == '--threads':
                self.threads = int(sys.argv[arg_index + 1])

    def has_valid_args(self) -> bool:
        """
        Verifica se há argumentos preenchidos para que a ferramenta execute

        ports e ip são argumentos requeridos para a ferramenta funcionar
        """
        return self.ports and self.ip != ''

    def has_allowed_ports(self) -> bool:
        """
        Verifica se o range de portas TCP é valido (visto que há portas de 1 até 2^16 - 1)
        """
        for port in self.ports:
            if port <=0 or port >= 2 ** 16:
                return False

        return self.ports and True
