import re
import sys


class ArgumentParser:
    """
    Classe que cuidará de analisar os argumentos recebidos por linha de comando referentes, talvez
    necessários, para a execução da ferramenta.

    Ao ser instânciada, o construtor olhará os argv's (através do sys) buscando por strings nas condicionais

    Ex: "python port_scanner.py --help" fará com que o código execute a função help()

    Ex: "python port_scanner.py -f 200 -t 300 8.8.8.8 --tcp" fará com que o código saiba que
    o range de ports é [200; 300], o IP a ser scanneado é 8.8.8.8 e deverá ser feito um scan TCP

    Note que dá para fazer um scan TCP e/ou UDP, além de receber um JSON como output da ferramenta
    """

    def __init__(self):
        """
        Construtor que verifica os argumentos relacionados à ferramenta vindo da linha de comando
        """
        self.min = 0
        self.max = 0
        self.ip = ''
        self.udp = self.tcp = self.json = False

        for arg_index in range(len(sys.argv)):
            arg = sys.argv[arg_index]

            if arg in ('-h', '-i', '--help'):
                self.help()
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

            # Isso é um RegEx para verificar se o argumento de IP está mesmo no padrão de um IP. Mais sobre RegEx:
            # https://dev.to/catherinecodes/a-regex-cheatsheet-for-all-those-regex-haters-and-lovers--2cj1

            elif re.match(r"^[0-2]?[0-9]?[1-9](\.[0-2]?[0-9]?[0-9]){3}$", arg):
                self.ip = arg

    def has_valid_args(self) -> bool:
        """
        Verifica se há argumentos preenchidos para que a ferramenta execute

        min, max, ip, tcp e/ou udp são argumentos requeridos para a ferramenta funcionar
        """
        return 0 not in (self.min, self.max) and self.ip != '' and (self.tcp or self.udp)

    def has_allowed_port_range(self) -> bool:
        """
        Verifica se o range de portas TCP/UDP é valido (visto que há portas de 1 até 2^16 - 1)
        """
        return 1 <= self.min <= self.max <= (2 ** 16 - 1)

    def help(self) -> None:
        """
        Função que exibirá um informativo de como usar a ferramenta, junto de seus argumentos
        """
        raise NotImplementedError
