# Port Scanner

## Sobre
O projeto é um analisador simples de portas TCP/IP, que verifica se as portas de um certo IP, recebidas por input do usuário estão abertas e/ou filtradas ou fechadas.

No momento, a ferramenta só executa a análise TCP por conexão ou UDP.

Ainda, a ferramenta pode converter o output da análise em um JSON, caso seja necessário guardá-lo em um formato de serialização universal (possibilitando o uso do resultado da análise facilmente em qualquer outra aplicação).

## Pré-requisitos
1. Python __^ 3.5__

## Como instalar
### Instalando Python
* [Tutorial da Python Brasil para Windows](https://python.org.br/instalacao-windows/)

* [Tutorial da Python Brasil para Mac OS X](https://python.org.br/instalacao-mac/)

* [Tutorial da Python Brasil para Linux](https://python.org.br/instalacao-linux/)

### Instalando o Port Scanner
- Clone o repositório;
- Execute o arquivo [portscanner.py](portscanner.py).

### Exemplos de uso
```console
python3 portscanner.py --ip 127.0.0.1 --ports 80,443,22 --tcp
python portscanner.py --ip 127.0.0.1 --ports 53,22 --udp
./portscanner.py --ip 127.0.0.1 --ports 80,443 --tcp --udp --json
```

OBS: Informações de uso da ferramenta estão disponíveis ao executar o programa sem nenhum argumento ou ao chamar "--help".

## Menções importantes
* Técnicas de scan usadas pelo Nmap: [Inglês](https://nmap.org/book/man-port-scanning-techniques.html) e [português](https://nmap.org/man/pt_BR/man-port-scanning-techniques.html)

* Artigos do [Diogo M. Martins](https://github.com/diogommartins) 
sobre concorrência e paralelismo em Python: 
[Parte 1](https://diogommartins.wordpress.com/2017/04/07/concorrencia-e-paralelismo-threads-multiplos-processos-e-asyncio-parte-1/) e 
[Parte 2](https://diogommartins.wordpress.com/2017/04/22/concorrencia-e-paralelismo-threads-multiplos-processos-e-asyncio-parte-2/)

## Autoria e licença
A autoria está descrita na licença, anexa em [LICENSE](LICENSE). O projeto está licenciado sobre o MIT, e consequentemente está disponível para ser alterado por terceiros levando em conta a autoria original.
