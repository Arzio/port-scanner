# Port Scanner

## Sobre
O projeto é um analisador simples de portas TCP, que verifica se as portas recebidas por input do usuário estão abertas ou fechadas.

Ainda, a ferramenta pode converter o output da análise em um JSON, caso seja necessário guardá-lo em um formato de serialização universal.

## Pré-requisitos
1. Python __^ 3.5__

## Como instalar
### Instalando Python
* [Tutorial da Python Brasil para Windows](https://python.org.br/instalacao-windows/)

* [Tutorial da Python Brasil para Mac OS X](https://python.org.br/instalacao-mac/)

* [Tutorial da Python Brasil para Linux](https://python.org.br/instalacao-linux/)

### Instalando o Port Scanner
- Clone o repositório;
- Execute o arquivo [portscanner.py](portscanner.py) como argumento do python CLI ou apenas chame o mesmo.

OBS: Informações de uso da ferramenta estão disponíveis ao executar o programa sem nenhum argumento ou ao chamar "--help".

## Menções importantes
* [Técnicas de scan usadas pelo Nmap](https://nmap.org/book/man-port-scanning-techniques.html)

* Artigos do [Diogo M. Martins](https://github.com/diogommartins) 
sobre concorrência e paralelismo em Python: 
[Parte 1](https://diogommartins.wordpress.com/2017/04/07/concorrencia-e-paralelismo-threads-multiplos-processos-e-asyncio-parte-1/) e 
[Parte 2](https://diogommartins.wordpress.com/2017/04/22/concorrencia-e-paralelismo-threads-multiplos-processos-e-asyncio-parte-2/)

## Autoria e licença
A autoria está descrita na licença, anexa em [LICENSE](LICENSE). O projeto está licenciado sobre o MIT, e consequentemente está disponível para ser alterado por terceiros levando em conta a autoria original.
