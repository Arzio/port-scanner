# Port Scanner

## About
It's a port scanner that gives information about connection on given TCP/UDP ports for a given IP, telling if they are open/filtered/closed.

At the moment, it only uses the TCP CONNECT method for scanning TCP ports.

Moreover, it can convert the result output to a JSON.

## Requirements
1. Python 3.x.x

## Installation
- Clone the repository; 
- Execute [portscanner.py](portscanner.py).

## Usage
You can use the arg "--help" to know more details about the usage.

There are some samples of usage:
```
./portscanner.py --ip 127.0.0.1 --ports T:80,443,22
./portscanner.py --ip 127.0.0.1 --ports U:53,161,162
./portscanner.py --ip 127.0.0.1 --ports T:80,443,22 --ports U:53,161,162 --json
``` 

## License
[LICENSE](LICENSE)
