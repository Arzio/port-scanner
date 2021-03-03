# Port Scanner

It's a port scanner that gives information about connection on given TCP/UDP ports for a given IP, telling if they are open/filtered/closed.

At the moment, it only uses the TCP CONNECT method for scanning TCP ports.

Moreover, it can convert the result output to a JSON.

![Demo](demo.gif)

## Installation

It was made with Python **3.7.x**, so it's guaranteed to run on it. However, it's expected to run on every **3.x.x** version.

After installing or using an existent Python runtime, just clone the repository to your machine.

## Usage

You can use the argument "--help" to see more details about the usage.
```
./portscanner --ip 127.0.0.1 --ports T:80,443,22
./portscanner --ip 127.0.0.1 --ports U:53,161,162
./portscanner --ip 127.0.0.1 --ports T:80,443,22 --ports U:53,161,162 --json
```

## Contributing

[CONTRIBUTING](CONTRIBUTING.md)

## License

[MIT](LICENSE)
