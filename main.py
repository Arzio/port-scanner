#!/usr/bin/env python3

import json

from args.argument_parser import ArgumentParser
from scan.connection_method import ConnectionMethod
from scan.port_scanner import PortScanner


# TODO: Implement observer design pattern
def main() -> None:
    arg_parser = ArgumentParser()

    if not arg_parser.has_valid_args():
        print('Invalid args')
        exit(1)

    if not arg_parser.has_allowed_port_range():
        print('Range not allowed')
        exit(2)

    ps = PortScanner(arg_parser.ip, tuple(range(arg_parser.min, arg_parser.max + 1)))

    if arg_parser.json:
        results = list()

        if arg_parser.tcp:
            results.extend(ps.scan_to_list(ConnectionMethod.TCP))

        if arg_parser.udp:
            results.extend(ps.scan_to_list(ConnectionMethod.UDP))

        json_object = json.dumps(results, default=lambda sr: sr.__dict__(), indent=4)
        print(json_object)

    else:
        print("METHOD\tIP\t\tPORT\tOPEN")

        if arg_parser.tcp:
            ps.scan(ConnectionMethod.TCP)

        if arg_parser.udp:
            ps.scan(ConnectionMethod.UDP)


if __name__ == '__main__':
    try:
        main()

    except KeyboardInterrupt:
        exit()
