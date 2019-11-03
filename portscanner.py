#!/usr/bin/env python3

import json

from portscanner.argsparser import ArgsParser, help_message
from portscanner.core import ScanController


def main() -> None:
    arg_parser = ArgsParser()

    if not arg_parser.has_valid_args():
        help_message()

    if not arg_parser.has_allowed_ports():
        print('Some ports are forbidden')
        exit(1)

    ps = ScanController(arg_parser.ip, arg_parser.ports)

    if arg_parser.json:
        results = ps.scan_to_list(arg_parser.threads)
        json_object = json.dumps(results, default=lambda sr: sr.__dict__(), indent=4)
        print(json_object)

    else:
        print("METHOD/IP/PORT/OPEN")
        ps.scan(arg_parser.threads)


if __name__ == '__main__':
    try:
        main()

    except KeyboardInterrupt:
        exit()
