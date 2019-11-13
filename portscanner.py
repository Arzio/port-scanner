#!/usr/bin/env python3

import json

from portscanner.argumentparser import ArgumentParser
from portscanner.core import ScanController


def main() -> None:
    arg_parser = ArgumentParser()

    if not arg_parser.has_valid_args():
        arg_parser.help_message()

    if not arg_parser.has_allowed_ports():
        print('There are given ports which doesnt exists')
        exit(1)

    ps = ScanController(arg_parser.ip, arg_parser.ports)

    if arg_parser.json:
        results = ps.scan_to_list(arg_parser.methods, arg_parser.threads)
        json_object = json.dumps(results, default=lambda sr: sr.__dict__(), indent=4)
        print(json_object)

    else:
        print("METHOD\tIP\t\tPORT\tSTATUS")
        ps.scan(arg_parser.methods, arg_parser.threads)


if __name__ == '__main__':
    try:
        main()

    except KeyboardInterrupt:
        exit()
