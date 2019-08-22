import sys
import socket
import re

def main():
    min = max = ip = None

    for i in sys.argv:
        arg = str(i)

        if arg == "-f" or arg == "--from":
            min = int(sys.argv[sys.argv.index(i) + 1])

        elif arg == "-t" or arg == "--to":
            max = int(sys.argv[sys.argv.index(i) + 1])
        
        elif re.match(r"^(\d{1,3}\.){3}\d{1,3}$", arg):
            ip = arg

    if None in (min, max, ip):
        print("Invalid args")
        exit

if __name__ == "__main__":
    main()