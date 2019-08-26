import sys
import socket
import re
import datetime

def help():
    print("Yee")

def main():
    min = max = ip = None

    for arg_index in range(len(sys.argv)):
        arg = sys.argv[arg_index]

        if arg in ("-h", "--help"):
            help()
            exit()

        elif arg in ("-f", "--from"):
            min = int(sys.argv[arg_index + 1])

        elif arg in ("-t", "--to"):
            max = int(sys.argv[arg_index + 1])
        
        elif re.match(r"^(\d{1,3}\.){3}\d{1,3}$", arg):
            ip = arg

    if None in (min, max, ip):
        print("Invalid args")
        exit

    start = datetime.datetime.now()

    print("Scanning TCP ports at {}".format(ip))
    
    for port in range(min, max + 1):
        con = socket.socket()
        dest = (ip, port)

        if con.connect_ex(dest) == 0:
            print("TCP Port {} is open!".format(port))

        con.close()

    time_taken = (datetime.datetime.now() - start).total_seconds()

    print("Scanning finished, it took {} seconds".format(time_taken))

if __name__ == "__main__":
    main()