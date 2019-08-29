from flask import Flask, request, jsonify, Response
from portscanner import ArgumentParser, PortScanner, ConnectionMethod

app = Flask(__name__)

@app.route('/scan', methods = ['POST'])
def scan() -> Response:
    if (request.is_json):
        arg_parser = ArgumentParser(request.get_json())

        if not arg_parser.has_valid_args():
            return jsonify({'status': 'INVALID_ARGS'}), 200
        
        if not arg_parser.has_allowed_port_range():
            return jsonify({'status': 'INVALID_RANGE'}), 200
        
        ps = PortScanner(arg_parser.ip, range(arg_parser.min, arg_parser.max + 1))
        tcp_ports = list()
        udp_ports = list()

        if arg_parser.tcp:
            tcp_ports = ps.scan_to_list(ConnectionMethod.TCP)
    
        if arg_parser.udp:
            udp_ports = ps.scan_to_list(ConnectionMethod.UDP)

        return jsonify({'status': 'OK', 'tcp': tcp_ports, 'udp': udp_ports}), 200
    
    return Response(status = 406)

if __name__ == '__main__':
    app.run()