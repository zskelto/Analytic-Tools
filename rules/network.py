import socket, uuid

class Network():
    def __init__(self):
        self.ip = socket.gethostbyname(socket.gethostname())
        self.mac = ':'.join([('%x' % uuid.getnode())[i:i+2] for i in range(0,12,2)])
        self.connections = {}

    def check_tcp(self,packet):
        if(self.ip != packet['ip']['src']):
            ip = packet['ip']['src']
            self.connections[ip] = {}
        else:
            self.connections[ip] = {}
        return 

    def check_udp(packet):
        return

    def check_icmp(packet):
        return
