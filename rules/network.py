import socket, uuid

class Network():
    def __init__(self):
        self.ip = socket.gethostbyname(socket.gethostname())
        self.mac = ':'.join([('%x' % uuid.getnode())[i:i+2] for i in range(0,12,2)])

def check_tcp(packet):
    return 

def check_udp(packet):
    return

def check_icmp(packet):
    return
