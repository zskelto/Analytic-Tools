import socket, uuid

class Network():
    def __init__(self):
        self.ip = socket.gethostbyname(socket.gethostname())
        self.mac = ':'.join([('%x' % uuid.getnode())[i:i+2] for i in range(0,12,2)])
        self.connections = {}

    def check_tcp(self,packet):
        if(self.mac != packet['eth']['src_mac']):
            ip = packet['ip']['src']
        else:
            ip = packet['ip']['dst']
        
        if not(ip in self.connections):
            self.connections[ip] = {'SYN-Count':0,'Last-Flag':0}
        
        if(packet['ip']['src'] == ip):
            #Recieved SYN
            if(packet['tcp']['flag'] == 2):
                self.connections[ip]['SYN-Count'] += 1
                self.connections[ip]['Last-Flag'] = 2
            #Recieved ACK
            elif(packet['tcp']['flag'] == 16):
                if(self.connections[ip]['Last-Flag'] == 2):
                    self.connections[ip]['SYN-Count'] -= 1
        return 

    def check_udp(packet):
        return

    def check_icmp(packet):
        return
