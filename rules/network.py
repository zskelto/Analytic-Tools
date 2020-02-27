import socket, uuid

class Network():
    def __init__(self):
        self.mac = ':'.join([('%x' % uuid.getnode())[i:i+2] for i in range(0,12,2)])
        self.syn = {}

    def check_tcp(self,packet):
        if(self.mac != packet['eth']['src_mac']):
            ip = packet['ip']['src']
            port = packet['tcp']['dst_port']

            ##SYN Flood Check
            #Checks if IP has been logged for SYN flood
            if (not(ip in self.syn) and (packet['tcp']['flag'] == 2)):
                self.syn[ip] = {'port':[port]}
            #Has been logged and recieved SYN
            elif(packet['tcp']['flag'] == 2):
                if(port in self.syn[ip]['port']):
                    #TODO: Log SYN Flood in Network.log
                else:
                    self.syn[ip]['port'].append(port)
            #Recieved ACK
            elif(packet['tcp']['flag'] == 16):
                if(port in self.syn[ip]['port']):
                    self.syn[ip]['port'].remove(port)

            ##SYN Scan
            #TODO
        return 0

    def check_udp(packet):
        return

    def check_icmp(packet):
        return
