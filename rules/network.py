import socket, uuid, datetime

class Network():
    def __init__(self):
        self.mac = ':'.join([('%x' % uuid.getnode())[i:i+2] for i in range(0,12,2)])
        self.logfile = open('logs/network.log','a')
        self.syn = {}

    def check_tcp(self,packet):
        if(self.mac != packet['eth']['src_mac']):
            ip = packet['ip']['src']
            port = packet['tcp']['dst_port']
            ##SYN Flood Check
            #Checks if IP has been logged for SYN flood
            if ((not(ip in self.syn)) and (packet['tcp']['flag'] == 2)):
                self.syn[ip] = {'port':[port]}
            #Has been logged and recieved SYN
            elif(packet['tcp']['flag'] == 2):
                if(port in self.syn[ip]['port']):
                    info = ""
                    info += "[ALERT]SYN Flood: "
                    info += str(datetime.datetime.now()) + ' '
                    info += ip + ' '
                    info += str(port) + '\n'
                    self.logfile.write(info)

                else:
                    self.syn[ip]['port'].append(port)
            #Has been logged and recieved ACK
            elif((ip in self.syn) and packet['tcp']['flag'] == 16):
                if(port in self.syn[ip]['port']):
                    info = ''
                    info += '[INFO] Connection Started: '
                    info += str(datetime.datetime.now()) + ' '
                    info += ip + ' '
                    info += str(port) + '\n'
                    self.logfile.write(info)
                    self.syn[ip]['port'].remove(port)
                    if(self.syn[ip]['port'] == []):
                        self.syn.pop(ip,None)
            elif(packet['tcp']['flag'] == 1 or packet['tcp']['flag'] == 17):
                info = '[INFO] Connection Ended: '
                info += str(datetime.datetime.now()) + ' '
                info += ip + ' '
                info += str(port) + '\n'
                self.logfile.write(info)

            ##SYN Scan
            #TODO
        return 0

    def check_udp(packet):
        return

    def check_icmp(packet):
        return
