import socket, uuid, datetime

class Network():
    def __init__(self):
        self.mac = ':'.join([('%x' % uuid.getnode())[i:i+2] for i in range(0,12,2)])
        self.logfile = 'logs/network.log'
        self.connections = []
        self.syn = {}

    def check_tcp(self,packet):
        info = ''
        conn = {}
        syn = {}
        src_ip = packet['ip']['src']
        dst_ip = packet['ip']['dst']
        src_port = packet['tcp']['src_port']
        dst_port = packet['tcp']['dst_port']
        flag  = packet['tcp']['flag']
        
        syn['src_ip'] = src_ip
        syn['src_port'] = src_port
        syn['dst_ip'] = dst_ip
        syn['dst_port'] = dst_port
        syn['status'] = 'SYN'
        conn = syn.copy()
        conn['status'] = 'Connected'

        #SYN Recieved/Sent
        if(flag == 2):
            if(self.connections == []):
                self.connections.append(syn)
            elif((not(syn in self.connections)) and (not(conn in self.connections))):
                self.connections.append(syn)
            #SYN Flood
            else:
                info = '[ALERT] SYN Flood: '
                info += str(datetime.datetime.now()) + ' '
                info += src_ip + ' '
                info += str(src_port) + ' '
                info += dst_ip + ' '
                info += str(dst_port) + '\n'
                f = open(self.logfile,'a')
                f.write(info)
                f.close()
        
        #ACK Recieved/Sent
        if(flag == 16):
            if(syn in self.connections):
                i = self.connections.index(syn)
                self.connections[i] = conn
                info = '[INFO] Connection Started: '
                info += str(datetime.datetime.now()) + ' '
                info += src_ip + ' '
                info += str(src_port) + ' '
                info += dst_ip + ' '
                info += str(dst_port) + '\n'
                f = open(self.logfile,'a')
                f.write(info)
                f.close()
        
        #FIN/FIN-ACK Recieved/Sent
        if(flag == 1 or flag == 17):
            if(conn in self.connections):
                self.connections.remove(conn)
                info = '[INFO] Connection Ended: '
                info += str(datetime.datetime.now()) + ' '
                info += src_ip + ' '
                info += str(src_port) + ' '
                info += dst_ip + ' '
                info += str(dst_port) + '\n'
                f = open(self.logfile,'a')
                f.write(info)
                f.close()
        return info

    def check_udp(packet):
        return

    def check_icmp(packet):
        return
