import socket, uuid, datetime

class Network():
    def __init__(self, syn_flood=0, tcp_port_scan=0, tcp_rst_attack=0):
        self.mac = ':'.join([('%x' % uuid.getnode())[i:i+2] for i in range(0,12,2)])
        self.syn_flood = syn_flood
        self.tcp_port_scan = tcp_port_scan
        self.tcp_rst_attack = tcp_rst_attack
        self.notice = 'logs/notice.log'
        self.conn = 'logs/conn.log'
        self.connections = []
        self.syn = {}

        f = open(self.notice, 'w')
        f.close()
        f = open(self.conn,'w')
        f.close()

    def check_tcp(self,packet):
        info = ''
        conn = {}
        syn = {}
        syn_reverse = {}
        conn_reverse = {}
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

        syn_reverse['src_ip'] = dst_ip
        syn_reverse['src_port'] = dst_port
        syn_reverse['dst_ip'] = src_ip
        syn_reverse['dst_port'] = src_port
        syn_reverse['status'] = 'SYN'
        conn_reverse = syn.copy()
        conn_reverse['status'] = 'Connected'

        #SYN Recieved/Sent
        if(flag == 2):
            if(self.connections == []):
                self.connections.append(syn)
            elif((not(syn in self.connections)) and (not(conn in self.connections))):
                self.connections.append(syn)
            #SYN Flood
            elif self.syn_flood == 1:
                info = '[ALERT] SYN Flood: '
                info += str(datetime.datetime.now()) + ' '
                info += src_ip + ' '
                info += str(src_port) + ' '
                info += dst_ip + ' '
                info += str(dst_port) + '\n'
                f = open(self.notice,'a')
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
                f = open(self.conn,'a')
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
                f = open(self.conn,'a')
                f.write(info)
                f.close()

        #RST Recieved/Sent       
        if(flag == 4 or flag == 20):
            if((syn_reverse in self.connections) and (self.tcp_port_scan == 1)):
                info = '[ALERT] TCP Port Scan: '
                info += str(datetime.datetime.now()) + ' '
                info += src_ip + ' '
                info += str(src_port) + ' '
                info += dst_ip + ' '
                info += str(dst_port) + '\n'
                f = open(self.notice,'a')
                f.write(info)
                f.close()
            elif(self.tcp_rst_attack == 1):
                info = '[ALERT] TCP RST Attack: '
                info += str(datetime.datetime.now()) + ' '
                info += src_ip + ' '
                info += str(src_port) + ' '
                info += dst_ip + ' '
                info += str(dst_port) + '\n'
                f = open(self.notice,'a')
                f.write(info)
                f.close()

        return info

    def check_udp(packet):
        return

    def check_icmp(packet):
        return
