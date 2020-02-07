import socket, sys, struct

def collect_packets():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    i = 0
    while i < 5:
        packet = s.recvfrom(65565)
        packet = packet[0]
        parse(packet)
        i = i + 1

def bin_to_mac(addr):
    return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])

def parse(packet):
    data = {}
    data['eth'] = parse_eth(packet)
    if(data['eth']['protocol'] == 8):
        data['ip'] = parse_ip(packet)
    print(data)

def parse_eth(packet):
    eth_length = 14
    eth_header = struct.unpack('!6s6sH',packet[:eth_length])
    dest_mac = bin_to_mac(eth_header[0])
    src_mac = bin_to_mac(eth_header[1])
    return {'dest_mac':dest_mac,'src_mac':src_mac,'protocol':socket.ntohs(eth_header[2])}

def parse_ip(packet):
    ip = struct.unpack('!BBHHHBBH4s4s',packet[14:34])
    version = ip[0] >> 4
    ip_length = (ip[0] & 0x0F) * 4
    ttl = ip[5]
    protocol = ip[6]
    src_ip = socket.inet_ntoa(ip[8])
    dest_ip = socket.inet_ntoa(ip[9])
    return {'version':version, 'length':ip_length, 'ttl':ttl, 'protocol':protocol, 'src':src_ip, 'dst':dest_ip}

def parse_tcp(packet):
    return

def parse_udp(packet):
    return

def parse_icmp(packet):
    return
