import socket, sys, struct

def collect_packets():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    i = 0
    while i < 20:
        packet = s.recvfrom(65565)
        packet = packet[0]
        print(parse(packet))
        i = i + 1
    s.close()

def bin_to_mac(addr):
    return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])

def parse(packet):
    data = {}
    data['eth'] = parse_eth(packet)
    if(data['eth']['protocol'] == 8):
        data['ip'] = parse_ip(packet)
        if(data['ip']['protocol'] == 6):
            data['tcp'] = parse_tcp(packet,data['ip']['length'])
        elif(data['ip']['protocol'] == 17):
            data['udp'] = parse_udp(packet,data['ip']['length'])
        elif(data['ip']['protocol'] == 1):
            data['icmp'] = parse_icmp(packet,data['ip']['length'])
    return data

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

def parse_tcp(packet,ip_length):
    tcp = struct.unpack('!HHLLBBHHH',packet[14+ip_length:14+ip_length+20])
    src_port = tcp[0]
    dst_port = tcp[1]
    tcp_length = (tcp[4] >> 4) * 4
    flags = tcp[5]
    data = packet[14+ip_length+tcp_length:]
    return {'src_port':src_port, 'dst_port':tcp[1], 'length':tcp_length,'flag':flags,'data':data}

def parse_udp(packet, ip_length):
    udp = struct.unpack('!HHHH',packet[14+ip_length:14+ip_length+8])
    src_port = udp[0]
    dst_port = udp[1]
    udp_length = udp[2]
    data = packet[14+ip_length+udp_length:]
    return {'src_port':src_port, 'dst_port':dst_port, 'length':udp_length, 'data':data}

def parse_icmp(packet, ip_length):
    icmp = struct.unpack('!BBHL',packet[14+ip_length:14+ip_length+8])
    icmp_type = icmp[0]
    icmp_code = icmp[1]
    return {'type':icmp_type, 'code':icmp_code}
