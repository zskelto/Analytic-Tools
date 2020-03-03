import lib.packet
import rules.network
import socket

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
n = rules.network.Network()
f = open(n.logfile,'w')
f.close()

while 1:
    packet = s.recvfrom(65565)
    packet = packet[0]
    p = lib.packet.parse(packet)
    if(p['eth']['protocol'] == 8 and p['ip']['protocol'] == 6):
        info = n.check_tcp(p)
        if(info != ''):
            print(info,end="")
