import lib.packet
import rules.network
import socket

#Creates socket to listen through
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
#Setting variables
syn_flood = 0
verbose = 0
tcp_port_scan = 0
tcp_rst_attack = 0
#Read settings from settings.config
f = open('settings.config','r')
config = f.readlines()
for settings in config:
    if settings == 'syn_flood 1\n':
        syn_flood = 1
    elif settings == 'verbose 1\n':
        verbose = 1
    elif settings == 'tcp_port_scan 1\n':
        tcp_port_scan = 1
    elif settings == 'tcp_rst_attack 1\n':
        tcp_rst_attack = 1
f.close()
#Initialize network analyzer
n = rules.network.Network(syn_flood,tcp_port_scan,tcp_rst_attack)

while 1:
    #Intercept packet
    packet = s.recvfrom(65565)
    packet = packet[0]
    #Parse packet
    p = lib.packet.parse(packet)
    print(p)
    #Inspect TCP packet
    if(p['eth']['protocol'] == 8 and p['ip']['protocol'] == 6):
        info = n.check_tcp(p)
        if(info != ''and verbose == 1):
            print(info,end="")
