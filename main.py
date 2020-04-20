import lib.packet
import lib.virustotal
import rules.network
import socket
import hashlib

#Creates socket to listen through
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
#Setting variables
syn_flood = 0
verbose = 0
tcp_port_scan = 0
tcp_rst_attack = 0
file_scan = 0
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
    elif settings == 'file_scan 1\n':
        file_scan = 1
f.close()
f = open('apikey.txt','r')
apikey = f.read().replace('\n','')
f.close()
#Initialize network analyzer
n = rules.network.Network(syn_flood,tcp_port_scan,tcp_rst_attack)
v = lib.virustotal.VirusTotal(apikey)
if file_scan == 0:
    while 1:
        #Intercept packet
        packet = s.recvfrom(65565)
        packet = packet[0]
        #Parse packet
        p = lib.packet.parse(packet)
        #Inspect TCP packet
        if(p['eth']['protocol'] == 8 and p['ip']['protocol'] == 6):
            info = n.check_tcp(p)
            if(info != ''and verbose == 1):
                print(info,end="")
else:
    response = v.file_scan("test.exe")
    print("Submitting test.exe to virustotal...")
    print(response)
    with open("test.exe",'rb') as file_to_check:
        data = file_to_check.read()
        md5 = hashlib.md5(data).hexdigest()
        print("MD5: " + md5)
    response = v.file_report(md5)
    print(str(response['positives']) + '/' + str(response['total']) + ' positives')

