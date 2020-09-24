#! /usr/bin/env python3
#import sys
#from scapy.all import *
 
#addr_const = "192.168.1"
#for addr in (1,255):
#	ans= sr1(ARP(pdst=addr_const+str(addr)),timeout=2, verbose=0)
#	if ans:
#		print ("[+] host found " + addr_const+str(addr))

from __future__ import print_function
from scapy.all import *
import time
import socket
import netifaces

direc = {"10.0.0.75" : " "}


#usage getMyInformation().get("netmask") 
def getMyInformation():
	addr=netifaces.ifaddresses('tap1')
	return addr[netifaces.AF_INET][0]
	#return a dictionary {'broadcast': u'192.168.0.255', 'netmask': u'255.255.255.0', 'addr': u'192.168.0.30'}
print (getMyInformation())

def myEther():
    return Ether()





def showPackets(packet):
    # Match ARP requests
    #print(ls(packet)) #ls() listar los campos del paquete
    #ask if op is  1 (request) or 2 (replies))



        

    if packet.type == 2054:
        print(packet.summary())
        print(ls(packet[ARP]))

        if "20.0.0" in packet[ARP].psrc or "20.0.0" in packet[ARP].psrc:
        
            if packet[ARP].op == ARP.who_has: 
                    
                #alike 
                myDir=getMyInformation().get("addr").split(".")
                otherDir=packet[ARP].psrc.split(".")
                boolean= True
                i=0
                while  boolean and i < 3:
                    if myDir[i]!= otherDir[i]: #while para saber si esta en el mismo broadcast
                        boolean=False
                    i+=1        
                if boolean== False: #no esta en misma red
                    
                    for i in direc:
                        if direc[i] == " " and packet[ARP].psrc == "20.0.0.2" :
                            #print(packet.summary())
                            #print(ls(packet[ARP]))
                            direc[i]=packet[ARP].psrc
                            reply = ARP(op=ARP.is_at, hwsrc="66:f3:35:08:91:bb", psrc=packet[ARP].pdst, hwdst=packet[ARP].hwsrc, pdst=packet[ARP].psrc)
                            go = Ether(dst="ff:ff:ff:ff:ff:ff", src="66:f3:35:08:91:bb") / reply
                            sendp(go, iface="tap1")

                            break
                else: #si estan en la misma red
                    if packet[ARP].psrc in direc:
                        print("es misma red")
                      
                        reply = ARP(op=ARP.is_at, hwsrc="66:f3:35:08:91:bb", psrc="packet[ARP].pdst", hwdst=packet[ARP].hwsrc, pdst=packet[ARP].psrc)
                        go = Ether(dst="ff:ff:ff:ff:ff:ff", src="66:f3:35:08:91:bb") / reply
                        
                       
    else:

        if packet[Ether].type == 2048: 
            
            if packet[IP].src=="10.0.0.75" and packet[IP].dst=="20.0.0.3" :
                print("mensaje************************************************+")
                print(packet.summary())
                print(ls(packet))

            if packet[IP].src=="10.0.0.75" and packet[IP].dst=="10.0.0.3" :
                print("mensaje************************************************+")
                print(packet.summary())
                print(ls(packet))
            if packet[IP].src=="20.0.0.2" and packet[IP].dst=="20.0.0.3" :
                print("mensaje************************************************+")
                print(packet.summary())
                print(ls(packet))
            if packet[IP].src=="10.0.0.3" and packet[IP].dst=="10.0.0.75" :
                print("mensaje************************************************+")
                print(packet.summary())
                print(ls(packet))
                packet[IP].src = "20.0.0.3"
                packet[IP].dst = "20.0.0.2"
                packet[Ether].src="66:f3:35:08:91:bb"
                packet[Ether].dst="00:50:79:66:68:02"
                x= packet
                sendp(x, iface="tap1")
                print(packet.summary())
                print(ls(packet))



            if "20.0." in packet[IP].src and "20.0." in packet[IP].dst :
                if 1:  #if "20.0." in packet[IP].dst or "10.0." in packet[IP].dst:
                    if packet[ICMP].type ==8 :


                        #print("spoffing--- paquete sin modificar..................-"
                        packet[IP].src="10.0.0.75"
                        packet[Ether].src="66:f3:35:08:91:bb"
                        packet[Ether].dst="c2:01:2f:ac:00:00"
                        
                        x= packet
                        sendp(x, iface="tap1")


                        packet[IP].dst = "10.0.0.3"
                        packet[Ether].src="66:f3:35:08:91:bb"
                        packet[Ether].dst="00:50:79:66:68:00"
                        x= packet
                        sendp(x, iface="tap1")
                        #p= IP(src="10.0.0.4", dst="10.0.0.3")/ICMP()
                        
                        #print(ls(packet))
                        #send(p, iface="tap1")
                        
                    else:
                        if packet[IP].src=="10.0.0.3" and "10.0.0.75" == packet[IP].dsr:
                            if packet[ICMP].type ==0 :
                                print ("")
                                print ("paquetes icmp 20.0.0.3 y 10.0.0.4")
                                packet[IP].src="20.0.0.3"
                                #x= packet
                                #sendp(x, iface="tap1")


                                packet[IP].dst = "20.0.0.2"
                                x= packet
                                #sendp(x, iface="tap1")
                                print (ls(x))


            
            
     
    return
sniff(iface="tap1" ,prn=showPackets)


#import pcapy
#devs=pcapy.findalldevs()
#inf = devs[0]

#print inf
#cap= pcapy.open_live(inf,65536, 1, 0)

#count=1

#while count:
	#(header, payload)= cap.next()
	#print count
	#count+=1
