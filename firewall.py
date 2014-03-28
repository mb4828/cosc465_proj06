import sys
import os
import os.path
sys.path.append(os.path.join(os.environ['HOME'],'pox'))
sys.path.append(os.path.join(os.getcwd(),'pox'))
import pox.lib.packet as pktlib
from pox.lib.packet import ethernet,ETHER_BROADCAST,IP_ANY
from pox.lib.packet import arp,ipv4,icmp,unreach,udp,tcp
from pox.lib.addresses import EthAddr,IPAddr,netmask_to_cidr,cidr_to_netmask,parse_cidr
import time

class Firewall(object):
    def __init__(self):
        self.fwt = self.buildfwt()

    def buildfwt(self):
        '''
        Returns a table containing a representation of the firewall rules

        Rule syntax:
        [permit|deny] ip src [srcnet|any] dst [dstnet|any]
        [permit|deny| icmp src [srcnet|any] dst [dstnet|any]
        [permit|deny] [udp|tcp] src [srcnet|any] srcport [portno|any] dst [dstnet|any] dstport [portno|any]

        Final list entry syntax:
        [p|d,  0=ip|1=icmp|2=udp|3=tcp, 0=any|(IPAddr,masklen)*4,           0=noratelimit|ratelimit]
        0      1                        2-5 (src, srcport, dst, dstport)    6
        '''
        print "Compiling firewall rules table..."
        fwt = []
        f = open("firewall_rules.txt",'r')
        line = 0
        counter = 0

        while 1:
            entry = f.readline()
            line += 1

            if entry == "": 
                break
            elif entry[0] == "#": 
                continue
            elif entry[0] == "\n": 
                continue
            else:
                entry = entry.strip(' \n')
                counter += 1
            
            esplit = entry.split()
            tent = []
            
            # permit/deny
            if esplit[0] == "deny": 
                tent.append('d')
            elif esplit[0] == "permit": 
                tent.append('p')
            else:
                print "Entry line " + str(line) + " is invalid: " + str(esplit[0])
                continue

            # packet type
            mode=0
            if esplit[1] == "ip": 
                tent.append(0)
            elif esplit[1] == "icmp": 
                tent.append(1)
            elif esplit[1] == "udp": 
                tent.append(2)
                mode=1
            elif esplit[1] == "tcp":
                tent.append(3)
                mode=1
            else:
                print "Entry line " + str(line) + " is invalid: " + str(esplit[1])
                continue

            # src, srcport, dst, dstport
            x=6; y=2
            if mode:
                if (len(esplit) != 10) and (len(esplit) != 12):
                    print "Entry length line " + str(line) + " is invalid: " + str(esplit)
                    continue
                x=9; y=4
            else:
                if (len(esplit) != 6) and (len(esplit) != 8):
                    print "Entry length line " + str(line) + " is invalid: " + str(esplit)
                    continue
                
            for i in range(3,x,y):
                # src/dst
                if esplit[i] == "any": tent.append(0)
                else:
                    ipsplit = esplit[i].split('/')
                    if len(ipsplit) == 1:
                        tent.append( (IPAddr(ipsplit[0]), 32 ) )
                    else:
                        tent.append( (IPAddr(ipsplit[0]), int(ipsplit[1])) )

                if mode:
                    # srcport/dstport
                    if esplit[i+2] == "any":
                        tent.append(0)
                    else:
                        tent.append(int(esplit[i+2]))
                else:
                    tent.append("x")

            # rate limit
            if mode and len(esplit)==12:
                tent.append(esplit[11])
            elif len(esplit)==8:
                tent.append(esplit[7])
            else:
                tent.append(0)

            fwt.append(tent)

        print str(counter) + " rules compiled"
        return fwt

def tests():
    f = Firewall()

    #ip = ipv4()
    #ip.srcip = IPAddr("172.16.42.1")
    #ip.dstip = IPAddr("10.0.0.2")
    #ip.protocol = 17
    #xudp = udp()
    #xudp.srcport = 53
    #xudp.dstport = 53
    #xudp.payload = "Hello, world"
    #xudp.len = 8 + len(xudp.payload)
    #ip.payload = xudp

    #print len(ip) # print the length of the packet, just for fun

    # you can name this method what ever you like, but you'll
    # need some method that gets periodically invoked for updating
    # token bucket state for any rules with rate limits
    #f.update_token_buckets()

    # again, you can name your "checker" as you want, but the
    # idea here is that we call some method on the firewall to
    # test whether a given packet should be permitted or denied.
    #assert(f.allow(ip) == True)

    # if you want to simulate a time delay and updating token buckets,
    # you can just call time.sleep and then update the buckets.
    #time.sleep(0.5)
    #f.update_token_buckets()

if __name__ == '__main__':
    # only call tests() if this file gets invoked directly,
    # not if it is imported.
    tests()
