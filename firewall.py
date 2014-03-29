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

    def allow(self, ippkt):
        '''
        Returns 1 if an IP packet should be allowed through the firewall and 0 otherwise
        '''
        print ippkt.dump()

        if ippkt.v != 4:
            return 0    # no IPv6 packets allowed!

        for rule in self.fwt:
            print "*"*8; print rule

            # check pkt src and dst with rule src and dst
            rulesrc = (rule[1][0]).toUnsigned()
            srcmask = cidr_to_netmask(rule[1][1]).toUnsigned()
            ruledst = (rule[2][0]).toUnsigned()
            dstmask = cidr_to_netmask(rule[2][1]).toUnsigned()

            srcmatch = (ippkt.srcip.toUnsigned() & srcmask) == rulesrc
            dstmatch = (ippkt.dstip.toUnsigned() & dstmask) == ruledst
            
            print "srcmatch: " + str(srcmatch) + "\ndstmatch: " + str(dstmatch)

            if (not srcmatch) and (not dstmatch):
                print "rule does not match pkt src and dst"
                continue

            # check pkt protocol with rule protocol
            print "rule id: " + str(rule[0])
            if (ippkt.protocol != ippkt.UDP_PROTOCOL) and (ippkt.protocol != ippkt.TCP_PROTOCOL):
                print "not special - should have rule id 0,1,4,5"
                if rule[0]==0 and ippkt.protocol!=ippkt.ICMP_PROTOCOL:      return 0    # deny ip
                elif rule[0]==1 and ippkt.protocol==ippkt.ICMP_PROTOCOL:    return 0    # deny icmp
                elif rule[0]==4 and ippkt.protocol!=ippkt.ICMP_PROTOCOL:    return 1    # permit ip
                elif rule[0]==5 and ippkt.protocol==ippkt.ICMP_PROTOCOL:    return 1    # permit icmp
                else:
                    print "error!"
                    return -1
            else:
                print "special - should have rule id 2,3,6,7"

                # check pkt ports with rule ports
                sportmatch = (rule[3] == ippkt.payload.srcport) or (rule[3] == 0)
                dportmatch = (rule[4] == ippkt.payload.dstport) or (rule[4] == 0)

                print "sportmatch: " + str(sportmatch) + "\ndportmatch: " + str(dportmatch)

                if (not sportmatch) and (not dportmatch):
                    print "rule does not match udp/tcp port"
                    continue

                if rule[0]==2 and ippkt.protocol==ippkt.UDP_PROTOCOL:       return 0    # deny udp
                elif rule[0]==3 and ippkt.protocol==ippkt.TCP_PROTOCOL:     return 0    # deny tcp
                elif rule[0]==6 and ippkt.protocol==ippkt.UDP_PROTOCOL:     return 1    # permit udp
                elif rule[0]==7 and ippkt.protocol==ippkt.TCP_PROTOCOL:     return 1    # permit tcp
                else:
                    print "error!"
                    return -1

            return -1

    def buildfwt(self):
        '''
        Returns a list containing a representation of the firewall rules in the order in which they appear

        Input rule syntax:
        [permit|deny] ip src [srcnet|any] dst [dstnet|any]
        [permit|deny| icmp src [srcnet|any] dst [dstnet|any]
        [permit|deny] [udp|tcp] src [srcnet|any] srcport [portno|any] dst [dstnet|any] dstport [portno|any]

        Output list entry syntax:
        [protocol, (source IP, masklen), (dest IP, masklen), src port, dst port]

        Protocol assignments:
        (0) 000 = deny ip       (4) 100 = permit ip
        (1) 001 = deny icmp     (5) 101 = permit icmp
        (2) 010 = deny udp      (6) 110 = permit udp
        (3) 011 = deny tcp      (7) 111 = permit tcp

        Wildcard IP: 255.255.255.255
        '''
        print "Compiling firewall rules table..."
        fwt = []
        f = open("firewall_rules.txt",'r')
        line=0; counter=0

        while 1:
            entry = f.readline()
            line += 1

            # initial checks
            if entry == "": break
            elif entry[0] == "#": continue
            elif entry[0] == "\n": continue
            else:
                entry = entry.strip(' \n')
                counter += 1

            # variables
            esplit = entry.split()
            fwtent = []
            special = 0

            # protocol
            if esplit[0] == "deny":
                if esplit[1]=="ip":     fwtent.append(0)
                elif esplit[1]=="icmp": fwtent.append(1)
                elif esplit[1]=="udp":  fwtent.append(2); special=1
                elif esplit[1]=="tcp":  fwtent.append(3); special=1
                else: print "Error in entry line " + str(line) + ": " + str(esplit[1]); continue
            elif esplit[0] == "permit":
                if esplit[1]=="ip":     fwtent.append(4)
                elif esplit[1]=="icmp": fwtent.append(5)
                elif esplit[1]=="udp":  fwtent.append(6); special=1
                elif esplit[1]=="tcp":  fwtent.append(7); special=1
                else: print "Error in entry line " + str(line) + ": " + str(esplit[1]); continue
            else:
                print "Error in entry line " + str(line) + ": " + str(esplit[0]); continue
            
            # src IP, dst IP
            if special: pickup=[3,7]    # src IP at 3, dst IP at 7
            else: pickup=[3,5]          # src IP at 3, dst IP at 5

            for i in range(2):
                if esplit[pickup[i]]=="any": fwtent.append((IPAddr("255.255.255.255"),32))
                else: fwtent.append(parse_cidr(esplit[pickup[i]]))

            # src port, dst port
            if special:
                pickup=[5,9]            # src port at 5, dst port at 9

                for i in range(2):
                    if esplit[pickup[i]]=="any": fwtent.append(0)
                    else: fwtent.append(int(esplit[pickup[i]]))
            else:
                fwtent.append('x'); fwtent.append('x')

            #print entry; print fwtent; print "*"*32 
            fwt.append(fwtent)

        print str(line-1) + " lines read; " + str(counter) + " rules compiled\n"
        return fwt

def tests():
    f = Firewall()

    ip = ipv4()
    ip.srcip = IPAddr("172.16.42.1")
    ip.dstip = IPAddr("10.0.0.2")
    ip.protocol = 17
    xudp = udp()
    xudp.srcport = 53
    xudp.dstport = 53
    xudp.payload = "Hello, world"
    xudp.len = 8 + len(xudp.payload)
    ip.payload = xudp

    #print len(ip) # print the length of the packet, just for fun

    # you can name this method what ever you like, but you'll
    # need some method that gets periodically invoked for updating
    # token bucket state for any rules with rate limits
    #f.update_token_buckets()

    # again, you can name your "checker" as you want, but the
    # idea here is that we call some method on the firewall to
    # test whether a given packet should be permitted or denied.
    assert(f.allow(ip) == True)

    # if you want to simulate a time delay and updating token buckets,
    # you can just call time.sleep and then update the buckets.
    #time.sleep(0.5)
    #f.update_token_buckets()

if __name__ == '__main__':
    # only call tests() if this file gets invoked directly, not if it is imported.
    tests()
