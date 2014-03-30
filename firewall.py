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

class TBucket(object):
    def __init__(self, bid, r):
        self.bid = bid          # id of the token bucket
        self.r = r              # rate limit on the bucket
        self.numtoks = 0        # number of tokens in the bucket

    def update(self):
        '''
        Updates the token bucket according to the assigned rate limit r
        '''
        if self.numtoks <= 2*self.r:
            self.numtoks += self.r/2
            if self.numtoks > 2*self.r:     # check for overflow
                self.numtoks = 2*self.r
        print str(self.r/2) + " tokens added to bucket " + str(self.bid) + " totaling " + str(self.numtoks)   

    def remove(self, n):
        '''
        Attempts to remove n tokens from the bucket. Returns 1 if successful, 0 otherwise
        '''
        if n <= self.numtoks:
            self.numtoks -= n
            return 1
        return 0

    def __repr__(self):
        return "TBucket("+str(self.bid)+", "+str(self.r)+", "+str(self.numtoks)+")"

class Firewall(object):
    def __init__(self):
        self.fwt = []               # firewall rules list
        self.tbuckets = []          # token bucket list

        self.fwt = self.buildfwt()

    def update_token_buckets(self):
        '''
        Calls the update function on every token bucket in self.tbuckets
        '''
        for bucket in self.tbuckets:
            bucket.update()

    def allow(self, ippkt):
        '''
        Returns 1 if an IP packet should be allowed through the firewall and 0 otherwise
        '''
        print "FIREWALL:\n" + ippkt.dump()

        if ippkt.v != 4:
            print "PACKET DENIED: not IPv4"
            return 0    # no IPv6 packets allowed!

        ruleid = 0
        for rule in self.fwt:
            ruleid += 1
            #print "*"*64; print str(ruleid) + ": " + str(rule)

            # check rule src and dst with pkt src and dst
            rulesrc = (rule[1][0]).toUnsigned()
            srcmask = cidr_to_netmask(rule[1][1]).toUnsigned()
            ruledst = (rule[2][0]).toUnsigned()
            dstmask = cidr_to_netmask(rule[2][1]).toUnsigned()

            srcmatch = ((ippkt.srcip.toUnsigned() & srcmask) == rulesrc) or (rule[1][0] == IPAddr('0.0.0.0'))
            dstmatch = ((ippkt.dstip.toUnsigned() & dstmask) == ruledst) or (rule[2][0] == IPAddr('0.0.0.0'))
            #print "srcmatch: " + str(srcmatch) + "\ndstmatch: " + str(dstmatch)

            if not (srcmatch and dstmatch):
                #print "rule does not match pkt src/dst"
                continue

            # check rule ports with ippkt ports
            if ((rule[0]==6 or rule[0]==7) and (ippkt.protocol==ippkt.UDP_PROTOCOL or ippkt.protocol==ippkt.TCP_PROTOCOL)):
                sportmatch = (rule[3] == ippkt.payload.srcport) or (rule[3] == 0)
                dportmatch = (rule[4] == ippkt.payload.dstport) or (rule[4] == 0)
                print "sportmatch: " + str(sportmatch) + "\ndportmatch: " + str(dportmatch)

                if not (sportmatch and dportmatch):
                    #print "rule does not match udp/tcp port"
                    continue

            # check rule protocol with packet protocol
            if ((rule[0]==0) or                                             # deny ip
                (rule[0]==1 and ippkt.protocol==ippkt.ICMP_PROTOCOL) or     # deny icmp
                (rule[0]==2 and ippkt.protocol==ippkt.UDP_PROTOCOL ) or     # deny udp
                (rule[0]==3 and ippkt.protocol==ippkt.TCP_PROTOCOL )):      # deny tcp
                print "PACKET DENIED: rule is type 0-3"
                return 0

            # if we've reached this point, the rule definitely applies to this packet and we
            # should decide whether the packet is allowed through based on our token buckets
            break

        # check token buckets
        for bucket in self.tbuckets:
            if bucket.bid == ruleid:
                if bucket.remove(len(ippkt)): 
                    print str(len(ippkt)) + " tokens removed from bucket " + str(bucket.bid) + " leaving " \
                            + str(bucket.numtoks) + "\nPACKET APPROVED"
                    return 1
                else: 
                    print "PACKET DENIED: insufficient tokens in bucket"
                    return 0

        print "PACKET APPROVED"
        return 1

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
        '''
        print "Compiling firewall rules list..."
        fwt = []
        f = open("firewall_rules.txt",'r')
        line=0; counter=0

        while 1:
            entry = f.readline()
            line += 1

            # identify rules
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
                if esplit[pickup[i]]=="any": fwtent.append((IPAddr("0.0.0.0"),32))
                else: fwtent.append(parse_cidr(esplit[pickup[i]]))

            # src port, dst port
            if special:
                pickup=[5,9]            # src port at 5, dst port at 9

                for i in range(2):
                    if esplit[pickup[i]]=="any": fwtent.append(0)
                    else: fwtent.append(int(esplit[pickup[i]]))
            else:
                fwtent.append('x'); fwtent.append('x')

            # create token bucket if necessary and append to self.tbuckets
            if esplit[0]=="permit" and (len(esplit)==12 or len(esplit)==8):
                self.tbuckets.append(TBucket(counter,int(esplit[-1])))

            #print entry; print fwtent; print "*"*32 
            fwt.append(fwtent)

        print str(line-1) + " lines read; " + str(counter) + " rules compiled\n"
        return fwt

def tests():
    f = Firewall()

    ip1 = ipv4()
    ip1.srcip = IPAddr("172.16.42.1")
    ip1.dstip = IPAddr("10.0.0.2")
    ip1.protocol = 17
    xudp1 = udp()
    xudp1.srcport = 53
    xudp1.dstport = 53
    xudp1.payload = "Hello, world"
    xudp1.len = 8 + len(xudp1.payload)
    ip1.payload = xudp1

    ip2 = ipv4()
    ip2.srcip = IPAddr("172.16.40.1")
    ip2.dstip = IPAddr("10.0.0.1")
    ip2.protocol = ip2.ICMP_PROTOCOL
    icmppkt = icmp()
    icmppkt.type = pktlib.TYPE_ECHO_REQUEST
    ping = pktlib.echo()
    ping.id = 5
    ping.seq = 10
    icmppkt.payload = ping
    ip2.payload = icmppkt

    ip3 = ipv4()
    ip3.srcip = IPAddr("172.16.38.0")
    ip3.dstip = IPAddr("10.0.0.5")
    ip3.protocol = ip2.ICMP_PROTOCOL
    icmppkt = icmp()
    icmppkt.type = pktlib.TYPE_ECHO_REQUEST
    ping = pktlib.echo()
    ping.id = 5
    ping.seq = 10
    icmppkt.payload = ping
    ip3.payload = icmppkt

    i=0
    while i<10:
        print "+"*70
        f.update_token_buckets()
        f.allow(ip2)
        f.allow(ip3)
        time.sleep(0.5)
        i+=1

    #print len(ip) # print the length of the packet, just for fun

    # you can name this method what ever you like, but you'll
    # need some method that gets periodically invoked for updating
    # token bucket state for any rules with rate limits
    #f.update_token_buckets()

    # again, you can name your "checker" as you want, but the
    # idea here is that we call some method on the firewall to
    # test whether a given packet should be permitted or denied.
    #f.allow(ip1)
    #f.allow(ip2)

    # if you want to simulate a time delay and updating token buckets,
    # you can just call time.sleep and then update the buckets.
    #time.sleep(0.5)
    #f.update_token_buckets()

if __name__ == '__main__':
    # only call tests() if this file gets invoked directly, not if it is imported.
    tests()
