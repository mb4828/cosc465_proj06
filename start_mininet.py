#!/usr/bin/python

import sys

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import lg
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import irange, custom, quietRun, dumpNetConnections
from mininet.cli import CLI

from time import sleep, time
from subprocess import Popen, PIPE
import subprocess
import argparse
import os

parser = argparse.ArgumentParser(description="Mininet portion of pyrouter")
# no arguments needed as yet :-)
args = parser.parse_args()
lg.setLogLevel('info')

class PyRouterTopo(Topo):

    def __init__(self, args):
        # Add default members to class.
        super(PyRouterTopo, self).__init__()

        # Host and link configuration
        #
        #
        #  hint1 --- hint2 
        #         |
        #        sw1
        #          \
        #           router----hext1
        #          /
        #       hext2 
        #
        self.addHost('hint1')
        self.addHost('hint2')
        self.addHost('hext1')
        self.addHost('hext2')
        self.addSwitch('sw1')
        self.addHost('router')
        
        for node in ['sw1','hext1','hext2']:
            self.addLink(node, 'router', bw=1000, delay="10ms")
        for node in ['hint1','hint2']:
            self.addLink(node, 'sw1', bw=1000)

def set_ip_pair(net, node1, node2, ip1, ip2):
    node1 = net.get(node1)
    ilist = node1.connectionsTo(net.get(node2)) # returns list of tuples
    intf = ilist[0]
    intf[0].setIP(ip1)
    intf[1].setIP(ip2)

def set_ip(net, node, ifname, addr):
    node_object = net.get(node)
    intf = node_object.intf(ifname)
    intf.setIP(addr)

def reset_macs(net, node, macbase):
    ifnum = 1
    node_object = net.get(node)
    for intf in node_object.intfList():
        if node not in str(intf):
            continue # don't set lo or other interfaces
        node_object.setMAC(macbase.format(ifnum), intf)
        ifnum += 1

    for intf in node_object.intfList():
        print node,intf,node_object.MAC(intf)

def set_def_route(net, fromnode, gw):
    node_object = net.get(fromnode)
    node_object.cmdPrint("route add default gw {}".format(gw))

def setup_addressing(net):
    router = net.get('router')
    # prevent normal kernel processing for Ethernet and IP packets
    router.cmdPrint('ebtables -t nat -F')
    router.cmdPrint('ebtables -t nat -P PREROUTING DROP')
    router.cmdPrint('ebtables -t nat --list')
    router.cmdPrint('ebtables -F')
    router.cmdPrint('ebtables -P INPUT DROP')
    router.cmdPrint('ebtables --list')
    router.cmdPrint('iptables -F')
    router.cmdPrint('iptables -P INPUT DROP')
    router.cmdPrint('iptables --list')
    router.cmdPrint('sysctl -w net.ipv4.conf.all.arp_ignore=8')

    reset_macs(net, 'hint1', '00:00:00:00:01:{:02x}')
    reset_macs(net, 'hint2', '00:00:00:00:02:{:02x}')
    reset_macs(net, 'hext1', '00:00:00:00:10:{:02x}')
    reset_macs(net, 'hext2', '00:00:00:00:20:{:02x}')
    reset_macs(net, 'sw1', '00:00:00:00:0a:{:02x}')
    reset_macs(net, 'router', '00:00:00:00:0b:{:02x}')

    set_ip_pair(net,'router','hext1','192.168.100.1/30','192.168.100.2/30')
    set_ip_pair(net,'router','hext2','192.168.200.1/30','192.168.200.2/30')

    set_ip(net, 'router', 'router-eth0', '172.16.42.254/24')
    set_ip(net, 'hint1', 'hint1-eth0', '172.16.42.1/24')
    set_ip(net, 'hint2', 'hint2-eth0', '172.16.42.2/24')

    # default router to 172.16.42.254
    set_def_route(net, 'hint1', '172.16.42.254')
    set_def_route(net, 'hint2', '172.16.42.254')
    set_def_route(net, 'hext1', '192.168.100.1')
    set_def_route(net, 'hext2', '192.168.200.1')

    forwarding_table = open('forwarding_table.txt', 'w')    
    table = '''192.168.42.0 255.255.255.0 192.168.100.2 router-eth1
192.168.0.0 255.255.0.0 192.168.200.2 router-eth2
'''
    forwarding_table.write(table)
    forwarding_table.close()

def main():
    topo = PyRouterTopo(args)
    net = Mininet(topo=topo, link=TCLink, cleanup=True, autoSetMacs=True)
    setup_addressing(net)
    net.staticArp()
    net.interact()

if __name__ == '__main__':
    main()
