#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, Controller, RemoteController
from mininet.link import TCLink
from mininet.util import irange,dumpNodeConnections
from mininet.log import setLogLevel


class CustomTopology3(Topo):
    "Linear topology of k switches, with one host per switch."

    def __init__(self, **opts):
        """Init.
            k: number of switches (and hosts)
            hconf: host configuration options
            lconf: link configuration options"""

        super(CustomTopology3, self).__init__(**opts)
        s_l = self.addSwitch('s1')
        s_u = self.addSwitch('s2')
        self.addLink(node1="s1", node2="s2")
        s_r = self.addSwitch('s3')
        self.addLink(node1="s2", node2="s3")
        s_d = self.addSwitch('s4')
        self.addLink(node1="s3", node2="s4")
        self.addLink(node1="s4", node2="s1")
        self.addLink(node1="s1", node2="s3")

        h1_s_r = self.addHost('h1')
        l1_s_r = self.addLink(node1="h1", node2="s1")

        h1_s_r = self.addHost('h2')
        l1_s_u = self.addLink(node1="h2", node2="s2")

        h1_s_u = self.addHost('h3')
        l1_s_u = self.addLink(node1="h3", node2="s3")
        h2_s_u = self.addHost('h4')
        l2_s_u = self.addLink(node1="h4", node2="s3")

        h1_s_d = self.addHost('h5')
        l1_s_d = self.addLink(node1="h5", node2="s4")
        h2_s_d = self.addHost('h6')
        l2_s_d = self.addLink(node1="h6", node2="s4")


topos = { 'customtopo3': CustomTopology3}
