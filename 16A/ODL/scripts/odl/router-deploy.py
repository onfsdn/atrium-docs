#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import RemoteController, OVSSwitch
from sdnip import OVSSwitchONOS, L2OVSSwitch, ONOSCluster, BgpRouter, SdnipHost
from sdnip import ONOSHostSdnipCluster

class SDNTopo( Topo ):
    "Sets up control plane components for Router deployment"
    
    def __init__( self, *args, **kwargs ):
        Topo.__init__( self, *args, **kwargs )
        
        # Set up Control Plane OVS
        s1 = self.addSwitch('s1', dpid='00000000000000aa')

        # Set up BGP speaker
        sdnAs = 100

        bgp1eth0 = { 'ipAddrs' : ['1.1.1.11/24'] }

        bgp1eth1 = [
            { 'vlan' : 100,
              'mac':'00:00:00:00:00:01', 
              'ipAddrs' : ['192.168.10.101/24'] },
            { 'vlan' : 200,
              'mac':'00:00:00:00:00:02', 
              'ipAddrs' : ['192.168.20.101/24'] },
            { 'vlan' : 210,
              'mac':'00:00:00:00:00:05', 
              'ipAddrs' : ['192.168.40.101/24'] }
        ]

        bgp1Intfs = { 'bgp1-eth0' : bgp1eth0,
                      'bgp1-eth1' : bgp1eth1 }

        #neighbors = [{'address':'192.168.10.1', 'as':200},
        #             {'address':'192.168.20.1', 'as':300},
        #             {'address':'192.168.40.1', 'as':500},
        #             {'address':'1.1.1.1', 'as':sdnAs, 'port':2000}]
        neighbors = [{'address':'192.168.20.1', 'as':300},
                     {'address':'192.168.40.1', 'as':500},
                     {'address':'1.1.1.1', 'as':sdnAs, 'port':2000}]
        bgp1 = self.addHost( "bgp1", intfDict=bgp1Intfs, asNum=sdnAs, 
                             neighbors=neighbors, routes=[], cls=BgpRouter)
        
        # Set up control plane connectivity

        root1 = self.addHost('root1', ip='1.1.1.1/24', inNamespace=False)

        self.addLink( bgp1, root1 )
        self.addLink( bgp1, s1 )

if __name__ == "__main__":
    setLogLevel('debug')
    topo = SDNTopo()

    remoteController = RemoteController('onos', ip='192.168.2.102', port=6653)
    net = Mininet(topo=topo, controller=remoteController, switch=OVSSwitch)

    net.start()

    CLI(net)

    net.stop()

    info("done\n")
