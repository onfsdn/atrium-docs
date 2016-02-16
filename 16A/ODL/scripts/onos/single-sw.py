#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import Intf
from mininet.log import setLogLevel, info
from mininet.node import RemoteController, OVSSwitch
from sdnip import OVSSwitchONOS, L2OVSSwitch, ONOSCluster, BgpRouter, SdnipHost
from sdnip import ONOSHostSdnipCluster

class SDNTopo( Topo ):
    "Sets up control plane components for Router deployment"
    
    def __init__( self, *args, **kwargs ):
        Topo.__init__( self, *args, **kwargs )

        # Set up data plane switch - this is the emulated router dataplane
        # Note: The controller needs to be configured with the specific driver that
        # will be attached to this switch.

        router = self.addSwitch('router', dpid='0000000000000002')

        # Set up BGP peer1 and host1 in AS65001
        # host1 connects to peer1 and represents multiple ip-addrs within AS65001 reachable via peer1
        #peer1As = 65001

        #peer1eth0 = [
        #    { 'vlan': 100,
        #      'mac':'00:00:00:00:10:01', 
        #      'ipAddrs' : ['192.168.10.1/24'] }
        #]
        #peer1eth1 = { 'ipAddrs' : ['1.0.0.254/16'] }
        #peer1Intfs = { 'peer1-eth0' : peer1eth0,
        #               'peer1-eth1' : peer1eth1 }
        #peer1networks = ['1.0.0.0/16']
        #neighborsOfP1 = [{'address':'192.168.10.101', 'as':65000}]
        #peer1 = self.addHost( "peer1", intfDict=peer1Intfs, asNum=peer1As, 
        #                      neighbors=neighborsOfP1, routes=peer1networks, cls=BgpRouter)

        #ips1 = ['1.0.%s.1/24' %ip for ip in range(0,11)]
        #host1 = self.addHost('host1', cls=SdnipHost, ips=ips1, gateway='1.0.0.254')
        
        # Set up BGP peer2 and host2 in AS65002
        # host2 connects to peer2 and represents multiple ip-addrs within AS65002 reachable via peer2
        #peer2As = 65002

        #peer2eth0 = [
        #    { 'vlan': 200,
        #      'mac':'00:00:00:00:20:01', 
        #      'ipAddrs' : ['192.168.20.1/24'] }
        #]
        #peer2eth1 = { 'ipAddrs' : ['2.0.0.254/16'] }
        #peer2Intfs = { 'peer2-eth0' : peer2eth0,
        #               'peer2-eth1' : peer2eth1 }
        #peer2networks = ['2.0.0.0/16']
        #neighborsOfP2 = [{'address':'192.168.20.101', 'as':65000}]
        
        #peer2 = self.addHost( "peer2", intfDict=peer2Intfs, asNum=peer2As, 
        #                      neighbors=neighborsOfP2, routes=peer2networks, cls=BgpRouter)

        #ips2 = ['2.0.%s.1/24' %ip for ip in range(0,11)]
        #host2 = self.addHost('host2', cls=SdnipHost, ips=ips2, gateway='2.0.0.254')

        # Set up data plane connectivity
        #self.addLink( router, peer1 )
        #self.addLink( router, peer2 )
        #self.addLink( peer1, host1 )
        #self.addLink( peer2, host2 )

        # Set up management plane and connectivity


if __name__ == "__main__":
    setLogLevel('debug')
    topo = SDNTopo()

    remoteController = RemoteController('onos', ip='192.168.2.103', port=6633)
    net = Mininet(topo=topo, controller=remoteController, switch=OVSSwitch)

    # addting the eth1 and eth2 to the router
    router = net.switches[0]
    Intf("eth1", router)
    Intf("eth2", router)
    Intf("eth3", router)
    net.start()
    
    CLI(net)

    net.stop()

    info("done\n")
