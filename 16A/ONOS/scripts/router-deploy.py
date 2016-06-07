#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import RemoteController, OVSSwitch
from sdnip import OVSSwitchONOS, L2OVSSwitch, ONOSCluster, BgpRouter, SdnipHost
from sdnip import ONOSHostSdnipCluster
from mininet.link import Intf

class SDNTopo( Topo ):
    "Sets up control plane components for Router deployment"
    
    def __init__( self, *args, **kwargs ):
        Topo.__init__( self, *args, **kwargs )
     
        # Set up the SDN router's quagga BGP instance i.e the BGP speaker
        # first set the AS number for the SDN router
        sdnAs = 65000

        # Quagga Host (qh) interfaces
        # eth0 interface is used to communicate with ONOS 
        qheth0 = { 'ipAddrs' : ['1.1.1.11/24'] }
        # eth1 interface is used to communicate with peers
        qheth1 = [
            # tagged interface
            { 'vlan': 100,
              'mac':'00:00:00:00:00:01', 
              'ipAddrs' : ['192.168.10.101/24'] },
            # untagged interface 
            { 'mac':'00:00:00:00:00:02', 
              'ipAddrs' : ['192.168.20.101/24'] }
        ]

        qhIntfs = { 'qh-eth0' : qheth0,
                    'qh-eth1' : qheth1 }
        # bgp peer config
        neighbors = [{'address':'192.168.10.1', 'as':65001},
                     {'address':'192.168.20.1', 'as':65002}]
                     
        # create the quagga linux host and instantiate quagga BGP
        qh = self.addHost( "qh", intfDict=qhIntfs, asNum=sdnAs, 
                           sdnRouter=True, onosIpAddr='1.1.1.1',
                           neighbors=neighbors, routes=[], cls=BgpRouter )
        
        # Set up control plane connectivity
        root1 = self.addHost('root1', ip='1.1.1.1/24', inNamespace=False)
        self.addLink( qh, root1 )

        # Set up OVS as a regular L2 bridge to connect Quagga host to a physical VM interface
        # The VM interface should be connected to a front panel port on the dataplane
        # as per the new Atrium router architecture.
        # Here we create the switch and connect it to the Quagga host. After the network
        # is created, we create a second interface on the switch and connect it to the
        # VM interface.
        s1 = self.addSwitch('s1', dpid='00000000000000aa')
        self.addLink( qh, s1 )

if __name__ == "__main__":
    setLogLevel('debug')
    topo = SDNTopo()

    net = Mininet(topo=topo, controller=RemoteController, switch=OVSSwitch)

    # Create a second interface on the switch and connect it to the VM 'eth1' external facing interface
    s1 = net.get('s1')
    ext_intf = Intf('eth1', node=s1)

    net.start()
    
    # Ensure that OVS behaves as a regular L2 bridge (ie. remove any controller config)
    s1.cmd('ovs-vsctl set-controller s1 none')
    s1.cmd('ovs-vsctl set-fail-mode s1 standalone')

    CLI(net)

    net.stop()

    info("done\n")
