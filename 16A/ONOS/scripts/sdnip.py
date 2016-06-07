#!/usr/bin/python

# Libraries for creating SDN-IP networks

from mininet.topo import Topo
from mininet.node import OVSSwitch, Controller, Host
from mininet.net import Mininet
from mininet.log import info, debug
from mininet.cli import CLI
from mininet.util import netParse, ipStr
from ipaddress import ip_network, ip_address, ip_interface
import imp, os, sys

# Import the ONOS classes from onos.py in the ONOS repository
#if not 'ONOS_ROOT' in os.environ:
#    print 'ONOS_ROOT is not set.'
#    print 'Try running the script with \'sudo -E\' to pass your environment in.'
#    sys.exit(1)

#onos_path = os.path.join(os.path.abspath(os.environ['ONOS_ROOT']), 'tools/test/topos/onos.py')
#onos = imp.load_source('onos', onos_path)
#from onos import ONOS

class L2OVSSwitch(OVSSwitch):
    "An OVS switch that acts like a legacy L2 learning switch"

    def __init__(self, name, **params):
        OVSSwitch.__init__(self, name, failMode='standalone', **params)

    def start(self, controllers):
        # This switch should always have no controllers
        OVSSwitch.start(self, [])


class SdnipHost(Host):
    def __init__(self, name, ips, gateway, *args, **kwargs):
        super(SdnipHost, self).__init__(name, *args, **kwargs)

        self.ips = ips
        self.gateway = gateway

    def config(self, **kwargs):
        Host.config(self, **kwargs)

        debug("configuring route %s" % self.gateway)

        self.cmd('ip addr flush dev %s' % self.defaultIntf())
        for ip in self.ips:
            self.cmd('ip addr add %s dev %s' % (ip, self.defaultIntf()))

        self.cmd('ip route add default via %s' % self.gateway)

class Router(Host):
    
    def __init__(self, name, intfDict, *args, **kwargs):
        super(Router, self).__init__(name, **kwargs)

        self.intfDict = intfDict
        
    def config(self, **kwargs):
        super(Host, self).config(**kwargs)
        
        self.cmd('sysctl net.ipv4.ip_forward=1')

        for intf, configs in self.intfDict.items():
            self.cmd('ip addr flush dev %s' % intf)
            self.cmd('sysctl net.ipv4.conf.%s.rp_filter=0' % intf)
            if not isinstance(configs, list):
                configs = [configs]
                
            for attrs in configs:
                # Configure the vlan if there is one    
                if 'vlan' in attrs:
                    vlanName = '%s.%s' % (intf, attrs['vlan'])
                    self.cmd('ip link add link %s name %s type vlan id %s' % 
                             (intf, vlanName, attrs['vlan']))
                    addrIntf = vlanName
                    self.cmd('sysctl net.ipv4.conf.%s/%s.rp_filter=0' % (intf, attrs['vlan']))
                else:
                    addrIntf = intf
                    
                # Now configure the addresses on the vlan/native interface
                if 'mac' in attrs:
                    self.cmd('ip link set %s down' % addrIntf)
                    self.cmd('ip link set %s address %s' % (addrIntf, attrs['mac']))
                    self.cmd('ip link set %s up' % addrIntf)
                for addr in attrs['ipAddrs']:
                    self.cmd('ip addr add %s dev %s' % (addr, addrIntf))

class BgpRouter(Router):
    
    binDir = '/usr/local/sbin'
    
    def __init__(self, name, intfDict,
                 asNum, neighbors, routes=[],
                 quaggaConfFile=None,
                 zebraConfFile=None,
                 sdnRouter=False,
                 onosIpAddr="",
                 runDir='/var/run/quagga', *args, **kwargs):
        super(BgpRouter, self).__init__(name, intfDict, **kwargs)
        
        self.runDir = runDir
        self.routes = routes
        self.sdnRouter = sdnRouter
        self.onosIpAddr = onosIpAddr
        
        if quaggaConfFile is not None:
            self.quaggaConfFile = quaggaConfFile
            self.zebraConfFile = zebraConfFile
        else:
            self.quaggaConfFile = '%s/quagga%s.conf' % (runDir, name)
            self.zebraConfFile = '%s/zebra%s.conf' % (runDir, name)
            
            self.asNum = asNum
            self.neighbors = neighbors
            
            self.generateConfig()
            
        self.socket = '%s/zebra%s.api' % (self.runDir, self.name)
        self.quaggaPidFile = '%s/quagga%s.pid' % (self.runDir, self.name)
        self.zebraPidFile = '%s/zebra%s.pid' % (self.runDir, self.name)

    def config(self, **kwargs):
        super(BgpRouter, self).config(**kwargs)

        self.cmd('%s/zebra -d -f %s -z %s -i %s'
                 % (BgpRouter.binDir, self.zebraConfFile, self.socket, self.zebraPidFile))
        self.cmd('%s/bgpd -d -f %s -z %s -i %s'
                 % (BgpRouter.binDir, self.quaggaConfFile, self.socket, self.quaggaPidFile))

    def generateConfig(self):
        self.generateQuagga()
        self.generateZebra()
        
    def generateQuagga(self):
        configFile = open(self.quaggaConfFile, 'w+')
        
        def writeLine(indent, line):
            intentStr = ''
            for _ in range(0, indent):
                intentStr += '  '
            configFile.write('%s%s\n' % (intentStr, line))
            
        def getRouterId(interfaces):
            intfAttributes = interfaces.itervalues().next()
            print intfAttributes
            if isinstance(intfAttributes, list):
                # Try use the first set of attributes, but if using vlans they might not have addresses
                intfAttributes = intfAttributes[1] if not intfAttributes[0]['ipAddrs'] else intfAttributes[0]
            return intfAttributes['ipAddrs'][0].split('/')[0]
        
        writeLine(0, 'hostname %s' % self.name);
        writeLine(0, 'password %s' % 'sdnip')
        writeLine(0, '!')
        writeLine(0, 'router bgp %s' % self.asNum)
        writeLine(1, 'bgp router-id %s' % getRouterId(self.intfDict))
        writeLine(1, 'timers bgp %s' % '3 9')
        writeLine(1, '!')
        
        for neighbor in self.neighbors:
            writeLine(1, 'neighbor %s remote-as %s' % (neighbor['address'], neighbor['as']))
            writeLine(1, 'neighbor %s ebgp-multihop' % neighbor['address'])
            writeLine(1, 'neighbor %s timers connect %s' % (neighbor['address'], '5'))
            writeLine(1, 'neighbor %s advertisement-interval %s' % (neighbor['address'], '1'))
            if 'port' in neighbor:
                writeLine(1, 'neighbor %s port %s' % (neighbor['address'], neighbor['port']))
            writeLine(1, '!')
            
        for route in self.routes:
            writeLine(1, 'network %s' % route)
        
        configFile.close()
    
    def generateZebra(self):
        configFile = open(self.zebraConfFile, 'w+')
        configFile.write('hostname %s\n' % self.name)
        configFile.write('password %s\n' % 'sdnip')
        if self.sdnRouter is True:
            configFile.write('fpm connection ip %s port 2620\n' % self.onosIpAddr)
        configFile.close()

    def terminate(self):
        self.cmd("ps ax | grep '%s' | awk '{print $1}' | xargs kill" 
                 % (self.socket))

        super(BgpRouter, self).terminate()

class AutonomousSystem(object):
    
    psIdx = 1
    
    def __init__(self, asNum):
        self.asNum = asNum
        self.neighbors=[]
        self.vlanAddresses={}
        
    def peerWith(self, myAddress, theirAddress, theirAsNum, vlan=None):
        # TODO convert IP addresses later on
        if vlan in self.vlanAddresses:
            self.vlanAddresses[vlan].append(myAddress.with_prefixlen)
        else:
            self.vlanAddresses[vlan] = [myAddress.with_prefixlen]

        self.neighbors.append({'address':theirAddress.ip, 'as':theirAsNum})
        
    @staticmethod
    def generatePeeringAddresses():
        network = ip_network(u'192.168.%s.0/24' % AutonomousSystem.psIdx)
        AutonomousSystem.psIdx += 1
        
        return ip_interface('%s/%s' % (network[1], network.prefixlen)), \
            ip_interface('%s/%s' % (network[2], network.prefixlen))
        
    @staticmethod
    def addPeering(as1, as2, address1=None, address2=None, useVlans=False):
        vlan = AutonomousSystem.psIdx if useVlans else None
        
        if address1 is None or address2 is None:
            (address1, address2) = AutonomousSystem.generatePeeringAddresses()
            
        as1.peerWith(address1, address2, as2.asNum, vlan=vlan)
        as2.peerWith(address2, address1, as1.asNum, vlan=vlan)

class ExternalAutonomousSystem(AutonomousSystem):

    def __init__(self, num, routes, neighbors=[]):
        super(ExternalAutonomousSystem, self).__init__(65000+num)
        self.num = num
        self.routes = routes
        
        for neighbor in neighbors:
            self.neighbors.append(neighbor)

    def addTopoElements(self, topology, connectAtSwitch):
        self.addRouterAndHost(topology, connectAtSwitch)

    def addRouterAndHost(self, topology, connectAtSwitch):
        intfNumber = 1
        # Set up router
        nativeAddresses = self.vlanAddresses.pop(None, [])
        peeringIntf = [{'mac' : '00:00:00:00:%02x:%02x' % (self.num, intfNumber),
                       'ipAddrs' : nativeAddresses}]
        
        for vlan, addresses in self.vlanAddresses.items():
            peeringIntf.append({'vlan':vlan,
                                'mac':'00:00:00:%02x:%02x:%02x' % (self.num, vlan, intfNumber),
                                'ipAddrs':addresses})
        
        internalAddresses=[]
        for route in self.routes:
            internalAddresses.append('%s/%s' % (self.getLastAddress(route), route.prefixlen))

        internalIntf = {'ipAddrs' : internalAddresses}

        routerName = 'r%i' % self.num
        hostName = 'h%i' % self.num

        intfs = {'%s-eth0' % routerName : peeringIntf,
                 '%s-eth1' % routerName : internalIntf}

        router = topology.addHost(routerName,  
                                  asNum=self.asNum, neighbors=self.neighbors,
                                  routes=self.routes,
                                  cls=BgpRouter, intfDict=intfs)

        defaultRoute = internalAddresses[0].split('/')[0]

        host = topology.addHost(hostName, cls=SdnipHost,
                                ips=[self.getFirstAddress(route) for route in self.routes],
                                gateway=defaultRoute)

        topology.addLink(connectAtSwitch, router)
        topology.addLink(router, host)

    def getLastAddress(self, network):
        return ip_address(network.network_address + network.num_addresses - 2)
    
    def getFirstAddress(self, network):
        return '%s/%s' % (network[1], network.prefixlen)

class RouteServerAutonomousSystem(ExternalAutonomousSystem):

    def __init__(self, routerAddress, *args, **kwargs):
        ExternalAutonomousSystem.__init__(self, *args, **kwargs)

        self.routerAddress = routerAddress

    def addTopoElements(self, topology, connectAtSwitch):

        switch = topology.addSwitch('as%isw' % self.num, cls=L2OVSSwitch)

        self.addRouterAndHost(topology, self.routerAddress, switch)

        rsName = 'rs%i' % self.num
        routeServer = topology.addHost(rsName,
                                       self.asnum, self.neighbors,
                                       cls=BgpRouter,
                                       intfDict={'%s-eth0' % rsName : {'ipAddrs':[self.peeringAddress]}})

        topology.addLink(routeServer, switch)
        topology.addLink(switch, connectAtSwitch)
        
class SdnAutonomousSystem(AutonomousSystem):
    def __init__(self, onosIps, numBgpSpeakers=1, asNum=65000, peerIntfConfig=None,
                 features=['onos-app-sdnip']):
        super(SdnAutonomousSystem, self).__init__(asNum)
        self.onosIps = onosIps
        self.numBgpSpeakers = numBgpSpeakers
        self.peerIntfConfig = peerIntfConfig
        self.features = features
        
        for onosIp in onosIps:
            self.neighbors.append({'address':onosIp, 'as':asNum, 'port':2000})
        
    def addTopoElements(self, topology, connectAtSwitch, controlSwitch):
        for i in range(1, self.numBgpSpeakers+1):
            name = 'bgp%s' % i
            
            eth0 = { 'ipAddrs' : ['1.1.1.%s/24' % (10+i)] }
            if self.peerIntfConfig is not None:
                eth1 = self.peerIntfConfig
            else:
                nativeAddresses = self.vlanAddresses.pop(None, [])
                eth1 = [{ 'mac':'00:00:00:00:00:%02x' % i, 
                         'ipAddrs' : nativeAddresses }]
                
                for vlan, addresses in self.vlanAddresses.items():
                    eth1.append({'vlan':vlan,
                                'mac':'00:00:00:%02x:%02x:00' % (i, vlan),
                                'ipAddrs':addresses})
            
            
            intfs = { '%s-eth0' % name : eth0,
                      '%s-eth1' % name : eth1 }
            
            # TODO peer with each other
            bgp = topology.addHost( name, cls=BgpRouter, asNum=self.asNum, 
                                    neighbors=self.neighbors,
                                    intfDict=intfs )
            
            topology.addLink( bgp, controlSwitch )
            topology.addLink( bgp, connectAtSwitch )

class RouteSet():
    def __init__(self, subnets):
        self.subnets = subnets

class GeneratedRouteSet(RouteSet):
    def __init__(self, baseRange, numRoutes, subnetSize=None):
        network = ip_network(baseRange)
        super(GeneratedRouteSet, self).__init__(list(network.subnets(new_prefix=subnetSize)))
        
def generateRoutes(baseRange, numRoutes, subnetSize=None):
    baseNetwork = ip_network(baseRange)
    
    # We need to get at least 2 addresses out of each subnet, so the biggest
    # prefix length we can have is /30
    maxPrefixLength = baseNetwork.max_prefixlen - 2
    
    if subnetSize is not None:
        return list(baseNetwork.subnets(new_prefix=subnetSize))
    
    trySubnetSize = baseNetwork.prefixlen + 1
    while trySubnetSize <= maxPrefixLength and \
            len(list(baseNetwork.subnets(new_prefix=trySubnetSize))) < numRoutes:
        trySubnetSize += 1
        
    if trySubnetSize > maxPrefixLength:
        raise Exception("Can't get enough routes from input parameters")
    
    return list(baseNetwork.subnets(new_prefix=trySubnetSize))[:numRoutes]
    
class ONOSHostCluster(object):
    def __init__(self, controlSubnet='192.168.1.0/24', numInstances=1, basename='ONOS',
                 features=[]):
        self.controlSubnet = controlSubnet
        self.numInstances = numInstances
        self.basename = basename
        self.instances = []
        self.features = features
        
    def create(self, topology):
        cs0 = topology.addSwitch('cs0', cls=L2OVSSwitch)
        
        ctrlIp, ctrlPrefixLen = netParse(self.controlSubnet)
        
        for i in range(1, self.numInstances + 1):
            strCtrlIp = '%s/%i' % (ipStr(ctrlIp + i), ctrlPrefixLen)

            c = topology.addHost('%s%s' % (self.basename, i), cls=ONOS, inNamespace=True,
                              ip=strCtrlIp,
                              features=['onos-app-config', 'onos-app-proxyarp',
                                        'onos-core'] + self.features,
                              reactive=False)
            
            topology.addLink(c, cs0, params1={ 'ip' : strCtrlIp })
            
            self.instances.append(c)
            
        # Connect switch to root namespace so that data network
        # switches will be able to talk to us
        highestIp = '%s/%i' % (ipStr(ctrlIp + (2 ** (32 - ctrlPrefixLen)) - 2), ctrlPrefixLen)
        root = topology.addHost('root', inNamespace=False, ip=highestIp)
        topology.addLink(root, cs0)
        
class ONOSHostSdnipCluster(ONOSHostCluster):
    
    def __init__(self, dataSubnet='10.0.0.0/24', features=['onos-app-sdnip'], **kwargs):
        super(ONOSHostSdnipCluster, self).__init__(features=features, **kwargs)

        self.dataSubnet = dataSubnet
        
    def create(self, topology):
        super(ONOSHostSdnipCluster, self).create(topology)
        
        cs1 = topology.addSwitch('cs1', cls=L2OVSSwitch)
        
        dataIp, dataPrefixLen = netParse(self.dataSubnet)
        for i in range(1, len(self.instances) + 1):
            c = self.instances[i-1]
            strDataIp = '%s/%i' % (ipStr(dataIp + i), dataPrefixLen)
            topology.addLink(c, cs1, params1={ 'ip' : strDataIp })
            
        return cs1
    

class ONOSCluster(Controller):

    def __init__(self, hosts, **kwargs):
        Controller.__init__(self, 'cluster')

        self.hosts = hosts

    def start(self):
        self.ctrls = []
        for host in self.hosts:
            if isinstance(host, Controller):
                self.ctrls.append(host)
                host.start()

    def stop(self):
        for host in self.hosts:
            if isinstance(host, Controller):
                host.stop()

    def clist(self):
        "Return list of Controller proxies for this ONOS cluster"
        print 'controllers:', self.ctrls
        return self.ctrls

class OVSSwitchONOS(OVSSwitch):
    "OVS switch which connects to multiple controllers"
    def start(self, controllers):
        assert len(controllers) == 1
        c0 = controllers[ 0 ]
        assert type(c0) == ONOSCluster
        controllers = c0.clist()
        OVSSwitch.start(self, controllers)

class TestTopo(Topo):

    def __init__(self, **kwargs):
        Topo.__init__(self, **kwargs)

        s1 = self.addSwitch('s1')

        q1 = self.addHost('q1')
        h1 = self.addHost('h1')
        self.addLink(h1, q1)
        self.addLink(q1, s1)

        q2 = self.addHost('q2')
        h2 = self.addHost('h2')
        self.addLink(h2, q2)
        self.addLink(q2, s1)

        # Control network
        cluster = ONOSHostCluster(controlSubnet='192.168.50.0/24',
                        numInstances=2)
        cluster.create(self)

if __name__ == '__main__':
    info("Testing SDN-IP libraries\n")
    topo = TestTopo()
    net = Mininet(topo=topo, controller=None, switch=OVSSwitchONOS)
    net.addController(ONOSCluster(net.hosts))

    net.start()

    CLI(net)

    net.stop();
