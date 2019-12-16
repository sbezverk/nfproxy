package proxy

import (
	"reflect"
	"sync"
	"time"

	utilnftables "github.com/google/nftables"
	"github.com/sbezverk/nfproxy/pkg/nftables"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"
	utilproxy "k8s.io/kubernetes/pkg/proxy/util"
	utilnet "k8s.io/utils/net"
)

var (
	nfRuleRetryInterval = time.Second * 30
)

// Proxy defines interface
type Proxy interface {
	AddService(svc *v1.Service)
	DeleteService(svc *v1.Service)
	UpdateService(svcOld, svcNew *v1.Service)
	AddEndpoints(ep *v1.Endpoints)
	DeleteEndpoints(ep *v1.Endpoints)
	UpdateEndpoints(epOld, epNew *v1.Endpoints)
}

type proxy struct {
	hostname      string
	nfti          *nftables.NFTInterface
	mu            sync.Mutex // protects the following fields
	serviceMap    ServiceMap
	endpointsMap  EndpointsMap
	portsMap      map[utilproxy.LocalPort]utilproxy.Closeable
	epProgMapLock sync.Mutex
	epProgMap     map[epKey]chan struct{}
}

type epKey struct {
	proto  v1.Protocol
	ipaddr string
	port   int32
}

// NewProxy return a new instance of nfproxy
func NewProxy(nfti *nftables.NFTInterface, hostname string, recorder record.EventRecorder) Proxy {
	return &proxy{
		hostname:     hostname,
		nfti:         nfti,
		portsMap:     make(map[utilproxy.LocalPort]utilproxy.Closeable),
		serviceMap:   make(ServiceMap),
		endpointsMap: make(EndpointsMap),
		epProgMap:    make(map[epKey]chan struct{}),
	}
}

func (p *proxy) AddService(svc *v1.Service) {
	if svc == nil {
		return
	}
	svcName := types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}
	if utilproxy.ShouldSkipService(svcName, svc) {
		return
	}
	for i := range svc.Spec.Ports {
		servicePort := &svc.Spec.Ports[i]
		svcPortName := ServicePortName{NamespacedName: svcName, Port: servicePort.Name, Protocol: servicePort.Protocol}
		baseSvcInfo := newBaseServiceInfo(servicePort, svc)
		p.mu.Lock()
		p.serviceMap[svcPortName] = newServiceInfo(servicePort, svc, baseSvcInfo)
		p.mu.Unlock()
	}
}

func (p *proxy) DeleteService(svc *v1.Service) {

}
func (p *proxy) UpdateService(svcOld, svcNew *v1.Service) {

}

func (p *proxy) AddEndpoints(ep *v1.Endpoints) {
	klog.Infof("Add endpoint: %s/%s subset: %+v", ep.Namespace, ep.Name, ep.Subsets)
	for i := range ep.Subsets {
		ss := &ep.Subsets[i]
		for i := range ss.Ports {
			port := &ss.Ports[i]
			if port.Port == 0 {
				klog.Warningf("ignoring invalid endpoint port %s", port.Name)
				continue
			}
			svcPortName := ServicePortName{
				NamespacedName: types.NamespacedName{Namespace: ep.Namespace, Name: ep.Name},
				Port:           port.Name,
				Protocol:       port.Protocol,
			}
			for i := range ss.Addresses {
				addr := &ss.Addresses[i]
				if addr.IP == "" {
					klog.Warningf("ignoring invalid endpoint port %s with empty host", port.Name)
					continue
				}
				// Check if combination of Protocol, ip addres and port already exists in endpoint ongoing programming map
				// it should not happen during Add operation and indicate a software issue, warning is logged to alert.
				p.epProgMapLock.Lock()
				epStopCh, ok := p.epProgMap[epKey{port.Protocol, addr.IP, port.Port}]
				p.epProgMapLock.Unlock()
				if ok {
					//					klog.Warningf("nfproxy: Attempting to add already known endpoint for protocol: %s ip address: %s port: %d", port.Protocol, addr.IP, port.Port)
					// Shutting down EP programmer go routine for port.Protocol, addr.IP, port.Port
					epStopCh <- struct{}{}
					// Deleting entry from epProgMap
					p.epProgMapLock.Lock()
					delete(p.epProgMap, epKey{port.Protocol, addr.IP, port.Port})
					p.epProgMapLock.Unlock()
				}
				p.addEndpoint(svcPortName, addr, port)
			}
		}
	}
}

func (p *proxy) addEndpoint(svcPortName ServicePortName, addr *v1.EndpointAddress, port *v1.EndpointPort) {
	isLocal := addr.NodeName != nil && *addr.NodeName == p.hostname
	ipFamily, ipTableFamily := getIPFamily(addr.IP)
	baseEndpointInfo := newBaseEndpointInfo(ipFamily, port.Protocol, addr.IP, int(port.Port), isLocal, nil)
	// Adding to endpoint base information, structures to carry nftables related info
	baseEndpointInfo.epnft = &nftables.EPnft{
		Interface: p.nfti,
		Rule:      make(map[utilnftables.TableFamily]nftables.EPRule),
	}
	cn := servicePortEndpointChainName(svcPortName.String(), string(port.Protocol), baseEndpointInfo.Endpoint)
	// Initializing ip table family depending on endpoint's family ipv4 or ipv6
	epRule := nftables.EPRule{
		Chain: cn,
		// RuleID 0 is indicator that the nftables rule has not been yet programmed, once it is programed
		// RuleID will be updated to real value.
		RuleID: nil,
	}
	baseEndpointInfo.epnft.Rule[ipTableFamily] = epRule
	p.mu.Lock()
	p.endpointsMap[svcPortName] = append(p.endpointsMap[svcPortName], newEndpointInfo(baseEndpointInfo, port.Protocol))
	p.mu.Unlock()
	// Starting go routine which will attempt to program nftables rules, on success it will update RuleID,
	// remove entry from epProgMap for key port.Protocol, addr.IP, port.Port and exit
	p.epProgMapLock.Lock()
	p.epProgMap[epKey{port.Protocol, addr.IP, port.Port}] = make(chan struct{})
	p.epProgMapLock.Unlock()
	go p.addEndpointRule(&epRule, ipTableFamily, cn, addr.IP, port.Protocol, port.Port)
}

func getIPFamily(ipaddr string) (v1.IPFamily, utilnftables.TableFamily) {
	var ipFamily v1.IPFamily
	var ipTableFamily utilnftables.TableFamily
	if utilnet.IsIPv6String(ipaddr) {
		ipFamily = v1.IPv6Protocol
		ipTableFamily = utilnftables.TableFamilyIPv6
	} else {
		ipFamily = v1.IPv4Protocol
		ipTableFamily = utilnftables.TableFamilyIPv4
	}
	return ipFamily, ipTableFamily
}

func (p *proxy) addEndpointRule(epRule *nftables.EPRule, ipTableFamily utilnftables.TableFamily, cn string, ipaddr string, proto v1.Protocol, port int32) {
	klog.Infof("nfproxy: addEndpointRule attempt to program rules for %+v", epKey{proto, ipaddr, port})
	p.epProgMapLock.Lock()
	stopCh := p.epProgMap[epKey{proto, ipaddr, port}]
	p.epProgMapLock.Unlock()
	retrier := time.NewTicker(nfRuleRetryInterval)
	var ruleIDs []uint64
	var err error
	for {
		ruleIDs, err = nftables.AddEndpointRules(p.nfti, ipTableFamily, cn, ipaddr, proto, port)
		if err == nil {
			break
		}
		select {
		case <-stopCh:
			retrier.Stop()
			return
		case <-retrier.C:
		}
	}
	// Programming nftables rule has succeeded, updating RuleID and removing entry from epProgMap
	p.mu.Lock()
	epRule.RuleID = ruleIDs
	p.mu.Unlock()
	p.epProgMapLock.Lock()
	delete(p.epProgMap, epKey{proto, ipaddr, port})
	p.epProgMapLock.Unlock()
	klog.Infof("nfproxy: addEndpointRule suceeded for %+v", epKey{proto, ipaddr, port})
}

func (p *proxy) DeleteEndpoints(ep *v1.Endpoints) {
	klog.Infof("Delete endpoint: %s/%s subset: %+v", ep.Namespace, ep.Name, ep.Subsets)
	for i := range ep.Subsets {
		ss := &ep.Subsets[i]
		for i := range ss.Ports {
			port := &ss.Ports[i]
			if port.Port == 0 {
				klog.Warningf("ignoring invalid endpoint port %s", port.Name)
				continue
			}
			svcPortName := ServicePortName{
				NamespacedName: types.NamespacedName{Namespace: ep.Namespace, Name: ep.Name},
				Port:           port.Name,
				Protocol:       port.Protocol,
			}
			p.mu.Lock()
			eps, ok := p.endpointsMap[svcPortName]
			p.mu.Unlock()
			if !ok {
				// endpointsMap does not carry information for svcPortName, it means the event of adding endpoint was missed
				// log warning message and move on as nothing else left to do.
				klog.Warningf("nfproxy: Attempting to delete unknown to nfproxy service port name: %s", svcPortName.String())
				continue
			}
			//			klog.Infof("Exisiting endpoints: %+v Number of exisiting endpoint: %d", eps, len(eps))
			for i := range ss.Addresses {
				addr := &ss.Addresses[i]
				if addr.IP == "" {
					klog.Warningf("ignoring invalid endpoint port %s with empty host", port.Name)
					continue
				}
				// Check if combination of Protocol, ip addres and port already exists in endpoint ongoing programming map
				// if exists, it indicates that endpoint still has not succeeded to have nftables rule to be programmed. In this case
				// go routing should be stopped and epProgMap cleaned up from port.Protocol, addr.IP, port.Port key
				if epStopCh, ok := p.epProgMap[epKey{port.Protocol, addr.IP, port.Port}]; ok {
					// Shutting down EP programmer go routine for port.Protocol, addr.IP, port.Port
					epStopCh <- struct{}{}
					// Deleting entry from epProgMap
					p.epProgMapLock.Lock()
					delete(p.epProgMap, epKey{port.Protocol, addr.IP, port.Port})
					p.epProgMapLock.Unlock()
					continue
				}
				p.deleteEndpoint(svcPortName, addr, port, eps)
			}
			//			klog.V(3).Infof("Deleting endpoints for %q to %+v", svcPortName, formatEndpointsList(p.endpointsMap[svcPortName]))
			if len(p.endpointsMap[svcPortName]) == 0 {
				//				klog.Infof("number of endpoints for key: %+v is 0, removing entry from p.endpointsMap", svcPortName)
				p.mu.Lock()
				delete(p.endpointsMap, svcPortName)
				p.mu.Unlock()
			}
		}
	}
}

func (p *proxy) deleteEndpoint(svcPortName ServicePortName, addr *v1.EndpointAddress, port *v1.EndpointPort, eps []Endpoint) {
	isLocal := addr.NodeName != nil && *addr.NodeName == p.hostname
	ipFamily, ipTableFamily := getIPFamily(addr.IP)
	ep2d := newBaseEndpointInfo(ipFamily, port.Protocol, addr.IP, int(port.Port), isLocal, nil)
	//				klog.Infof("To delete endpoint: %s", ep2d.Endpoint)
	for i, ep := range eps {
		ep2c, ok := ep.(*endpointsInfo)
		if !ok {
			// Not recognize, skipping it
			continue
		}
		//					klog.Infof("Existing endpoint: %s", ep2c.BaseEndpointInfo.Endpoint)
		if ep2c.Equal(ep2d) {
			//						klog.Infof("Found match to delete: %s existing: %s", ep2d.Endpoint, ep2c.BaseEndpointInfo.Endpoint)
			cn := ep2c.BaseEndpointInfo.epnft.Rule[ipTableFamily].Chain
			ruleID := ep2c.BaseEndpointInfo.epnft.Rule[ipTableFamily].RuleID
			// Update eps by removing endpoint entry for port.Protocol, addr.IP, port.Port
			p.mu.Lock()
			p.endpointsMap[svcPortName] = eps[:i]
			p.endpointsMap[svcPortName] = append(p.endpointsMap[svcPortName], eps[i+1:]...)
			p.mu.Unlock()
			// Starting go routine which will attempt to delete nftables rules, on success it will
			// remove entry from epProgMap for key port.Protocol, addr.IP, port.Port and exit
			p.epProgMapLock.Lock()
			p.epProgMap[epKey{port.Protocol, addr.IP, port.Port}] = make(chan struct{})
			p.epProgMapLock.Unlock()
			go p.deleteEndpointRules(ipTableFamily, cn, ruleID, addr.IP, port.Protocol, port.Port)
		}
	}
}

func (p *proxy) deleteEndpointRules(ipTableFamily utilnftables.TableFamily, cn string, ruleID []uint64, ipaddr string, proto v1.Protocol, port int32) {
	p.epProgMapLock.Lock()
	stopCh := p.epProgMap[epKey{proto, ipaddr, port}]
	p.epProgMapLock.Unlock()
	retrier := time.NewTicker(nfRuleRetryInterval)

	for {
		err := nftables.DeleteEndpointRules(p.nfti, ipTableFamily, cn, ruleID)
		if err == nil {
			break
		}
		klog.Warningf("failed to delete endpoint %+v with error: %+v, retrying in %+v", epKey{proto, ipaddr, port}, err, nfRuleRetryInterval)
		select {
		case <-stopCh:
			retrier.Stop()
			return
		case <-retrier.C:
		}
	}
	// Programming nftables rule has succeeded, updating RuleID and removing entry from epProgMap
	p.epProgMapLock.Lock()
	delete(p.epProgMap, epKey{proto, ipaddr, port})
	p.epProgMapLock.Unlock()
	klog.Infof("nfproxy: deleteEndpointRules suceeded for %+v", epKey{proto, ipaddr, port})
}

func (p *proxy) UpdateEndpoints(epOld, epNew *v1.Endpoints) {
	klog.Infof("Updte endpoint: %s/%s subset: %+v", epNew.Namespace, epNew.Name, epNew.Subsets)
	if !reflect.DeepEqual(epOld.Subsets, epNew.Subsets) {
		klog.Info("Old and New Endpoint have different Subsets")
		for i := range epNew.Subsets {
			ss := &epNew.Subsets[i]
			for i := range ss.Ports {
				port := &ss.Ports[i]
				if port.Port == 0 {
					klog.Warningf("ignoring invalid endpoint port %s", port.Name)
					continue
				}
				svcPortName := ServicePortName{
					NamespacedName: types.NamespacedName{Namespace: epNew.Namespace, Name: epNew.Name},
					Port:           port.Name,
					Protocol:       port.Protocol,
				}
				for i := range ss.Addresses {
					addr := &ss.Addresses[i]
					if addr.IP == "" {
						klog.Warningf("ignoring invalid endpoint port %s with empty host", port.Name)
						continue
					}
					if !isPortInSubset(epOld.Subsets, port) {
						p.addEndpoint(svcPortName, addr, port)
					}
				}
			}
		}
		for i := range epOld.Subsets {
			ss := &epOld.Subsets[i]
			for i := range ss.Ports {
				port := &ss.Ports[i]
				if port.Port == 0 {
					klog.Warningf("ignoring invalid endpoint port %s", port.Name)
					continue
				}
				svcPortName := ServicePortName{
					NamespacedName: types.NamespacedName{Namespace: epOld.Namespace, Name: epOld.Name},
					Port:           port.Name,
					Protocol:       port.Protocol,
				}
				eps, ok := p.endpointsMap[svcPortName]
				if !ok {
					continue
				}
				for i := range ss.Addresses {
					addr := &ss.Addresses[i]
					if addr.IP == "" {
						klog.Warningf("ignoring invalid endpoint port %s with empty host", port.Name)
						continue
					}
					if !isPortInSubset(epNew.Subsets, port) {
						p.deleteEndpoint(svcPortName, addr, port, eps)
					}
				}
			}
		}
	}
}

func isPortInSubset(subsets []v1.EndpointSubset, port *v1.EndpointPort) bool {
	for _, s := range subsets {
		for _, p := range s.Ports {
			if p.Name == port.Name && p.Port == port.Port && p.Protocol == port.Protocol {
				return true
			}
		}
	}
	return false
}
