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
	klog.Infof("AddService for a service %s/%s", svc.Namespace, svc.Name)
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
		p.addService(svcPortName, servicePort, svc, baseSvcInfo)
	}
}

func (p *proxy) addService(svcPortName ServicePortName, servicePort *v1.ServicePort, svc *v1.Service, baseSvcInfo *BaseServiceInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	klog.Infof("addService for a service port name: %s protocol: %s address: %s port: %d",
		svcPortName.String(), baseSvcInfo.Protocol(), baseSvcInfo.ClusterIP(), baseSvcInfo.Port())
	_, ok := p.serviceMap[svcPortName]
	if ok {
		klog.Warningf("Service port name %+v already exists", svcPortName)
		return
	}
	// TODO, Consider moving it to newBaseServiceInfo
	tableFamily := utilnftables.TableFamilyIPv4
	if utilnet.IsIPv6String(svc.Spec.ClusterIP) {
		tableFamily = utilnftables.TableFamilyIPv6
	}
	cn := servicePortSvcChainName(svcPortName.String(), string(servicePort.Protocol), baseSvcInfo.String())
	baseSvcInfo.svcnft.Interface = p.nfti
	baseSvcInfo.svcnft.Chains = nftables.GetSvcChain(tableFamily, cn)

	// If svcPortName does not have entry in the map, it ill return nil and len of nil would be 0
	eps := p.endpointsMap[svcPortName]
	l := len(eps)
	if l != 0 {
		baseSvcInfo.svcnft.WithEndpoints = true
	}
	p.serviceMap[svcPortName] = newServiceInfo(servicePort, svc, baseSvcInfo)

	if l == 0 {
		klog.Infof("Service: %s address: %s port: %d does not have endpoints, programming to drop incoming traffic",
			svcPortName.String(), svc.Spec.ClusterIP, uint16(servicePort.Port))
		if err := nftables.AddToNoEndpointsList(p.nfti, tableFamily, svc.Spec.ClusterIP, uint16(servicePort.Port)); err != nil {
			klog.Errorf("failed to add %s to No Endpoints Set with error: %+v", svcPortName.String(), err)
		}
	} else {
		klog.Infof("service port name: %s has already %d endpoints", svcPortName.String(), l)
	}
	// Programming Service's chains
}

func (p *proxy) DeleteService(svc *v1.Service) {
	klog.Infof("DeleteService for a service %s/%s", svc.Namespace, svc.Name)
	if svc == nil {
		return
	}
	svcName := types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}
	for i := range svc.Spec.Ports {
		servicePort := &svc.Spec.Ports[i]
		svcPortName := ServicePortName{NamespacedName: svcName, Port: servicePort.Name, Protocol: servicePort.Protocol}
		baseSvcInfo := newBaseServiceInfo(servicePort, svc)
		p.deleteService(svcPortName, servicePort, svc, baseSvcInfo)
	}
}

func (p *proxy) deleteService(svcPortName ServicePortName, servicePort *v1.ServicePort, svc *v1.Service, baseSvcInfo *BaseServiceInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	klog.Infof("deleteService for a service port name: %s protocol: %s address: %s port: %d",
		svcPortName.String(), baseSvcInfo.Protocol(), baseSvcInfo.ClusterIP(), baseSvcInfo.Port())
	_, ok := p.serviceMap[svcPortName]
	if !ok {
		klog.Warningf("Service port name %+v does not exist", svcPortName)
		return
	}
	// TODO removing Service's chains and then remove svcPortName from map
	delete(p.serviceMap, svcPortName)
}

func (p *proxy) UpdateService(svcOld, svcNew *v1.Service) {

}

func (p *proxy) AddEndpoints(ep *v1.Endpoints) {
	klog.Infof("Add endpoint: %s/%s", ep.Namespace, ep.Name)
	p.UpdateEndpoints(&v1.Endpoints{Subsets: []v1.EndpointSubset{}}, ep)
}

func (p *proxy) addEndpoint(svcPortName ServicePortName, addr *v1.EndpointAddress, port *v1.EndpointPort) {
	isLocal := addr.NodeName != nil && *addr.NodeName == p.hostname
	ipFamily, ipTableFamily := getIPFamily(addr.IP)
	baseEndpointInfo := newBaseEndpointInfo(ipFamily, port.Protocol, addr.IP, int(port.Port), isLocal, nil)
	// Adding to endpoint base information, structures to carry nftables related info
	baseEndpointInfo.epnft = &nftables.EPnft{
		Interface: p.nfti,
		Rule:      make(map[utilnftables.TableFamily]nftables.Rule),
	}
	cn := servicePortEndpointChainName(svcPortName.String(), string(port.Protocol), baseEndpointInfo.Endpoint)
	// Initializing ip table family depending on endpoint's family ipv4 or ipv6
	epRule := nftables.Rule{
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
	go p.addEndpointRule(&epRule, ipTableFamily, cn, svcPortName, &epKey{port.Protocol, addr.IP, port.Port})
}

func (p *proxy) addEndpointRule(epRule *nftables.Rule, tableFamily utilnftables.TableFamily, cn string, svcPortName ServicePortName, key *epKey) {
	klog.Infof("nfproxy: addEndpointRule attempt to program rules for %+v", *key)
	p.epProgMapLock.Lock()
	stopCh := p.epProgMap[*key]
	p.epProgMapLock.Unlock()
	retrier := time.NewTicker(nfRuleRetryInterval)
	var ruleIDs []uint64
	var err error
	for {
		ruleIDs, err = nftables.AddEndpointRules(p.nfti, tableFamily, cn, key.ipaddr, key.proto, key.port)
		if err == nil {
			break
		}
		klog.Infof("key: %+v nftables.AddEndpointRules returned error: %+v", *key, err)
		select {
		case <-stopCh:
			retrier.Stop()
			return
		case <-retrier.C:
		}
	}
	// Programming nftables rule has succeeded, updating RuleID and removing entry from epProgMap
	p.epProgMapLock.Lock()
	delete(p.epProgMap, *key)
	p.epProgMapLock.Unlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	epRule.RuleID = ruleIDs

	// Endpoint rule has been programmed successfully, now it is safe to update Service object
	svc, ok := p.serviceMap[svcPortName]
	if ok {
		bsvc := svc.(*serviceInfo).BaseServiceInfo
		if !bsvc.svcnft.WithEndpoints {
			klog.Infof("Found a service %s without endpoints, removing it from no-endpoints-set", svcPortName.String())
			// Service did not have any endpoints until now
			klog.Infof("Attempting to remove %s:%d from \"No Endpoints Set\"", svc.ClusterIP().String(), svc.Port())
			if err := nftables.RemoveFromNoEndpointsList(p.nfti, tableFamily, svc.ClusterIP().String(), uint16(svc.Port())); err != nil {
				klog.Errorf("failed to remove %s from \"No Endpoints Set\" with error: %+v", svcPortName.String(), err)
				return
			}
			bsvc.svcnft.WithEndpoints = true
		}
	}
	klog.Infof("nfproxy: addEndpointRule suceeded for %+v", *key)
}

func (p *proxy) DeleteEndpoints(ep *v1.Endpoints) {
	klog.Infof("Delete endpoint: %s/%s", ep.Namespace, ep.Name)
	p.UpdateEndpoints(ep, &v1.Endpoints{Subsets: []v1.EndpointSubset{}})
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
	//	klog.Infof("nfproxy: deleteEndpointRules suceeded for %+v", epKey{proto, ipaddr, port})
}

func (p *proxy) UpdateEndpoints(epOld, epNew *v1.Endpoints) {
	// klog.Infof("Updte endpoint: %s/%s", epNew.Namespace, epNew.Name)
	if !reflect.DeepEqual(epOld.Subsets, epNew.Subsets) {
		klog.Info("Old and New Endpoint have different Subsets")
		// First check if any new endpoint rules needs to be added
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
				// If key does not exist, then nothing to delete, going to the next entry
				if !ok {
					continue
				}
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
					if !isPortInSubset(epNew.Subsets, port) {
						p.deleteEndpoint(svcPortName, addr, port, eps)
					}
				}
				// TODO it is common code with DeleteEndpoint, make it a func
				p.mu.Lock()
				if len(p.endpointsMap[svcPortName]) == 0 {
					klog.Infof("no more endpoints found for %s", svcPortName.String())
					// No endpoints for svcPortName key is available, need to add svcPortName to No Endpoint Set
					svc, ok := p.serviceMap[svcPortName]
					if ok {
						klog.Infof("Attempting to add %s to No Endpoints Set", svcPortName.String())
						_, tableFamily := getIPFamily(svc.ClusterIP().String())
						if err := nftables.AddToNoEndpointsList(p.nfti, tableFamily, svc.ClusterIP().String(), uint16(svc.Port())); err != nil {
							klog.Errorf("failed to add %s to No Endpoints Set with error: %+v", svcPortName.String(), err)
						} else {
							klog.Errorf("succeeded to add %s to No Endpoints Set", svcPortName.String())
							// Set service flag that there is no endpoints
							bsvc := svc.(*serviceInfo)
							bsvc.svcnft.WithEndpoints = false
						}
					}
					delete(p.endpointsMap, svcPortName)
				}
				p.mu.Unlock()
			}
		}
	}
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
