package proxy

import (
	"fmt"
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
	hostname     string
	nfti         *nftables.NFTInterface
	mu           sync.Mutex // protects the following fields
	serviceMap   ServiceMap
	endpointsMap EndpointsMap
	portsMap     map[utilproxy.LocalPort]utilproxy.Closeable
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
		svcPortName := getSvcPortName(svc.Name, svc.Namespace, servicePort.Name, servicePort.Protocol)
		baseSvcInfo := newBaseServiceInfo(servicePort, svc)
		p.addService(svcPortName, servicePort, svc, baseSvcInfo)
	}
}

func (p *proxy) addService(svcPortName ServicePortName, servicePort *v1.ServicePort, svc *v1.Service, baseSvcInfo *BaseServiceInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	//	klog.Infof("addService for a service port name: %s protocol: %s address: %s port: %d",
	//		svcPortName.String(), baseSvcInfo.Protocol(), baseSvcInfo.ClusterIP(), baseSvcInfo.Port())

	if _, ok := p.serviceMap[svcPortName]; ok {
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
	baseSvcInfo.svcnft.WithEndpoints = false
	// Programming Service's chain
	if err := nftables.AddServiceChain(p.nfti, tableFamily, cn); err != nil {
		klog.Errorf("failed to add service chain %s for service %s with error: %+v", cn, svcPortName.String(), err)
	}
	// Programming Service's cluster ip
	if clip := baseSvcInfo.ClusterIP(); clip != nil {
		klog.Infof("Service: %s cluster ip: %s", svcPortName.String(), clip.String())
		id, err := nftables.ProgramServiceClusterIP(p.nfti, tableFamily, cn, clip.String(), baseSvcInfo.Protocol(), baseSvcInfo.Port())
		if err != nil {
			klog.Errorf("Failed to program Service %s cluster IP rule with error: %+v", svcPortName.String(), err)
		}
		baseSvcInfo.svcnft.Chains[tableFamily].Chain[nftables.K8sNATServices].RuleID = id
	}
	// Programming Service's node port
	if np := baseSvcInfo.NodePort(); np != 0 {
		klog.Infof("Service: %s node port: %d", svcPortName.String(), np)
	}
	// Programming Service's external ips
	if extip := baseSvcInfo.ExternalIPStrings(); len(extip) != 0 {
		klog.Infof("Service: %s external ip: %+v", svcPortName.String(), extip)
		id, err := nftables.ProgramServiceExternalIP(p.nfti, tableFamily, cn, extip, baseSvcInfo.Protocol(), baseSvcInfo.Port())
		if err != nil {
			klog.Errorf("Failed to program Service %s cluster IP rule with error: %+v", svcPortName.String(), err)
		}
		// Appending rules' IDs generated for Service's external IPs
		baseSvcInfo.svcnft.Chains[tableFamily].Chain[nftables.K8sNATServices].RuleID = append(baseSvcInfo.svcnft.Chains[tableFamily].Chain[nftables.K8sNATServices].RuleID, id...)
	}
	// Programming Service's loadbalancer ips
	if lbip := baseSvcInfo.LoadBalancerIPStrings(); len(lbip) != 0 {
		klog.Infof("Service: %s loadbalancer ip: %+v", svcPortName.String(), lbip)
	}
	// If svcPortName does not have entry in the map, it will return nil and len of nil would be 0
	if len(p.endpointsMap[svcPortName]) == 0 {
		//		klog.Infof("service port name: %s does not have endpoints", svcPortName.String())
		if err := nftables.AddToNoEndpointsList(p.nfti, tableFamily, string(servicePort.Protocol), svc.Spec.ClusterIP, uint16(servicePort.Port)); err != nil {
			klog.Errorf("failed to add %s to No Endpoints Set with error: %+v", svcPortName.String(), err)
		}
		// else {
		// klog.Infof("succeeded to add %s to No Endpoints Set", svcPortName.String())
		// }
	}
	// All services chains/rules are ready, safe to add svcPortName th serviceMap
	p.serviceMap[svcPortName] = newServiceInfo(servicePort, svc, baseSvcInfo)
	//	klog.Infof("finished add service processing: %s", svcPortName.String())

	printSvcPortEntry(svcPortName, p.serviceMap)
}

// getServicePortEndpointChains return a slice of strings containing a specific ServicePortName all endpoints chains
func (p *proxy) getServicePortEndpointChains(svcPortName ServicePortName, tableFamily utilnftables.TableFamily) []string {
	chains := []string{}
	for _, ep := range p.endpointsMap[svcPortName] {
		epBase, ok := ep.(*endpointsInfo)
		if !ok {
			// Not recognize, skipping it
			continue
		}
		chains = append(chains, epBase.epnft.Rule[tableFamily].Chain)
	}

	return chains
}

func (p *proxy) DeleteService(svc *v1.Service) {
	klog.Infof("DeleteService for a service %s/%s", svc.Namespace, svc.Name)
	if svc == nil {
		return
	}
	for i := range svc.Spec.Ports {
		servicePort := &svc.Spec.Ports[i]
		svcPortName := getSvcPortName(svc.Name, svc.Namespace, servicePort.Name, servicePort.Protocol)
		p.deleteService(svcPortName, servicePort, svc)
	}
}

func (p *proxy) deleteService(svcPortName ServicePortName, servicePort *v1.ServicePort, svc *v1.Service) {
	p.mu.Lock()
	defer p.mu.Unlock()
	svcInfo, ok := p.serviceMap[svcPortName]
	if !ok {
		klog.Warningf("Service port name %+v does not exist", svcPortName)
		return
	}
	baseInfo, _ := svcInfo.(*serviceInfo)
	klog.Infof("deleteService for a service port name: %s protocol: %s address: %s port: %d",
		svcPortName.String(), string(svcPortName.Protocol), baseInfo.ClusterIP().String(), servicePort.Port)
	_, tableFamily := getIPFamily(baseInfo.ClusterIP().String())

	if !baseInfo.svcnft.WithEndpoints {
		// svcPortName does not have any endpoints, need to remove service entry from "No endpointd Set"
		//	klog.Infof("Attempting to remove %s:%d from \"No Endpoints Set\"", baseInfo.ClusterIP().String(), servicePort.Port)
		if err := nftables.RemoveFromNoEndpointsList(p.nfti, tableFamily, string(svcPortName.Protocol), baseInfo.ClusterIP().String(), uint16(servicePort.Port)); err != nil {
			klog.Errorf("failed to remove %s from \"No Endpoints Set\" with error: %+v", svcPortName.String(), err)
		}
	}
	// Remove svcPortName related chains and rules
	scn := baseInfo.svcnft.Chains[tableFamily].Service
	for chain, rules := range baseInfo.svcnft.Chains[tableFamily].Chain {
		if len(rules.RuleID) != 0 {
			if err := nftables.DeleteServiceRules(p.nfti, tableFamily, chain, rules.RuleID); err != nil {
				klog.Errorf("failed to delete rules chain: %s service port name: %s with error: %+v", chain, svcPortName.String(), err)
			}
		}
	}
	if err := nftables.DeleteChain(p.nfti, tableFamily, scn); err != nil {
		klog.Errorf("failed to delete service chain: %s service port name: %s with error: %+v", scn, svcPortName.String(), err)
	}

	// Delete svcPortName from known svcPortName map
	delete(p.serviceMap, svcPortName)
}

func (p *proxy) UpdateService(svcOld, svcNew *v1.Service) {

}

func (p *proxy) AddEndpoints(ep *v1.Endpoints) {
	klog.Infof("Add endpoint: %s/%s", ep.Namespace, ep.Name)
	p.UpdateEndpoints(&v1.Endpoints{Subsets: []v1.EndpointSubset{}}, ep)
}

func (p *proxy) addEndpoint(svcPortName ServicePortName, addr *v1.EndpointAddress, port *v1.EndpointPort) error {
	isLocal := addr.NodeName != nil && *addr.NodeName == p.hostname
	ipFamily, ipTableFamily := getIPFamily(addr.IP)
	baseEndpointInfo := newBaseEndpointInfo(ipFamily, port.Protocol, addr.IP, int(port.Port), isLocal, nil)
	// Adding to endpoint base information, structures to carry nftables related info
	baseEndpointInfo.epnft = &nftables.EPnft{
		Interface: p.nfti,
		Rule:      make(map[utilnftables.TableFamily]*nftables.Rule),
	}
	cn := servicePortEndpointChainName(svcPortName.String(), string(port.Protocol), baseEndpointInfo.Endpoint)
	// Initializing ip table family depending on endpoint's family ipv4 or ipv6
	epRule := nftables.Rule{
		Chain: cn,
		// RuleID 0 is indicator that the nftables rule has not been yet programmed, once it is programed
		// RuleID will be updated to real value.
		RuleID: nil,
	}
	baseEndpointInfo.epnft.Rule[ipTableFamily] = &epRule
	if err := p.addEndpointRule(&epRule, ipTableFamily, cn, svcPortName, &epKey{port.Protocol, addr.IP, port.Port}); err != nil {
		return err
	}
	//	klog.Infof("nfproxy: addEndpointRule suceeded for %+v", epKey{port.Protocol, addr.IP, port.Port})
	p.mu.Lock()
	defer p.mu.Unlock()
	p.endpointsMap[svcPortName] = append(p.endpointsMap[svcPortName], newEndpointInfo(baseEndpointInfo, port.Protocol))
	if err := p.UpdateServiceChain(svcPortName, ipTableFamily); err != nil {
		klog.Errorf("failed to update service %s chain with endpoint rule with error: %+v", svcPortName.String(), err)
		return err
	}
	return nil
}

func (p *proxy) addEndpointRule(epRule *nftables.Rule, tableFamily utilnftables.TableFamily, cn string, svcPortName ServicePortName, key *epKey) error {
	//	klog.Infof("nfproxy: addEndpointRule attempt to program rules for %+v", *key)
	var ruleIDs []uint64
	var err error

	ruleIDs, err = nftables.AddEndpointRules(p.nfti, tableFamily, cn, key.ipaddr, key.proto, key.port)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	epRule.RuleID = ruleIDs

	return nil
}

// UpdateServiceChain programs rules for a specific ServicePortName, it is called for every endpoint add/delete
// event.
func (p *proxy) UpdateServiceChain(svcPortName ServicePortName, tableFamily utilnftables.TableFamily) error {
	svc, ok := p.serviceMap[svcPortName]
	if ok {
		entry := svc.(*serviceInfo)
		if !entry.svcnft.WithEndpoints {
			// Service did not have any endpoints until now
			if err := nftables.RemoveFromNoEndpointsList(p.nfti, tableFamily, string(svcPortName.Protocol), svc.ClusterIP().String(), uint16(svc.Port())); err != nil {
				klog.Errorf("failed to remove %s from \"No Endpoints Set\" with error: %+v", svcPortName.String(), err)
			} else {
				entry.svcnft.WithEndpoints = true
			}
		}
		// Programming rules for existing endpoints
		epsChains := p.getServicePortEndpointChains(svcPortName, tableFamily)
		cn := entry.svcnft.Chains[tableFamily].Service
		svcRules := entry.svcnft.Chains[tableFamily].Chain[cn]
		// Check if the service still has any backends
		if len(epsChains) != 0 {
			rules, err := nftables.ProgramServiceEndpoints(p.nfti, tableFamily, cn, epsChains, svcRules.RuleID)
			if err != nil {
				klog.Errorf("failed to program endpoints rules for service %s with error: %+v", svcPortName.String(), err)
				return err
			}
			// Storing Service's rule id so it can be used later for modification or deletion.
			// cn carries service's name of chain, a connecion point with endpoints backending the service.
			svcRules.RuleID = rules
		} else {
			// Service has no endpoints left needs to remove the rule if any
			if err := nftables.DeleteServiceRules(p.nfti, tableFamily, cn, svcRules.RuleID); err != nil {
				klog.Errorf("failed to remove rule for service %s with error: %+v", svcPortName.String(), err)
				return err
			}
			svcRules.RuleID = svcRules.RuleID[:0]
		}
	}

	return nil
}

func (p *proxy) DeleteEndpoints(ep *v1.Endpoints) {
	klog.Infof("Delete endpoint: %s/%s", ep.Namespace, ep.Name)
	p.UpdateEndpoints(ep, &v1.Endpoints{Subsets: []v1.EndpointSubset{}})
}

func (p *proxy) deleteEndpoint(svcPortName ServicePortName, addr *v1.EndpointAddress, port *v1.EndpointPort, eps []Endpoint) {
	isLocal := addr.NodeName != nil && *addr.NodeName == p.hostname
	ipFamily, ipTableFamily := getIPFamily(addr.IP)
	ep2d := newBaseEndpointInfo(ipFamily, port.Protocol, addr.IP, int(port.Port), isLocal, nil)
	for i, ep := range eps {
		ep2c, ok := ep.(*endpointsInfo)
		if !ok {
			// Not recognize, skipping it
			continue
		}
		if ep2c.Equal(ep2d) {
			// Update eps by removing endpoint entry for port.Protocol, addr.IP, port.Port
			p.mu.Lock()
			p.endpointsMap[svcPortName] = eps[:i]
			p.endpointsMap[svcPortName] = append(p.endpointsMap[svcPortName], eps[i+1:]...)
			p.mu.Unlock()
			cn := ep2c.BaseEndpointInfo.epnft.Rule[ipTableFamily].Chain
			ruleID := ep2c.BaseEndpointInfo.epnft.Rule[ipTableFamily].RuleID
			if err := p.deleteEndpointRules(ipTableFamily, cn, ruleID, svcPortName, &epKey{port.Protocol, addr.IP, port.Port}); err != nil {
				return
			}
		}
	}
}

func (p *proxy) deleteEndpointRules(ipTableFamily utilnftables.TableFamily, cn string, ruleID []uint64, svcPortName ServicePortName, key *epKey) error {
	// klog.Infof("nfproxy: deleteEndpointRulese attempt to delete rules for endpoint chain: %s", cn)
	// Right away update the service's rule to exclude deleted endpoint
	if err := p.UpdateServiceChain(svcPortName, ipTableFamily); err != nil {
		klog.Infof("failed to update service %s chain with endpoint rule with error: %+v", svcPortName.String(), err)
		return err
	}
	if err := nftables.DeleteEndpointRules(p.nfti, ipTableFamily, cn, ruleID); err != nil {
		return err
	}
	// Deleting endpoint's chain
	if err := nftables.DeleteChain(p.nfti, ipTableFamily, cn); err != nil {
		klog.Errorf("failed to delete endpoint chain: %s with error: %+v", cn, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// Check if it was last endpoint for a service port name
	if len(p.endpointsMap[svcPortName]) == 0 {
		klog.Infof("no more endpoints found for %s", svcPortName.String())
		// No endpoints for svcPortName key is available, need to add svcPortName to No Endpoint Set
		svc, ok := p.serviceMap[svcPortName]
		if ok {
			// klog.Infof("Attempting to add %s to No Endpoints Set", svcPortName.String())
			_, tableFamily := getIPFamily(svc.ClusterIP().String())
			if err := nftables.AddToNoEndpointsList(p.nfti, tableFamily, string(svcPortName.Protocol), svc.ClusterIP().String(), uint16(svc.Port())); err != nil {
				klog.Errorf("failed to add %s to No Endpoints Set with error: %+v", svcPortName.String(), err)
			} else {
				// klog.Infof("succeeded to add %s to No Endpoints Set", svcPortName.String())
				// Set service flag that there is no endpoints
				bsvc := svc.(*serviceInfo)
				bsvc.svcnft.WithEndpoints = false
			}
		}
		delete(p.endpointsMap, svcPortName)
	}
	return nil
}

func (p *proxy) UpdateEndpoints(epOld, epNew *v1.Endpoints) {
	if epNew.Namespace == "" && epNew.Name == "" {
		// When service gets deleted the endpoint controller triggers an update for an endpoint with no name or namespace
		// ignoring it
		return
	}
	klog.Infof("Update endpoint: %s/%s", epNew.Namespace, epNew.Name)
	if !reflect.DeepEqual(epOld.Subsets, epNew.Subsets) {
		// First check if any new endpoint rules needs to be added
		for i := range epNew.Subsets {
			ss := &epNew.Subsets[i]
			for i := range ss.Ports {
				port := &ss.Ports[i]
				if port.Port == 0 {
					klog.Warningf("ignoring invalid endpoint port %s", port.Name)
					continue
				}
				svcPortName := getSvcPortName(epNew.Name, epNew.Namespace, port.Name, port.Protocol)
				for i := range ss.Addresses {
					addr := &ss.Addresses[i]
					if addr.IP == "" {
						klog.Warningf("ignoring invalid endpoint port %s with empty host", port.Name)
						continue
					}
					if !isPortInSubset(epOld.Subsets, port) {
						if err := p.addEndpoint(svcPortName, addr, port); err != nil {
							klog.Errorf("Update endpoint: %s/%s failed with error: %+v", epNew.Namespace, epNew.Name, err)
						}
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
				svcPortName := getSvcPortName(epOld.Name, epOld.Namespace, port.Name, port.Protocol)
				// TODO review possible racing scenarios
				p.mu.Lock()
				eps, ok := p.endpointsMap[svcPortName]
				p.mu.Unlock()
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
					if !isPortInSubset(epNew.Subsets, port) {
						p.deleteEndpoint(svcPortName, addr, port, eps)
					}
				}
			}
		}
	}
	//	klog.Infof("Finished processing update endpoint: %s/%s", epNew.Namespace, epNew.Name)
}

func getSvcPortName(name, namespace string, portName string, protocol v1.Protocol) ServicePortName {
	return ServicePortName{
		NamespacedName: types.NamespacedName{Namespace: namespace, Name: name},
		Port:           portName,
		Protocol:       protocol,
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

func printSvcPortEntry(svcPortName ServicePortName, svc ServiceMap) {
	se, ok := svc[svcPortName]
	if !ok {
		return
	}
	entry := se.(*serviceInfo)
	fmt.Printf("Service port name: %s with endpoints: %t service chain name: %s\n", svcPortName.String(), entry.svcnft.WithEndpoints, entry.serviceNameString)
	for tf, svcchains := range entry.svcnft.Chains {
		fmt.Printf("Service table family: %+v service name: %s\n", tf, svcchains.Service)
		for cn, rules := range svcchains.Chain {
			fmt.Printf("Chain name: %s rules: %+v\n", cn, rules.RuleID)
		}
	}
}
