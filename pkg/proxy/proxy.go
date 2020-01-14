/*
Copyright 2020 The nfproxy Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package proxy

import (
	"reflect"
	"strconv"
	"sync"

	utilnftables "github.com/google/nftables"
	"github.com/sbezverk/nfproxy/pkg/nftables"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"
	utilproxy "k8s.io/kubernetes/pkg/proxy/util"
	utilnet "k8s.io/utils/net"
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
	cache        cache
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
		serviceMap:   make(ServiceMap),
		endpointsMap: make(EndpointsMap),
		cache: cache{
			svcCache: make(map[types.NamespacedName]*v1.Service),
			epCache:  make(map[types.NamespacedName]*v1.Endpoints),
		},
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
		p.addServicePort(svcPortName, servicePort, svc, baseSvcInfo)
	}
	// Storing new service in the cache for later reference
	p.cache.storeSvcInCache(svc)
}

func (p *proxy) addServicePort(svcPortName ServicePortName, servicePort *v1.ServicePort, svc *v1.Service, baseSvcInfo *BaseServiceInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.serviceMap[svcPortName]; ok {
		klog.Warningf("Service port name %+v already exists", svcPortName)
		return
	}
	// TODO, Consider moving it to newBaseServiceInfo
	tableFamily := utilnftables.TableFamilyIPv4
	if utilnet.IsIPv6String(svc.Spec.ClusterIP) {
		tableFamily = utilnftables.TableFamilyIPv6
	}
	svcID := servicePortSvcID(svcPortName.String(), string(servicePort.Protocol), baseSvcInfo.String())
	baseSvcInfo.svcnft.Interface = p.nfti
	baseSvcInfo.svcnft.Chains = nftables.GetSvcChain(tableFamily, svcID)
	baseSvcInfo.svcnft.WithEndpoints = false
	// Creating a set of chains (k8s-nfproxy-svc-{svcID},k8s-nfproxy-fw-{svcID}, k8s-nfproxy-xlb-{svcID}) for a service port
	if err := nftables.AddServiceChains(p.nfti, tableFamily, svcID); err != nil {
		klog.Errorf("failed to add service port %s chains with error: %+v", svcPortName.String(), err)
		return
	}
	// Populting cluster, external and loadbalancer sets with Service Port information
	if err := p.addServicePortToSets(baseSvcInfo, tableFamily, svcID); err != nil {
		klog.Errorf("failed to add service port %s to sets with error: %+v", svcPortName.String(), err)
		return
	}
	// If svcPortName does not exist in the map, it will return nil and len of nil would be 0
	if len(p.endpointsMap[svcPortName]) == 0 {
		if err := p.addToNoEndpointsList(baseSvcInfo, tableFamily); err != nil {
			klog.Errorf("failed to add %s to No Endpoints Set with error: %+v", svcPortName.String(), err)
			return
		}
	}
	// All services chains/rules are ready, safe to add svcPortName th serviceMap
	p.serviceMap[svcPortName] = newServiceInfo(servicePort, svc, baseSvcInfo)
}

func (p *proxy) DeleteService(svc *v1.Service) {
	klog.Infof("DeleteService for a service %s/%s", svc.Namespace, svc.Name)
	if svc == nil {
		return
	}
	for i := range svc.Spec.Ports {
		servicePort := &svc.Spec.Ports[i]
		svcPortName := getSvcPortName(svc.Name, svc.Namespace, servicePort.Name, servicePort.Protocol)
		p.deleteServicePort(svcPortName, servicePort, svc)
	}
	// removing deleted service from cache
	p.cache.removeSvcFromCache(svc.Name, svc.Namespace)
}

func (p *proxy) deleteServicePort(svcPortName ServicePortName, servicePort *v1.ServicePort, svc *v1.Service) {
	p.mu.Lock()
	defer p.mu.Unlock()
	svcInfo, ok := p.serviceMap[svcPortName]
	if !ok {
		klog.Warningf("Service port name %+v does not exist", svcPortName)
		return
	}
	baseInfo, _ := svcInfo.(*serviceInfo)
	_, tableFamily := getIPFamily(baseInfo.ClusterIP().String())

	if !baseInfo.svcnft.WithEndpoints {
		// svcPortName does not have any endpoints, need to remove service entry from "No endpointd Set"
		if err := p.removeFromNoEndpointsList(baseInfo, tableFamily); err != nil {
			klog.Errorf("failed to remove %s from \"No Endpoints Set\" with error: %+v", svcPortName.String(), err)
		}
	}
	// Remove svcPortName related chains and rules
	// Populting cluster, external and loadbalancer sets with Service Port information
	if err := p.removeServicePortFromSets(baseInfo, tableFamily, baseInfo.svcnft.Chains[tableFamily].ServiceID); err != nil {
		klog.Errorf("failed to remove service port %s to sets with error: %+v", svcPortName.String(), err)
	}
	// Remove svcPortName related chains and rules
	for chain, rules := range baseInfo.svcnft.Chains[tableFamily].Chain {
		if len(rules.RuleID) != 0 {
			if err := nftables.DeleteServiceRules(p.nfti, tableFamily, chain, rules.RuleID); err != nil {
				klog.Errorf("failed to delete rules chain: %s service port name: %s with error: %+v", chain, svcPortName.String(), err)
			}
		}
	}
	// Removing service port specific chains
	if err := nftables.DeleteServiceChains(p.nfti, tableFamily, baseInfo.svcnft.Chains[tableFamily].ServiceID); err != nil {
		klog.Errorf("failed to delete chains for service port name: %s with error: %+v", svcPortName.String(), err)
	}

	// Delete svcPortName from known svcPortName map
	delete(p.serviceMap, svcPortName)
}

func (p *proxy) UpdateService(svcOld, svcNew *v1.Service) {
	klog.Infof("UpdateService for a service %s/%s", svcNew.Namespace, svcNew.Name)

	// Check if the version of Last Known Service's version matches with svcOld version
	// mismatch would indicate lost update.
	ver, err := p.cache.getCachedSvcVersion(svcNew.Name, svcNew.Namespace)
	if err != nil {
		klog.Warningf("UpdateService did not find service %s/%s in cache, it is a big, please file an issue", svcNew.Namespace, svcNew.Name)
	} else {
		if svcOld.ObjectMeta.GetResourceVersion() != ver {
			klog.Warningf("mismatch version detected between old service %s/%s and last known stored in cache", svcNew.Namespace, svcNew.Name)
		} else {
			klog.Warningf("old service %s/%s and last known stored in cache are in sync, version: %s", svcNew.Namespace, svcNew.Name, ver)
		}
	}
	storedSvc, _ := p.cache.getLastKnownSvcFromCache(svcNew.Name, svcNew.Namespace)

	for i := range svcNew.Spec.Ports {
		servicePort := &svcNew.Spec.Ports[i]
		svcPortName := getSvcPortName(svcNew.Name, svcNew.Namespace, servicePort.Name, servicePort.Protocol)
		// baseSvcInfo := newBaseServiceInfo(servicePort, svcNew)
		old, found := isServicePortInPorts(storedSvc.Spec.Ports, servicePort)
		if !found {
			continue
		}
		klog.Infof("Service Port name %s eeds update old: %+v new: %+v", svcPortName, svcOld.Spec.Ports[old], servicePort)
	}
	/*
		for i := range svcNew.Spec.Ports {
			servicePort := &svcNew.Spec.Ports[i]
			svcPortName := getSvcPortName(svcNew.Name, svcNew.Namespace, servicePort.Name, servicePort.Protocol)
			baseSvcInfo := newBaseServiceInfo(servicePort, svcNew)
			if _, found := isServicePortInPorts(svcOld.Spec.Ports, servicePort); !found {
				p.addServicePort(svcPortName, servicePort, svcNew, baseSvcInfo)
			}
		}
		for i := range svcOld.Spec.Ports {
			servicePort := &svcOld.Spec.Ports[i]
			svcPortName := getSvcPortName(svcOld.Name, svcOld.Namespace, servicePort.Name, servicePort.Protocol)
			// baseSvcInfo := newBaseServiceInfo(servicePort, svcNew)
			if _, found := isServicePortInPorts(svcNew.Spec.Ports, servicePort); !found {
				p.deleteServicePort(svcPortName, servicePort, svcOld)
			}
		}
	*/
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
			if err := p.removeFromNoEndpointsList(entry, tableFamily); err != nil {
				klog.Errorf("failed to remove %s from \"No Endpoints Set\" with error: %+v", svcPortName.String(), err)
			} else {
				entry.svcnft.WithEndpoints = true
			}
		}
		// Programming rules for existing endpoints
		epsChains := p.getServicePortEndpointChains(svcPortName, tableFamily)
		cn := nftables.K8sSvcPrefix + entry.svcnft.Chains[tableFamily].ServiceID
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
	//	klog.Infof("Delete endpoint: %s/%s", ep.Namespace, ep.Name)
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
			_, tableFamily := getIPFamily(svc.ClusterIP().String())
			if err := p.addToNoEndpointsList(svc, tableFamily); err != nil {
				klog.Errorf("failed to add %s to No Endpoints Set with error: %+v", svcPortName.String(), err)
			} else {
				bsvc := svc.(*serviceInfo)
				// Set service flag that there is no endpoints
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
	//	klog.Infof("Update endpoint: %s/%s", epNew.Namespace, epNew.Name)
	if reflect.DeepEqual(epOld.Subsets, epNew.Subsets) {
		// Subsets are equal, other changes are not important for nfproxy,
		// ignoring them
		return
	}
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
				// TODO (sbezverk) this logic handles only ADD, but does not update of the existing one
				// Add update logic and unit tests.
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

// BootstrapRules programs rules so the controller could reach API server
// when it runs "in-cluster" mode.
func BootstrapRules(p Proxy, host, extAddr string, port string) error {
	// TODO (sbezverk) Consider adding ip address validation
	pn, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	ipFamily, _ := getIPFamily(host)
	svc := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubernetes",
			Namespace: "default",
		},
		Spec: v1.ServiceSpec{
			IPFamily: &ipFamily,
			Ports: []v1.ServicePort{
				{
					// TODO (sbezverk) What if it is not secured cluster?
					Name:       "https",
					Protocol:   v1.ProtocolTCP,
					Port:       int32(pn),
					TargetPort: intstr.FromString(port),
				},
			},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: host,
		},
	}
	endpoint := v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubernetes",
			Namespace: "default",
		},
		Subsets: []v1.EndpointSubset{
			{
				Addresses: []v1.EndpointAddress{
					{
						IP: extAddr,
					},
				},
				Ports: []v1.EndpointPort{
					{
						Name:     "https",
						Protocol: v1.ProtocolTCP,
						// TODO (sbezverk) find a way to get this port from environment
						Port: int32(6443),
					},
				},
			},
		},
	}
	p.AddService(&svc)
	p.AddEndpoints(&endpoint)

	return nil
}
