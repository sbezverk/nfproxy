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
	"fmt"
	"strings"
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
	s := time.Now()
	defer klog.V(5).Infof("AddService ran for: %d nanoseconds", time.Since(s))
	// Storing new service in the cache for later reference
	p.cache.storeSvcInCache(svc)
	klog.V(5).Infof("AddService for a service %s/%s", svc.Namespace, svc.Name)
	if svc == nil {
		return
	}
	klog.V(6).Infof("AddService for a service Spec: %+v Status: %+v", svc.Spec, svc.Status)
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
	// Check if new ServicePort already has or not corresponding endpoints entries, if not then
	// ServicePort is added to No Endpoint set.
	if len(p.endpointsMap[svcPortName]) == 0 {
		if err := p.addToNoEndpointsList(baseSvcInfo, tableFamily); err != nil {
			klog.Errorf("failed to add %s to No Endpoints Set with error: %+v", svcPortName.String(), err)
		}
		baseSvcInfo.svcnft.WithEndpoints = false
	} else {
		baseSvcInfo.svcnft.WithEndpoints = true
	}
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
	// All services chains/rules are ready, safe to add svcPortName th serviceMap
	p.serviceMap[svcPortName] = newServiceInfo(servicePort, svc, baseSvcInfo)
	if err := p.updateServiceChain(svcPortName, tableFamily); err != nil {
		klog.Errorf("failed to update service %s chain with endpoint rule with error: %+v", svcPortName.String(), err)
	}
}

// rekeyServicePort gets ServicePort info stored for the oldSvcPortName and stores it back
// with the new key.
func (p *proxy) rekeyServicePort(oldSvcPortName, newSvcPortName ServicePortName) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	d, ok := p.serviceMap[oldSvcPortName]
	if !ok {
		return fmt.Errorf("service port name %+v does not exist", oldSvcPortName)
	}
	p.serviceMap[newSvcPortName] = d
	delete(p.serviceMap, oldSvcPortName)
	return nil
}

func (p *proxy) DeleteService(svc *v1.Service) {
	s := time.Now()
	defer klog.V(5).Infof("DeleteService ran for: %d nanoseconds", time.Since(s))
	klog.V(5).Infof("DeleteService for a service %s/%s", svc.Namespace, svc.Name)
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
	// Creating new baseinfo based on the current state of the service port
	baseInfo := newBaseServiceInfo(servicePort, svc)
	// Storing state of Endpoints in new baseinfo for proper cleanup from no-endpoint set
	baseInfo.svcnft = svcInfo.(*serviceInfo).BaseServiceInfo.svcnft
	baseInfo.svcName = svcInfo.(*serviceInfo).BaseServiceInfo.svcName
	baseInfo.svcNamespace = svcInfo.(*serviceInfo).BaseServiceInfo.svcNamespace
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
		klog.Errorf("failed to remove service port %s from sets with error: %+v", svcPortName.String(), err)
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

// TODO (sbezverk) Add update logic when Spec's fields example ExternalIPs, LoadbalancerIP etc are updated.
func (p *proxy) UpdateService(svcOld, svcNew *v1.Service) {
	s := time.Now()
	defer klog.V(5).Infof("UpdateService ran for: %d nanoseconds", time.Since(s))
	klog.V(5).Infof("UpdateService for a service %s/%s", svcNew.Namespace, svcNew.Name)
	klog.V(6).Infof("UpdateService for a service Spec: %+v Status: %+v", svcNew.Spec, svcNew.Status)
	// Check if the version of Last Known Service's version matches with svcOld version
	// mismatch would indicate lost update.
	var storedSvc *v1.Service
	ver, err := p.cache.getCachedSvcVersion(svcNew.Name, svcNew.Namespace)
	if err != nil {
		klog.Errorf("UpdateService did not find service %s/%s in cache, it is a bug, please file an issue", svcNew.Namespace, svcNew.Name)
		// Since cache does not have old known service entry, use svcOld
		storedSvc = svcOld
	} else {
		// TODO add logic to check version, if oldSvc's version more recent than storedSvc, then use oldSvc as the most current old object.
		if svcOld.ObjectMeta.GetResourceVersion() != ver {
			klog.Warningf("mismatch version detected between old service %s/%s and last known stored in cache", svcNew.Namespace, svcNew.Name)
		} else {
			klog.V(5).Infof("old service %s/%s and last known stored in cache are in sync, version: %s", svcNew.Namespace, svcNew.Name, ver)
		}
		storedSvc, _ = p.cache.getLastKnownSvcFromCache(svcNew.Name, svcNew.Namespace)
	}
	// Step 1 is to detect all changes with ServicePorts
	// TODO (sbezverk) Check for changes for ServicePort's NodePort.
	p.processServicePortChanges(svcNew, storedSvc)
	// Step 2 is to detect changes for External IPs; add new and remove old ones
	p.processExternalIPChanges(svcNew, storedSvc)
	// Step 3 is to detect changes for LoadBalancer IPs; add new and remove old ones
	p.processLoadBalancerIPChange(svcNew, storedSvc)

	// Update service in cache after applying all changes
	p.cache.storeSvcInCache(svcNew)
}

func (p *proxy) AddEndpoints(ep *v1.Endpoints) {
	s := time.Now()
	defer klog.V(5).Infof("AddEndpoints ran for: %d nanoseconds", time.Since(s))
	p.cache.storeEpInCache(ep)
	klog.V(6).Infof("Add endpoint: %s/%s", ep.Namespace, ep.Name)
	//	p.UpdateEndpoints(&v1.Endpoints{Subsets: []v1.EndpointSubset{}}, ep)
	info, err := processEpSubsets(ep)
	if err != nil {
		klog.Errorf("failed to add Endpoint %s/%s with error: %+v", ep.Namespace, ep.Name, err)
		return
	}
	for _, e := range info {
		klog.V(5).Infof("adding Endpoint %s/%s port %+v", ep.Namespace, ep.Name, *e.port)
		if err := p.addEndpoint(e.name, e.addr, e.port); err != nil {
			klog.Errorf("failed to add Endpoint %s/%s port %+v with error: %+v", ep.Namespace, ep.Name, e.port, err)
			return
		}
	}
}

func (p *proxy) addEndpoint(svcPortName ServicePortName, addr *v1.EndpointAddress, port *v1.EndpointPort) error {
	p.mu.Lock()
	defer p.mu.Unlock()
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
	p.endpointsMap[svcPortName] = append(p.endpointsMap[svcPortName], newEndpointInfo(baseEndpointInfo, port.Protocol))
	if err := p.updateServiceChain(svcPortName, ipTableFamily); err != nil {
		klog.Errorf("failed to update service %s chain with endpoint rule with error: %+v", svcPortName.String(), err)
		return err
	}
	return nil
}

func (p *proxy) addEndpointRule(epRule *nftables.Rule, tableFamily utilnftables.TableFamily, cn string, svcPortName ServicePortName, key *epKey) error {
	var ruleIDs []uint64
	var err error

	ruleIDs, err = nftables.AddEndpointRules(p.nfti, tableFamily, cn, key.ipaddr, key.proto, key.port)
	if err != nil {
		return err
	}
	epRule.RuleID = ruleIDs

	return nil
}

// updateServiceChain programs rules for a specific ServicePortName, it is called for every endpoint add/delete
// event.
func (p *proxy) updateServiceChain(svcPortName ServicePortName, tableFamily utilnftables.TableFamily) error {
	svc, ok := p.serviceMap[svcPortName]
	if !ok {
		return nil
	}
	entry := svc.(*serviceInfo)
	if len(p.endpointsMap[svcPortName]) == 0 {
		if entry.svcnft.WithEndpoints {
			if err := p.addToNoEndpointsList(svc, tableFamily); err != nil {
				klog.Errorf("failed to add %s to No Endpoints Set with error: %+v", svcPortName.String(), err)
			}
		}
		entry.svcnft.WithEndpoints = false
	} else {
		if !entry.svcnft.WithEndpoints {
			// ServicePort did not have any endpoints until now, removing from no endpoint set
			if err := p.removeFromNoEndpointsList(entry, tableFamily); err != nil {
				klog.Errorf("failed to remove %s from \"No Endpoints Set\" with error: %+v", svcPortName.String(), err)
			}
		}
		entry.svcnft.WithEndpoints = true
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

	return nil
}

func (p *proxy) DeleteEndpoints(ep *v1.Endpoints) {
	s := time.Now()
	defer klog.V(5).Infof("AddService ran for: %d nanoseconds", time.Since(s))
	klog.V(5).Infof("Delete endpoint: %s/%s", ep.Namespace, ep.Name)
	info, err := processEpSubsets(ep)
	if err != nil {
		klog.Errorf("failed to delete Endpoint %s/%s with error: %+v", ep.Namespace, ep.Name, err)
		return
	}
	for _, e := range info {
		p.mu.Lock()
		eps, ok := p.endpointsMap[e.name]
		p.mu.Unlock()
		if !ok {
			continue
		}
		klog.V(5).Infof("Removing Endpoint %s/%s port %+v", ep.Namespace, ep.Name, e.port)
		if err := p.deleteEndpoint(e.name, e.addr, e.port, eps); err != nil {
			klog.Errorf("failed to remove Endpoint %s/%s port %+v with error: %+v", ep.Namespace, ep.Name, e.port, err)
			continue
		}
	}
	p.cache.removeEpFromCache(ep.Name, ep.Namespace)
}

func (p *proxy) deleteEndpoint(svcPortName ServicePortName, addr *v1.EndpointAddress, port *v1.EndpointPort, eps []Endpoint) error {
	p.mu.Lock()
	defer p.mu.Unlock()
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
			p.endpointsMap[svcPortName] = eps[:i]
			p.endpointsMap[svcPortName] = append(p.endpointsMap[svcPortName], eps[i+1:]...)
			cn := ep2c.BaseEndpointInfo.epnft.Rule[ipTableFamily].Chain
			ruleID := ep2c.BaseEndpointInfo.epnft.Rule[ipTableFamily].RuleID
			// Update the service's rule to exclude deleted endpoint
			if err := p.updateServiceChain(svcPortName, ipTableFamily); err != nil {
				klog.Errorf("failed to update service %s chain with endpoint rule with error: %+v", svcPortName.String(), err)
				return err
			}
			if err := p.deleteEndpointRules(ipTableFamily, cn, ruleID, svcPortName, &epKey{port.Protocol, addr.IP, port.Port}); err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *proxy) deleteEndpointRules(ipTableFamily utilnftables.TableFamily, cn string, ruleID []uint64, svcPortName ServicePortName, key *epKey) error {
	if err := nftables.DeleteEndpointRules(p.nfti, ipTableFamily, cn, ruleID); err != nil {
		return err
	}
	// Deleting endpoint's chain
	if err := nftables.DeleteChain(p.nfti, ipTableFamily, cn); err != nil {
		klog.Errorf("failed to delete endpoint chain: %s with error: %+v", cn, err)
		return err
	}
	// Check if it was last endpoint for a service port name
	if len(p.endpointsMap[svcPortName]) == 0 {
		klog.V(5).Infof("no more endpoints found for %s", svcPortName.String())
		// No endpoints for svcPortName key is available, need to add svcPortName to No Endpoint Set
		delete(p.endpointsMap, svcPortName)
	}
	return nil
}

// epInfo is used to carry a single processed instance of EP's Subset
type epInfo struct {
	name ServicePortName
	addr *v1.EndpointAddress
	port *v1.EndpointPort
}

func processEpSubsets(ep *v1.Endpoints) ([]epInfo, error) {
	var ports []epInfo
	for i := range ep.Subsets {
		ss := &ep.Subsets[i]
		for i := range ss.Ports {
			port := &ss.Ports[i]
			if port.Port == 0 {
				return nil, fmt.Errorf("found invalid endpoint port %s", port.Name)
			}
			svcPortName := getSvcPortName(ep.Name, ep.Namespace, port.Name, port.Protocol)
			for i := range ss.Addresses {
				addr := &ss.Addresses[i]
				if addr.IP == "" {
					return nil, fmt.Errorf("found invalid endpoint port %s with empty host", port.Name)
				}
				ports = append(ports, epInfo{name: svcPortName, addr: addr, port: port})
			}
		}
	}

	return ports, nil
}

func (p *proxy) UpdateEndpoints(epOld, epNew *v1.Endpoints) {
	s := time.Now()
	defer klog.V(5).Infof("UpdateEndpoints ran for: %d nanoseconds", time.Since(s))
	if epNew.Namespace == "" && epNew.Name == "" {
		// When service gets deleted the endpoint controller triggers an update for an endpoint with no name or namespace
		// ignoring it
		return
	}
	klog.V(6).Infof("UpdateEndpoint for endpoint: %s/%s", epNew.Namespace, epNew.Name)
	// Check if the version of Last Known Endpoint's version matches with epOld version
	// mismatch would indicate lost update.
	var storedEp *v1.Endpoints
	ver, err := p.cache.getCachedEpVersion(epNew.Name, epNew.Namespace)
	if err != nil {
		klog.Errorf("UpdateEndpoint did not find Endpoint %s/%s in cache, it is a bug, please file an issue", epNew.Namespace, epNew.Name)
		storedEp = epOld
	} else {
		// TODO add logic to check version, if oldEp's version more recent than storedEp, then use oldEp as the most current old object.
		oldVer := epOld.ObjectMeta.GetResourceVersion()
		if oldVer != ver {
			klog.Warningf("mismatch version detected between old Endpoint %s/%s and last known stored in cache %s/%s",
				epNew.Namespace, epNew.Name, oldVer, ver)
		}
		storedEp, _ = p.cache.getLastKnownEpFromCache(epNew.Name, epNew.Namespace)
	}
	// Check for new Endpoint's ports, if found adding them into EndpointMap and corresponding programming rules.
	info, err := processEpSubsets(epNew)
	if err != nil {
		klog.Errorf("failed to update Endpoint %s/%s with error: %+v", epNew.Namespace, epNew.Name, err)
		return
	}
	for _, e := range info {
		if !isPortInSubset(storedEp.Subsets, e.port) {
			klog.V(5).Infof("updating Endpoint %s/%s port %+v", epNew.Namespace, epNew.Name, *e.port)
			if err := p.addEndpoint(e.name, e.addr, e.port); err != nil {
				klog.Errorf("failed to update Endpoint %s/%s port %+v with error: %+v", epNew.Namespace, epNew.Name, *e.port, err)
				return
			}
		}
	}
	// Check for removed endpoint's ports, if found, remvoing all entries from EndpointMap
	info, _ = processEpSubsets(storedEp)
	for _, e := range info {
		p.mu.Lock()
		eps, ok := p.endpointsMap[e.name]
		p.mu.Unlock()
		if !ok {
			continue
		}
		if !isPortInSubset(epNew.Subsets, e.port) {
			klog.V(5).Infof("removing Endpoint %s/%s port %+v", epNew.Namespace, epNew.Name, *e.port)
			if err := p.deleteEndpoint(e.name, e.addr, e.port, eps); err != nil {
				klog.Errorf("failed to remove Endpoint %s/%s port %+v with error: %+v", epNew.Namespace, epNew.Name, *e.port, err)
				continue
			}
		}
	}
	p.cache.storeEpInCache(epNew)
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

// processServicePortChanges is called from the service Update handler, it checks for any changes in
// ServicePorts and re-programs nftables.
func (p *proxy) processServicePortChanges(svcNew *v1.Service, storedSvc *v1.Service) {
	// Check for Service's IPFamily to program changes in the right table.
	tableFamily := utilnftables.TableFamilyIPv4
	if utilnet.IsIPv6String(svcNew.Spec.ClusterIP) {
		tableFamily = utilnftables.TableFamilyIPv6
	}
	// TODO need to use IPFamily eventually
	//	if *svcNew.Spec.IPFamily == v1.IPv6Protocol {
	//		tableFamily = utilnftables.TableFamilyIPv6
	//	}
	for i := range svcNew.Spec.Ports {
		servicePort := &svcNew.Spec.Ports[i]
		svcPortName := getSvcPortName(svcNew.Name, svcNew.Namespace, servicePort.Name, servicePort.Protocol)
		baseSvcInfo := newBaseServiceInfo(servicePort, svcNew)
		id, found := isServicePortInPorts(storedSvc.Spec.Ports, servicePort)
		// if new servicePort is not found in the stored last known service and svcPortName does not already exist in ServiceMap
		// then it is genuine new port, so addig it and then move to next
		p.mu.Lock()
		_, ok := p.serviceMap[svcPortName]
		p.mu.Unlock()
		if !found && !ok {
			// Adding new service port
			p.addServicePort(svcPortName, servicePort, svcNew, baseSvcInfo)
			continue
		}
		// If ServicePortName does not match, it means Protocol/Port pair has not been changed,
		// otherwise ServicePort would not have been found.
		// Changes of Port.Name or Port.Protocol result in a new ServicePortName generated, hence the old one
		// needs to be replaced.
		oldServicePortName := getSvcPortName(storedSvc.Name, storedSvc.Namespace, storedSvc.Spec.Ports[id].Name, storedSvc.Spec.Ports[id].Protocol)
		if storedSvc.Spec.Ports[id].Name != servicePort.Name {
			// In case of a Port.Name change no reprogramming is required. All is required, copy old ServicePort's data and store it in
			// the map with new svcPortName key.
			if err := p.rekeyServicePort(oldServicePortName, svcPortName); err != nil {
				klog.Warningf("update of ServicePortName failed with error %w", err)
			}
			klog.V(5).Infof("Rekeyed old Service port %+v with new %+v", oldServicePortName, svcPortName)
			continue
		}
		// If Port.Protocol got changed to prevent traffic drop, first add updated to new Protocol:Port rules
		// then remove the old ones
		if storedSvc.Spec.Ports[id].Protocol != servicePort.Protocol ||
			storedSvc.Spec.Ports[id].Port != servicePort.Port {
			// Deleting old ServicePort
			p.deleteServicePort(oldServicePortName, &storedSvc.Spec.Ports[id], storedSvc)
			// Add updated ServicePort
			p.addServicePort(svcPortName, servicePort, svcNew, baseSvcInfo)
			klog.V(5).Infof("Service Port name has been updated old: %+v new: %+v", oldServicePortName, svcPortName)
		}
		// Check if there is a change in NodePort, if there is, then update NodePort set with new value.
		if storedSvc.Spec.Ports[id].NodePort != svcNew.Spec.Ports[i].NodePort {
			svc := p.serviceMap[svcPortName].(*serviceInfo).BaseServiceInfo.String()
			svcID := servicePortSvcID(svcPortName.String(), string(servicePort.Protocol), svc)
			// Adding new NodePort if it is not 0, NodePort of 0 in svcNew.Spec.Ports[i].NodePort indicates the removal of NodePort
			// from Service Port completely, in this case operation of addition is skipped.
			if svcNew.Spec.Ports[i].NodePort != 0 {
				if err := nftables.AddToNodeportSet(p.nfti, tableFamily, servicePort.Protocol, uint16(svcNew.Spec.Ports[i].NodePort), nftables.K8sSvcPrefix+svcID); err != nil {
					klog.Errorf("update/add of NodePort %d for Service Port name: %+v failed with error %w", svcNew.Spec.Ports[i].NodePort, svcPortName, err)
				}
			}
			// Removing old NodePort if it is not 0, NodePort of 0 in storedSvc.Spec.Ports[i].NodePort indicates the addition of NodePort
			// to the Service Port which did not have NodePort before, in this case operation of removal is skipped.
			if storedSvc.Spec.Ports[i].NodePort != 0 {
				if err := nftables.RemoveFromNodeportSet(p.nfti, tableFamily, servicePort.Protocol, uint16(storedSvc.Spec.Ports[id].NodePort), nftables.K8sSvcPrefix+svcID); err != nil {
					klog.Errorf("update/remove of NodePort %d for Service Port name: %+v failed with error %w", storedSvc.Spec.Ports[id].NodePort, svcPortName, err)
				}
			}
			klog.V(5).Infof("NodePort changed from %d to %d for Service Port name: %+v", storedSvc.Spec.Ports[id].NodePort, svcNew.Spec.Ports[i].NodePort, svcPortName)
		}
	}
	// Processing deleted or undiscoverably changed ServicePorts, if ServicePort exists in storedSvc.Spec.Ports but
	// does not exist in svcNew.Spec.Ports delete it.
	for i := range storedSvc.Spec.Ports {
		servicePort := &storedSvc.Spec.Ports[i]
		svcPortName := getSvcPortName(storedSvc.Name, storedSvc.Namespace, servicePort.Name, servicePort.Protocol)
		if _, found := isServicePortInPorts(svcNew.Spec.Ports, servicePort); !found {
			p.deleteServicePort(svcPortName, servicePort, storedSvc)
			klog.V(5).Infof("removed Service port %+v", svcPortName)
		}
	}

}

// processExternalIPChanges is called from the service Update handler, it checks for any changes in
// ExternalIPs and re-program new entries for all ServicePort of the changed service.
func (p *proxy) processExternalIPChanges(svcNew *v1.Service, storedSvc *v1.Service) {
	if !compareSliceOfString(storedSvc.Spec.ExternalIPs, svcNew.Spec.ExternalIPs) {
		// Check for new ExternalIPs to add
		for _, addr := range svcNew.Spec.ExternalIPs {
			if isStringInSlice(addr, storedSvc.Spec.ExternalIPs) {
				continue
			}
			klog.V(5).Infof("detected a new ExternalIP %s", addr)
			tableFamily := utilnftables.TableFamilyIPv4
			if utilnet.IsIPv6String(addr) {
				tableFamily = utilnftables.TableFamilyIPv6
			}
			for _, servicePort := range svcNew.Spec.Ports {
				svcPortName := getSvcPortName(svcNew.Name, svcNew.Namespace, servicePort.Name, servicePort.Protocol)
				svc := p.serviceMap[svcPortName].(*serviceInfo).BaseServiceInfo.String()
				svcID := servicePortSvcID(svcPortName.String(), string(servicePort.Protocol), svc)
				nftables.AddToSet(p.nfti, tableFamily, servicePort.Protocol, addr, uint16(servicePort.Port), nftables.K8sExternalIPSet, nftables.K8sSvcPrefix+svcID)
				nftables.AddToSet(p.nfti, tableFamily, servicePort.Protocol, addr, uint16(servicePort.Port), nftables.K8sMarkMasqSet, nftables.K8sNATDoMarkMasq)
			}
		}
		// Check for ExternalIPs to delete
		for _, addr := range storedSvc.Spec.ExternalIPs {
			if isStringInSlice(addr, svcNew.Spec.ExternalIPs) {
				continue
			}
			klog.V(5).Infof("detected deleted ExternalIP %s", addr)
			tableFamily := utilnftables.TableFamilyIPv4
			if utilnet.IsIPv6String(addr) {
				tableFamily = utilnftables.TableFamilyIPv6
			}
			for _, servicePort := range svcNew.Spec.Ports {
				svcPortName := getSvcPortName(svcNew.Name, svcNew.Namespace, servicePort.Name, servicePort.Protocol)
				svcBaseInfoString := p.serviceMap[svcPortName].(*serviceInfo).BaseServiceInfo.String()
				svcID := servicePortSvcID(svcPortName.String(), string(servicePort.Protocol), svcBaseInfoString)
				nftables.RemoveFromSet(p.nfti, tableFamily, servicePort.Protocol, addr, uint16(servicePort.Port), nftables.K8sExternalIPSet, nftables.K8sSvcPrefix+svcID)
				nftables.RemoveFromSet(p.nfti, tableFamily, servicePort.Protocol, addr, uint16(servicePort.Port), nftables.K8sMarkMasqSet, nftables.K8sNATDoMarkMasq)
			}
		}
	}
}

// processLoadBalancerIPChange is called from the service Update handler, it checks for any changes in
// ExternalIPs and re-program new entries for all ServicePort of the changed service.
func (p *proxy) processLoadBalancerIPChange(svcNew *v1.Service, storedSvc *v1.Service) {
	// Check if new and stored service status is equal or not, if equal no processing required
	if !isIngressEqual(svcNew.Status.LoadBalancer.Ingress, storedSvc.Status.LoadBalancer.Ingress) {
		// Check new Service Loadbalancer status for entries missing in stored Service
		for _, lbingress := range svcNew.Status.LoadBalancer.Ingress {
			// TODO figure out what to do if addr.Host is used
			if _, found := isAddressInIngress(storedSvc.Status.LoadBalancer.Ingress, lbingress.IP); !found {
				klog.V(5).Infof("adding new LoadBalancerIP: %s", lbingress.IP)
				addr := lbingress.IP
				tableFamily := utilnftables.TableFamilyIPv4
				if utilnet.IsIPv6String(addr) {
					tableFamily = utilnftables.TableFamilyIPv6
				}
				for _, servicePort := range svcNew.Spec.Ports {
					svcPortName := getSvcPortName(svcNew.Name, svcNew.Namespace, servicePort.Name, servicePort.Protocol)
					svc := p.serviceMap[svcPortName].(*serviceInfo).BaseServiceInfo.String()
					svcID := servicePortSvcID(svcPortName.String(), string(servicePort.Protocol), svc)
					nftables.AddToSet(p.nfti, tableFamily, servicePort.Protocol, addr, uint16(servicePort.Port), nftables.K8sLoadbalancerIPSet, nftables.K8sSvcPrefix+svcID)
					nftables.AddToSet(p.nfti, tableFamily, servicePort.Protocol, addr, uint16(servicePort.Port), nftables.K8sMarkMasqSet, nftables.K8sNATDoMarkMasq)
				}
			}
		}
		// Check stored Service Loadbalancer status for entries missing in a new Service, if not found
		// it indicates removal of LoadBalancer IP
		for _, lbingress := range storedSvc.Status.LoadBalancer.Ingress {
			// TODO figure out what to do if addr.Host is used
			if _, found := isAddressInIngress(svcNew.Status.LoadBalancer.Ingress, lbingress.IP); !found {
				klog.V(5).Infof("removing old LoadBalancerIP: %s", lbingress.IP)
				addr := lbingress.IP
				tableFamily := utilnftables.TableFamilyIPv4
				if utilnet.IsIPv6String(addr) {
					tableFamily = utilnftables.TableFamilyIPv6
				}
				for _, servicePort := range svcNew.Spec.Ports {
					svcPortName := getSvcPortName(svcNew.Name, svcNew.Namespace, servicePort.Name, servicePort.Protocol)
					svc := p.serviceMap[svcPortName].(*serviceInfo).BaseServiceInfo.String()
					svcID := servicePortSvcID(svcPortName.String(), string(servicePort.Protocol), svc)
					nftables.RemoveFromSet(p.nfti, tableFamily, servicePort.Protocol, addr, uint16(servicePort.Port), nftables.K8sLoadbalancerIPSet, nftables.K8sSvcPrefix+svcID)
					nftables.RemoveFromSet(p.nfti, tableFamily, servicePort.Protocol, addr, uint16(servicePort.Port), nftables.K8sMarkMasqSet, nftables.K8sNATDoMarkMasq)
				}
			}
		}
	}
}

// isAddressInIngress returns bool and index of the address in v1.LoadBalancerIngress slice
func isAddressInIngress(ingress []v1.LoadBalancerIngress, address string) (int, bool) {
	for i, addr := range ingress {
		if strings.Compare(addr.IP, address) == 0 {
			return i, true
		}
	}
	return 0, false
}

// isIngressEqua checks equality of two v1.LoadBalancerIngress slices in terms of length and
// presence of the same IPs in both.
func isIngressEqual(a []v1.LoadBalancerIngress, b []v1.LoadBalancerIngress) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if _, found := isAddressInIngress(b, a[i].IP); !found {
			return false
		}
	}
	for i := 0; i < len(b); i++ {
		if _, found := isAddressInIngress(a, b[i].IP); !found {
			return false
		}
	}
	return true
}
