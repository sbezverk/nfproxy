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
	"sync"

	utilnftables "github.com/google/nftables"
	"github.com/sbezverk/nfproxy/pkg/nftables"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1beta1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"
)

// Proxy defines interface
type Proxy interface {
	AddService(svc *v1.Service)
	DeleteService(svc *v1.Service)
	UpdateService(svcOld, svcNew *v1.Service)
	AddEndpoints(ep *v1.Endpoints)
	DeleteEndpoints(ep *v1.Endpoints)
	UpdateEndpoints(epOld, epNew *v1.Endpoints)
	AddEndpointSlice(epsl *discovery.EndpointSlice)
	DeleteEndpointSlice(epsl *discovery.EndpointSlice)
	UpdateEndpointSlice(epslOld, epslNew *discovery.EndpointSlice)
}

type proxy struct {
	hostname     string
	nfti         *nftables.NFTInterface
	mu           sync.Mutex // protects the following fields
	serviceMap   ServiceMap
	endpointsMap EndpointsMap
	cache        cache
}

// NewProxy return a new instance of nfproxy
func NewProxy(nfti *nftables.NFTInterface, hostname string, recorder record.EventRecorder, endpointSlice bool) Proxy {
	proxy := &proxy{
		hostname:     hostname,
		nfti:         nfti,
		serviceMap:   make(ServiceMap),
		endpointsMap: make(EndpointsMap),
		cache: cache{
			svcCache: make(map[types.NamespacedName]*v1.Service),
		},
	}
	if endpointSlice {
		proxy.cache.epslCache = make(map[types.NamespacedName]*discovery.EndpointSlice)
	} else {
		proxy.cache.epCache = make(map[types.NamespacedName]*v1.Endpoints)
	}

	return proxy
}

// addAffinityEndpoint is called when Service Update handler detects change in Service's Session Affinity, specifically
// Session Affinity gets added to the service. This function will insert Update rule to every endpoint associated with a Service Port.
func (p *proxy) addAffinityEndpoint(eps []Endpoint, tableFamily utilnftables.TableFamily, svcID string, maxAgeSeconds int) error {
	for _, ep := range eps {
		chain := ep.(*endpointsInfo).BaseEndpointInfo.epnft.Rule[tableFamily].Chain
		index := ep.(*endpointsInfo).BaseEndpointInfo.epnft.Rule[tableFamily].EpIndex
		ruleID, err := nftables.AddEndpointUpdateRule(p.nfti, tableFamily, chain, index, svcID, maxAgeSeconds)
		if err != nil {
			return err
		}
		ep.(*endpointsInfo).BaseEndpointInfo.epnft.Rule[tableFamily].WithAffinity = true
		ep.(*endpointsInfo).BaseEndpointInfo.epnft.Rule[tableFamily].MaxAgeSeconds = maxAgeSeconds
		// Update rule in Endpoint chain must always be the very first one, inserting it before any already existing rules.
		ep.(*endpointsInfo).BaseEndpointInfo.epnft.Rule[tableFamily].RuleID = append(ruleID, ep.(*endpointsInfo).BaseEndpointInfo.epnft.Rule[tableFamily].RuleID...)
	}

	return nil
}

// deleteAffinityEndpoint is called when Service Update handler detects change in Service's Session Affinity,
// this function will remove Update rule from all endpoints associated with a Service Port.
func (p *proxy) deleteAffinityEndpoint(eps []Endpoint, tableFamily utilnftables.TableFamily) error {
	for _, ep := range eps {
		chain := ep.(*endpointsInfo).BaseEndpointInfo.epnft.Rule[tableFamily].Chain
		// If Session Affinity is enabled Update rule always has index 0 in am endpoint's chain rules slice
		ruleID := ep.(*endpointsInfo).BaseEndpointInfo.epnft.Rule[tableFamily].RuleID[0]
		klog.V(6).Infof("Deleting Update rule for endpoint chain: %s, rule handle: %d", chain, ruleID)
		if err := nftables.DeleteEndpointUpdateRule(p.nfti, tableFamily, chain, int(ruleID)); err != nil {
			return err
		}
		ep.(*endpointsInfo).BaseEndpointInfo.epnft.Rule[tableFamily].WithAffinity = false
		ep.(*endpointsInfo).BaseEndpointInfo.epnft.Rule[tableFamily].MaxAgeSeconds = 0
		// Update rule in Endpoint chain must always be the very first one, inserting it before any already existing rules.
		ep.(*endpointsInfo).BaseEndpointInfo.epnft.Rule[tableFamily].RuleID = ep.(*endpointsInfo).BaseEndpointInfo.epnft.Rule[tableFamily].RuleID[1:]
	}

	return nil
}

// getServicePortEndpointChains return a slice of strings containing a specific ServicePortName all endpoints chains
func (p *proxy) getServicePortEndpointChains(svcPortName ServicePortName, tableFamily utilnftables.TableFamily) []*nftables.EPRule {
	servicePortEndpoints := []*nftables.EPRule{}
	for _, ep := range p.endpointsMap[svcPortName] {
		epBase, ok := ep.(*endpointsInfo)
		if !ok {
			// Not recognize, skipping it
			continue
		}
		servicePortEndpoints = append(servicePortEndpoints, epBase.epnft.Rule[tableFamily])
	}

	return servicePortEndpoints
}

func (p *proxy) addEndpointRules(epRule *nftables.EPRule, tableFamily utilnftables.TableFamily, cn string, svcPortName ServicePortName, key *epKey) error {
	var ruleIDs []uint64
	var err error

	// If Corresponding Service Port has Affinity configured, then endpoint must have Update rule which will refresh Service Port
	// affinity map for an endpoint specific source address and index.
	if epRule.WithAffinity {
		ruleIDs, err = nftables.AddEndpointUpdateRule(p.nfti, tableFamily, cn, epRule.EpIndex, epRule.ServiceID, epRule.MaxAgeSeconds)
		if err != nil {
			return err
		}
		epRule.RuleID = ruleIDs
	}
	ruleIDs, err = nftables.AddEndpointRules(p.nfti, tableFamily, cn, key.ipaddr, key.proto, key.port, epRule.ServiceID)
	if err != nil {
		return err
	}
	if epRule.RuleID == nil {
		epRule.RuleID = ruleIDs
	} else {
		epRule.RuleID = append(epRule.RuleID, ruleIDs...)
	}

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
	svcRules := entry.svcnft.Chains[tableFamily].Chain[nftables.K8sSvcPrefix+entry.svcnft.ServiceID]
	// Check if the service still has any backends
	if len(epsChains) != 0 {
		rules, err := nftables.ProgramServiceEndpoints(p.nfti, tableFamily, entry.svcnft.ServiceID, epsChains, svcRules.RuleID, entry.svcnft.WithAffinity, svcPortName.String())
		if err != nil {
			klog.Errorf("failed to program endpoints rules for service %s with error: %+v", svcPortName.String(), err)
			return err
		}
		// Storing Service's rule id so it can be used later for modification or deletion.
		// cn carries service's name of chain, a connecion point with endpoints backending the service.
		svcRules.RuleID = rules
	} else {
		// Service has no endpoints left needs to remove the rule if any
		if err := nftables.DeleteServiceRules(p.nfti, tableFamily, nftables.K8sSvcPrefix+entry.svcnft.ServiceID, svcRules.RuleID); err != nil {
			klog.Errorf("failed to remove rule for service %s with error: %+v", svcPortName.String(), err)
			return err
		}
		svcRules.RuleID = svcRules.RuleID[:0]
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

func (p *proxy) addEndpoint(svcPortName ServicePortName, addr *v1.EndpointAddress, port *v1.EndpointPort) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	isLocal := addr.NodeName != nil && *addr.NodeName == p.hostname
	ipFamily, ipTableFamily := getIPFamily(addr.IP)
	baseEndpointInfo := newBaseEndpointInfo(ipFamily, port.Protocol, addr.IP, int(port.Port), isLocal, nil)
	// Adding to endpoint base information, structures to carry nftables related info
	baseEndpointInfo.epnft = &nftables.EPnft{
		Interface: p.nfti,
		Rule:      make(map[utilnftables.TableFamily]*nftables.EPRule),
	}
	cn := servicePortEndpointChainName(svcPortName.String(), string(port.Protocol), baseEndpointInfo.Endpoint)
	// Initializing ip table family depending on endpoint's family ipv4 or ipv6
	epRule := nftables.EPRule{
		EpIndex: len(p.endpointsMap[svcPortName]),
	}
	epRule.Chain = cn
	// RuleID nil is indicator that the nftables rule has not been yet programmed, once it is programed
	// RuleID will be updated to real value.
	epRule.RuleID = nil
	// Check if corresponding ServicePort has Service Affinity set and copy parameters to endpoint rule struct
	epRule.WithAffinity = false
	if svc, ok := p.serviceMap[svcPortName]; ok {
		epRule.WithAffinity = svc.(*serviceInfo).svcnft.WithAffinity
		epRule.MaxAgeSeconds = svc.(*serviceInfo).svcnft.MaxAgeSeconds
		epRule.ServiceID = svc.(*serviceInfo).svcnft.ServiceID
	}
	baseEndpointInfo.epnft.Rule[ipTableFamily] = &epRule
	if err := p.addEndpointRules(&epRule, ipTableFamily, cn, svcPortName, &epKey{port.Protocol, addr.IP, port.Port}); err != nil {
		klog.Errorf("failed to add endpoint rules for Service Port Name: %+v with error: %+v", svcPortName, err)
		return err
	}
	p.endpointsMap[svcPortName] = append(p.endpointsMap[svcPortName], newEndpointInfo(baseEndpointInfo, port.Protocol))
	if err := p.updateServiceChain(svcPortName, ipTableFamily); err != nil {
		klog.Errorf("failed to update service %s chain with endpoint rule with error: %+v", svcPortName.String(), err)
		return err
	}
	return nil
}
