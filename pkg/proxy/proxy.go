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
	klog.V(6).Infof("updating service chain for service %s address family %v", svcPortName.String(), tableFamily)
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
	if svcRules == nil {
		klog.Errorf("updating service chain for service %s address family %v failed as Rules array is nil, it is a bug, please file an issue.", svcPortName.String(), tableFamily)
		return nil
	}
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
