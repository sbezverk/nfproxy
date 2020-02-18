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
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/klog"
)

type epKey struct {
	proto  v1.Protocol
	ipaddr string
	port   int32
}

func (p *proxy) AddEndpoints(ep *v1.Endpoints) {
	s := time.Now()
	defer klog.V(5).Infof("AddEndpoints for %s/%s ran for: %d nanoseconds", ep.Namespace, ep.Name, time.Since(s))
	p.cache.storeEpInCache(ep)
	klog.V(5).Infof("Add endpoint: %s/%s", ep.Namespace, ep.Name)
	//	p.UpdateEndpoints(&v1.Endpoints{Subsets: []v1.EndpointSubset{}}, ep)
	info, err := processEpSubsets(ep)
	if err != nil {
		klog.Errorf("failed to add Endpoint %s/%s with error: %+v", ep.Namespace, ep.Name, err)
		return
	}
	for _, e := range info {
		klog.V(5).Infof("adding Endpoint %s/%s Service Port Name: %+v", ep.Namespace, ep.Name, e.name)
		if err := p.addEndpoint(e.name, e.addr, e.port); err != nil {
			klog.Errorf("failed to add Endpoint %s/%s port %+v with error: %+v", ep.Namespace, ep.Name, e.port, err)
			return
		}
	}
}

func (p *proxy) DeleteEndpoints(ep *v1.Endpoints) {
	s := time.Now()
	defer klog.V(5).Infof("DeleteEndpoints for %s/%s ran for: %d nanoseconds", ep.Namespace, ep.Name, time.Since(s))
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
				klog.Errorf("failed to delete endpoint rules service port name %+v with error: %+v", svcPortName, err)
				return err
			}
		}
	}

	return nil
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
			if len(ss.Addresses) == 0 {
			}
			for i := range ss.Addresses {
				addr := &ss.Addresses[i]
				if addr.IP == "" {
					return nil, fmt.Errorf("found invalid endpoint port %s with empty host", port.Name)
				}
				ports = append(ports, epInfo{name: svcPortName, addr: addr, port: port})
			}
			for i := range ss.NotReadyAddresses {
				addr := &ss.NotReadyAddresses[i]
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
	defer klog.V(5).Infof("UpdateEndpoints for %s/%s ran for: %d nanoseconds", epNew.Namespace, epNew.Name, time.Since(s))
	if epNew.Namespace == "" && epNew.Name == "" {
		// When service gets deleted the endpoint controller triggers an update for an endpoint with no name or namespace
		// ignoring it
		return
	}
	klog.V(5).Infof("UpdateEndpoint for endpoint: %s/%s", epNew.Namespace, epNew.Name)
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
		if !isPortInSubset(storedEp.Subsets, e.port, e.addr) {
			klog.V(5).Infof("updating Endpoint %s/%s Service Port name: %+v", epNew.Namespace, epNew.Name, e.name)
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
		if !isPortInSubset(epNew.Subsets, e.port, e.addr) {
			klog.V(5).Infof("removing Endpoint %s/%s port %+v", epNew.Namespace, epNew.Name, *e.port)
			if err := p.deleteEndpoint(e.name, e.addr, e.port, eps); err != nil {
				klog.Errorf("failed to remove Endpoint %s/%s port %+v with error: %+v", epNew.Namespace, epNew.Name, *e.port, err)
				continue
			}
		}
	}
	p.cache.storeEpInCache(epNew)
}
