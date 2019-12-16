/*
Copyright 2019 The Kubernetes Authors.

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
	"net"
	"strconv"

	"github.com/sbezverk/nfproxy/pkg/nftables"
	"k8s.io/klog"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1beta1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	utilproxy "k8s.io/kubernetes/pkg/proxy/util"
)

var supportedEndpointSliceAddressTypes = sets.NewString(
	string(discovery.AddressTypeIP), // IP is a deprecated address type
	string(discovery.AddressTypeIPv4),
	string(discovery.AddressTypeIPv6),
)

// BaseEndpointInfo contains base information that defines an endpoint.
// This could be used directly by proxier while processing endpoints,
// or can be used for constructing a more specific EndpointInfo struct
// defined by the proxier if needed.
type BaseEndpointInfo struct {
	IPFamily v1.IPFamily
	Endpoint string // TODO: should be an endpointString type
	// IsLocal indicates whether the endpoint is running in same host as kube-proxy.
	IsLocal  bool
	Topology map[string]string
	epnft    *nftables.EPnft
}

var _ Endpoint = &BaseEndpointInfo{}

// String is part of proxy.Endpoint interface.
func (info *BaseEndpointInfo) String() string {
	return info.Endpoint
}

// GetIsLocal is part of proxy.Endpoint interface.
func (info *BaseEndpointInfo) GetIsLocal() bool {
	return info.IsLocal
}

// GetTopology returns the topology information of the endpoint.
func (info *BaseEndpointInfo) GetTopology() map[string]string {
	return info.Topology
}

// IP returns just the IP part of the endpoint, it's a part of proxy.Endpoint interface.
func (info *BaseEndpointInfo) IP() string {
	return utilproxy.IPPart(info.Endpoint)
}

// Port returns just the Port part of the endpoint.
func (info *BaseEndpointInfo) Port() (int, error) {
	return utilproxy.PortPart(info.Endpoint)
}

// Equal is part of proxy.Endpoint interface.
func (info *BaseEndpointInfo) Equal(other Endpoint) bool {
	return info.String() == other.String() && info.GetIsLocal() == other.GetIsLocal()
}

func newBaseEndpointInfo(ipFamily v1.IPFamily, protocol v1.Protocol, IP string, port int, isLocal bool, topology map[string]string) *BaseEndpointInfo {
	return &BaseEndpointInfo{
		IPFamily: ipFamily,
		Endpoint: string(ipFamily) + ":" + net.JoinHostPort(IP, strconv.Itoa(port)) + "/" + string(protocol),
		IsLocal:  isLocal,
		Topology: topology,
	}
}

type makeEndpointFunc func(info *BaseEndpointInfo) Endpoint

// EndpointsMap maps a service name to a list of all its Endpoints.
type EndpointsMap map[ServicePortName][]Endpoint

// Merge ensures that the current EndpointsMap contains all <service, endpoints> pairs from the EndpointsMap passed in.
func (em EndpointsMap) merge(other EndpointsMap) {
	for svcPortName := range other {
		em[svcPortName] = other[svcPortName]
	}
}

// Unmerge removes the <service, endpoints> pairs from the current EndpointsMap which are contained in the EndpointsMap passed in.
func (em EndpointsMap) unmerge(other EndpointsMap) {
	for svcPortName := range other {
		delete(em, svcPortName)
	}
}

// GetLocalEndpointIPs returns endpoints IPs if given endpoint is local - local means the endpoint is running in same host as kube-proxy.
func (em EndpointsMap) getLocalEndpointIPs() map[types.NamespacedName]sets.String {
	localIPs := make(map[types.NamespacedName]sets.String)
	for svcPortName, epList := range em {
		for _, ep := range epList {
			if ep.GetIsLocal() {
				nsn := svcPortName.NamespacedName
				if localIPs[nsn] == nil {
					localIPs[nsn] = sets.NewString()
				}
				localIPs[nsn].Insert(ep.IP())
			}
		}
	}
	return localIPs
}

// detectStaleConnections modifies <staleEndpoints> and <staleServices> with detected stale connections. <staleServiceNames>
// is used to store stale udp service in order to clear udp conntrack later.
func detectStaleConnections(oldEndpointsMap, newEndpointsMap EndpointsMap, staleEndpoints *[]ServiceEndpoint, staleServiceNames *[]ServicePortName) {
	for svcPortName, epList := range oldEndpointsMap {
		if svcPortName.Protocol != v1.ProtocolUDP {
			continue
		}

		for _, ep := range epList {
			stale := true
			for i := range newEndpointsMap[svcPortName] {
				if newEndpointsMap[svcPortName][i].Equal(ep) {
					stale = false
					break
				}
			}
			if stale {
				klog.V(4).Infof("Stale endpoint %v -> %v", svcPortName, ep.String())
				*staleEndpoints = append(*staleEndpoints, ServiceEndpoint{Endpoint: ep.String(), ServicePortName: svcPortName})
			}
		}
	}

	for svcPortName, epList := range newEndpointsMap {
		if svcPortName.Protocol != v1.ProtocolUDP {
			continue
		}

		// For udp service, if its backend changes from 0 to non-0. There may exist a conntrack entry that could blackhole traffic to the service.
		if len(epList) > 0 && len(oldEndpointsMap[svcPortName]) == 0 {
			*staleServiceNames = append(*staleServiceNames, svcPortName)
		}
	}
}

// internal struct for endpoints information
type endpointsInfo struct {
	*BaseEndpointInfo
	protocol v1.Protocol
}

// returns a new proxy.Endpoint which abstracts a endpointsInfo
func newEndpointInfo(baseInfo *BaseEndpointInfo, protocol v1.Protocol) Endpoint {
	return &endpointsInfo{BaseEndpointInfo: baseInfo, protocol: protocol}
}
