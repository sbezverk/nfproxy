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
	"net"

	"github.com/sbezverk/nfproxy/pkg/nftables"
	"k8s.io/klog"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	apiservice "k8s.io/kubernetes/pkg/api/v1/service"
)

// BaseServiceInfo contains base information that defines a service.
// This could be used directly by proxier while processing services,
// or can be used for constructing a more specific ServiceInfo struct
// defined by the proxier if needed.
type BaseServiceInfo struct {
	svcName                  string
	svcNamespace             string
	ipFamily                 v1.IPFamily
	clusterIP                net.IP
	port                     int
	protocol                 v1.Protocol
	nodePort                 int
	loadBalancerStatus       v1.LoadBalancerStatus
	sessionAffinityType      v1.ServiceAffinity
	stickyMaxAgeSeconds      int
	externalIPs              []string
	loadBalancerSourceRanges []string
	healthCheckNodePort      int
	onlyNodeLocalEndpoints   bool
	topologyKeys             []string
	svcnft                   *nftables.SVCnft
}

var _ ServicePort = &BaseServiceInfo{}

// String is part of ServicePort interface.
func (info *BaseServiceInfo) String() string {
	return fmt.Sprintf("%s:%s:%d/%s", info.ipFamily, info.clusterIP, info.port, info.protocol)
}

// ClusterIP is part of ServicePort interface.
func (info *BaseServiceInfo) ClusterIP() net.IP {
	return info.clusterIP
}

// Port is part of ServicePort interface.
func (info *BaseServiceInfo) Port() int {
	return info.port
}

// SessionAffinityType is part of the ServicePort interface.
func (info *BaseServiceInfo) SessionAffinityType() v1.ServiceAffinity {
	return info.sessionAffinityType
}

// StickyMaxAgeSeconds is part of the ServicePort interface
func (info *BaseServiceInfo) StickyMaxAgeSeconds() int {
	return info.stickyMaxAgeSeconds
}

// Protocol is part of ServicePort interface.
func (info *BaseServiceInfo) Protocol() v1.Protocol {
	return info.protocol
}

// LoadBalancerSourceRanges is part of ServicePort interface
func (info *BaseServiceInfo) LoadBalancerSourceRanges() []string {
	return info.loadBalancerSourceRanges
}

// HealthCheckNodePort is part of ServicePort interface.
func (info *BaseServiceInfo) HealthCheckNodePort() int {
	return info.healthCheckNodePort
}

// NodePort is part of the ServicePort interface.
func (info *BaseServiceInfo) NodePort() int {
	return info.nodePort
}

// ExternalIPStrings is part of ServicePort interface.
func (info *BaseServiceInfo) ExternalIPStrings() []string {
	return info.externalIPs
}

// LoadBalancerIPStrings is part of ServicePort interface.
func (info *BaseServiceInfo) LoadBalancerIPStrings() []string {
	var ips []string
	for _, ing := range info.loadBalancerStatus.Ingress {
		ips = append(ips, ing.IP)
	}
	return ips
}

// OnlyNodeLocalEndpoints is part of ServicePort interface.
func (info *BaseServiceInfo) OnlyNodeLocalEndpoints() bool {
	return info.onlyNodeLocalEndpoints
}

// TopologyKeys is part of ServicePort interface.
func (info *BaseServiceInfo) TopologyKeys() []string {
	return info.topologyKeys
}

// ServiceMap maps a service to its ServicePort.
type ServiceMap map[ServicePortName]ServicePort

// internal struct for string service information
type serviceInfo struct {
	*BaseServiceInfo
	serviceNameString string
}

// returns a new proxy.ServicePort which abstracts a serviceInfo
func newServiceInfo(port *v1.ServicePort, service *v1.Service, baseInfo *BaseServiceInfo) ServicePort {
	info := &serviceInfo{BaseServiceInfo: baseInfo}

	// Store the following for performance reasons.
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	svcPortName := ServicePortName{NamespacedName: svcName, Port: port.Name}
	info.serviceNameString = svcPortName.String()

	return info
}

func newBaseServiceInfo(port *v1.ServicePort, service *v1.Service) *BaseServiceInfo {
	onlyNodeLocalEndpoints := false
	if apiservice.RequestsOnlyLocalTraffic(service) {
		onlyNodeLocalEndpoints = true
	}
	var stickyMaxAgeSeconds int
	if service.Spec.SessionAffinity == v1.ServiceAffinityClientIP {
		// Kube-apiserver side guarantees SessionAffinityConfig won't be nil when session affinity type is ClientIP
		stickyMaxAgeSeconds = int(*service.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds)
	}
	info := &BaseServiceInfo{
		svcName:      service.ObjectMeta.Name,
		svcNamespace: service.ObjectMeta.Namespace,
		clusterIP:    net.ParseIP(service.Spec.ClusterIP),
		port:         int(port.Port),
		protocol:     port.Protocol,
		nodePort:     int(port.NodePort),
		// Deep-copy in case the service instance changes
		loadBalancerStatus:     *service.Status.LoadBalancer.DeepCopy(),
		sessionAffinityType:    service.Spec.SessionAffinity,
		stickyMaxAgeSeconds:    stickyMaxAgeSeconds,
		onlyNodeLocalEndpoints: onlyNodeLocalEndpoints,
		//		topologyKeys:           service.Spec.TopologyKeys,
		svcnft: &nftables.SVCnft{},
	}
	if service.Spec.IPFamily != nil {
		info.ipFamily = *service.Spec.IPFamily
	} else {
		info.ipFamily = v1.IPv4Protocol
	}

	info.externalIPs = make([]string, len(service.Spec.ExternalIPs))
	info.loadBalancerSourceRanges = make([]string, len(service.Spec.LoadBalancerSourceRanges))
	copy(info.loadBalancerSourceRanges, service.Spec.LoadBalancerSourceRanges)
	copy(info.externalIPs, service.Spec.ExternalIPs)

	if apiservice.NeedsHealthCheck(service) {
		p := service.Spec.HealthCheckNodePort
		if p == 0 {
			klog.Errorf("Service %s/%s has no healthcheck nodeport", service.Namespace, service.Name)
		} else {
			info.healthCheckNodePort = int(p)
		}
	}

	return info
}
