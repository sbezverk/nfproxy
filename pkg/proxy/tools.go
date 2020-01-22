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
	"crypto/sha256"
	"encoding/base32"

	utilnftables "github.com/google/nftables"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilnet "k8s.io/utils/net"
)

// This is the same as servicePortChainName but with the endpoint included.
func servicePortEndpointChainName(servicePortName string, protocol string, endpoint string) string {
	hash := sha256.Sum256([]byte(servicePortName + protocol + endpoint))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return "k8s-nfproxy-sep-" + encoded[:16]
}

func servicePortSvcID(servicePortName string, protocol string, service string) string {
	hash := sha256.Sum256([]byte(servicePortName + protocol + service))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return encoded[:16]
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

// isServicePortInPorts checks if specified ServicePort exists in provided ServicePort slice
// and return index in the slice and true if found.
// ServicePort name and protocol are checked to determine if ServicePort exists
func isServicePortInPorts(ports []v1.ServicePort, servicePort *v1.ServicePort) (int, bool) {
	// First pass to check for matching name
	for i := 0; i < len(ports); i++ {
		if servicePort.Name == ports[i].Name {
			// Found match by name
			return i, true
		}
	}
	// In case if Port's name was changed for God knows what reasons
	// trying to match for Protocol and Port pair
	for i := 0; i < len(ports); i++ {
		if servicePort.Protocol == ports[i].Protocol &&
			servicePort.Port == ports[i].Port {
			return i, true
		}
	}

	// Port has not been found in the provided slice, indicating that it is either a new port
	// or delete port.
	return 0, false
}
