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
	"net"
	"net/url"
	"strconv"
	"strings"

	utilnftables "github.com/google/nftables"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilnet "k8s.io/utils/net"
)

// BootstrapRules programs rules so the controller could reach API server
// when it runs "in-cluster" mode.
func BootstrapRules(p Proxy, inHost, inPort string, extEndpoint *url.URL, endpointSlice bool) error {
	// TODO (sbezverk) Consider adding ip address validation
	extHost, extPort, _ := net.SplitHostPort(extEndpoint.Host)
	epn, _ := strconv.Atoi(extPort)
	e32p := int32(epn)
	ipn, _ := strconv.Atoi(inPort)
	i32p := int32(ipn)
	ipFamily, _ := getIPFamily(inHost)

	svc := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubernetes",
			Namespace: "default",
		},
		Spec: v1.ServiceSpec{
			IPFamilies: []v1.IPFamily{ipFamily},
			Ports: []v1.ServicePort{
				{
					Name:     extEndpoint.Scheme,
					Protocol: v1.ProtocolTCP,
					// API Server's internal port number
					Port:       i32p,
					TargetPort: intstr.FromString(inPort),
				},
			},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: inHost,
		},
	}
	p.AddService(&svc)
	if endpointSlice {
		ready := true
		name := extEndpoint.Scheme
		proto := v1.ProtocolTCP
		// Todo (sbezverk) must be passed as a parameter
		label := map[string]string{
			discovery.LabelServiceName: "kubernetes",
		}
		epsl := discovery.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kubernetes",
				Namespace: "default",
				Labels:    label,
			},
			Endpoints: []discovery.Endpoint{
				{
					// External API server IP
					Addresses: []string{extHost},
					Conditions: discovery.EndpointConditions{
						Ready: &ready,
					},
				},
			},
			Ports: []discovery.EndpointPort{
				{
					Name:     &name,
					Protocol: &proto,
					// External API server ports it listens on
					Port: &e32p,
				},
			},
		}

		epsl.AddressType = discovery.AddressTypeIPv4
		if ipFamily == v1.IPv6Protocol {
			epsl.AddressType = discovery.AddressTypeIPv6
		}
		p.AddEndpointSlice(&epsl)
	} else {
		endpoint := v1.Endpoints{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kubernetes",
				Namespace: "default",
			},
			Subsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{
						{
							IP: extHost,
						},
					},
					Ports: []v1.EndpointPort{
						{
							Name:     extEndpoint.Scheme,
							Protocol: v1.ProtocolTCP,
							Port:     e32p,
						},
					},
				},
			},
		}
		p.AddEndpoints(&endpoint)
	}

	return nil
}

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

func isPortInSubset(subsets []v1.EndpointSubset, port *v1.EndpointPort, addr *v1.EndpointAddress) bool {
	for _, s := range subsets {
		for _, subsetAddr := range s.Addresses {
			for _, p := range s.Ports {
				if p.Name == port.Name && p.Port == port.Port && p.Protocol == port.Protocol && strings.Compare(subsetAddr.IP, addr.IP) == 0 {
					return true
				}
			}
		}
		for _, subsetAddr := range s.NotReadyAddresses {
			for _, p := range s.Ports {
				if p.Name == port.Name && p.Port == port.Port && p.Protocol == port.Protocol && strings.Compare(subsetAddr.IP, addr.IP) == 0 {
					return true
				}
			}
		}
	}
	return false
}

// isPortInEndpointSlice looks for address/port pair, if found it returns true for found and also the ready state of endpoint in the slice
func isPortInEndpointSlice(epsl *discovery.EndpointSlice, port *v1.EndpointPort, address *v1.EndpointAddress) (bool, bool) {
	for _, e := range epsl.Endpoints {
		for _, p := range epsl.Ports {
			checkName := ""
			if p.Name != nil {
				checkName = *p.Name
			}
			checkPort := int32(0)
			if p.Port != nil {
				checkPort = *p.Port
			}
			var checkProto v1.Protocol
			if p.Protocol != nil {
				checkProto = *p.Protocol
			}
			if checkName == port.Name && checkPort == port.Port && checkProto == port.Protocol {
				for _, addr := range e.Addresses {
					if strings.Compare(addr, address.IP) == 0 {
						return *e.Conditions.Ready, true
					}
				}
			}
		}
	}

	return false, false
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

func compareSliceOfString(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if strings.Compare(a[i], b[i]) != 0 {
			return false
		}
	}

	return true
}

func isStringInSlice(a string, b []string) bool {
	for _, s := range b {
		if strings.Compare(a, s) == 0 {
			return true
		}
	}

	return false
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
