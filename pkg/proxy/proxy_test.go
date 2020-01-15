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
	v1 "k8s.io/api/core/v1"
	"testing"
)

func TestIsServicePortInPorts(t *testing.T) {
	tests := []struct {
		name  string
		ports []v1.ServicePort
		port  v1.ServicePort
		found bool
	}{
		{
			name: "Match by port name",
			ports: []v1.ServicePort{
				{
					Name:     "app2-udp-port",
					Protocol: v1.ProtocolUDP,
					Port:     int32(808),
				},
				{
					Name:     "app2-tcp-port2",
					Protocol: v1.ProtocolTCP,
					Port:     int32(8080),
				},
				{
					Name:     "app2-tcp-port",
					Protocol: v1.ProtocolTCP,
					Port:     int32(808),
				},
			},
			port: v1.ServicePort{
				Name:     "app2-tcp-port",
				Protocol: v1.ProtocolTCP,
				Port:     int32(8087),
			},
			found: true,
		},
		{
			name: "Match by Protocol and Port",
			ports: []v1.ServicePort{
				{
					Name:     "app2-udp-port",
					Protocol: v1.ProtocolUDP,
					Port:     int32(808),
				},
				{
					Name:     "app2-tcp-port2",
					Protocol: v1.ProtocolTCP,
					Port:     int32(8080),
				},
				{
					Name:     "app2-tcp-port",
					Protocol: v1.ProtocolTCP,
					Port:     int32(808),
				},
			},
			port: v1.ServicePort{
				Name:     "app2-tcp-port3",
				Protocol: v1.ProtocolTCP,
				Port:     int32(8080),
			},
			found: true,
		},
		{
			name: "No Match, Port Name and Protocol changed",
			ports: []v1.ServicePort{
				{
					Name:     "app2-udp-port",
					Protocol: v1.ProtocolUDP,
					Port:     int32(808),
				},
				{
					Name:     "app2-tcp-port2",
					Protocol: v1.ProtocolTCP,
					Port:     int32(8080),
				},
				{
					Name:     "app2-tcp-port",
					Protocol: v1.ProtocolTCP,
					Port:     int32(808),
				},
			},
			port: v1.ServicePort{
				Name:     "app2-tcp-port3",
				Protocol: v1.ProtocolSCTP,
				Port:     int32(8080),
			},
			found: false,
		},
		{
			name: "No Match, Port Name and Port changed",
			ports: []v1.ServicePort{
				{
					Name:     "app2-udp-port",
					Protocol: v1.ProtocolUDP,
					Port:     int32(808),
				},
				{
					Name:     "app2-tcp-port2",
					Protocol: v1.ProtocolTCP,
					Port:     int32(8080),
				},
				{
					Name:     "app2-tcp-port",
					Protocol: v1.ProtocolTCP,
					Port:     int32(808),
				},
			},
			port: v1.ServicePort{
				Name:     "app2-tcp-port3",
				Protocol: v1.ProtocolTCP,
				Port:     int32(8087),
			},
			found: false,
		},
	}
	for _, tt := range tests {
		_, gotFound := isServicePortInPorts(tt.ports, &tt.port)
		if tt.found {
			if !gotFound {
				t.Errorf("Test: \"%s\" failed, supposed to find but did not", tt.name)
			}
		} else {
			if gotFound {
				t.Errorf("Test: \"%s\" failed, supposed not to find but did", tt.name)
			}
		}
	}
}
