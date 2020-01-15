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
	utilnftables "github.com/google/nftables"
	"github.com/sbezverk/nfproxy/pkg/nftables"
)

// addServicePortToSets adds Service Port's Proto.Daddr.Port to cluster ip set, external ip set and
// loadbalance ip set.
func (p *proxy) addServicePortToSets(servicePort ServicePort, tableFamily utilnftables.TableFamily, svcID string) error {
	proto := servicePort.Protocol()
	port := uint16(servicePort.Port())
	clusterIP := servicePort.ClusterIP().String()
	// cluster IP needs to be added to 2 sets, to K8sClusterIPSet and if masquarade-all is true
	// then it needs to be added to K8sMarkMasqSet
	if err := nftables.AddToSet(p.nfti, tableFamily, proto, clusterIP, port, nftables.K8sClusterIPSet, nftables.K8sSvcPrefix+svcID); err != nil {
		return err
	}
	if err := nftables.AddToSet(p.nfti, tableFamily, proto, clusterIP, port, nftables.K8sMarkMasqSet, nftables.K8sNATDoMarkMasq); err != nil {
		return err
	}

	if extIPs := servicePort.ExternalIPStrings(); len(extIPs) != 0 {
		for _, extIP := range extIPs {
			if err := nftables.AddToSet(p.nfti, tableFamily, proto, extIP, port, nftables.K8sExternalIPSet, nftables.K8sSvcPrefix+svcID); err != nil {
				return err
			}
			if err := nftables.AddToSet(p.nfti, tableFamily, proto, extIP, port, nftables.K8sMarkMasqSet, nftables.K8sNATDoMarkMasq); err != nil {
				return err
			}
		}
	}
	if lbIPs := servicePort.LoadBalancerIPStrings(); len(lbIPs) != 0 {
		for _, lbIP := range lbIPs {
			if err := nftables.AddToSet(p.nfti, tableFamily, proto, lbIP, port, nftables.K8sLoadbalancerIPSet, nftables.K8sSvcPrefix+svcID); err != nil {
				return err
			}
			if err := nftables.AddToSet(p.nfti, tableFamily, proto, lbIP, port, nftables.K8sMarkMasqSet, nftables.K8sNATDoMarkMasq); err != nil {
				return err
			}
		}
	}
	if nodePort := servicePort.NodePort(); nodePort != 0 {
		if err := nftables.AddToNodeportSet(p.nfti, tableFamily, proto, uint16(nodePort), nftables.K8sSvcPrefix+svcID); err != nil {
			return err
		}
	}

	return nil
}

// addServicePortToSets adds Service Port's Proto.Daddr.Port to cluster ip set, external ip set and
// loadbalance ip set.
func (p *proxy) removeServicePortFromSets(servicePort ServicePort, tableFamily utilnftables.TableFamily, svcID string) error {
	proto := servicePort.Protocol()
	port := uint16(servicePort.Port())
	clusterIP := servicePort.ClusterIP().String()
	// cluster IP needs to be added to 2 sets, to K8sClusterIPSet and if masquarade-all is true
	// then it needs to be added to K8sMarkMasqSet
	if err := nftables.RemoveFromSet(p.nfti, tableFamily, proto, clusterIP, port, nftables.K8sClusterIPSet, nftables.K8sSvcPrefix+svcID); err != nil {
		return err
	}
	if err := nftables.RemoveFromSet(p.nfti, tableFamily, proto, clusterIP, port, nftables.K8sMarkMasqSet, nftables.K8sNATDoMarkMasq); err != nil {
		return err
	}

	if extIPs := servicePort.ExternalIPStrings(); len(extIPs) != 0 {
		for _, extIP := range extIPs {
			if err := nftables.RemoveFromSet(p.nfti, tableFamily, proto, extIP, port, nftables.K8sExternalIPSet, nftables.K8sSvcPrefix+svcID); err != nil {
				return err
			}
			if err := nftables.RemoveFromSet(p.nfti, tableFamily, proto, extIP, port, nftables.K8sMarkMasqSet, nftables.K8sNATDoMarkMasq); err != nil {
				return err
			}
		}
	}
	if lbIPs := servicePort.LoadBalancerIPStrings(); len(lbIPs) != 0 {
		for _, lbIP := range lbIPs {
			if err := nftables.RemoveFromSet(p.nfti, tableFamily, proto, lbIP, port, nftables.K8sLoadbalancerIPSet, nftables.K8sSvcPrefix+svcID); err != nil {
				return err
			}
			if err := nftables.RemoveFromSet(p.nfti, tableFamily, proto, lbIP, port, nftables.K8sMarkMasqSet, nftables.K8sNATDoMarkMasq); err != nil {
				return err
			}
		}
	}

	return nil
}

// addToNoEndpointsList adds to No Endpoints set  all without Endponts Service Port's proto.daddr.port
func (p *proxy) addToNoEndpointsList(servicePort ServicePort, tableFamily utilnftables.TableFamily) error {
	proto := servicePort.Protocol()
	port := uint16(servicePort.Port())
	if err := nftables.AddToSet(p.nfti, tableFamily, proto, servicePort.ClusterIP().String(), port, nftables.K8sNoEndpointsSet, nftables.K8sFilterDoReject); err != nil {
		return err
	}
	if extIPs := servicePort.ExternalIPStrings(); len(extIPs) != 0 {
		for _, extIP := range extIPs {
			if err := nftables.AddToSet(p.nfti, tableFamily, proto, extIP, port, nftables.K8sNoEndpointsSet, nftables.K8sFilterDoReject); err != nil {
				return err
			}
		}
	}
	if lbIPs := servicePort.LoadBalancerIPStrings(); len(lbIPs) != 0 {
		for _, lbIP := range lbIPs {
			if err := nftables.AddToSet(p.nfti, tableFamily, proto, lbIP, port, nftables.K8sNoEndpointsSet, nftables.K8sFilterDoReject); err != nil {
				return err
			}
		}
	}

	return nil
}

// removeFromNoEndpointsList removes to No Endpoints List all IPs/port pairs of a specific servicePort
func (p *proxy) removeFromNoEndpointsList(servicePort ServicePort, tableFamily utilnftables.TableFamily) error {
	proto := servicePort.Protocol()
	port := uint16(servicePort.Port())
	if err := nftables.RemoveFromSet(p.nfti, tableFamily, proto, servicePort.ClusterIP().String(), port, nftables.K8sNoEndpointsSet, nftables.K8sFilterDoReject); err != nil {
		return err
	}
	if extIPs := servicePort.ExternalIPStrings(); len(extIPs) != 0 {
		for _, extIP := range extIPs {
			if err := nftables.RemoveFromSet(p.nfti, tableFamily, proto, extIP, port, nftables.K8sNoEndpointsSet, nftables.K8sFilterDoReject); err != nil {
				return err
			}
		}
	}
	if lbIPs := servicePort.LoadBalancerIPStrings(); len(lbIPs) != 0 {
		for _, lbIP := range lbIPs {
			if err := nftables.RemoveFromSet(p.nfti, tableFamily, proto, lbIP, port, nftables.K8sNoEndpointsSet, nftables.K8sFilterDoReject); err != nil {
				return err
			}
		}
	}

	return nil
}
