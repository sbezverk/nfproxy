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
	"time"

	utilnftables "github.com/google/nftables"
	"github.com/sbezverk/nfproxy/pkg/nftables"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"
	utilproxy "k8s.io/kubernetes/pkg/proxy/util"
	utilnet "k8s.io/utils/net"
)

func (p *proxy) AddService(svc *v1.Service) {
	s := time.Now()
	defer klog.V(5).Infof("AddService for a service %s/%s ran for: %d nanoseconds", svc.Namespace, svc.Name, time.Since(s))
	// Storing new service in the cache for later reference
	p.cache.storeSvcInCache(svc)
	klog.V(5).Infof("AddService for a service %s/%s", svc.Namespace, svc.Name)
	if svc == nil {
		return
	}
	klog.V(6).Infof("AddService for a service Spec: %+v Status: %+v", svc.Spec, svc.Status)
	if svc.Spec.SessionAffinity == v1.ServiceAffinityClientIP {
		stickySeconds := int(*svc.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds)
		klog.V(5).Infof("Service %s/%s has SessionAffinity set for %d seconds", svc.Namespace, svc.Name, stickySeconds)
	}
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
	klog.V(5).Infof("add Service Port Name: %+v", svcPortName)
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
	baseSvcInfo.svcnft.ServiceID = svcID
	baseSvcInfo.svcnft.Chains = nftables.GetSvcChain(tableFamily, svcID)
	// Check if new ServicePort requests Affinity, get the timeout then
	if svc.Spec.SessionAffinity == v1.ServiceAffinityClientIP {
		baseSvcInfo.svcnft.WithAffinity = true
		baseSvcInfo.svcnft.MaxAgeSeconds = int(*svc.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds)
	}
	// Check if new ServicePort already has or not corresponding endpoints entries, if not then
	// ServicePort is added to No Endpoint set.
	if len(p.endpointsMap[svcPortName]) == 0 {
		klog.V(5).Infof("Service Port Name: %+v has no endpoints", svcPortName)
		if err := p.addToNoEndpointsList(baseSvcInfo, tableFamily); err != nil {
			klog.Errorf("failed to add %s to No Endpoints Set with error: %+v", svcPortName.String(), err)
		}
		baseSvcInfo.svcnft.WithEndpoints = false
	} else {
		klog.V(5).Infof("Service Port Name: %+v has %d endpoints", svcPortName, len(p.endpointsMap[svcPortName]))
		baseSvcInfo.svcnft.WithEndpoints = true
	}
	// Creating a set of chains (k8s-nfproxy-svc-{svcID}, k8s-nfproxy-fw-{svcID}, k8s-nfproxy-xlb-{svcID}) for a service port
	if err := nftables.AddServiceChains(p.nfti, tableFamily, svcID); err != nil {
		klog.Errorf("failed to add service port %s chains with error: %+v", svcPortName.String(), err)
		return
	}
	if baseSvcInfo.svcnft.WithAffinity {
		klog.V(6).Infof("Service Port: %+v needs Session Affinity rules", svcPortName)
		if err := nftables.AddServiceAffinityMap(p.nfti, tableFamily, svcID, baseSvcInfo.svcnft.MaxAgeSeconds); err != nil {
			klog.Errorf("failed to add service affinity map for port %s with error: %+v", svcPortName.String(), err)
			return
		}
		// Since ServicePort now has Service Affinity configuration, need to check if it has already Endpoints and if it is the case
		// each Endpoint needs "Update" rule to be inserted as a very first rule.
		if baseSvcInfo.svcnft.WithEndpoints {
			eps, _ := p.endpointsMap[svcPortName]
			klog.V(6).Infof("Service Port %+v needs its %d endpoint(s) to be programmed with update rule", svcPortName, len(eps))
			if err := p.addAffinityEndpoint(eps, tableFamily, svcID, baseSvcInfo.svcnft.MaxAgeSeconds); err != nil {
				klog.Errorf("failed to add endpoint affinity update rule for port %s with error: %+v", svcPortName.String(), err)
			}
		}
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

func (p *proxy) DeleteService(svc *v1.Service) {
	s := time.Now()
	defer klog.V(5).Infof("DeleteService for a service %s/%s ran for: %d nanoseconds", svc.Namespace, svc.Name, time.Since(s))
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
	klog.V(6).Infof("deleting service port: %s for service: %s/%s", svcPortName.String(), svc.Namespace, svc.Name)
	// Creating new baseinfo based on the current state of the service port

	//	baseInfo := newBaseServiceInfo(servicePort, svc)
	// Storing state of Endpoints in new baseinfo for proper cleanup from no-endpoint set
	baseInfo := svcInfo.(*serviceInfo).BaseServiceInfo

	//	baseInfo.svcnft = svcInfo.(*serviceInfo).BaseServiceInfo.svcnft
	//	baseInfo.svcName = svcInfo.(*serviceInfo).BaseServiceInfo.svcName
	//	baseInfo.svcNamespace = svcInfo.(*serviceInfo).BaseServiceInfo.svcNamespace
	_, tableFamily := getIPFamily(baseInfo.ClusterIP().String())

	if !baseInfo.svcnft.WithEndpoints {
		// svcPortName does not have any endpoints, need to remove service entry from "No endpointd Set"
		if err := p.removeFromNoEndpointsList(baseInfo, tableFamily); err != nil {
			klog.Errorf("failed to remove %s from \"No Endpoints Set\" with error: %+v", svcPortName.String(), err)
		}
	}
	// Remove svcPortName related chains and rules
	// Populting cluster, external and loadbalancer sets with Service Port information
	if err := p.removeServicePortFromSets(baseInfo, tableFamily, baseInfo.svcnft.ServiceID); err != nil {
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
	if baseInfo.svcnft.WithAffinity {
		if baseInfo.svcnft.WithEndpoints {
			eps, _ := p.endpointsMap[svcPortName]
			if err := p.deleteAffinityEndpoint(eps, tableFamily); err != nil {
				klog.Errorf("failed to delete endpoint affinity update rule for port %s with error: %+v", svcPortName.String(), err)
				return
			}
		}
		if err := nftables.DeleteServiceAffinityMap(p.nfti, tableFamily, baseInfo.svcnft.ServiceID); err != nil {
			klog.Errorf("failed to delete service affinity map for port %s with error: %+v", svcPortName.String(), err)
			return
		}
	}
	// Removing service port specific chains
	if err := nftables.DeleteServiceChains(p.nfti, tableFamily, baseInfo.svcnft.ServiceID); err != nil {
		klog.Errorf("failed to delete chains for service port name: %s with error: %+v", svcPortName.String(), err)
	}

	// Delete svcPortName from known svcPortName map
	delete(p.serviceMap, svcPortName)
}

// TODO (sbezverk) Add update logic when Spec's fields example ExternalIPs, LoadbalancerIP etc are updated.
func (p *proxy) UpdateService(svcOld, svcNew *v1.Service) {
	s := time.Now()
	defer klog.V(5).Infof("UpdateService for a service %s/%s ran for: %d nanoseconds", svcNew.Namespace, svcNew.Name, time.Since(s))
	klog.V(5).Infof("UpdateService for a service %s/%s", svcNew.Namespace, svcNew.Name)
	klog.V(6).Infof("Spec Old: %+v Spec New: %+v", svcOld.Spec, svcNew.Spec)
	klog.V(7).Infof("Status Old: %+v Status New: %+v", svcOld.Status, svcNew.Status)
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
	p.processServicePortChanges(svcNew, storedSvc)
	// Step 2 Check for change of ClusterIP address
	p.processClusterIPChanges(svcNew, storedSvc)
	// Step 3 is to detect changes for External IPs; add new and remove old ones
	p.processExternalIPChanges(svcNew, storedSvc)
	// Step 4 is to detect changes for LoadBalancer IPs; add new and remove old ones
	p.processLoadBalancerIPChange(svcNew, storedSvc)
	// Step 5 is to detect changes in Service Affinity
	p.processAffinityChange(svcNew, storedSvc)

	// TODO (sbezverk) Check for changes for ServicePort's NodePort.

	// Update service in cache after applying all changes
	p.cache.storeSvcInCache(svcNew)
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
			klog.V(6).Infof("Service Port Name %s had not been found, it has been added.", svcPortName)
			continue
		}
		// If ServicePortName does not match, it means Protocol/Port pair has not been changed,
		// otherwise ServicePort would not have been found.
		// Changes of Port.Name or Port.Protocol result in a new ServicePortName generated, hence the old one
		// needs to be replaced.
		oldServicePortName := getSvcPortName(storedSvc.Name, storedSvc.Namespace, storedSvc.Spec.Ports[id].Name, storedSvc.Spec.Ports[id].Protocol)
		if storedSvc.Spec.Ports[id].Name != servicePort.Name {
			// ServicePortName change is a major change as ServicePortName is used to generate chain names
			// it is safer to remove it and add a new one after.
			p.deleteServicePort(oldServicePortName, &storedSvc.Spec.Ports[id], storedSvc)
			p.addServicePort(svcPortName, servicePort, svcNew, baseSvcInfo)
			klog.V(6).Infof("Service Port Name was changed from %s to %s and old %s was removed.", oldServicePortName, svcPortName, oldServicePortName)
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
			klog.V(6).Infof("Service Port Name was changed from %s to %s and old %s was removed.", oldServicePortName, svcPortName, oldServicePortName)
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

// processClusterIPChanges is called from the service Update handler, it checks for achange in
// ClusterIP and re-program new entries for all ServicePorts.
func (p *proxy) processClusterIPChanges(svcNew *v1.Service, storedSvc *v1.Service) {
	if storedSvc.Spec.ClusterIP == svcNew.Spec.ClusterIP {
		return
	}
	if svcNew.Spec.ClusterIP != "" {
		addr := svcNew.Spec.ClusterIP
		klog.V(5).Infof("detected a new ClusterIP %s", addr)
		tableFamily := utilnftables.TableFamilyIPv4
		if utilnet.IsIPv6String(addr) {
			tableFamily = utilnftables.TableFamilyIPv6
		}
		for _, servicePort := range svcNew.Spec.Ports {
			svcPortName := getSvcPortName(svcNew.Name, svcNew.Namespace, servicePort.Name, servicePort.Protocol)
			svc := p.serviceMap[svcPortName].(*serviceInfo).BaseServiceInfo.String()
			svcID := servicePortSvcID(svcPortName.String(), string(servicePort.Protocol), svc)
			nftables.AddToSet(p.nfti, tableFamily, servicePort.Protocol, addr, uint16(servicePort.Port), nftables.K8sClusterIPSet, nftables.K8sSvcPrefix+svcID)
			//			nftables.AddToSet(p.nfti, tableFamily, servicePort.Protocol, addr, uint16(servicePort.Port), nftables.K8sMarkMasqSet, nftables.K8sNATDoMarkMasq)
		}
	}
	if storedSvc.Spec.ClusterIP != "" {
		addr := storedSvc.Spec.ClusterIP
		klog.V(5).Infof("detected deleted ClusterIP %s", addr)
		tableFamily := utilnftables.TableFamilyIPv4
		if utilnet.IsIPv6String(addr) {
			tableFamily = utilnftables.TableFamilyIPv6
		}
		for _, servicePort := range svcNew.Spec.Ports {
			svcPortName := getSvcPortName(svcNew.Name, svcNew.Namespace, servicePort.Name, servicePort.Protocol)
			svcBaseInfoString := p.serviceMap[svcPortName].(*serviceInfo).BaseServiceInfo.String()
			svcID := servicePortSvcID(svcPortName.String(), string(servicePort.Protocol), svcBaseInfoString)
			nftables.RemoveFromSet(p.nfti, tableFamily, servicePort.Protocol, addr, uint16(servicePort.Port), nftables.K8sClusterIPSet, nftables.K8sSvcPrefix+svcID)
			//			nftables.RemoveFromSet(p.nfti, tableFamily, servicePort.Protocol, addr, uint16(servicePort.Port), nftables.K8sMarkMasqSet, nftables.K8sNATDoMarkMasq)
		}
	}
}

// processExternalIPChanges is called from the service Update handler, it checks for any changes in
// ExternalIPs and re-program new entries for all ServicePorts.
func (p *proxy) processExternalIPChanges(svcNew *v1.Service, storedSvc *v1.Service) {
	if compareSliceOfString(storedSvc.Spec.ExternalIPs, svcNew.Spec.ExternalIPs) {
		return
	}
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

// processLoadBalancerIPChange is called from the service Update handler, it checks for any changes in
// LoadBalancer's IPs and re-program new entries for all ServicePorts.
func (p *proxy) processLoadBalancerIPChange(svcNew *v1.Service, storedSvc *v1.Service) {
	// Check if new and stored service status is equal or not, if equal no processing required
	if isIngressEqual(svcNew.Status.LoadBalancer.Ingress, storedSvc.Status.LoadBalancer.Ingress) {
		return
	}
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

// processAffinityChange is called from the service Update handler, it checks for changes in
// Affinity and re-program new entries for all ServicePort of the changed service.
func (p *proxy) processAffinityChange(svcNew *v1.Service, storedSvc *v1.Service) {
	if svcNew.Spec.SessionAffinity == storedSvc.Spec.SessionAffinity {
		return
	}
	klog.V(5).Infof("Change in Service Affinity of service %s/%s detected", svcNew.ObjectMeta.Namespace, svcNew.ObjectMeta.Name)
	_, tableFamily := getIPFamily(svcNew.Spec.ClusterIP)
	if svcNew.Spec.SessionAffinity == v1.ServiceAffinityClientIP {
		p.mu.Lock()
		defer p.mu.Unlock()
		klog.V(6).Infof("Adding Service Affinity to Service Ports")
		for _, servicePort := range svcNew.Spec.Ports {
			svcPortName := getSvcPortName(svcNew.Name, svcNew.Namespace, servicePort.Name, servicePort.Protocol)
			svc := p.serviceMap[svcPortName].(*serviceInfo).BaseServiceInfo.svcnft
			svcID := svc.ServiceID
			chain := nftables.K8sSvcPrefix + svcID
			maxAgeSeconds := svc.MaxAgeSeconds
			klog.V(6).Infof("Adding service affinity map for port: %s service ID: %s timeout: %d", svcPortName.String(), svcID, maxAgeSeconds)
			if err := nftables.AddServiceAffinityMap(p.nfti, tableFamily, svcID, maxAgeSeconds); err != nil {
				klog.Errorf("failed to add service affinity map for port %s with error: %+v", svcPortName.String(), err)
				continue
			}
			// Adding MatchAct rule to start using Service Port's Affinity map. This rule must be inserted before normal Load Balancing rule.
			id := svc.Chains[tableFamily].Chain[chain].RuleID[1]
			epchains := p.getServicePortEndpointChains(svcPortName, tableFamily)
			rid, err := nftables.AddServiceMatchActRule(p.nfti, tableFamily, svcID, epchains, id)
			if err != nil {
				klog.Errorf("failed to add MatchAct rule for port %s with error: %+v", svcPortName.String(), err)
				continue
			}
			// Rule removal succeeded, it is safe to remove MatchAct rule's handle from the chain's RuleID slice
			var temp []uint64
			temp = append(temp, svc.Chains[tableFamily].Chain[chain].RuleID[0])
			temp = append(temp, rid...)
			temp = append(temp, svc.Chains[tableFamily].Chain[chain].RuleID[1:]...)
			svc.Chains[tableFamily].Chain[chain].RuleID = temp
			// Since ServicePort now has Service Affinity configuration, need to check if it has already Endpoints and if it is the case
			// each Endpoint needs "Update" rule to be inserted as a very first rule.
			if !svc.WithEndpoints {
				continue
			}
			eps, _ := p.endpointsMap[svcPortName]
			if err := p.addAffinityEndpoint(eps, tableFamily, svcID, maxAgeSeconds); err != nil {
				klog.Errorf("failed to add endpoint affinity update rule for port %s with error: %+v", svcPortName.String(), err)
				continue
			}
			svc.WithAffinity = true
		}
		return
	}
	if svcNew.Spec.SessionAffinity == v1.ServiceAffinityNone {
		klog.V(5).Infof("Removing Service Affinity from Service Ports")
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, servicePort := range svcNew.Spec.Ports {
			svcPortName := getSvcPortName(svcNew.Name, svcNew.Namespace, servicePort.Name, servicePort.Protocol)
			svc := p.serviceMap[svcPortName].(*serviceInfo).BaseServiceInfo.svcnft
			svcID := svc.ServiceID
			chain := nftables.K8sSvcPrefix + svcID
			// Only if Service Port has endpoints, proceed with clenaing up Affinity related rules
			if svc.WithEndpoints {
				klog.V(5).Infof("Deleting service affinity MatchAct rule for port %s service ID: %s", svcPortName.String(), svcID)
				if len(svc.Chains[tableFamily].Chain[chain].RuleID) < 2 {
					klog.Errorf("failed to delete  MatchAct rule for port %s, rules slice's length is %d which is less than 2, it is a bug.", svcPortName.String(),
						len(svc.Chains[tableFamily].Chain[chain].RuleID))
					klog.Errorf("port %s, rules: %+v", svcPortName.String(), svc.Chains[tableFamily].Chain[chain].RuleID)
					continue
				}
				// Deleting MatchAct rule to go back to round robin load balancing, MatchAct rule is stored in chain's RuleID slice
				// by the index of 1, when Session Affinity is enabled.
				id := svc.Chains[tableFamily].Chain[chain].RuleID[1]
				if err := nftables.DeleteServiceRules(p.nfti, tableFamily, chain, []uint64{id}); err != nil {
					klog.Errorf("failed to delete  MatchAct rule for port %s with error: %+v", svcPortName.String(), err)
					continue
				}
				// Rule removal succeeded, it is safe to remove MatchAct rule's handle from the chain's RuleID slice
				var temp []uint64
				temp = append(temp, svc.Chains[tableFamily].Chain[chain].RuleID[0])
				// Since ServicePort now has Service Affinity configuration removed, need to check if it has already Endpoints and if it is the case
				// each Endpoint needs to have "Update" rule removed.
				eps, _ := p.endpointsMap[svcPortName]
				if err := p.deleteAffinityEndpoint(eps, tableFamily); err != nil {
					klog.Errorf("failed to delete endpoint affinity update rule for port %s with error: %+v", svcPortName.String(), err)
					continue
				}
				// Service Port chain has more than 2 rules if it has some endpoints, svc.WithEndpoints is true, hence adding other rules back to rules slice
				temp = append(temp, svc.Chains[tableFamily].Chain[chain].RuleID[2:]...)
				svc.Chains[tableFamily].Chain[chain].RuleID = temp
			}
			// There should be no more reference to Affinity map in any endpoints, it should be safe to delete it.
			klog.V(5).Infof("Deleting service affinity map %s for port %s", nftables.K8sAffinityMap+svcID, svcPortName.String())
			if err := nftables.DeleteServiceAffinityMap(p.nfti, tableFamily, svcID); err != nil {
				klog.Errorf("failed to delete service affinity map for port %s with error: %+v", svcPortName.String(), err)
				continue
			}
			// Cleanup completed, marking Service Port as without Session Affinity
			svc.WithAffinity = false
		}
	}
}
