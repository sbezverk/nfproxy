package proxy

import (
	"sync"

	"github.com/sbezverk/nftableslib"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"
	utilproxy "k8s.io/kubernetes/pkg/proxy/util"
	utilnet "k8s.io/utils/net"
)

// Proxy defines interface
type Proxy interface {
	AddService(svc *v1.Service)
	DeleteService(svc *v1.Service)
	UpdateService(svcOld, svcNew *v1.Service)
	AddEndpoints(ep *v1.Endpoints)
	DeleteEndpoints(ep *v1.Endpoints)
	UpdateEndpoints(epOld, epNew *v1.Endpoints)
}

func (p *proxy) AddService(svc *v1.Service) {
	if svc == nil {
		return
	}
	svcName := types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}
	if utilproxy.ShouldSkipService(svcName, svc) {
		return
	}
	for i := range svc.Spec.Ports {
		servicePort := &svc.Spec.Ports[i]
		svcPortName := ServicePortName{NamespacedName: svcName, Port: servicePort.Name, Protocol: servicePort.Protocol}
		baseSvcInfo := newBaseServiceInfo(servicePort, svc)
		klog.Infof("AddService service port name: %s   new service Info: %+v", svcPortName, newServiceInfo(servicePort, svc, baseSvcInfo))
		p.mu.Lock()
		p.serviceMap[svcPortName] = newServiceInfo(servicePort, svc, baseSvcInfo)
		p.mu.Unlock()
	}
}

func (p *proxy) DeleteService(svc *v1.Service) {

}
func (p *proxy) UpdateService(svcOld, svcNew *v1.Service) {

}
func (p *proxy) AddEndpoints(ep *v1.Endpoints) {
	for i := range ep.Subsets {
		ss := &ep.Subsets[i]
		for i := range ss.Ports {
			port := &ss.Ports[i]
			if port.Port == 0 {
				klog.Warningf("ignoring invalid endpoint port %s", port.Name)
				continue
			}
			svcPortName := ServicePortName{
				NamespacedName: types.NamespacedName{Namespace: ep.Namespace, Name: ep.Name},
				Port:           port.Name,
				Protocol:       port.Protocol,
			}
			for i := range ss.Addresses {
				addr := &ss.Addresses[i]
				if addr.IP == "" {
					klog.Warningf("ignoring invalid endpoint port %s with empty host", port.Name)
					continue
				}
				isLocal := addr.NodeName != nil && *addr.NodeName == p.hostname
				var ipFamily v1.IPFamily
				if utilnet.IsIPv6String(addr.IP) {
					ipFamily = v1.IPv6Protocol
				} else {
					ipFamily = v1.IPv4Protocol
				}
				baseEndpointInfo := newBaseEndpointInfo(ipFamily, port.Protocol, addr.IP, int(port.Port), isLocal, nil)
				klog.Infof("AddEndpoint: service port name: %s  new endpoint Info: %+v", svcPortName, newEndpointInfo(baseEndpointInfo, port.Protocol))
				p.endpointsMap[svcPortName] = append(p.endpointsMap[svcPortName], newEndpointInfo(baseEndpointInfo, port.Protocol))
			}
			klog.V(3).Infof("Setting endpoints for %q to %+v", svcPortName, formatEndpointsList(p.endpointsMap[svcPortName]))
		}
	}
}

func (p *proxy) DeleteEndpoints(ep *v1.Endpoints) {

}
func (p *proxy) UpdateEndpoints(epOld, epNew *v1.Endpoints) {

}

type proxy struct {
	hostname     string
	mu           sync.Mutex // protects the following fields
	serviceMap   ServiceMap
	endpointsMap EndpointsMap
	portsMap     map[utilproxy.LocalPort]utilproxy.Closeable
}

// NewProxy return a new instance of nfproxy
func NewProxy(ti nftableslib.TablesInterface, hostname string, recorder record.EventRecorder) Proxy {
	return &proxy{
		hostname:     hostname,
		portsMap:     make(map[utilproxy.LocalPort]utilproxy.Closeable),
		serviceMap:   make(ServiceMap),
		endpointsMap: make(EndpointsMap),
	}
}
