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
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// cache defines a struct to store latest version of the seen service or endpoint. Once a service/endpoint add received
// and processed (ServicePorts are created), it will be added to cache map with key
// types.NamespacedName of a service/endpoint.
type cache struct {
	sync.Mutex
	svcCache map[types.NamespacedName]*v1.Service
	epCache  map[types.NamespacedName]*v1.Endpoints
}

// getCachedSvcVersion return version of stored service
func (svc *cache) getCachedSvcVersion(name, namespace string) (string, error) {
	svc.Lock()
	defer svc.Unlock()
	s, ok := svc.svcCache[types.NamespacedName{Name: name, Namespace: namespace}]
	if !ok {
		return "", fmt.Errorf("service %s/%s not found in the cache", namespace, name)
	}

	return s.ObjectMeta.GetResourceVersion(), nil
}

// getLastKnownSvcFromCache return pointer to the latest known/stored instance of the service
func (svc *cache) getLastKnownSvcFromCache(name, namespace string) (*v1.Service, error) {
	svc.Lock()
	defer svc.Unlock()
	s, ok := svc.svcCache[types.NamespacedName{Name: name, Namespace: namespace}]
	if !ok {
		return nil, fmt.Errorf("service %s/%s not found in the cache", namespace, name)
	}

	return s, nil
}

// storeSvcInCache stores in the cache instance of a service, if cache does not have already
// service, it will be added, if it already has, iy will be replaced with the one passed
// as a parameter.
func (svc *cache) storeSvcInCache(s *v1.Service) {
	svc.Lock()
	defer svc.Unlock()
	if _, ok := svc.svcCache[types.NamespacedName{Name: s.ObjectMeta.Name, Namespace: s.ObjectMeta.Namespace}]; ok {
		delete(svc.svcCache, types.NamespacedName{Name: s.ObjectMeta.Name, Namespace: s.ObjectMeta.Namespace})
	}
	svc.svcCache[types.NamespacedName{Name: s.ObjectMeta.Name, Namespace: s.ObjectMeta.Namespace}] = s
}

// removeSvcFromCache removes stored service from cache.
func (svc *cache) removeSvcFromCache(name, namespace string) {
	svc.Lock()
	defer svc.Unlock()
	if _, ok := svc.svcCache[types.NamespacedName{Name: name, Namespace: namespace}]; ok {
		delete(svc.svcCache, types.NamespacedName{Name: name, Namespace: namespace})
	}
}
