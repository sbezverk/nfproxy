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
	"reflect"
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"
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
func (c *cache) getCachedSvcVersion(name, namespace string) (string, error) {
	c.Lock()
	defer c.Unlock()
	s, ok := c.svcCache[types.NamespacedName{Name: name, Namespace: namespace}]
	if !ok {
		return "", fmt.Errorf("service %s/%s not found in the cache", namespace, name)
	}

	return s.ObjectMeta.GetResourceVersion(), nil
}

// getLastKnownSvcFromCache return pointer to the latest known/stored instance of the service
func (c *cache) getLastKnownSvcFromCache(name, namespace string) (*v1.Service, error) {
	klog.V(6).Infof("retrieving service %s/%s from the cache", namespace, name)
	c.Lock()
	defer c.Unlock()
	s, ok := c.svcCache[types.NamespacedName{Name: name, Namespace: namespace}]
	if !ok {
		return nil, fmt.Errorf("service %s/%s not found in the cache", namespace, name)
	}

	return s.DeepCopy(), nil
}

// storeSvcInCache stores in the cache instance of a service, if cache does not have already
// service, it will be added, if it already has, iy will be replaced with the one passed
// as a parameter.
func (c *cache) storeSvcInCache(s *v1.Service) {
	klog.V(6).Infof("storing service %s/%s in the cache", s.ObjectMeta.Namespace, s.ObjectMeta.Name)
	c.Lock()
	defer c.Unlock()
	c.svcCache[types.NamespacedName{Name: s.ObjectMeta.Name, Namespace: s.ObjectMeta.Namespace}] = s.DeepCopy()
	stored := c.svcCache[types.NamespacedName{Name: s.ObjectMeta.Name, Namespace: s.ObjectMeta.Namespace}]
	if !reflect.DeepEqual(s, stored) {
		klog.Errorf("mismatch detected between stored: %+v and original service: %+v", stored, s)
	}
}

// removeSvcFromCache removes stored service from cache.
func (c *cache) removeSvcFromCache(name, namespace string) {
	klog.V(6).Infof("removing service %s/%s from the cache", namespace, name)
	c.Lock()
	defer c.Unlock()
	if _, ok := c.svcCache[types.NamespacedName{Name: name, Namespace: namespace}]; ok {
		delete(c.svcCache, types.NamespacedName{Name: name, Namespace: namespace})
	} else {
		klog.Warningf("service %s/%s not found in the cache", namespace, name)
	}
}

// getCachedEpVersion return version of stored endpoint
func (c *cache) getCachedEpVersion(name, namespace string) (string, error) {
	c.Lock()
	defer c.Unlock()
	ep, ok := c.epCache[types.NamespacedName{Name: name, Namespace: namespace}]
	if !ok {
		return "", fmt.Errorf("endpoint %s/%s not found in the cache", namespace, name)
	}

	return ep.ObjectMeta.GetResourceVersion(), nil
}

// getLastKnownEpFromCache return pointer to the latest known/stored instance of the endpoint
func (c *cache) getLastKnownEpFromCache(name, namespace string) (*v1.Endpoints, error) {
	c.Lock()
	defer c.Unlock()
	ep, ok := c.epCache[types.NamespacedName{Name: name, Namespace: namespace}]
	if !ok {
		return nil, fmt.Errorf("endpoint %s/%s not found in the cache", namespace, name)
	}

	return ep.DeepCopy(), nil
}

// storeEpInCache stores in the cache instance of a endpoint, if cache does not have already
// endpoint, it will be added, if it already has, iy will be replaced with the one passed
// as a parameter.
func (c *cache) storeEpInCache(ep *v1.Endpoints) {
	c.Lock()
	defer c.Unlock()
	c.epCache[types.NamespacedName{Name: ep.ObjectMeta.Name, Namespace: ep.ObjectMeta.Namespace}] = ep.DeepCopy()
}

// removeEpFromCache removes stored service from cache.
func (c *cache) removeEpFromCache(name, namespace string) {
	c.Lock()
	defer c.Unlock()
	if _, ok := c.svcCache[types.NamespacedName{Name: name, Namespace: namespace}]; ok {
		delete(c.svcCache, types.NamespacedName{Name: name, Namespace: namespace})
	} else {
		klog.Warningf("endpoint %s/%s not found in the cache", namespace, name)
	}
}
