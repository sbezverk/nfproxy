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

package controller

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	informer "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	"github.com/sbezverk/nfproxy/pkg/proxy"
)

// Controller exposes methods for Services and Endpoints controllers
type Controller interface {
	Start()
	Stop()
}

type controller struct {
	services        informer.ServiceInformer
	servicesSynced  cache.InformerSynced
	endpoints       informer.EndpointsInformer
	endpointsSynced cache.InformerSynced

	epWatcher        watch.Interface
	svcWatcher       watch.Interface
	epWatcherCancel  context.CancelFunc
	svcWatcherCancel context.CancelFunc
	epWatcherCtx     context.Context
	svcWatcherCtx    context.Context
	proxy            proxy.Proxy
}

func (c *controller) handleAddService(obj interface{}) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
		return
	}
	c.proxy.AddService(svc)
}

func (c *controller) handleUpdateService(newObj interface{}) {
	svcNew, ok := newObj.(*v1.Service)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", newObj))
		return
	}
	c.proxy.UpdateService(svcNew)
}

func (c *controller) handleDeleteService(obj interface{}) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
			return
		}
		if _, ok = tombstone.Obj.(*v1.Service); !ok {
			utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
			return
		}
	}
	c.proxy.DeleteService(svc)
}

func (c *controller) handleAddEndpoint(obj interface{}) {
	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
		return
	}
	klog.V(5).Infof("controller received add endpoint event for %s/%s", ep.Namespace, ep.Name)
	c.proxy.AddEndpoints(ep)
}

func (c *controller) handleUpdateEndpoint(newObj interface{}) {
	epNew, ok := newObj.(*v1.Endpoints)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", newObj))
		return
	}
	c.proxy.UpdateEndpoints(epNew)
}

func (c *controller) handleDeleteEndpoint(obj interface{}) {
	if !c.endpointsSynced() {
		return
	}
	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
			return
		}
		if _, ok = tombstone.Obj.(*v1.Service); !ok {
			utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
			return
		}
	}
	c.proxy.DeleteEndpoints(ep)
}

func (c *controller) watchForEndpoints(epEvents watch.Interface) {
	var recv watch.Event
	var ok bool
	for {
		select {
		case recv, ok = <-epEvents.ResultChan():
			if !ok {
				klog.Info("endpoints watcher channel has been closed")
				return
			}
			switch recv.Type {
			case watch.Added:
				go c.handleAddEndpoint(recv.Object)
			case watch.Deleted:
				go c.handleDeleteEndpoint(recv.Object)
			case watch.Modified:
				go c.handleUpdateEndpoint(recv.Object)
			default:
			}
		case <-c.epWatcherCtx.Done():
			klog.Info("endpoints watcher recieved stop signal")
			return
		}
	}
}

func (c *controller) watchForServices(svcEvents watch.Interface) {
	var recv watch.Event
	var ok bool
	for {
		select {
		case recv, ok = <-svcEvents.ResultChan():
			if !ok {
				klog.Info("services watcher channel has been closed")
				return
			}
			switch recv.Type {
			case watch.Added:
				go c.handleAddService(recv.Object)
			case watch.Deleted:
				go c.handleDeleteService(recv.Object)
			case watch.Modified:
				go c.handleUpdateService(recv.Object)
			default:
			}
		case <-c.svcWatcherCtx.Done():
			klog.Info("services watcher recieved stop signal")
			return
		}
	}
}

func (c *controller) Start() {
	go c.watchForEndpoints(c.epWatcher)
	go c.watchForServices(c.svcWatcher)
}

func (c *controller) Stop() {
	c.epWatcherCancel()
	c.svcWatcherCancel()
}

// NewController return a new instance of Services and Endpoints controller
func NewController(clientset *kubernetes.Clientset, proxy proxy.Proxy) Controller {
	klog.Info("Setting up new Services and Endpoints controller...")
	epCtx, epCancel := context.WithCancel(context.TODO())
	svcCtx, svcCancel := context.WithCancel(context.TODO())
	controller := controller{
		proxy:            proxy,
		epWatcherCancel:  epCancel,
		svcWatcherCancel: svcCancel,
		epWatcherCtx:     epCtx,
		svcWatcherCtx:    svcCtx,
	}
	epWatcher, err := clientset.CoreV1().Endpoints("").Watch(metav1.ListOptions{})
	if err != nil {
		return nil
	}
	controller.epWatcher = epWatcher

	svcWatcher, err := clientset.CoreV1().Services("").Watch(metav1.ListOptions{})
	if err != nil {
		return nil
	}
	controller.svcWatcher = svcWatcher

	return &controller
}
