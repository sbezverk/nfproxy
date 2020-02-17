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
	"fmt"

	v1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	corev1informer "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"

	"github.com/sbezverk/nfproxy/pkg/proxy"
)

const serviceControllerAgentName = "nfproxy-svc"

// ServiceController defines interface for managing Services controller
type ServiceController interface {
	Start(<-chan struct{}) error
}

type serviceController struct {
	kubeClientset kubernetes.Interface
	svcsSynced    cache.InformerSynced
	recorder      record.EventRecorder
	proxy         proxy.Proxy
}

func (c *serviceController) handleAddService(obj interface{}) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
		return
	}
	klog.V(5).Infof("service add event for %s/%s", svc.ObjectMeta.Namespace, svc.ObjectMeta.Name)
	//	if svc.Name == "app2" {
	c.proxy.AddService(svc)
	//	}
}

func (c *serviceController) handleUpdateService(oldObj, newObj interface{}) {
	svcOld, ok := oldObj.(*v1.Service)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", oldObj))
		return
	}
	svcNew, ok := newObj.(*v1.Service)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", newObj))
		return
	}
	if svcOld.ObjectMeta.ResourceVersion == svcNew.ObjectMeta.ResourceVersion {
		return
	}
	klog.V(5).Infof("service update event for %s/%s", svcNew.ObjectMeta.Namespace, svcNew.ObjectMeta.Name)
	//	if svcNew.Name == "app2" || svcOld.Name == "app2" {
	c.proxy.UpdateService(svcOld, svcNew)
	//	}
}

func (c *serviceController) handleDeleteService(obj interface{}) {
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
	klog.V(5).Infof("service delete event for %s/%s", svc.ObjectMeta.Namespace, svc.ObjectMeta.Name)
	//	if svc.Name == "app2" {
	c.proxy.DeleteService(svc)
	//	}
}

func (c *serviceController) Start(stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()

	// Start the informer factories to begin populating the informer caches
	klog.Info("Starting nfproxy Service controller")

	// Wait for the caches to be synced before starting workers
	klog.Info("Waiting for informer caches to sync for Service controller")
	if ok := cache.WaitForCacheSync(stopCh, c.svcsSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync for Service controller")
	}

	return nil
}

// NewServiceController returns a new serices controller wathing and calling Proxy methods
// for services add/delete/update events.
func NewServiceController(
	proxy proxy.Proxy,
	kubeClientset kubernetes.Interface,
	svcInformer corev1informer.ServiceInformer) ServiceController {

	klog.V(4).Info("Creating event broadcaster for Service controller")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeClientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: serviceControllerAgentName})

	controller := &serviceController{
		kubeClientset: kubeClientset,
		svcsSynced:    svcInformer.Informer().HasSynced,
		recorder:      recorder,
		proxy:         proxy,
	}

	klog.Info("Setting up event handlers for Service Controller")

	// Set up an event handler for when Svc resources change
	svcInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.handleAddService,
		UpdateFunc: controller.handleUpdateService,
		DeleteFunc: controller.handleDeleteService,
	})

	return controller
}
