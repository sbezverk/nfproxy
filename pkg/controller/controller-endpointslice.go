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
	discovery "k8s.io/api/discovery/v1beta1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers/discovery/v1beta1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"

	"github.com/sbezverk/nfproxy/pkg/proxy"
)

const epSliceControllerAgentName = "nfproxy-endpointslice"

// EndpointSliceController defines interface for managing EndpointSlice controller
type EndpointSliceController interface {
	Start(<-chan struct{}) error
}

type endpointSliceController struct {
	kubeClientset kubernetes.Interface
	epsliceSynced cache.InformerSynced
	recorder      record.EventRecorder
	proxy         proxy.Proxy
}

func (c *endpointSliceController) handleAddEndpointSlice(obj interface{}) {
	epsl, ok := obj.(*discovery.EndpointSlice)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
		return
	}
	klog.V(5).Infof("endpoint slice add event for %s/%s Object: %+v", epsl.ObjectMeta.Namespace, epsl.ObjectMeta.Name, epsl)
	//	if ep.Name == "app2" {
	// c.proxy.AddEndpoints(ep)
	//	}
}

func (c *endpointSliceController) handleUpdateEndpointSlice(oldObj, newObj interface{}) {
	epslOld, ok := oldObj.(*discovery.EndpointSlice)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", oldObj))
		return
	}
	epslNew, ok := newObj.(*discovery.EndpointSlice)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", newObj))
		return
	}

	if epslOld.ObjectMeta.ResourceVersion == epslNew.ObjectMeta.ResourceVersion {
		return
	}

	klog.V(6).Infof("endpoint slice update event for %s/%s Subsets old: %+v Subsets new: %+v", epslNew.ObjectMeta.Namespace, epslNew.ObjectMeta.Name,
		epslOld.Ports, epslNew.Ports)
	//	if epOld.Name == "app2" || epNew.Name == "app2" {
	// c.proxy.UpdateEndpoints(epOld, epNew)
	//	}
}

func (c *endpointSliceController) handleDeleteEndpointSlice(obj interface{}) {
	epsl, ok := obj.(*discovery.EndpointSlice)
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
	klog.V(5).Infof("endpoint slice delete event for %s/%s Object: %+v", epsl.ObjectMeta.Namespace, epsl.ObjectMeta.Name, epsl)
	//	if ep.Name == "app2" {
	// c.proxy.DeleteEndpoints(ep)
	//	}
}

func (c *endpointSliceController) Start(stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()

	// Start the informer factories to begin populating the informer caches
	klog.Info("Starting nfproxy EndpointSlice controller")

	// Wait for the caches to be synced before starting workers
	klog.Info("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(stopCh, c.epsliceSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	return nil
}

// NewController returns a new cnat controller
func NewEndpointSliceController(
	proxy proxy.Proxy,
	kubeClientset kubernetes.Interface,
	epSliceInformer v1beta1.EndpointSliceInformer) EndpointSliceController {

	klog.V(4).Info("Creating event broadcaster for EndpointSlice controller")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeClientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: epSliceControllerAgentName})

	controller := &endpointSliceController{
		kubeClientset: kubeClientset,
		epsliceSynced: epSliceInformer.Informer().HasSynced,
		recorder:      recorder,
		proxy:         proxy,
	}

	klog.Info("Setting up event handlers for EndpointSlice controller")

	epSliceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.handleAddEndpointSlice,
		UpdateFunc: controller.handleUpdateEndpointSlice,
		DeleteFunc: controller.handleDeleteEndpointSlice,
	})

	return controller
}
