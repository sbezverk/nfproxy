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

const endpointControllerAgentName = "nfproxy-endpoints"

// EndpointsController defines interface for managing Endpoints controller
type EndpointsController interface {
	Start(<-chan struct{}) error
}

type endpointsController struct {
	kubeClientset kubernetes.Interface
	epsSynced     cache.InformerSynced
	recorder      record.EventRecorder
	proxy         proxy.Proxy
}

func (c *endpointsController) handleAddEndpoint(obj interface{}) {
	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
		return
	}
	klog.V(5).Infof("endpoint add event for %s/%s", ep.ObjectMeta.Namespace, ep.ObjectMeta.Name)
	if ep.Name == "app2" {
		c.proxy.AddEndpoints(ep)
	}
}

func (c *endpointsController) handleUpdateEndpoint(oldObj, newObj interface{}) {
	epOld, ok := oldObj.(*v1.Endpoints)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", oldObj))
		return
	}
	epNew, ok := newObj.(*v1.Endpoints)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", newObj))
		return
	}

	if epOld.ObjectMeta.ResourceVersion == epNew.ObjectMeta.ResourceVersion {
		return
	}
	if epNew.ObjectMeta.Name == "kube-controller-manager" || epNew.ObjectMeta.Name == "kube-scheduler" {
		return
	}
	klog.V(5).Infof("endpoint update event for %s/%s", epNew.ObjectMeta.Namespace, epNew.ObjectMeta.Name)
	klog.V(6).Infof("endpoint %s/%s Subsets old: %+v Subsets new: %+v", epNew.ObjectMeta.Namespace, epNew.ObjectMeta.Name, epOld.Subsets, epNew.Subsets)
	if epOld.Name == "app2" || epNew.Name == "app2" {
		c.proxy.UpdateEndpoints(epOld, epNew)
	}
}

func (c *endpointsController) handleDeleteEndpoint(obj interface{}) {
	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
			return
		}
		if _, ok = tombstone.Obj.(*v1.Endpoints); !ok {
			utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
			return
		}
	}
	klog.V(5).Infof("endpoint delete event for %s/%s", ep.ObjectMeta.Namespace, ep.ObjectMeta.Name)
	if ep.Name == "app2" {
		c.proxy.DeleteEndpoints(ep)
	}
}

func (c *endpointsController) Start(stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()

	// Start the informer factories to begin populating the informer caches
	klog.Info("Starting nfproxy Endpoints controller")

	// Wait for the caches to be synced before starting workers
	klog.Info("Waiting for informer caches to sync for Endpoints controller")
	if ok := cache.WaitForCacheSync(stopCh, c.epsSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync for Endpoints controller")
	}

	return nil
}

// NewEndpointsController returns a new Endpoints controller
func NewEndpointsController(
	proxy proxy.Proxy,
	kubeClientset kubernetes.Interface,
	epInformer corev1informer.EndpointsInformer) EndpointsController {

	klog.V(4).Info("Creating event broadcaster for Endpoints controller")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeClientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: endpointControllerAgentName})

	controller := &endpointsController{
		kubeClientset: kubeClientset,
		epsSynced:     epInformer.Informer().HasSynced,
		recorder:      recorder,
		proxy:         proxy,
	}

	klog.Info("Setting up event handlers for Endpoints controller")

	epInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.handleAddEndpoint,
		UpdateFunc: controller.handleUpdateEndpoint,
		DeleteFunc: controller.handleDeleteEndpoint,
	})

	return controller
}
