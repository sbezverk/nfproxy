package controller

import (
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	informer "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	"github.com/sbezverk/nfproxy/pkg/proxy"
)

// Controller exposes methods for Services and Endpoints controllers
type Controller interface {
	Run(<-chan struct{}) error
}

type controller struct {
	clientset       *kubernetes.Clientset
	services        informer.ServiceInformer
	servicesSynced  cache.InformerSynced
	endpoints       informer.EndpointsInformer
	endpointsSynced cache.InformerSynced
	proxy           proxy.Proxy
}

func (c *controller) handleAddService(obj interface{}) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
		return
	}
	c.proxy.AddService(svc)
}

func (c *controller) handleUpdateService(oldObj, newObj interface{}) {
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
		klog.Infof("Resync update for service: %s/%s", svcNew.ObjectMeta.Namespace, svcNew.ObjectMeta.Name)
		return
	}
	c.proxy.UpdateService(svcOld, svcNew)
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
	c.proxy.AddEndpoints(ep)
}

func (c *controller) handleUpdateEndpoint(oldObj, newObj interface{}) {
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
		klog.Infof("Resync update for service: %s/%s", epNew.ObjectMeta.Namespace, epNew.ObjectMeta.Name)
		return
	}
	c.proxy.UpdateEndpoints(epOld, epNew)
}

func (c *controller) handleDeleteEndpoint(obj interface{}) {
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

func (c *controller) Run(stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()

	if ok := cache.WaitForCacheSync(stopCh, c.servicesSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}
	klog.Info("Services cache has synced...")
	if ok := cache.WaitForCacheSync(stopCh, c.endpointsSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}
	klog.Info("Endpoints cache has synced...")

	return nil
}

// NewController return a new instance of Services and Endpoints controller
func NewController(clientset *kubernetes.Clientset, proxy proxy.Proxy) Controller {
	klog.Info("Setting up new Services and Endpoints controller...")
	controller := controller{
		proxy: proxy,
	}
	informerFactory := informers.NewSharedInformerFactoryWithOptions(clientset, time.Minute*5)
	// Setting up Services informer
	controller.services = informerFactory.Core().V1().Services()
	controller.services.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.handleAddService,
		UpdateFunc: controller.handleUpdateService,
		DeleteFunc: controller.handleDeleteService,
	})
	// Setting up Endpoints informer
	controller.endpoints = informerFactory.Core().V1().Endpoints()
	controller.endpoints.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.handleAddEndpoint,
		UpdateFunc: controller.handleUpdateEndpoint,
		DeleteFunc: controller.handleDeleteEndpoint,
	})

	controller.servicesSynced = controller.services.Informer().HasSynced
	controller.endpointsSynced = controller.endpoints.Informer().HasSynced
	informerFactory.Start(wait.NeverStop)
	klog.Info("controller is ready...")

	return &controller
}
