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

package main

import (
	"flag"
	"math"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"net/http"
	_ "net/http/pprof"

	"github.com/sbezverk/nfproxy/pkg/controller"
	"github.com/sbezverk/nfproxy/pkg/nftables"
	"github.com/sbezverk/nfproxy/pkg/proxy"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"k8s.io/component-base/logs"
	"k8s.io/klog"
	utilnode "k8s.io/kubernetes/pkg/util/node"
)

var (
	kubeconfig      string
	ipv4ClusterCIDR string
	ipv6ClusterCIDR string
	endpointSlice   bool
)

type epController interface {
	Start(<-chan struct{}) error
}

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Absolute path to the kubeconfig file.")
	flag.StringVar(&ipv4ClusterCIDR, "ipv4clustercidr", "", "The IPv4 CIDR range of pods in the cluster.")
	flag.StringVar(&ipv6ClusterCIDR, "ipv6clustercidr", "", "The IPv6 CIDR range of pods in the cluster.")
	flag.BoolVar(&endpointSlice, "endpointslice", false, "Enables to use EndpointSlice instead of Endpoints. Default is flase.")
}

func setupSignalHandler() (stopCh <-chan struct{}) {
	stop := make(chan struct{})
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		close(stop)
		<-c
		os.Exit(1) // second signal. Exit directly.
	}()

	return stop
}

func main() {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")

	rand.Seed(time.Now().UnixNano())

	logs.InitLogs()
	defer logs.FlushLogs()

	go func() {
		klog.Info(http.ListenAndServe("localhost:6767", nil))
	}()
	// Get kubernetes client set
	client, err := controller.GetClientset(kubeconfig)
	if err != nil {
		klog.Errorf("nfproxy failed to get kubernetes clientset with error: %+v", err)
		os.Exit(1)
	}

	// Attempt to Init nftables, if fails exit with error
	// TODO Add validation of ipv4ClusterCIDR, ipv6ClusterCIDR for a valid IPv4 or IPv6 address
	// One is allowed to be empty but not both.
	nfti, err := nftables.InitNFTables(ipv4ClusterCIDR, ipv6ClusterCIDR)
	if err != nil {
		klog.Errorf("nfproxy failed to initialize nftables with error: %+v", err)
		os.Exit(1)
	}

	// Create event recorder
	hostname, err := utilnode.GetHostname("")
	if err != nil {
		klog.Errorf("nfproxy failed to get local host name with error: %+v", err)
		os.Exit(1)
	}
	eventBroadcaster := record.NewBroadcaster()
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "nfproxy", Host: hostname})

	// Create new instance of a proxy process
	nfproxy := proxy.NewProxy(nfti, hostname, recorder, endpointSlice)
	// For "in-cluster" mode a rule to reach API server must be programmed, otherwise
	// the services/endpoints controller cannot reach it.
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host != "" && port != "" {
		strAddr := os.Getenv("API_PUBLIC_ENDPOINT")
		if strAddr == "" {
			klog.Errorf("nfproxy in \"in-cluster\" more requires env variable \"API_PUBLIC_ENDPOINT\" to be set to nfproxy pod's IP address")
			os.Exit(1)
		}
		// TODO, move to validtion func
		endpoint, err := url.Parse(strAddr)
		if err != nil {
			klog.Errorf("nfproxy failed to parse api server endpoint with error: %+v", err)
			os.Exit(1)
		}
		if endpoint.Scheme == "" {
			if err != nil {
				klog.Errorf("nfproxy failed to parse api server endpoint with error: %+v", err)
				os.Exit(1)
			}
		}
		ehost, eport, _ := net.SplitHostPort(endpoint.Host)
		if host == "" || port == "" {
			if err != nil {
				klog.Errorf("nfproxy failed to parse api server endpoint with error: %+v", err)
				os.Exit(1)
			}
		}
		if net.ParseIP(ehost) == nil {
			klog.Errorf("nfproxy failed to parse api server endpoint with error: %+v", err)
			os.Exit(1)
		}
		np, err := strconv.Atoi(eport)
		if err != nil {
			klog.Errorf("nfproxy failed to parse api server endpoint with error: %+v", err)
			os.Exit(1)
		}
		if np == 0 || np > math.MaxUint16 {
			klog.Errorf("nfproxy failed to parse api server endpoint with error: %+v", err)
			os.Exit(1)
		}
		klog.Infof("Programming bootstrap rule for kubernetes api endpoint: %+v", strAddr)
		if err := proxy.BootstrapRules(nfproxy, host, port, endpoint, endpointSlice); err != nil {
			klog.Errorf("nfproxy failed to add bootstrap rules with error: %+v", err)
			os.Exit(1)
		}
	}

	kubeInformerFactory := kubeinformers.NewSharedInformerFactory(client, time.Minute*10)

	svcController := controller.NewServiceController(nfproxy, client, kubeInformerFactory.Core().V1().Services())

	// If EndpointSlice support is requested and feature gate for EndpointSLice is enabled,
	// instantiate EndpointSlice controller, otherwise Endpoints controller will be used.
	var ep epController
	if endpointSlice {
		ep = controller.NewEndpointSliceController(nfproxy, client, kubeInformerFactory.Discovery().V1beta1().EndpointSlices())
	} else {
		ep = controller.NewEndpointsController(nfproxy, client, kubeInformerFactory.Core().V1().Endpoints())
	}

	kubeInformerFactory.Start(wait.NeverStop)

	if err = svcController.Start(wait.NeverStop); err != nil {
		klog.Fatalf("Error running Service controller: %s", err.Error())
	}
	if err = ep.Start(wait.NeverStop); err != nil {
		klog.Fatalf("Error running endpoint controller: %s", err.Error())
	}

	stopCh := setupSignalHandler()
	<-stopCh
	klog.Info("Received stop signal, shuting down controller")

	os.Exit(0)
}
