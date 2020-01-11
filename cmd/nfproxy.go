package main

import (
	"flag"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sbezverk/nfproxy/pkg/controller"
	"github.com/sbezverk/nfproxy/pkg/nftables"
	"github.com/sbezverk/nfproxy/pkg/proxy"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
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
)

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Absolute path to the kubeconfig file.")
	flag.StringVar(&ipv4ClusterCIDR, "ipv4clustercidr", "", "The IPv4 CIDR range of pods in the cluster.")
	flag.StringVar(&ipv6ClusterCIDR, "ipv6clustercidr", "", "The IPv6 CIDR range of pods in the cluster.")
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
	nfproxy := proxy.NewProxy(nfti, hostname, recorder)
	// For "in-cluster" mode a rule to reach API server must be programmed, otherwise a controller
	// running "in-cluster" cannot reach it.
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host != "" && port != "" {
		if err := proxy.BootstrapRules(nfproxy, host, port); err != nil {
			klog.Errorf("nfproxy failed to add bootstrap rules with error: %+v", err)
			os.Exit(1)
		}
	}

	controller := controller.NewController(client, nfproxy)
	if err := controller.Run(wait.NeverStop); err != nil {
		klog.Errorf("nfproxy failed to start controller with error: %s", err)
		os.Exit(1)
	}

	stopCh := setupSignalHandler()
	<-stopCh
	klog.Info("Received stop signal, shuting down controller")

	os.Exit(0)
}
