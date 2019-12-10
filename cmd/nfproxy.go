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
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/component-base/logs"
	"k8s.io/klog"
)

var (
	kubeconfig string
)

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Absolute path to the kubeconfig file.")
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
	flag.Set("logtostderr", "true")

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
	ti, err := nftables.InitNFTables()
	if err != nil {
		klog.Errorf("nfproxy failed to initialize nftables with error: %+v", err)
		os.Exit(1)
	}
	// Program initializes default nftables proxy's rules
	//
	controller := controller.NewController(client)
	if err := controller.Run(wait.NeverStop); err != nil {
		klog.Errorf("nfproxy failed to start controller with error: %s", err)
		os.Exit(1)
	}

	proxy.NewProxy(ti)

	stopCh := setupSignalHandler()
	select {
	case <-stopCh:
		klog.Info("Received stop signal, shuting down controller")
	}

	os.Exit(0)
}
