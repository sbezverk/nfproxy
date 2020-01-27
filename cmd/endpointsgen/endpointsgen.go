package main

import (
	"flag"
	"os"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/sbezverk/nfproxy/pkg/controller"
	eg "github.com/sbezverk/nfproxy/pkg/endpointsgen"
)

var (
	kubeconfig     = flag.String("kubeconfig", "", "Absolute path to the kubeconfig file.")
	stackMode      = flag.String("stack-mode", "ipv4", "Defines which stack is tested, acceptable values are: ipv4, ipv6, dual")
	svcNumber      = flag.Int("svc", 1, "Number of services to generate")
	subsetNumber   = flag.Int("subset", 1, "Number of Subsets in a single endpoint")
	ipNumber       = flag.Int("ip", 1, "Number of addresses in an endpoint subset")
	startIPv4      = flag.String("start-ipv4", "1.0.0.0", "Starting ipv4 for endpoint's subset's addrersses")
	startIPv6      = flag.String("start-ipv6", "2001:1::0", "Starting ipv6 for endpoint's subset's addrersses")
	namespace      = flag.String("namespace", "endpoints-test", "Namespace where endpoints are generated.")
	initialCleanup = flag.Bool("initial-cleanup", true, "Clean up all service and endpoints from the namespace prior attempting to create them.")
	postCleanup    = flag.Bool("post-cleanup", false, "Clean up all service and endpoints from the namespace after running tests.")
	maxETCD        = flag.Bool("max-etcd", false, "ETCD is configured for max size of backend strage.")
	cleanupOnly    = flag.Bool("just-cleanup", false, "Clean up all service and endpoints from the namespace and exit. ")
)

func main() {

	flag.Parse()
	flag.Set("logtostderr", "true")

	switch strings.ToLower(*stackMode) {
	case "ipv4":
		// Check if startIPv4 is a valid IPv4 address
		if !eg.IsValidIPv4(*startIPv4) {
			glog.Errorf("invalid starting ipv4 address %s", *startIPv4)
			os.Exit(1)
		}
	case "ipv6":
		// Check if startIPv6 is a valid IPv6 address
		if !eg.IsValidIPv6(*startIPv6) {
			glog.Errorf("invalid starting ipv6 address %s", *startIPv6)
			os.Exit(1)
		}
	case "dual":
		glog.Errorf("Not yet supported, check back later")
		os.Exit(1)
		// Check if startIPv4 is a valid IPv4 address and if startIPv6 is a valid IPv6 address
		//		if !eg.IsValidIPv4(*startIPv4) || !eg.IsValidIPv6(*startIPv6) {
		//			glog.Errorf("one of starting ipv4: %s or ipv6: %s addresses is invalid", *startIPv4, *startIPv6)
		//			os.Exit(1)
		//		}
	default:
		glog.Errorf("invalid stack mode value %s", *stackMode)
		os.Exit(1)
	}

	k8s, err := controller.GetClientset(*kubeconfig)
	if err != nil {
		glog.Errorf("Failed to create a client: %+v", err)
		os.Exit(1)
	}

	if err := eg.EnsureNamespace(k8s, *namespace); err != nil {
		glog.Errorf("Namespace %s doesn not exist and failed to create it with error: %+v", *namespace, err)
		os.Exit(1)
	}

	if *cleanupOnly {
		start := time.Now()
		glog.Infof("Clean up only operation started at: %s", start.Format(time.StampMilli))
		eg.CleanServicesAndEndpoints(k8s, *namespace)
		glog.Infof("It took %f seconds for clean up of old services and endpoints", time.Since(start).Seconds())
		os.Exit(0)
	}

	if *subsetNumber**svcNumber > 10240 && !*maxETCD {
		glog.Errorf("Creating %d number of Endpoints and Services will require maximizing etcd backend data store.", *subsetNumber**svcNumber)
		glog.Errorf("Use this '--quota-backend-bytes=8589934592' configuation key to maximize the size of etcd data store.")
		glog.Errorf("If it has already been done, use '--max-etcd=true' when you run this program. ")
		os.Exit(1)
	}
	if *initialCleanup {
		start := time.Now()
		glog.Infof("Initial clean up operation started at: %s", start.Format(time.StampMilli))
		eg.CleanServicesAndEndpoints(k8s, *namespace)
		glog.Infof("It took %f seconds for initial clean up of old services and endpoints", time.Since(start).Seconds())
	}

	start := time.Now()
	glog.Infof("Generate and create test Service and Endpoints started at: %s", start.Format(time.StampMilli))
	if err := eg.GenerateTestObjects(k8s, *namespace, *stackMode, *svcNumber, *subsetNumber, *ipNumber, *startIPv4, *startIPv6); err != nil {
		glog.Errorf("Failed to create test obects: %+v", err)
		os.Exit(1)
	}
	glog.Infof("It took %f seconds to program %d service %d endpoints each with %d IP/Port pairs",
		time.Since(start).Seconds(), *svcNumber, *svcNumber, *subsetNumber**ipNumber)

	if *postCleanup {
		start := time.Now()
		glog.Infof("Initial clean up operation started at: %s", start.Format(time.StampMilli))
		eg.CleanServicesAndEndpoints(k8s, *namespace)
		glog.Infof("It took %f seconds for post clean up of services and endpoints", time.Since(start).Seconds())
	}
}
