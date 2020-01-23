package endpointsgen

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/uuid"
	v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	portBase        = 16384
	stressTestLabel = "endpoints/stressTest"
)

// EnsureNamespace checks if the namespace exists and if not attempts to create it
func EnsureNamespace(k8s *kubernetes.Clientset, namespace string) error {
	namespaces, err := k8s.CoreV1().Namespaces().List(meta_v1.ListOptions{})
	if err != nil {
		return err
	}
	for _, ns := range namespaces.Items {
		if ns.ObjectMeta.Name == namespace {
			return nil
		}
	}
	_, err = k8s.CoreV1().Namespaces().Create(&v1.Namespace{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: namespace,
		},
	})
	return err
}

// CreateEndPoint creates endpoint with specified name
func CreateEndPoint(k8s *kubernetes.Clientset, eps []v1.Endpoints) error {
	for _, ep := range eps {
		if _, err := k8s.CoreV1().Endpoints(ep.ObjectMeta.Namespace).Create(&ep); err != nil {
			return err
		}
	}
	return nil
}

// CreateService creates service with specified name
func CreateService(k8s *kubernetes.Clientset, svcs []v1.Service) error {
	for _, svc := range svcs {
		if _, err := k8s.CoreV1().Services(svc.ObjectMeta.Namespace).Create(&svc); err != nil {
			return err
		}
	}
	return nil
}

// DeleteEndPoints deletes all endpoints in a namespace
func DeleteEndPoints(k8s *kubernetes.Clientset, namespace string) error {
	err := k8s.CoreV1().Endpoints(namespace).DeleteCollection(&meta_v1.DeleteOptions{}, meta_v1.ListOptions{
		LabelSelector: stressTestLabel,
	})
	return err
}

// DeleteServices deletes all services in a namespace
func DeleteServices(k8s *kubernetes.Clientset, namespace string) error {
	svcList, err := k8s.CoreV1().Services(namespace).List(meta_v1.ListOptions{
		LabelSelector: stressTestLabel,
	})
	if err == nil {
		for _, s := range svcList.Items {
			_ = k8s.CoreV1().Services(namespace).Delete(s.ObjectMeta.Name, &meta_v1.DeleteOptions{})
		}
	}
	return err
}

// CleanServicesAndEndpoints deletes all services and endpoint in a namespace
func CleanServicesAndEndpoints(k8s *kubernetes.Clientset, namespace string) {
	_ = DeleteEndPoints(k8s, namespace)
	_ = DeleteServices(k8s, namespace)
}

func checkStartingIP(ip string, number int, ipv6 bool) ([]byte, error) {
	var addr []byte
	firstByteLimit := 223
	if ipv6 {
		addr = net.ParseIP(ip).To16()
		firstByteLimit = 32
	} else {
		addr = net.ParseIP(ip).To4()
	}
	total := int((254 - addr[len(addr)-1]))
	for i := len(addr) - 2; i > 0; i-- {
		total += (int(255-addr[i]) * total)
		// Check if we reached the required number
		if total > number {
			return addr, nil
		}
	}
	// Last byte has special treatment for IPv4 address max is 223.X.X.X
	// for IPv6 20XX::X
	if int(addr[0]) < firstByteLimit {
		total += ((firstByteLimit - int(addr[0])) * total)
	}

	if number > total {
		return nil, fmt.Errorf("start with ip address: %s, does not allow generating of %d sequential addresses", ip, number)
	}

	return addr, nil
}

// GenerateTestObjects generates services, endpoints based on passed parameters
// For each Service object, an Endpoint object with number of Subsets, and each subset with a number of Addrersses
// is create
func GenerateTestObjects(k8s *kubernetes.Clientset, namespace, stackMode string, svcNumber, subsetNumber, ipInSubset int, startIPv4, startIPv6 string) error {
	totalIPs := svcNumber * subsetNumber * ipInSubset
	var ipv6 bool
	var addr []byte
	var err error
	switch stackMode {
	case "ipv4":
		addr, err = checkStartingIP(startIPv4, totalIPs, false)
		if err != nil {
			return err
		}
		ipv6 = false
	case "ipv6":
		addr, err = checkStartingIP(startIPv6, totalIPs, true)
		if err != nil {
			return err
		}
		ipv6 = true
	case "dual":
	}
	// Generating IP Addresses/Ports and Subsets which later will be used for Endpoints.
	subsets := generateSusbsets(addr, ipv6, totalIPs, ipInSubset)
	// Generating Endpoints, the number of Endpoints equivalent to the number of Services.
	endpoints := generateEndpoints(subsets, namespace, subsetNumber)
	// Generating Service, the number of Services is specified in svcNumber parameter.
	services := generateServices(endpoints, namespace)

	if err := CreateService(k8s, services); err != nil {
		return err
	}
	if err := CreateEndPoint(k8s, endpoints); err != nil {
		return err
	}

	return nil
}

// CreateEndPoint creates endpoint with specified name
func generateServices(endpoints []v1.Endpoints, namespace string) []v1.Service {
	svcs := make([]v1.Service, 0)
	for i := 0; i < len(endpoints); i++ {
		ports := make([]v1.ServicePort, 0)
		for _, subset := range endpoints[i].Subsets {
			for _, port := range subset.Ports {
				ports = append(ports, v1.ServicePort{
					Name:     port.Name,
					Protocol: port.Protocol,
					Port:     port.Port,
				})
			}
		}
		svcs = append(svcs, v1.Service{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      endpoints[i].ObjectMeta.Name,
				Namespace: endpoints[i].ObjectMeta.Namespace,
				Labels:    map[string]string{stressTestLabel: "true"},
			},
			Spec: v1.ServiceSpec{
				Ports: ports,
			},
		})
	}

	return svcs
}

// CreateEndPoint creates endpoint with specified name
func generateEndpoints(subsets []v1.EndpointSubset, namespace string, subsetNumber int) []v1.Endpoints {
	eps := make([]v1.Endpoints, 0)
	sbs := make([]v1.EndpointSubset, 0)
	e := 0
	for i := 0; i < len(subsets); i++ {
		sbs = append(sbs, subsets[i])
		if e == subsetNumber-1 {
			host := uuid.New()
			eps = append(eps, v1.Endpoints{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "app-" + host.String()[:13],
					Namespace: namespace,
					Labels:    map[string]string{stressTestLabel: "true"},
				},
				Subsets: sbs,
			})
			sbs = make([]v1.EndpointSubset, 0)
			e = 0
		} else {
			e++
		}
	}

	return eps
}

// IsValidIPv4 returns true if passed in a string ip address is a valid ipv4 address
func IsValidIPv4(ipAddr string) bool {
	if net.ParseIP(ipAddr).To4() != nil {
		return true
	}
	return false
}

// IsValidIPv6 returns true if passed in a string ip address is a valid ipv6 address
func IsValidIPv6(ipAddr string) bool {
	if net.ParseIP(ipAddr).To16() != nil {
		return true
	}
	return false
}

// generateSusbsets generates slice of endpoint's subsets, individual subset will have a number
// of Addresses and Ports as specified in ipPerSubset parameter.
func generateSusbsets(addr []byte, ipv6 bool, number, ipPerSubset int) []v1.EndpointSubset {
	subsets := make([]v1.EndpointSubset, 0)
	var port uint16 = portBase
	genAddr := make([]byte, len(addr))
	epAddr := make([]v1.EndpointAddress, 0)
	epPort := make([]v1.EndpointPort, 0)
	copy(genAddr, addr)
	var addrLength int
	if ipv6 {
		addrLength = 16
	} else {
		addrLength = 4
	}
	// Counter for a number of Addresses/Ports pair in each Subset
	s := 0
	// Generating needed number of ip address
	for i := 0; i < number; i++ {
		for e := addrLength - 1; e > 0; e-- {
			if genAddr[e]+1 == 255 {
				genAddr[e] = 1
				continue
			} else {
				genAddr[e]++
				break
			}
		}
		str := genAddrString(genAddr, ipv6)
		var hostName, portName string
		if ipv6 {
			hostName = "host-" + strings.Replace(str, ":", "-", -1)
			portName = strings.Replace(str, ":", "-", -1)
		} else {
			hostName = "host-" + strings.Replace(str, ".", "-", -1)
			portName = strings.Replace(str, ".", "-", -1)
		}

		epAddr = append(epAddr, v1.EndpointAddress{
			IP:       str,
			Hostname: hostName,
		})
		epPort = append(epPort, v1.EndpointPort{
			Name:     portName,
			Port:     int32(port),
			Protocol: v1.ProtocolTCP,
		})

		if s == ipPerSubset-1 {
			subsets = append(subsets, v1.EndpointSubset{
				Addresses: epAddr,
				Ports:     epPort,
			})
			// Cleanup for the next cycle
			s = 0
			epAddr = make([]v1.EndpointAddress, 0)
			epPort = make([]v1.EndpointPort, 0)
		} else {
			s++
		}
		port++
	}

	return subsets
}

func genAddrString(genAddr []byte, ipv6 bool) string {
	var str string
	var addrLength int
	if ipv6 {
		addrLength = 16
	} else {
		addrLength = 4
	}
	t := 0
	for e := 0; e < addrLength; e++ {
		if ipv6 {
			str += fmt.Sprintf("%02X", genAddr[e])
			if t == 1 {
				if e < addrLength-1 {
					str += fmt.Sprintf(":")
					t = 0
				}
			} else {
				t++
			}
		} else {
			str += fmt.Sprintf("%d", genAddr[e])
			if e < addrLength-1 {
				str += fmt.Sprintf(".")
			}
		}
	}

	return str
}

func printGenAddr(genAddr []byte, ipv6 bool) {
	var addrLength int
	if ipv6 {
		addrLength = 16
	} else {
		addrLength = 4
	}
	t := 0
	for e := 0; e < addrLength; e++ {
		if ipv6 {
			fmt.Printf("%02X", genAddr[e])
			if t == 1 {
				if e < addrLength-1 {
					fmt.Printf(":")
					t = 0
				}
			} else {
				t++
			}
		} else {
			fmt.Printf("%d", genAddr[e])
			if e < addrLength-1 {
				fmt.Printf(".")
			}
		}
	}
	fmt.Printf("\n")
}
