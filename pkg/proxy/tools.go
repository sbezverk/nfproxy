package proxy

import (
	"crypto/sha256"
	"encoding/base32"
)

// This is the same as servicePortChainName but with the endpoint included.
func servicePortEndpointChainName(servicePortName string, protocol string, endpoint string) string {
	hash := sha256.Sum256([]byte(servicePortName + protocol + endpoint))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return "k8s-nfproxy-sep-" + encoded[:16]
}

func servicePortSvcChainName(servicePortName string, protocol string, service string) string {
	hash := sha256.Sum256([]byte(servicePortName + protocol + service))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return "k8s-nfproxy-svc-" + encoded[:16]
}
