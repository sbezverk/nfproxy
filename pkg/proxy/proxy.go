package proxy

import "github.com/sbezverk/nftableslib"

// Proxy defines interface methods for nfproxy instance
type Proxy interface{}

type proxy struct{}

// NewProxy return a new instance of nfproxy
func NewProxy(nftableslib.TablesInterface) Proxy {
	return proxy{}
}
