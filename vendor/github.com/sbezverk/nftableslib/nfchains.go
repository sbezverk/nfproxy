package nftableslib

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/nftables"
)

// ChainsInterface defines third level interface operating with nf chains
type ChainsInterface interface {
	Chains() ChainFuncs
}

// ChainPolicy defines type for chain policies
type ChainPolicy uint32

const (
	// ChainPolicyAccept defines "accept" chain policy
	ChainPolicyAccept ChainPolicy = 1
	// ChainPolicyDrop defines "drop" chain policy
	ChainPolicyDrop ChainPolicy = 0
	// ChainReadyTimeout defines maximum time to wait for a chain to be ready
	ChainReadyTimeout = time.Millisecond * 100
	// ChainDeleteTimeout defines maximum time to wait for a chain to be ready
	ChainDeleteTimeout = time.Second * 60
)

// ChainAttributes defines attributes which can be apply to a chain of BASE type
type ChainAttributes struct {
	Type     nftables.ChainType
	Hook     nftables.ChainHook
	Priority nftables.ChainPriority
	Device   string
	Policy   ChainPolicy
}

// Validate validate attributes passed for a base chain creation
func (cha *ChainAttributes) Validate() error {
	if cha.Type == "" {
		return fmt.Errorf("base chain must have type set")
	}
	// TODO Add additional attributes validation

	return nil
}

// ChainFuncs defines funcations to operate with chains
type ChainFuncs interface {
	Chain(name string) (RulesInterface, error)
	Create(name string, attributes *ChainAttributes) error
	CreateImm(name string, attributes *ChainAttributes) error
	Delete(name string) error
	DeleteImm(name string) error
	Exist(name string) bool
	Sync() error
	Dump() ([]byte, error)
	Get() ([]string, error)
}

type nfChains struct {
	conn  NetNS
	table *nftables.Table
	sync.Mutex
	chains map[string]*nfChain
}

type nfChain struct {
	baseChain bool
	chain     *nftables.Chain
	RulesInterface
}

// Chain return Rules Interface for a specified chain
func (nfc *nfChains) Chain(name string) (RulesInterface, error) {
	nfc.Lock()
	defer nfc.Unlock()
	// Check if nf table with the same family type and name  already exists
	if c, ok := nfc.chains[name]; ok {
		return c.RulesInterface, nil

	}
	return nil, fmt.Errorf("chain %s does not exist", name)
}

// Chains return a list of methods available for Chain operations
func (nfc *nfChains) Chains() ChainFuncs {
	return nfc
}

func (nfc *nfChains) create(name string, attributes *ChainAttributes) error {
	if _, ok := nfc.chains[name]; ok {
		return fmt.Errorf("chain %s already exist in table %s", name, nfc.table.Name)
	}
	var baseChain bool
	var c *nftables.Chain
	if attributes != nil {
		if err := attributes.Validate(); err != nil {
			return err
		}
		baseChain = true
		defaultPolicy := nftables.ChainPolicyAccept
		c = nfc.conn.AddChain(&nftables.Chain{
			Name:     name,
			Hooknum:  attributes.Hook,
			Priority: attributes.Priority,
			Table:    nfc.table,
			Type:     attributes.Type,
			Policy:   &defaultPolicy,
		})
	} else {
		baseChain = false
		c = nfc.conn.AddChain(&nftables.Chain{
			Name:  name,
			Table: nfc.table,
		})
	}
	nfc.chains[name] = &nfChain{
		chain:          c,
		baseChain:      baseChain,
		RulesInterface: newRules(nfc.conn, nfc.table, c),
	}

	return nil
}

func (nfc *nfChains) Create(name string, attributes *ChainAttributes) error {
	nfc.Lock()
	defer nfc.Unlock()

	return nfc.create(name, attributes)
}

func (nfc *nfChains) CreateImm(name string, attributes *ChainAttributes) error {
	nfc.Lock()
	defer nfc.Unlock()
	if err := nfc.create(name, attributes); err != nil {
		return err
	}
	// Flush notifies netlink to proceed with prgramming of a chain
	if err := nfc.conn.Flush(); err != nil {
		return err
	}

	timeout := time.NewTimer(ChainReadyTimeout)
	ticker := time.NewTicker(ChainReadyTimeout / 10)
	defer ticker.Stop()
	for {
		// Need to make sure that chain is ready before returning control to the caller
		ready, err := nfc.Ready(name)
		if err != nil {
			// Checking for Readiness failed, removing the chain from the store
			// and return error to the caller
			nfc.Delete(name)
			return err
		}
		if ready {
			timeout.Stop()
			return nil
		}
		select {
		case <-timeout.C:
			nfc.Delete(name)
			return fmt.Errorf("timeout waiting for chain %s to become ready, last error: %+v", name, err)
		case <-ticker.C:
			continue
		}
	}
}

func (nfc *nfChains) Delete(name string) error {
	nfc.Lock()
	defer nfc.Unlock()
	if ch, ok := nfc.chains[name]; ok {
		nfc.conn.DelChain(ch.chain)
		delete(nfc.chains, name)
	}

	return nil
}

func (nfc *nfChains) DeleteImm(name string) error {
	var err error
	if err = nfc.Delete(name); err != nil {
		return err
	}
	timeout := time.NewTimer(ChainDeleteTimeout)
	ticker := time.NewTicker(ChainDeleteTimeout / 10)
	defer ticker.Stop()
	for {
		// Flush notifies netlink to proceed with prgramming of a chain
		if err = nfc.conn.Flush(); err == nil {
			return nil
		}
		select {
		case <-timeout.C:
			return err
		case <-ticker.C:
			continue
		}
	}
}

func (nfc *nfChains) Sync() error {
	chains, err := nfc.conn.ListChains()
	if err != nil {
		return err
	}
	for _, chain := range chains {
		if chain.Table.Name == nfc.table.Name && chain.Table.Family == nfc.table.Family {
			if _, ok := nfc.chains[chain.Name]; !ok {
				baseChain := false
				if chain.Type != "" && chain.Hooknum != 0 {
					baseChain = true
				}
				nfc.Lock()
				nfc.chains[chain.Name] = &nfChain{
					chain:          chain,
					baseChain:      baseChain,
					RulesInterface: newRules(nfc.conn, nfc.table, chain),
				}
				nfc.Unlock()
				if err := nfc.chains[chain.Name].Rules().Sync(); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (nfc *nfChains) Dump() ([]byte, error) {
	nfc.Lock()
	defer nfc.Unlock()
	var data []byte

	for _, c := range nfc.chains {
		b, err := json.Marshal(&c.chain)
		if err != nil {
			return nil, err
		}
		data = append(data, b...)
		b, err = c.Rules().Dump()
		if err != nil {
			return nil, err
		}
		data = append(data, b...)
	}

	return data, nil
}

// Exist checks is the chain already defined
func (nfc *nfChains) Exist(name string) bool {
	// Check if Chain exists in the store
	if _, ok := nfc.chains[name]; ok {
		return true
	}
	// It is not in the store, let's double check if it exists on the host
	chains, err := nfc.conn.ListChains()
	if err != nil {
		return false
	}
	for _, chain := range chains {
		if chain.Name == name {
			if nfc.table.Name == chain.Table.Name && nfc.table.Family == chain.Table.Family {
				// Found a chain is missing from the store, adding it
				// Sync will load all missing chain,
				// TODO Consider creating SyncChain(name) function.
				if err := nfc.Sync(); err == nil {
					return true
				}
				break
			}
		}
	}

	return false
}

// Get returns all tables defined for a specific TableFamily
func (nfc *nfChains) Get() ([]string, error) {
	chains, err := nfc.conn.ListChains()
	if err != nil {
		return nil, err
	}
	var chainNames []string
	for _, chain := range chains {
		if nfc.table.Name == chain.Table.Name && nfc.table.Family == chain.Table.Family {
			if _, ok := nfc.chains[chain.Name]; !ok {
				// Found chain which is not in the store
				// triggering Sync() to add it
				if err := nfc.Sync(); err != nil {
					return nil, fmt.Errorf("Found chain in table %s which was missing in the store, failed to add it with error: %+v", chain.Table.Name, err)
				}
			}
			chainNames = append(chainNames, chain.Name)
		}
	}

	return chainNames, nil
}

// Ready returns true if the chain is found in the list of programmed chains
func (nfc *nfChains) Ready(name string) (bool, error) {
	chains, err := nfc.conn.ListChains()
	if err != nil {
		return false, err
	}
	for _, chain := range chains {
		if nfc.table.Name == chain.Table.Name && nfc.table.Family == chain.Table.Family {
			if name == chain.Name {
				return true, nil
			}
		}
	}

	return false, nil
}

func newChains(conn NetNS, t *nftables.Table) ChainsInterface {
	return &nfChains{
		conn:   conn,
		table:  t,
		chains: make(map[string]*nfChain),
	}
}
