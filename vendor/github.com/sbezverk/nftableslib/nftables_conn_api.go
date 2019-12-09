package nftableslib

import (
	"github.com/google/nftables"
)

// NetNS defines interface needed to nf tables
type NetNS interface {
	Flush() error
	FlushRuleset()
	AddTable(*nftables.Table) *nftables.Table
	DelTable(*nftables.Table)
	ListTables() ([]*nftables.Table, error)
	AddChain(*nftables.Chain) *nftables.Chain
	DelChain(*nftables.Chain)
	ListChains() ([]*nftables.Chain, error)
	AddRule(*nftables.Rule) *nftables.Rule
	DelRule(*nftables.Rule) error
	GetRule(*nftables.Table, *nftables.Chain) ([]*nftables.Rule, error)
	AddSet(*nftables.Set, []nftables.SetElement) error
	DelSet(*nftables.Set)
	GetSets(*nftables.Table) ([]*nftables.Set, error)
	GetSetElements(*nftables.Set) ([]nftables.SetElement, error)
	SetAddElements(*nftables.Set, []nftables.SetElement) error
	SetDeleteElements(*nftables.Set, []nftables.SetElement) error
}
