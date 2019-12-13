package nftables

import (
	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"
)

const (
	nfV4TableName = "kube-nfproxy-v4"
	nfV6TableName = "kube-nfproxy-v6"
)

// NFTInterface provides interfaces to access ipv4/6 chains and ipv4/6 sets
type NFTInterface struct {
	CIv4 nftableslib.ChainsInterface
	CIv6 nftableslib.ChainsInterface
	SIv4 nftableslib.SetsInterface
	SIv6 nftableslib.SetsInterface
}

// EPRule defines nftables chain name, rule and once programmed, rule id
type EPRule struct {
	Chain  string
	Rule   nftableslib.Rule
	RuleID []uint64
}

// EPnft defines per endpoint nftables info. This information allows manipulating
// rules, sets in ipv4 and ipv6 tables and chains.
type EPnft struct {
	Interface *NFTInterface
	Rule      map[nftables.TableFamily]EPRule
}

// InitNFTables initializes connection to netfilter and instantiates nftables table interface
func InitNFTables() (*NFTInterface, error) {
	//  Initializing connection to netfilter
	ti, err := initNFTables()
	if err != nil {
		return nil, err
	}
	// Creating required tables for ipv4 and ipv6 families
	if err := ti.Tables().CreateImm(nfV4TableName, nftables.TableFamilyIPv4); err != nil {
		return nil, err
	}
	if err := ti.Tables().CreateImm(nfV6TableName, nftables.TableFamilyIPv6); err != nil {
		return nil, err
	}
	nfti, err := getNFTInterface(ti)
	if err != nil {
		return nil, err
	}
	if err := programCommonChainsRules(nfti); err != nil {
		return nil, err
	}

	return nfti, nil
}

func initNFTables() (nftableslib.TablesInterface, error) {
	conn := nftableslib.InitConn()
	ti := nftableslib.InitNFTables(conn)

	return ti, nil
}

// getNFTInterface returns nftables interfaces to access methods available for
// nftables chains and sets in both ipv4 and ipv6 families
func getNFTInterface(ti nftableslib.TablesInterface) (*NFTInterface, error) {
	civ4, err := ti.Tables().TableChains(nfV4TableName, nftables.TableFamilyIPv4)
	if err != nil {
		return nil, err
	}
	civ6, err := ti.Tables().TableChains(nfV6TableName, nftables.TableFamilyIPv6)
	if err != nil {
		return nil, err
	}
	siv4, err := ti.Tables().TableSets(nfV4TableName, nftables.TableFamilyIPv4)
	if err != nil {
		return nil, err
	}
	siv6, err := ti.Tables().TableSets(nfV6TableName, nftables.TableFamilyIPv6)
	if err != nil {
		return nil, err
	}
	return &NFTInterface{
		CIv4: civ4,
		CIv6: civ6,
		SIv4: siv4,
		SIv6: siv6,
	}, nil
}

// AddEndpointRules defines function which creates new nftables chain, rule and
// if successful return rule ID.
func AddEndpointRules(nfti *NFTInterface, tableFamily nftables.TableFamily, chain string,
	ipaddr string, proto v1.Protocol, port int32) ([]uint64, error) {
	var ruleProto byte
	var ci nftableslib.ChainsInterface
	switch proto {
	case v1.ProtocolTCP:
		ruleProto = unix.IPPROTO_TCP
	case v1.ProtocolUDP:
		ruleProto = unix.IPPROTO_UDP
	}
	switch tableFamily {
	case nftables.TableFamilyIPv4:
		ci = nfti.CIv4
	case nftables.TableFamilyIPv6:
		ci = nfti.CIv6
	}

	dnat := &nftableslib.NATAttributes{
		L3Addr:      [2]*nftableslib.IPAddr{setIPAddr(ipaddr)},
		Port:        [2]uint16{uint16(port)},
		FullyRandom: true,
	}
	dnatAction, _ := nftableslib.SetDNAT(dnat)
	rules := []nftableslib.Rule{
		{

			// -A KUBE-SEP-FS3FUULGZPVD4VYB -s 57.112.0.247/32 -j KUBE-MARK-MASQ
			L3: &nftableslib.L3Rule{
				Src: &nftableslib.IPAddrSpec{
					List: []*nftableslib.IPAddr{setIPAddr(ipaddr)},
				},
			},
			Meta: &nftableslib.Meta{
				Mark: &nftableslib.MetaMark{
					Set:   true,
					Value: 0x4000,
				},
			},
		},
		{
			// -A KUBE-SEP-FS3FUULGZPVD4VYB -p tcp -m tcp -j DNAT --to-destination 57.112.0.247:8080
			L4: &nftableslib.L4Rule{
				L4Proto: ruleProto,
			},
			Action: dnatAction,
		},
	}
	if err := ci.Chains().CreateImm(chain, nil); err != nil {
		return nil, err
	}
	id, err := programChainRules(ci, chain, rules)
	if err != nil {
		return nil, err
	}

	return id, nil
}

// DeleteEndpointRules delete nftables rules associated with an endpoint and then deletes endpoint's chain
func DeleteEndpointRules(nfti *NFTInterface, tableFamily nftables.TableFamily, chain string, ruleID []uint64) error {
	var ci nftableslib.ChainsInterface
	switch tableFamily {
	case nftables.TableFamilyIPv4:
		ci = nfti.CIv4
	case nftables.TableFamilyIPv6:
		ci = nfti.CIv6
	}

	if err := deleteChainRules(ci, chain, ruleID); err != nil {
		return err
	}

	if err := ci.Chains().DeleteImm(chain); err != nil {
		return err
	}

	return nil
}

func programChainRules(ci nftableslib.ChainsInterface, chain string, rules []nftableslib.Rule) ([]uint64, error) {
	var ids []uint64
	var err error
	ri, err := ci.Chains().Chain(chain)
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		id, err := ri.Rules().CreateImm(&r)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}

	return ids, nil
}

func deleteChainRules(ci nftableslib.ChainsInterface, chain string, rules []uint64) error {
	ri, err := ci.Chains().Chain(chain)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if err := ri.Rules().DeleteImm(r); err != nil {
			return err
		}
	}

	return nil
}
