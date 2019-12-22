package nftables

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog"
)

const (
	nfV4TableName = "kube-nfproxy-v4"
	nfV6TableName = "kube-nfproxy-v6"
)

var (
	nfRuleRetryInterval = time.Second * 30
)

// NFTInterface provides interfaces to access ipv4/6 chains and ipv4/6 sets
type NFTInterface struct {
	CIv4 nftableslib.ChainsInterface
	CIv6 nftableslib.ChainsInterface
	SIv4 nftableslib.SetsInterface
	SIv6 nftableslib.SetsInterface
}

// Rule defines nftables chain name, rule and once programmed, rule id
type Rule struct {
	Chain  string
	RuleID []uint64
}

// EPnft defines per endpoint nftables info. This information allows manipulating
// rules, sets in ipv4 and ipv6 tables and chains.
type EPnft struct {
	Interface *NFTInterface
	Rule      map[nftables.TableFamily]Rule
}

// SVCChain defines a map of chains a service uses for its rules, the key is chain names
type SVCChain struct {
	Chain map[string]Rule
}

// SVCnft defines per IP Family nftables chains used by individual service.
type SVCnft struct {
	Interface     *NFTInterface
	Chains        map[nftables.TableFamily]SVCChain
	WithEndpoints bool
}

// InitNFTables initializes connection to netfilter and instantiates nftables table interface
func InitNFTables(clusterCIDRIPv4, clusterCIDRIPv6 string) (*NFTInterface, error) {
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
	if err := programCommonChainsRules(nfti, clusterCIDRIPv4, clusterCIDRIPv6); err != nil {
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
		return nil, fmt.Errorf("AddEndpointRules: ci.Chains().CreateImm exit with error: %+v", err)
	}
	id, err := programChainRules(ci, chain, rules)
	if err != nil {
		return nil, fmt.Errorf("AddEndpointRules: programChainRules exit with error: %+v", err)
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
		return nil, fmt.Errorf("programChainRules: ci.Chains().Chain exited with error: %+v", err)
	}
	for _, r := range rules {
		id, err := ri.Rules().CreateImm(&r)
		if err != nil {
			return nil, fmt.Errorf("programChainRules: ri.Rules().CreateImm exited with error: %+v", err)
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

// GetSvcChain builds a chain map used by a specific service
func GetSvcChain(tableFamily nftables.TableFamily, svcChainName string) map[nftables.TableFamily]SVCChain {
	chains := make(map[nftables.TableFamily]SVCChain)
	chain := SVCChain{
		Chain: make(map[string]Rule),
	}
	// k8sNATNodeports chain is used if service has any node ports
	chain.Chain[k8sNATNodeports] = Rule{
		Chain:  k8sNATNodeports,
		RuleID: nil,
	}
	// k8sNATServices is services chain used by all services to expose ips/ports
	chain.Chain[k8sNATServices] = Rule{
		Chain:  k8sNATServices,
		RuleID: nil,
	}
	//  svcChainName is services chain used by a specific service
	chain.Chain[svcChainName] = Rule{
		Chain:  k8sNATServices,
		RuleID: nil,
	}
	chains[tableFamily] = chain

	return chains
}

// AddToNoEndpointsList adds service's ip and port to No Endpoints Set to reject incoming to the service traffic
func AddToNoEndpointsList(nfti *NFTInterface, tableFamily nftables.TableFamily, proto string, addr string, port uint16) error {
	si := nfti.SIv4
	ipaddr := net.ParseIP(addr).To4()
	dataType := nftables.TypeIPAddr
	if tableFamily == nftables.TableFamilyIPv6 {
		si = nfti.SIv6
		ipaddr = net.ParseIP(addr).To16()
		dataType = nftables.TypeIP6Addr
	}
	se := []nftables.SetElement{}
	ra := setActionVerdict(unix.NFT_JUMP, k8sFilterDoReject)
	element, err := nftableslib.MakeConcatElement([]nftables.SetDatatype{dataType, nftables.TypeInetService},
		[]nftableslib.ElementValue{{IPAddr: ipaddr}, {InetService: &port}}, ra)
	if err != nil {
		return fmt.Errorf("failed to create a concat element with error: %+v", err)
	}
	se = append(se, *element)

	if err = si.Sets().SetAddElements(k8sNoEndpointsSet, se); err != nil {
		// TODO Add logic to retry, for now just error out
		if errors.Is(err, unix.EBUSY) {
			klog.Warningf("nfproxy: SetAddElements for %s:%s:%d failed with error: %v", proto, addr, port, errors.Unwrap(err))
			return err
		}
		if errors.Is(err, unix.EEXIST) {
			klog.Warningf("nfproxy: SetAddElements for %s:%s:%d already exists", proto, addr, port)
			return nil
		}
		klog.Errorf("nfproxy: SetAddElements for %s:%s:%d failed with error: %v", proto, addr, port, err)
		return err
	}

	klog.Infof("nfproxy: SetAddElements for %s:%s:%d succeeded", proto, addr, port)
	return nil
}

// RemoveFromNoEndpointsList removes service's ip and port from No Endpoints Set to allow service's traffic in
func RemoveFromNoEndpointsList(nfti *NFTInterface, tableFamily nftables.TableFamily, proto string, addr string, port uint16) error {
	si := nfti.SIv4
	ipaddr := net.ParseIP(addr).To4()
	dataType := nftables.TypeIPAddr
	if tableFamily == nftables.TableFamilyIPv6 {
		si = nfti.SIv6
		ipaddr = net.ParseIP(addr).To16()
		dataType = nftables.TypeIP6Addr
	}

	se := []nftables.SetElement{}
	ra := setActionVerdict(unix.NFT_JUMP, k8sFilterDoReject)
	element, err := nftableslib.MakeConcatElement([]nftables.SetDatatype{dataType, nftables.TypeInetService},
		[]nftableslib.ElementValue{{IPAddr: ipaddr}, {InetService: &port}}, ra)
	if err != nil {
		return fmt.Errorf("failed to create a concat element with error: %+v", err)
	}
	se = append(se, *element)

	if err = si.Sets().SetDelElements(k8sNoEndpointsSet, se); err != nil {
		if errors.Is(err, unix.EBUSY) {
			// TODO Add logic to retry, for now just error out
			klog.Warningf("nfproxy: SetDelElements for %s:%s:%d failed with error: %v", proto, addr, port, errors.Unwrap(err))
			return err
		}
		if errors.Is(err, unix.ENOENT) {
			klog.Warningf("nfproxy: SetDelElements for %s:%s:%d does not exist", proto, addr, port)
			return nil
		}
		klog.Errorf("nfproxy: SetDelElements for %s:%s:%d failed with error: %v", proto, addr, port, err)
		return err
	}

	klog.Infof("nfproxy: SetDelElements for %s:%s:%d succeeded", proto, addr, port)
	return nil
}
