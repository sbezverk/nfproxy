/*
Copyright 2020 The nfproxy Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

// NFTInterface provides interfaces to access ipv4/6 chains and ipv4/6 sets
type NFTInterface struct {
	ClusterCidrIpv4 string
	ClusterCidrIpv6 string
	CIv4            nftableslib.ChainsInterface
	CIv6            nftableslib.ChainsInterface
	SIv4            nftableslib.SetsInterface
	SIv6            nftableslib.SetsInterface
	sets            map[string]*nftables.Set
}

// Rule defines nftables chain name, rule and once programmed, rule id is stored in RuleID slice.
type Rule struct {
	Chain  string
	RuleID []uint64
}

// EPRule defines Endpoint specific nftables rule, it carries endpoint specific variables in addition
// to common ones found in Rule struct
type EPRule struct {
	Rule
	// EpIndex defines an endpoint index for a specific service port. If the service port
	// has multiple endpoints, each and point has a unique index. It is used for Service Affinity
	// implementation as endpoint's "update" rule must update only its own index.
	EpIndex       int
	WithAffinity  bool
	MaxAgeSeconds int
	ServiceID     string
}

// EPnft defines per endpoint nftables info. This information allows manipulating
// rules, sets in ipv4 and ipv6 tables and chains.
type EPnft struct {
	Interface *NFTInterface
	Rule      map[nftables.TableFamily]*EPRule
}

// SVCChain defines a map of chains a service uses for its rules, the key is chain names, it is combined from
// a chain prefix "k8s-nfproxy-svc-" or "k8s-nfproxy-fw-" and service's unique ID
type SVCChain struct {
	Chain map[string]*Rule
}

// SVCnft defines per IP Family nftables chains used by individual service.
type SVCnft struct {
	Interface     *NFTInterface
	Chains        map[nftables.TableFamily]SVCChain
	WithEndpoints bool
	WithAffinity  bool
	MaxAgeSeconds int
	ServiceID     string
}

// InitNFTables initializes connection to netfilter and instantiates nftables table interface
func InitNFTables(clusterCIDRIPv4, clusterCIDRIPv6 string) (*NFTInterface, error) {
	//  Initializing connection to netfilter
	ti := initNFTables()

	// TODO (sbezverk) Consider rebuilding data structures based on discovered data
	if ti.Tables().Exist(nfV4TableName, nftables.TableFamilyIPv4) {
		// Table already exists, removing it
		ti.Tables().DeleteImm(nfV4TableName, nftables.TableFamilyIPv4)
	}
	if ti.Tables().Exist(nfV6TableName, nftables.TableFamilyIPv6) {
		// Table already exists, removing it
		ti.Tables().DeleteImm(nfV6TableName, nftables.TableFamilyIPv6)
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
	nfti.ClusterCidrIpv4 = clusterCIDRIPv4
	nfti.ClusterCidrIpv6 = clusterCIDRIPv6
	nfti.sets = make(map[string]*nftables.Set)

	if err := programCommonChainsRules(nfti, clusterCIDRIPv4, clusterCIDRIPv6); err != nil {
		return nil, err
	}

	return nfti, nil
}

func initNFTables() nftableslib.TablesInterface {
	conn := nftableslib.InitConn()
	return nftableslib.InitNFTables(conn)
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
	ipaddr string, proto v1.Protocol, port int32, serviceID string) ([]uint64, error) {
	ci := ciForTableFamily(nfti, tableFamily)
	dnat := &nftableslib.NATAttributes{
		L3Addr:      [2]*nftableslib.IPAddr{setIPAddr(ipaddr)},
		FullyRandom: true,
	}
	if port != 0 {
		dnat.Port = [2]uint16{uint16(port)}
	}
	dnatAction, _ := nftableslib.SetDNAT(dnat)
	rules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
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
					Mask:  0x4000,
				},
			},
		},
		{
			Action: dnatAction,
		},
	}
	if serviceID != "" {
		rules[0].UserData = nftableslib.MakeRuleComment("endpoint for " + K8sSvcPrefix + serviceID)
	}
	if err := ci.Chains().CreateImm(chain, nil); err != nil {
		return nil, fmt.Errorf("AddEndpointRules: ci.Chains().CreateImm exit with error: %+v", err)
	}
	id, err := programChainRules(ci, chain, rules, 0)
	if err != nil {
		return nil, fmt.Errorf("AddEndpointRules: programChainRules exit with error: %+v", err)
	}

	return id, nil
}

// AddEndpointUpdateRule creates an ednpoint chain and programs Update rule, this rules will update
// (refresh) endpoint entry in a Service Affinity map.
func AddEndpointUpdateRule(nfti *NFTInterface, tableFamily nftables.TableFamily, chain string, index int, svcID string, timeout int) ([]uint64, error) {
	ci := ciForTableFamily(nfti, tableFamily)
	si := nfti.SIv4
	if tableFamily == nftables.TableFamilyIPv6 {
		si = nfti.SIv6
	}
	s, err := si.Sets().GetSetByName(K8sAffinityMap + svcID)
	if err != nil {
		return nil, err
	}
	rules := []nftableslib.Rule{
		{
			Dynamic: &nftableslib.Dynamic{
				Match: nftableslib.MatchTypeL3Src,
				Op:    unix.NFT_DYNSET_OP_UPDATE,
				Key:   uint32(index),
				SetRef: &nftableslib.SetRef{
					Name: s.Name,
					ID:   s.ID,
				},
			},
		},
	}

	if err := ci.Chains().CreateImm(chain, nil); err != nil {
		return nil, fmt.Errorf("failed to create endpoint chain %s with error: %+v", chain, err)
	}
	ri, err := ci.Chains().Chain(chain)
	if err != nil {
		return nil, fmt.Errorf("fail to get rules' interface for endpoint chain %s with error: %+v", chain, err)
	}
	rules[0].Position = 0
	id, err := ri.Rules().InsertImm(&rules[0])
	if err != nil {
		return nil, fmt.Errorf("fail to insert Update rule program endpoints rules for service chain %s with error: %+v", chain, err)
	}

	return []uint64{id}, nil
}

// DeleteEndpointUpdateRule removes Update rule when Service Port's Session Affinity confiugration is removed.
func DeleteEndpointUpdateRule(nfti *NFTInterface, tableFamily nftables.TableFamily, chain string, updateRuleID int) error {
	ci := ciForTableFamily(nfti, tableFamily)
	ri, err := ci.Chains().Chain(chain)
	if err != nil {
		return fmt.Errorf("fail to get rules' interface for endpoint chain %s with error: %+v", chain, err)
	}

	if err := ri.Rules().DeleteImm(uint64(updateRuleID)); err != nil {
		return fmt.Errorf("fail to delete Update rule program endpoints rules for service chain %s with error: %+v", chain, err)
	}

	return nil
}

// DeleteEndpointRules delete nftables rules associated with an endpoint and then deletes endpoint's chain
func DeleteEndpointRules(nfti *NFTInterface, tableFamily nftables.TableFamily, chain string, ruleID []uint64) error {
	ci := ciForTableFamily(nfti, tableFamily)

	if err := deleteChainRules(ci, chain, ruleID); err != nil {
		return err
	}

	return nil
}

// DeleteServiceRules deletes nftables rules associated with a service
func DeleteServiceRules(nfti *NFTInterface, tableFamily nftables.TableFamily, chain string, ruleID []uint64) error {
	ci := ciForTableFamily(nfti, tableFamily)

	if err := deleteChainRules(ci, chain, ruleID); err != nil {
		return err
	}

	return nil
}

// DeleteChain deletes chain associated with a service or an endpoint
func DeleteChain(nfti *NFTInterface, tableFamily nftables.TableFamily, chain string) error {
	ci := ciForTableFamily(nfti, tableFamily)

	return ci.Chains().DeleteImm(chain)
}

func programChainRules(ci nftableslib.ChainsInterface, chain string, rules []nftableslib.Rule, position int) ([]uint64, error) {
	var ids []uint64
	var id uint64
	var err error
	ri, err := ci.Chains().Chain(chain)
	if err != nil {
		return nil, err
	}
	id = uint64(position)
	for i := 0; i < len(rules); i++ {
		rules[i].Position = int(id)
		id, err = ri.Rules().CreateImm(&rules[i])
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

// GetSvcChain builds a chain map used by a specific service
func GetSvcChain(tableFamily nftables.TableFamily, svcID string) map[nftables.TableFamily]SVCChain {
	chains := make(map[nftables.TableFamily]SVCChain)
	chain := SVCChain{
		Chain: make(map[string]*Rule),
	}
	//  K8sSvcPrefix+svcID is services chain used by a specific service
	chain.Chain[K8sSvcPrefix+svcID] = &Rule{
		Chain:  K8sSvcPrefix + svcID,
		RuleID: nil,
	}
	//	chain.Chain[K8sFwPrefix+svcID] = &Rule{
	//		Chain:  K8sFwPrefix + svcID,
	//		RuleID: nil,
	//	}
	//	chain.Chain[K8sXlbPrefix+svcID] = &Rule{
	//		Chain:  K8sXlbPrefix + svcID,
	//		RuleID: nil,
	//	}
	chains[tableFamily] = chain

	return chains
}

// AddToSet adds service's proto.ip.port to a set specified by set parameter
func AddToSet(nfti *NFTInterface, tableFamily nftables.TableFamily, proto v1.Protocol, addr string, port uint16,
	set string, chain string) error {
	si := nfti.SIv4
	ipaddr := net.ParseIP(addr).To4()
	dataType := nftables.TypeIPAddr
	if tableFamily == nftables.TableFamilyIPv6 {
		si = nfti.SIv6
		ipaddr = net.ParseIP(addr).To16()
		dataType = nftables.TypeIP6Addr
		klog.V(6).Infof("IPv6 Family is requested, address: [%s]", ipaddr)
	}
	se := []nftables.SetElement{}
	ra := setActionVerdict(unix.NFT_JUMP, chain)
	protoB := protoByteFromV1Proto(proto)
	element, err := nftableslib.MakeConcatElement([]nftables.SetDatatype{nftables.TypeInetProto, dataType, nftables.TypeInetService},
		[]nftableslib.ElementValue{{InetProto: &protoB}, {IPAddr: ipaddr}, {InetService: &port}}, ra)
	if err != nil {
		return fmt.Errorf("failed to create a concat element with error: %+v", err)
	}
	se = append(se, *element)

	if err = si.Sets().SetAddElements(set, se); err != nil {
		// TODO Add logic to retry, for now just error out
		if errors.Is(err, unix.EBUSY) {
			klog.Errorf("AddToSet %s for %s:%s:%d failed with error: %v", set, proto, addr, port, errors.Unwrap(err))
			return err
		}
		if errors.Is(err, unix.EEXIST) {
			klog.Warningf("AddToSet %s for %s:%s:%d already exists", set, proto, addr, port)
			return nil
		}
		klog.Errorf("AddToSet %s for %s:%s:%d failed with error: %v", set, proto, addr, port, err)
		return err
	}

	return nil
}

// RemoveFromSet removes service's proto.ip.port from a set specified by a parameter set
func RemoveFromSet(nfti *NFTInterface, tableFamily nftables.TableFamily, proto v1.Protocol, addr string, port uint16,
	set string, chain string) error {
	si := nfti.SIv4
	ipaddr := net.ParseIP(addr).To4()
	dataType := nftables.TypeIPAddr
	if tableFamily == nftables.TableFamilyIPv6 {
		si = nfti.SIv6
		ipaddr = net.ParseIP(addr).To16()
		dataType = nftables.TypeIP6Addr
	}

	se := []nftables.SetElement{}
	ra := setActionVerdict(unix.NFT_JUMP, chain)
	protoB := protoByteFromV1Proto(proto)
	element, err := nftableslib.MakeConcatElement([]nftables.SetDatatype{nftables.TypeInetProto, dataType, nftables.TypeInetService},
		[]nftableslib.ElementValue{{InetProto: &protoB}, {IPAddr: ipaddr}, {InetService: &port}}, ra)
	if err != nil {
		return fmt.Errorf("failed to create a concat element with error: %+v", err)
	}
	se = append(se, *element)

	if err = si.Sets().SetDelElements(set, se); err != nil {
		if errors.Is(err, unix.EBUSY) {
			// TODO Add logic to retry, for now just error out
			klog.Errorf("RemoveFromSet %s for %s:%s:%d failed with error: %v", set, proto, addr, port, errors.Unwrap(err))
			return err
		}
		if errors.Is(err, unix.ENOENT) {
			klog.Warningf("RemoveFromSet %s does not find entry for  %s:%s:%d", set, proto, addr, port)
			return nil
		}
		klog.Errorf("RemoveFromSet %s for %s:%s:%d failed with error: %v", set, proto, addr, port, errors.Unwrap(err))
		return err
	}

	return nil
}

// AddToNodeportSet adds service's port to the nodeport set
func AddToNodeportSet(nfti *NFTInterface, tableFamily nftables.TableFamily, proto v1.Protocol, port uint16, chain string) error {
	si := nfti.SIv4
	if tableFamily == nftables.TableFamilyIPv6 {
		si = nfti.SIv6
	}
	se := []nftables.SetElement{}
	ra := setActionVerdict(unix.NFT_JUMP, chain)
	protoB := protoByteFromV1Proto(proto)
	element, err := nftableslib.MakeConcatElement([]nftables.SetDatatype{nftables.TypeInetProto, nftables.TypeInetService},
		[]nftableslib.ElementValue{{InetProto: &protoB}, {InetService: &port}}, ra)
	if err != nil {
		return fmt.Errorf("failed to create a concat element with error: %+v", err)
	}
	se = append(se, *element)

	if err = si.Sets().SetAddElements(K8sNodeportSet, se); err != nil {
		// TODO Add logic to retry, for now just error out
		if errors.Is(err, unix.EBUSY) {
			klog.Errorf("AddToNodeportSet for %s:%d failed with error: %v", proto, port, errors.Unwrap(err))
			return err
		}
		if errors.Is(err, unix.EEXIST) {
			klog.Warningf("AddToNodeportSet for %s:%d already exists", proto, port)
			return nil
		}
		klog.Errorf("AddToNodeportSet for %s:%d failed with error: %v", proto, port, err)
		return err
	}

	return nil
}

// RemoveFromNodeportSet removes service's proto.ip.port from a set specified by a parameter set
func RemoveFromNodeportSet(nfti *NFTInterface, tableFamily nftables.TableFamily, proto v1.Protocol, port uint16, chain string) error {
	si := nfti.SIv4
	if tableFamily == nftables.TableFamilyIPv6 {
		si = nfti.SIv6
	}
	se := []nftables.SetElement{}
	ra := setActionVerdict(unix.NFT_JUMP, chain)
	protoB := protoByteFromV1Proto(proto)
	element, err := nftableslib.MakeConcatElement([]nftables.SetDatatype{nftables.TypeInetProto, nftables.TypeInetService},
		[]nftableslib.ElementValue{{InetProto: &protoB}, {InetService: &port}}, ra)
	if err != nil {
		return fmt.Errorf("failed to create a concat element with error: %+v", err)
	}
	se = append(se, *element)

	if err = si.Sets().SetDelElements(K8sNodeportSet, se); err != nil {
		// TODO Add logic to retry, for now just error out
		if errors.Is(err, unix.EBUSY) {
			klog.Errorf("RemoveFromNodeportSet for %s:%d failed with error: %v", proto, port, errors.Unwrap(err))
			return err
		}
		if errors.Is(err, unix.ENOENT) {
			klog.Warningf("RemoveFromNodeportSet for %s:%d does not exist", proto, port)
			return nil
		}
		klog.Errorf("RemoveFromNodeportSet for %s:%d failed with error: %v", proto, port, err)
		return err
	}

	return nil
}

// AddServiceChains adds a specific to service port chains k8s-nfproxy-svc-{svcID},k8s-nfproxy-fw-{svcID}, k8s-nfproxy-xlb-{svcID}
func AddServiceChains(nfti *NFTInterface, tableFamily nftables.TableFamily, svcID string) error {
	for _, prefix := range []string{K8sSvcPrefix /*, K8sFwPrefix, K8sXlbPrefix*/} {
		ci := ciForTableFamily(nfti, tableFamily)
		if err := ci.Chains().CreateImm(prefix+svcID, nil); err != nil {
			return err
		}
	}
	return nil
}

// DeleteServiceChains removes a specific to service port chains k8s-nfproxy-svc-{svcID},k8s-nfproxy-fw-{svcID}, k8s-nfproxy-xlb-{svcID}
func DeleteServiceChains(nfti *NFTInterface, tableFamily nftables.TableFamily, svcID string) error {
	for _, prefix := range []string{K8sSvcPrefix /*, K8sFwPrefix, K8sXlbPrefix*/} {
		ci := ciForTableFamily(nfti, tableFamily)
		if err := ci.Chains().DeleteImm(prefix + svcID); err != nil {
			return err
		}
	}
	return nil
}

// ProgramServiceEndpoints programms endpoints to the service chain, if multiple endpoint exists, endpoint rules
// will be programmed for loadbalancing.
func ProgramServiceEndpoints(nfti *NFTInterface, tableFamily nftables.TableFamily, svcID string, epchains []*EPRule, ruleID []uint64,
	withAffinity bool, svcPortName string) ([]uint64, error) {
	var id []uint64

	chain := K8sSvcPrefix + svcID
	ci := ciForTableFamily(nfti, tableFamily)
	// Adding first rule of Service Port Chain, Counter
	ri, err := ci.Chains().Chain(chain)
	if err != nil {
		return nil, fmt.Errorf("fail to get rules interface for service chain %s with error: %+v", chain, err)
	}
	rules := []nftableslib.Rule{
		nftableslib.Rule{
			Counter:  &nftableslib.Counter{},
			UserData: nftableslib.MakeRuleComment("service chain for Service Port Name " + svcPortName),
		},
	}
	// If Service Port has Session Affinity then MatchAct rule must be inserted before normal load balancing rule.
	if withAffinity {
		si := nfti.SIv4
		if tableFamily == nftables.TableFamilyIPv6 {
			si = nfti.SIv6
		}
		// Getting info for Service Port's Affinity map
		s, err := si.Sets().GetSetByName(K8sAffinityMap + svcID)
		if err != nil {
			return nil, err
		}
		act := make(map[int]*nftableslib.RuleAction, len(epchains))
		// Preparing elements for Act.
		for i := 0; i < len(epchains); i++ {
			// Each Endpoint has an Index allocated at the time when it gets created, this index must be a key
			// in Action vmap.
			act[epchains[i].EpIndex] = setActionVerdict(unix.NFT_JUMP, epchains[i].Chain)
		}
		rules = append(rules, nftableslib.Rule{
			MatchAct: &nftableslib.MatchAct{
				Match: nftableslib.MatchTypeL3Src,
				MatchRef: &nftableslib.SetRef{
					Name:  s.Name,
					ID:    s.ID,
					IsMap: true,
				},
				ActElement: act,
			},
		})
	}
	// Start of a normal rule preparation process
	epChain := []string{}
	for i := 0; i < len(epchains); i++ {
		epChain = append(epChain, epchains[i].Chain)
	}
	loadbalanceAction, err := nftableslib.SetLoadbalance(epChain, unix.NFT_JUMP, unix.NFT_NG_RANDOM)
	if err != nil {
		return nil, err
	}
	rules = append(rules, nftableslib.Rule{
		Action: loadbalanceAction,
	})
	if len(ruleID) == 0 {
		// Since ruleID len is 0, it is the first time when the service has endpoints' rule programmed
		id, err = programChainRules(ci, chain, rules, 0)
		if err != nil {
			return nil, fmt.Errorf("fail to program endpoints rules for service chain %s with error: %+v", chain, err)
		}
	} else {
		// Preserving existing rules
		id = ruleID
		// In normal (no Session Affinity) case, Load Balancing rule's handle would be stored at position 1 of RuleID slice,
		// right after Counter rule id which is always at position 0.
		loadBalanceRuleIndex := 1
		// Service has previously progrmmed endpoint rule, need to Insert a new rule and then delete the old one
		if withAffinity {
			// if withAffinity is true then rule index 1 will always carry MatchAct rule which needs to be replaced
			rules[1].Position = int(ruleID[1])
			rid, err := ri.Rules().InsertImm(&rules[1])
			if err != nil {
				return nil, fmt.Errorf("fail to program endpoints rules for service chain %s with error: %+v", chain, err)
			}
			if err := ri.Rules().DeleteImm(ruleID[1]); err != nil {
				klog.Errorf("failed to delete old endpoints rule for service chain %s with error: %+v", chain, err)
			}
			id[1] = rid
			// Since it is Session Affinity case, then Load Balancing rule handle position would be moved to 2.
			loadBalanceRuleIndex++
		}
		rules[loadBalanceRuleIndex].Position = int(ruleID[loadBalanceRuleIndex])
		rid, err := ri.Rules().InsertImm(&rules[loadBalanceRuleIndex])
		if err != nil {
			return nil, fmt.Errorf("fail to program endpoints rules for service chain %s with error: %+v", chain, err)
		}
		if err := ri.Rules().DeleteImm(ruleID[loadBalanceRuleIndex]); err != nil {
			klog.Errorf("failed to delete old endpoints rule for service chain %s with error: %+v", chain, err)
		}
		id[loadBalanceRuleIndex] = rid
	}

	return id, nil
}

func ciForTableFamily(nfti *NFTInterface, tableFamily nftables.TableFamily) nftableslib.ChainsInterface {
	if tableFamily == nftables.TableFamilyIPv6 {
		return nfti.CIv6
	}
	return nfti.CIv4
}

func protoByteFromV1Proto(proto v1.Protocol) byte {
	var protoByte byte
	switch proto {
	case v1.ProtocolTCP:
		protoByte = unix.IPPROTO_TCP
	case v1.ProtocolUDP:
		protoByte = unix.IPPROTO_UDP
	case v1.ProtocolSCTP:
		protoByte = unix.IPPROTO_SCTP
	default:
		protoByte = unix.IPPROTO_TCP
	}

	return protoByte
}

func programClusterIPRules(ci nftableslib.ChainsInterface, rules []nftableslib.Rule) ([]uint64, error) {
	var ids []uint64
	var err error
	ri, err := ci.Chains().Chain(K8sNATServices)
	if err != nil {
		return nil, err
	}

	// Cluster IP rules always inserted at the beginning of K8sNATServices chain followed by External and Loadbalancer rules
	rules[0].Position = 0
	id, err := ri.Rules().InsertImm(&rules[0])
	if err != nil {
		return nil, err
	}
	ids = append(ids, id)
	for i := 1; i < len(rules); i++ {
		rules[i].Position = int(id)
		id, err := ri.Rules().CreateImm(&rules[i])
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}

	return ids, nil
}

// AddServiceAffinityMap creates a map used for Service's Affinity implementation. When service affinity is
// enabled, this map will be updated by "update/refreshed" from aging out by a rule of each aviable endpoint.
func AddServiceAffinityMap(nfti *NFTInterface, tableFamily nftables.TableFamily, svcID string, timeout int) error {
	si := nfti.SIv4
	if tableFamily == nftables.TableFamilyIPv6 {
		si = nfti.SIv6
	}

	affinityMap := nftableslib.SetAttributes{
		Name:       K8sAffinityMap + svcID,
		Constant:   false,
		IsMap:      true,
		HasTimeout: true,
		Timeout:    time.Duration(time.Second * time.Duration(timeout)),
		KeyType:    nftables.TypeIPAddr,
		DataType:   nftables.TypeInteger,
	}

	_, err := si.Sets().CreateSet(&affinityMap, nil)
	if err != nil {
		return fmt.Errorf("failed to create affinity map %s with error: %+v", K8sAffinityMap+svcID, err)
	}

	return nil
}

// DeleteServiceAffinityMap removes service's affinity map
func DeleteServiceAffinityMap(nfti *NFTInterface, tableFamily nftables.TableFamily, svcID string) error {
	si := nfti.SIv4
	if tableFamily == nftables.TableFamilyIPv6 {
		si = nfti.SIv6
	}

	if err := si.Sets().DelSet(K8sAffinityMap + svcID); err != nil {
		return fmt.Errorf("failed to delete affinity map %s with error: %+v", K8sAffinityMap+svcID, err)
	}

	return nil
}

// AddServiceMatchActRule programms Service Port's MatchAct rule. This rule is inserted as a second rule (after the counter rule)
// in order to process packet based on the content of Service Port's Affinity map. If the map has an entry for a specific source,
// then traffic will be send to the same endpoint chain instead of round robin load balancing between available endpoints.
func AddServiceMatchActRule(nfti *NFTInterface, tableFamily nftables.TableFamily, svcID string, epchains []*EPRule, ruleID uint64) ([]uint64, error) {
	var err error

	chain := K8sSvcPrefix + svcID
	ci := ciForTableFamily(nfti, tableFamily)
	// Adding first rule of Service Port Chain, Counter
	ri, err := ci.Chains().Chain(chain)
	if err != nil {
		return nil, fmt.Errorf("fail to get rules interface for service chain %s with error: %+v", chain, err)
	}
	si := nfti.SIv4
	if tableFamily == nftables.TableFamilyIPv6 {
		si = nfti.SIv6
	}
	// Getting info for Service Port's Affinity map
	s, err := si.Sets().GetSetByName(K8sAffinityMap + svcID)
	if err != nil {
		return nil, err
	}
	act := make(map[int]*nftableslib.RuleAction, len(epchains))
	// Preparing elements for Act.
	for i := 0; i < len(epchains); i++ {
		// Each Endpoint has an Index allocated at the time when it gets created, this index must be a key
		// in Action vmap.
		act[epchains[i].EpIndex] = setActionVerdict(unix.NFT_JUMP, epchains[i].Chain)
	}
	rules := nftableslib.Rule{
		MatchAct: &nftableslib.MatchAct{
			Match: nftableslib.MatchTypeL3Src,
			MatchRef: &nftableslib.SetRef{
				Name:  s.Name,
				ID:    s.ID,
				IsMap: true,
			},
			ActElement: act,
		},
	}

	// Inserting MatchAct rule right after the first rule.
	rules.Position = int(ruleID)
	rid, err := ri.Rules().InsertImm(&rules)
	if err != nil {
		return nil, fmt.Errorf("fail to program MatchAct rule for service chain %s with error: %+v", chain, err)
	}

	return []uint64{rid}, nil
}
