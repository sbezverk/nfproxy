package nftables

import (
	"errors"
	"fmt"
	"net"

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
	Rule      map[nftables.TableFamily]*Rule
}

// SVCChain defines a map of chains a service uses for its rules, the key is chain names, it is combined from
// a chain prefix "k8s-nfproxy-svc-" or "k8s-nfproxy-fw-" and service's unique ID
type SVCChain struct {
	// Service carries the name of service's specific chain, this chain usually points to one or more endpoit chains
	ServiceID string
	Chain     map[string]*Rule
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
	nfti.ClusterCidrIpv4 = clusterCIDRIPv4
	nfti.ClusterCidrIpv6 = clusterCIDRIPv6

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
	ci := ciForTableFamily(nfti, tableFamily)
	protoByte := protoByteFromV1Proto(proto)

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
				L4Proto: protoByte,
			},
			Action: dnatAction,
		},
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
		ServiceID: svcID,
		Chain:     make(map[string]*Rule),
	}
	// k8sNATNodeports chain is used if service has any node ports
	chain.Chain[K8sNATNodeports] = &Rule{
		Chain:  K8sNATNodeports,
		RuleID: nil,
	}
	// k8sNATServices is services chain used by all services to expose ips/ports
	chain.Chain[K8sNATServices] = &Rule{
		Chain:  K8sNATServices,
		RuleID: nil,
	}
	//  K8sSvcPrefix+svcID is services chain used by a specific service
	chain.Chain[K8sSvcPrefix+svcID] = &Rule{
		Chain:  K8sSvcPrefix + svcID,
		RuleID: nil,
	}
	chain.Chain[K8sFwPrefix+svcID] = &Rule{
		Chain:  K8sFwPrefix + svcID,
		RuleID: nil,
	}
	chain.Chain[K8sXlbPrefix+svcID] = &Rule{
		Chain:  K8sXlbPrefix + svcID,
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
	ra := setActionVerdict(unix.NFT_JUMP, K8sFilterDoReject)
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

	//	klog.Infof("nfproxy: SetAddElements for %s:%s:%d succeeded", proto, addr, port)
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
	ra := setActionVerdict(unix.NFT_JUMP, K8sFilterDoReject)
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

	//	klog.Infof("nfproxy: SetDelElements for %s:%s:%d succeeded", proto, addr, port)
	return nil
}

// AddServiceChain adds a specific service's chain
func AddServiceChain(nfti *NFTInterface, tableFamily nftables.TableFamily, chain string) error {
	ci := ciForTableFamily(nfti, tableFamily)
	if err := ci.Chains().CreateImm(chain, nil); err != nil {
		return err
	}

	return nil
}

// ProgramServiceEndpoints programms endpoints to the service chain, if multiple endpoint exists, endpoint rules
// will be programmed for loadbalancing.
func ProgramServiceEndpoints(nfti *NFTInterface, tableFamily nftables.TableFamily, chain string, epchains []string, ruleID []uint64) ([]uint64, error) {
	var err error
	var id uint64

	ci := ciForTableFamily(nfti, tableFamily)

	loadbalanceAction, err := nftableslib.SetLoadbalance(epchains)
	if err != nil {
		return nil, err
	}
	rule := nftableslib.Rule{
		Action: loadbalanceAction,
	}
	ri, err := ci.Chains().Chain(chain)
	if err != nil {
		return nil, fmt.Errorf("fail to program endpoints rules for service chain %s with error: %+v", chain, err)
	}
	if len(ruleID) == 0 {
		// Since ruleID len is 0, it is the first time when the service has endpoints' rule programmed
		id, err = ri.Rules().CreateImm(&rule)
		if err != nil {
			return nil, fmt.Errorf("fail to program endpoints rules for service chain %s with error: %+v", chain, err)
		}
	} else {
		// Service has previously progrmmed endpoint rule, need to Insert a new rule and then delete the old one
		rule.Position = int(ruleID[0])
		id, err = ri.Rules().InsertImm(&rule)
		if err != nil {
			return nil, fmt.Errorf("fail to program endpoints rules for service chain %s with error: %+v", chain, err)
		}
		if err := ri.Rules().DeleteImm(ruleID[0]); err != nil {
			klog.Errorf("failed to delete old endpoints rule for service chain %s with error: %+v", chain, err)
		}
	}

	return []uint64{id}, nil
}

// ProgramServiceClusterIP programs Service's cluster ip rules in k8sNATServices chain
func ProgramServiceClusterIP(nfti *NFTInterface, tableFamily nftables.TableFamily, chain string,
	clusterIP string, proto v1.Protocol, port int) ([]uint64, error) {
	var err error
	var id []uint64

	ci := ciForTableFamily(nfti, tableFamily)
	protoByte := protoByteFromV1Proto(proto)
	clusterCidr := nfti.ClusterCidrIpv4
	if tableFamily == nftables.TableFamilyIPv6 {
		clusterCidr = nfti.ClusterCidrIpv6
	}
	clusterIPRules := []nftableslib.Rule{
		{
			// -A KUBE-SERVICES ! -s 57.112.0.0/12 -d 57.142.221.21/32 -p tcp -m comment --comment "default/app:http-web cluster IP" -m tcp --dport 80 -j KUBE-MARK-MASQ
			// -A KUBE-SERVICES -d 57.142.221.21/32 -p tcp -m comment --comment "default/app:http-web cluster IP" -m tcp --dport 80 -j KUBE-SVC-57XVOCFNTLTR3Q27
			L3: &nftableslib.L3Rule{
				Src: &nftableslib.IPAddrSpec{
					RelOp: nftableslib.NEQ,
					List:  []*nftableslib.IPAddr{setIPAddr(clusterCidr)},
				},
				Dst: &nftableslib.IPAddrSpec{
					List: []*nftableslib.IPAddr{setIPAddr(clusterIP)},
				},
			},
			L4: &nftableslib.L4Rule{
				L4Proto: protoByte,
				Dst: &nftableslib.Port{
					List: nftableslib.SetPortList([]int{port}),
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
			L3: &nftableslib.L3Rule{
				Dst: &nftableslib.IPAddrSpec{
					List: []*nftableslib.IPAddr{setIPAddr(clusterIP)},
				},
			},
			L4: &nftableslib.L4Rule{
				L4Proto: protoByte,
				Dst: &nftableslib.Port{
					List: nftableslib.SetPortList([]int{port}),
				},
			},
			Action: setActionVerdict(unix.NFT_JUMP, chain),
		},
	}

	id, err = programClusterIPRules(ci, clusterIPRules)
	if err != nil {
		return nil, err
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

// ProgramServiceExternalIP programs Service's external ips rules in k8sNATServices chain
func ProgramServiceExternalIP(nfti *NFTInterface, tableFamily nftables.TableFamily, chain string,
	externalIP []string, proto v1.Protocol, port int, position int) ([]uint64, error) {
	var err error
	var id []uint64

	ci := ciForTableFamily(nfti, tableFamily)
	protoByte := protoByteFromV1Proto(proto)

	var externalIPRules []nftableslib.Rule
	// Loop through all external IPs and generate set of rules for each
	for _, extIP := range externalIP {
		externalIPRules = append(externalIPRules,
			nftableslib.Rule{
				// -A KUBE-SERVICES -d 192.168.80.104/32 -p tcp -m comment --comment "default/portal:portal external IP" -m tcp --dport 8989 -j KUBE-MARK-MASQ
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddrSpec{
						List: []*nftableslib.IPAddr{setIPAddr(extIP)},
					},
				},
				L4: &nftableslib.L4Rule{
					L4Proto: protoByte,
					Dst: &nftableslib.Port{
						List: nftableslib.SetPortList([]int{port}),
					},
				},
				Meta: &nftableslib.Meta{
					Mark: &nftableslib.MetaMark{
						Set:   true,
						Value: 0x4000,
					},
				},
			},
			nftableslib.Rule{
				// -A KUBE-SERVICES -d 192.168.80.104/32 -p tcp -m comment --comment "default/portal:portal external IP" -m tcp --dport 8989 -m physdev ! --physdev-is-in -m addrtype ! --src-type LOCAL -j KUBE-SVC-MUPXPVK4XAZHSWAR
				Fib: &nftableslib.Fib{
					ResultADDRTYPE: true,
					FlagSADDR:      true,
					Data:           []byte{unix.RTN_LOCAL},
					RelOp:          nftableslib.NEQ,
				},
				Meta: &nftableslib.Meta{
					Expr: []nftableslib.MetaExpr{
						{
							Key:   unix.NFT_META_IIFNAME,
							Value: []byte("bridge"),
							RelOp: nftableslib.NEQ,
						},
					},
				},
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddrSpec{
						List: []*nftableslib.IPAddr{setIPAddr(extIP)},
					},
				},
				L4: &nftableslib.L4Rule{
					L4Proto: protoByte,
					Dst: &nftableslib.Port{
						List: nftableslib.SetPortList([]int{port}),
					},
				},
				Action: setActionVerdict(unix.NFT_JUMP, chain),
			},
			nftableslib.Rule{
				// -A KUBE-SERVICES -d 192.168.80.104/32 -p tcp -m comment --comment "default/portal:portal external IP" -m tcp --dport 8989 -m addrtype --dst-type LOCAL -j KUBE-SVC-MUPXPVK4XAZHSWAR
				Fib: &nftableslib.Fib{
					ResultADDRTYPE: true,
					FlagDADDR:      true,
					Data:           []byte{unix.RTN_LOCAL},
				},
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddrSpec{
						List: []*nftableslib.IPAddr{setIPAddr(extIP)},
					},
				},
				L4: &nftableslib.L4Rule{
					L4Proto: protoByte,
					Dst: &nftableslib.Port{
						List: nftableslib.SetPortList([]int{port}),
					},
				},
				Action: setActionVerdict(unix.NFT_JUMP, chain),
			})
	}

	id, err = programChainRules(ci, K8sNATServices, externalIPRules, position)
	if err != nil {
		return nil, err
	}

	return id, nil
}

// ProgramServiceLoadBalancerIP programs Service's LoadBalancer ips rules in k8sNATServices chain
func ProgramServiceLoadBalancerIP(nfti *NFTInterface, tableFamily nftables.TableFamily, chain string,
	lbIPs []string, proto v1.Protocol, port int, position int) ([]uint64, error) {
	var err error
	var id []uint64

	ci := ciForTableFamily(nfti, tableFamily)
	protoByte := protoByteFromV1Proto(proto)

	var lbIPRules []nftableslib.Rule
	// Loop through all Load Balancer IPs and generate set of rules for each
	for _, lbIP := range lbIPs {
		lbIPRules = append(lbIPRules,
			nftableslib.Rule{
				// -A KUBE-SERVICES -d 192.168.180.240/32 -p tcp -m comment --comment "default/app2:http-web2 loadbalancer IP" -m tcp --dport 808 -j KUBE-FW-H77O6A5PM6DG4AKY
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddrSpec{
						List: []*nftableslib.IPAddr{setIPAddr(lbIP)},
					},
				},
				L4: &nftableslib.L4Rule{
					L4Proto: protoByte,
					Dst: &nftableslib.Port{
						List: nftableslib.SetPortList([]int{port}),
					},
				},
				Action: setActionVerdict(unix.NFT_JUMP, chain),
			})
	}

	id, err = programChainRules(ci, K8sNATServices, lbIPRules, position)
	if err != nil {
		return nil, err
	}

	return id, nil
}

// ProgramServiceNodePort programs Service's Nodeport in K8sNATNodeports chain
func ProgramServiceNodePort(nfti *NFTInterface, tableFamily nftables.TableFamily, chain string, proto v1.Protocol, port int) ([]uint64, error) {
	var err error
	var id []uint64

	ci := ciForTableFamily(nfti, tableFamily)
	protoByte := protoByteFromV1Proto(proto)

	var nodeportRules []nftableslib.Rule
	nodeportRules = append(nodeportRules,
		nftableslib.Rule{
			// -A KUBE-NODEPORTS -p tcp -m comment --comment "istio-system/istio-ingressgateway:tls" -m tcp --dport 30725 -j KUBE-MARK-MASQ
			// -A KUBE-NODEPORTS -p tcp -m comment --comment "istio-system/istio-ingressgateway:tls" -m tcp --dport 30725 -j KUBE-SVC-S4S242M2WNFIAT6Y
			L4: &nftableslib.L4Rule{
				L4Proto: protoByte,
				Dst: &nftableslib.Port{
					List: nftableslib.SetPortList([]int{port}),
				},
			},
			// If not all nodeports needed to be marked, this block can be done conditionally
			Meta: &nftableslib.Meta{
				Mark: &nftableslib.MetaMark{
					Set:   true,
					Value: 0x4000,
				},
			},
			Action: setActionVerdict(unix.NFT_JUMP, chain),
		})

	id, err = programChainRules(ci, K8sNATNodeports, nodeportRules, 0)
	if err != nil {
		return nil, err
	}

	return id, nil
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
