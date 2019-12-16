package nftables

import (
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/sbezverk/nftableslib"
	"golang.org/x/sys/unix"
)

const (
	filterInput       = "nfproxy-filter-input"
	filterOutput      = "nfproxy-filter-output"
	filterForward     = "nfproxy-filter-forward"
	k8sFilterFirewall = "k8s-nfproxy-filter-firewall"
	k8sFilterServices = "k8s-nfproxy-filter-services"
	k8sFilterForward  = "k8s-nfproxy-filter-forward"
	k8sFilterDoReject = "k8s-nfproxy-filter-do-reject"

	natPrerouting     = "nfproxy-nat-preroutin"
	natOutput         = "nfproxy-nat-output"
	natPostrouting    = "nfproxy-nat-postrouting"
	k8sNATMarkDrop    = "k8s-nfproxy-nat-mark-drop"
	k8sNATMarkMasq    = "k8s-nfproxy-nat-mark-masq"
	k8sNATServices    = "k8s-nfproxy-nat-services"
	k8sNATNodeports   = "k8s-nfproxy-nat-nodeports"
	k8sNATPostrouting = "k8s-nfproxy-nat-postrouting"
)

func setActionVerdict(key int, chain ...string) *nftableslib.RuleAction {
	ra, err := nftableslib.SetVerdict(key, chain...)
	if err != nil {
		fmt.Printf("failed to SetVerdict with error: %+v\n", err)
		return nil
	}
	return ra
}

func setIPAddr(addr string) *nftableslib.IPAddr {
	a, err := nftableslib.NewIPAddr(addr)
	if err != nil {
		fmt.Printf("error %+v return from NewIPAddr for address: %s\n", err, addr)
		return nil
	}
	return a
}

func setupNFProxyChains(ci nftableslib.ChainsInterface) error {
	// nat type chains
	natChains := []struct {
		name  string
		attrs *nftableslib.ChainAttributes
	}{
		{
			name: filterInput,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeFilter,
				Priority: 0,
				Hook:     nftables.ChainHookInput,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name: filterOutput,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeFilter,
				Priority: 0,
				Hook:     nftables.ChainHookOutput,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name: filterForward,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeFilter,
				Priority: 0,
				Hook:     nftables.ChainHookForward,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name:  k8sFilterFirewall,
			attrs: nil,
		},
		{
			name:  k8sFilterServices,
			attrs: nil,
		},
		{
			name:  k8sFilterForward,
			attrs: nil,
		},
		{
			name:  k8sFilterDoReject,
			attrs: nil,
		},
		{
			name: natPrerouting,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeNAT,
				Priority: 0,
				Hook:     nftables.ChainHookPrerouting,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name: natOutput,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeNAT,
				Priority: 0,
				Hook:     nftables.ChainHookOutput,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name: natPostrouting,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeNAT,
				Priority: 0,
				Hook:     nftables.ChainHookPostrouting,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name:  k8sNATMarkDrop,
			attrs: nil,
		},
		{
			name:  k8sNATServices,
			attrs: nil,
		},
		{
			name:  k8sNATNodeports,
			attrs: nil,
		},
		{
			name:  k8sNATPostrouting,
			attrs: nil,
		},
	}
	for _, chain := range natChains {
		if err := ci.Chains().CreateImm(chain.name, chain.attrs); err != nil {
			return fmt.Errorf("failed to create chain %s with error: %+v", chain.name, err)
		}
	}

	return nil
}

func setupInitialNATRules(ci nftableslib.ChainsInterface) error {
	preroutingRules := []nftableslib.Rule{
		{
			// -A PREROUTING -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
			Action: setActionVerdict(unix.NFT_JUMP, k8sNATServices),
		},
	}
	if _, err := programChainRules(ci, natPrerouting, preroutingRules); err != nil {
		return err
	}

	outputRules := []nftableslib.Rule{
		{
			// -A OUTPUT -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
			Action: setActionVerdict(unix.NFT_JUMP, k8sNATServices),
		},
	}
	if _, err := programChainRules(ci, natOutput, outputRules); err != nil {
		return err
	}

	postroutingRules := []nftableslib.Rule{
		{
			// -A POSTROUTING -m comment --comment "kubernetes postrouting rules" -j KUBE-POSTROUTING
			Action: setActionVerdict(unix.NFT_JUMP, k8sNATPostrouting),
		},
	}
	if _, err := programChainRules(ci, natPostrouting, postroutingRules); err != nil {
		return err
	}

	markDropRules := []nftableslib.Rule{
		{
			// -A KUBE-MARK-DROP -j MARK --set-xmark 0x8000/0x8000
			Meta: &nftableslib.Meta{
				Mark: &nftableslib.MetaMark{
					Set:   true,
					Value: 0x8000,
				},
			},
		},
	}
	if _, err := programChainRules(ci, k8sNATMarkDrop, markDropRules); err != nil {
		return err
	}

	masqAction, _ := nftableslib.SetMasq(true, false, true)
	k8sPostroutingRules := []nftableslib.Rule{
		{
			// -A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -m mark --mark 0x4000/0x4000 -j MASQUERADE
			Meta: &nftableslib.Meta{
				Mark: &nftableslib.MetaMark{
					Set:   false,
					Value: 0x4000,
				},
			},
			Action: masqAction,
		},
	}
	if _, err := programChainRules(ci, k8sNATPostrouting, k8sPostroutingRules); err != nil {
		return err
	}

	return nil
}

func setupInitialFilterRules(ci nftableslib.ChainsInterface, clusterCIDR string) error {
	inputRules := []nftableslib.Rule{
		{
			// -A INPUT -m conntrack --ctstate NEW -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
			Conntracks: []*nftableslib.Conntrack{
				{
					Key:   unix.NFT_CT_STATE,
					Value: binaryutil.BigEndian.PutUint32(nftableslib.CTStateNew),
				},
			},
			Action: setActionVerdict(unix.NFT_JUMP, k8sFilterServices),
		},
		{
			// -A INPUT -j KUBE-FIREWALL
			Action: setActionVerdict(unix.NFT_JUMP, k8sFilterFirewall),
		},
	}
	// Programming rules for Filter Chain Input hook
	if _, err := programChainRules(ci, filterInput, inputRules); err != nil {
		return err
	}

	forwardRules := []nftableslib.Rule{
		{
			// -A FORWARD -m comment --comment "kubernetes forwarding rules" -j KUBE-FORWARD
			Action: setActionVerdict(unix.NFT_JUMP, k8sFilterForward),
		},
		{
			// -A FORWARD -m conntrack --ctstate NEW -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
			Conntracks: []*nftableslib.Conntrack{
				{
					Key:   unix.NFT_CT_STATE,
					Value: binaryutil.BigEndian.PutUint32(nftableslib.CTStateNew),
				},
			},
			Action: setActionVerdict(unix.NFT_JUMP, k8sFilterServices),
		},
	}
	// Programming rules for Filter Chain Forward hook
	if _, err := programChainRules(ci, filterForward, forwardRules); err != nil {
		return err
	}

	outputRules := []nftableslib.Rule{
		{
			// -A OUTPUT -m conntrack --ctstate NEW -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
			Conntracks: []*nftableslib.Conntrack{
				{
					Key:   unix.NFT_CT_STATE,
					Value: binaryutil.BigEndian.PutUint32(nftableslib.CTStateNew),
				},
			},
			Action: setActionVerdict(unix.NFT_JUMP, k8sFilterServices),
		},
		{
			// -A OUTPUT -j KUBE-FIREWALL
			Action: setActionVerdict(unix.NFT_JUMP, k8sFilterFirewall),
		},
	}
	// Programming rules for Filter Chain Output hook
	if _, err := programChainRules(ci, filterOutput, outputRules); err != nil {
		return err
	}

	firewallRules := []nftableslib.Rule{
		{
			// -A KUBE-FIREWALL -m comment --comment "kubernetes firewall for dropping marked packets" -m mark --mark 0x8000/0x8000 -j DROP
			Meta: &nftableslib.Meta{
				Mark: &nftableslib.MetaMark{
					Set:   false,
					Value: 0x8000,
				},
			},
			Action: setActionVerdict(nftableslib.NFT_DROP),
		},
	}
	// Programming rules for Filter Chain Firewall hook
	if _, err := programChainRules(ci, k8sFilterFirewall, firewallRules); err != nil {
		return err
	}

	k8sForwardRules := []nftableslib.Rule{
		{
			// -A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
			Conntracks: []*nftableslib.Conntrack{
				{
					Key:   unix.NFT_CT_STATE,
					Value: binaryutil.BigEndian.PutUint32(nftableslib.CTStateInvalid),
				},
			},
			Action: setActionVerdict(nftableslib.NFT_DROP),
		},
		{
			// -A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
			Meta: &nftableslib.Meta{
				Mark: &nftableslib.MetaMark{
					Set:   false,
					Value: 0x4000,
				},
			},
			Action: setActionVerdict(nftableslib.NFT_ACCEPT),
		},
		{
			// -A KUBE-FORWARD -s 57.112.0.0/12 -m comment --comment "kubernetes forwarding conntrack pod source rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
			L3: &nftableslib.L3Rule{
				Src: &nftableslib.IPAddrSpec{
					List: []*nftableslib.IPAddr{setIPAddr(clusterCIDR)},
				},
			},
			Conntracks: []*nftableslib.Conntrack{
				{
					Key:   unix.NFT_CT_STATE,
					Value: binaryutil.BigEndian.PutUint32(nftableslib.CTStateRelated | nftableslib.CTStateEstablished),
				},
			},
			Action: setActionVerdict(nftableslib.NFT_ACCEPT),
		},
		{
			// -A KUBE-FORWARD -s 57.112.0.0/12 -m comment --comment "kubernetes forwarding conntrack pod source rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
			L3: &nftableslib.L3Rule{
				Dst: &nftableslib.IPAddrSpec{
					List: []*nftableslib.IPAddr{setIPAddr(clusterCIDR)},
				},
			},
			Conntracks: []*nftableslib.Conntrack{
				{
					Key:   unix.NFT_CT_STATE,
					Value: binaryutil.BigEndian.PutUint32(nftableslib.CTStateRelated | nftableslib.CTStateEstablished),
				},
			},
			Action: setActionVerdict(nftableslib.NFT_ACCEPT),
		},
	}
	// Programming rules for Filter Chain Firewall hook
	if _, err := programChainRules(ci, k8sFilterForward, k8sForwardRules); err != nil {
		return err
	}

	rejectAction, _ := nftableslib.SetReject(unix.NFT_REJECT_ICMP_UNREACH, unix.NFT_REJECT_ICMPX_PORT_UNREACH)
	k8sRejectRules := []nftableslib.Rule{
		{
			Action: rejectAction,
		},
	}
	// Programming rules for Filter Chain Firewall hook
	if _, err := programChainRules(ci, k8sFilterDoReject, k8sRejectRules); err != nil {
		return err
	}

	return nil
}

func setupk8sFilterRules(ti nftableslib.TablesInterface, ci nftableslib.ChainsInterface) error {
	// Emulating 1 ports sets for service without endpoints
	si, err := ti.Tables().TableSets("ipv4table", nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("failed to get sets interface for table ipv4table with error: %+v", err)
	}

	noEndpointSet := nftableslib.SetAttributes{
		Name:     "no-endpoints-services",
		Constant: false,
		IsMap:    true,
		KeyType:  nftableslib.GenSetKeyType(nftables.TypeIPAddr, nftables.TypeInetService),
		DataType: nftables.TypeVerdict,
	}
	se := []nftables.SetElement{}
	// It is a hack for now just to see it is working, ip and port will be extracted from the service object
	port1 := uint16(8989)
	ip1 := "192.168.80.104"
	ip2 := "57.131.151.19"
	ra := setActionVerdict(unix.NFT_JUMP, k8sFilterDoReject)
	se1, err := nftableslib.MakeConcatElement(nftables.TypeIPAddr, nftables.TypeInetService,
		nftableslib.ElementValue{IPAddr: net.ParseIP(ip1).To4()}, nftableslib.ElementValue{InetService: &port1}, ra)
	if err != nil {
		return fmt.Errorf("failed to create a concat element with error: %+v", err)
	}
	se2, err := nftableslib.MakeConcatElement(nftables.TypeIPAddr, nftables.TypeInetService,
		nftableslib.ElementValue{IPAddr: net.ParseIP(ip2).To4()}, nftableslib.ElementValue{InetService: &port1}, ra)
	if err != nil {
		return fmt.Errorf("failed to create a concat element with error: %+v", err)
	}
	se = append(se, *se1)
	se = append(se, *se2)
	neSet, err := si.Sets().CreateSet(&noEndpointSet, se)
	if err != nil {
		return fmt.Errorf("failed to create a set of svc ports without endpoints with error: %+v", err)

	}
	concatElements := make([]*nftableslib.ConcatElement, 0)
	concatElements = append(concatElements,
		&nftableslib.ConcatElement{
			EType: nftables.TypeIPAddr,
		},
	)
	concatElements = append(concatElements,
		&nftableslib.ConcatElement{
			EType:  nftables.TypeInetService,
			EProto: unix.IPPROTO_TCP,
		},
	)
	servicesRules := []nftableslib.Rule{
		{
			Concat: &nftableslib.Concat{
				VMap: true,
				SetRef: &nftableslib.SetRef{
					Name:  neSet.Name,
					ID:    neSet.ID,
					IsMap: true,
				},
				Elements: concatElements,
			},
		},
	}
	ri, err := ci.Chains().Chain(k8sFilterServices)
	if err != nil {
		return err
	}
	for _, r := range servicesRules {
		_, err := ri.Rules().CreateImm(&r)
		if err != nil {
			return err
		}
	}

	return nil
}

func programCommonChainsRules(nfti *NFTInterface, clusterCIDRIPv4, clusterCIDRIPv6 string) error {
	var clusterCIDR string
	for _, ci := range []nftableslib.ChainsInterface{nfti.CIv4, nfti.CIv6} {
		if ci == nfti.CIv4 {
			clusterCIDR = clusterCIDRIPv4
		} else {
			clusterCIDR = clusterCIDRIPv6
		}
		// Programming chains and initial rules only if localAddress is specified
		if clusterCIDR != "" {
			if err := setupNFProxyChains(ci); err != nil {
				return err
			}
			if err := setupInitialFilterRules(ci, clusterCIDR); err != nil {
				return err
			}
			if err := setupInitialNATRules(ci); err != nil {
				return err
			}
		}
	}
	return nil
}
