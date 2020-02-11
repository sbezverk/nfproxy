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
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/sbezverk/nftableslib"
	"golang.org/x/sys/unix"
)

const (
	FilterInput       = "filter-input"
	FilterOutput      = "filter-output"
	FilterForward     = "filter-forward"
	K8sFilterFirewall = "k8s-filter-firewall"
	K8sFilterServices = "k8s-filter-services"
	K8sFilterForward  = "k8s-filter-forward"
	K8sFilterDoReject = "k8s-filter-do-reject"

	NatPrerouting      = "nat-preroutin"
	NatOutput          = "nat-output"
	NatPostrouting     = "nat-postrouting"
	K8sNATMarkDrop     = "k8s-nat-mark-drop"
	K8sNATDoMarkMasq   = "k8s-nat-do-mark-masq"
	K8sNATMarkMasq     = "k8s-nat-mark-masq"
	K8sNATDoMasquerade = "k8s-nat-do-masquerade"
	K8sNATServices     = "k8s-nat-services"
	K8sNATNodeports    = "k8s-nat-nodeports"
	K8sNATPostrouting  = "k8s-nat-postrouting"

	K8sNoEndpointsSet    = "no-endpoints"
	K8sNodeportSet       = "nodeports"
	K8sMarkMasqSet       = "do-mark-masq"
	K8sClusterIPSet      = "cluster-ip"
	K8sExternalIPSet     = "external-ip"
	K8sLoadbalancerIPSet = "loadbalancer-ip"

	K8sSvcPrefix = "k8s-nfproxy-svc-"
	K8sFwPrefix  = "k8s-nfproxy-fw-"
	K8sXlbPrefix = "k8s-nfproxy-xlb-"

	K8sAffinityMap = "affinity-map-"
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
			name: FilterInput,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeFilter,
				Priority: 0,
				Hook:     nftables.ChainHookInput,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name: FilterOutput,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeFilter,
				Priority: 0,
				Hook:     nftables.ChainHookOutput,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name: FilterForward,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeFilter,
				Priority: 0,
				Hook:     nftables.ChainHookForward,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name:  K8sFilterFirewall,
			attrs: nil,
		},
		{
			name:  K8sFilterServices,
			attrs: nil,
		},
		{
			name:  K8sFilterForward,
			attrs: nil,
		},
		{
			name:  K8sFilterDoReject,
			attrs: nil,
		},
		{
			name: NatPrerouting,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeNAT,
				Priority: 0,
				Hook:     nftables.ChainHookPrerouting,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name: NatOutput,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeNAT,
				Priority: 0,
				Hook:     nftables.ChainHookOutput,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name: NatPostrouting,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeNAT,
				Priority: 0,
				Hook:     nftables.ChainHookPostrouting,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name:  K8sNATMarkDrop,
			attrs: nil,
		},
		{
			name:  K8sNATDoMarkMasq,
			attrs: nil,
		},
		{
			name:  K8sNATMarkMasq,
			attrs: nil,
		},
		{
			name:  K8sNATDoMasquerade,
			attrs: nil,
		},
		{
			name:  K8sNATServices,
			attrs: nil,
		},
		{
			name:  K8sNATNodeports,
			attrs: nil,
		},
		{
			name:  K8sNATPostrouting,
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

func setupStaticNATRules(sets map[string]*nftables.Set, ci nftableslib.ChainsInterface, cidr string, ipv6 bool) error {
	preroutingRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
		{
			// -A PREROUTING -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
			Action: setActionVerdict(unix.NFT_JUMP, K8sNATServices),
		},
	}
	if _, err := programChainRules(ci, NatPrerouting, preroutingRules, 0); err != nil {
		return err
	}

	outputRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
		{
			// -A OUTPUT -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
			Action: setActionVerdict(unix.NFT_JUMP, K8sNATServices),
		},
	}
	if _, err := programChainRules(ci, NatOutput, outputRules, 0); err != nil {
		return err
	}

	postroutingRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
		{
			// -A POSTROUTING -m comment --comment "kubernetes postrouting rules" -j KUBE-POSTROUTING
			Action: setActionVerdict(unix.NFT_JUMP, K8sNATPostrouting),
		},
	}
	if _, err := programChainRules(ci, NatPostrouting, postroutingRules, 0); err != nil {
		return err
	}

	markDropRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
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
	if _, err := programChainRules(ci, K8sNATMarkDrop, markDropRules, 0); err != nil {
		return err
	}

	masqAction, _ := nftableslib.SetMasq(false, false, false)
	k8sDoMasqRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
		{
			// Log for debugging purposes
			//			Log: &nftableslib.Log{
			//				Key:   unix.NFTA_LOG_LEVEL,
			//				Value: []byte{0x0, 0x0, 0x0, 0x7},
			//			},
			Action: masqAction,
		},
	}
	if _, err := programChainRules(ci, K8sNATDoMasquerade, k8sDoMasqRules, 0); err != nil {
		return err
	}

	k8sPostroutingRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
		{
			Action: setActionVerdict(unix.NFT_JUMP, K8sNATDoMasquerade),
		},
	}
	if _, err := programChainRules(ci, K8sNATPostrouting, k8sPostroutingRules, 0); err != nil {
		return err
	}

	var dataType nftables.SetDatatype
	dataType = nftables.TypeIPAddr
	if ipv6 {
		dataType = nftables.TypeIP6Addr
	}
	concatElements := []*nftableslib.ConcatElement{
		&nftableslib.ConcatElement{
			EType: nftables.TypeInetProto,
		},
		&nftableslib.ConcatElement{
			EType: dataType,
		},
		&nftableslib.ConcatElement{
			EType: nftables.TypeInetService,
		},
	}

	nodeportConcatElements := []*nftableslib.ConcatElement{
		&nftableslib.ConcatElement{
			EType: nftables.TypeInetProto,
		},
		&nftableslib.ConcatElement{
			EType: nftables.TypeInetService,
		},
	}

	staticServiceRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
		// TODO This rule should be added only if masquarade-all flag is set
		{
			L3: &nftableslib.L3Rule{
				Src: &nftableslib.IPAddrSpec{
					RelOp: nftableslib.NEQ,
					List:  []*nftableslib.IPAddr{setIPAddr(cidr)},
				},
			},
			Action: setActionVerdict(unix.NFT_JUMP, K8sNATMarkMasq),
		},
		{
			Concat: &nftableslib.Concat{
				VMap: true,
				SetRef: &nftableslib.SetRef{
					Name:  sets[K8sClusterIPSet].Name,
					ID:    sets[K8sClusterIPSet].ID,
					IsMap: true,
				},
				Elements: concatElements,
			},
		},
		{
			Concat: &nftableslib.Concat{
				VMap: true,
				SetRef: &nftableslib.SetRef{
					Name:  sets[K8sExternalIPSet].Name,
					ID:    sets[K8sExternalIPSet].ID,
					IsMap: true,
				},
				Elements: concatElements,
			},
		},
		{
			Concat: &nftableslib.Concat{
				VMap: true,
				SetRef: &nftableslib.SetRef{
					Name:  sets[K8sLoadbalancerIPSet].Name,
					ID:    sets[K8sLoadbalancerIPSet].ID,
					IsMap: true,
				},
				Elements: concatElements,
			},
		},
		// Must be the last rule
		{
			Fib: &nftableslib.Fib{
				ResultADDRTYPE: true,
				FlagDADDR:      true,
				Data:           []byte{unix.RTN_LOCAL},
			},
			UserData: []byte("kubernetes service nodeports; NOTE: this must be the last rule in this chain"),
			Action:   setActionVerdict(unix.NFT_JUMP, K8sNATNodeports),
		},
	}
	if _, err := programChainRules(ci, K8sNATServices, staticServiceRules, 0); err != nil {
		return err
	}

	staticNodeportRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
		{
			Concat: &nftableslib.Concat{
				VMap: true,
				SetRef: &nftableslib.SetRef{
					Name:  sets[K8sNodeportSet].Name,
					ID:    sets[K8sNodeportSet].ID,
					IsMap: true,
				},
				Elements: nodeportConcatElements,
			},
		},
	}
	if _, err := programChainRules(ci, K8sNATNodeports, staticNodeportRules, 0); err != nil {
		return err
	}

	// Marking for Masq rule, it will mark the packet and then return to the calling chain
	doMarkMasqRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
		{
			Meta: &nftableslib.Meta{
				Mark: &nftableslib.MetaMark{
					Set:   true,
					Value: 0x4000,
				},
			},
			Action: setActionVerdict(unix.NFT_RETURN),
		},
	}
	if _, err := programChainRules(ci, K8sNATDoMarkMasq, doMarkMasqRules, 0); err != nil {
		return err
	}

	masqRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
		{
			Concat: &nftableslib.Concat{
				VMap: true,
				SetRef: &nftableslib.SetRef{
					Name:  sets[K8sMarkMasqSet].Name,
					ID:    sets[K8sMarkMasqSet].ID,
					IsMap: true,
				},
				Elements: concatElements,
			},
		},
		{
			Action: setActionVerdict(unix.NFT_RETURN),
		},
	}
	if _, err := programChainRules(ci, K8sNATMarkMasq, masqRules, 0); err != nil {
		return err
	}

	return nil
}

func setupStaticFilterRules(ci nftableslib.ChainsInterface, clusterCIDR string) error {
	inputRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
		{
			// -A INPUT -m conntrack --ctstate NEW -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
			Conntracks: []*nftableslib.Conntrack{
				{
					Key:   unix.NFT_CT_STATE,
					Value: binaryutil.BigEndian.PutUint32(nftableslib.CTStateNew),
				},
			},
			Action: setActionVerdict(unix.NFT_JUMP, K8sFilterServices),
		},
		{
			// -A INPUT -j KUBE-FIREWALL
			Action: setActionVerdict(unix.NFT_JUMP, K8sFilterFirewall),
		},
	}
	// Programming rules for Filter Chain Input hook
	if _, err := programChainRules(ci, FilterInput, inputRules, 0); err != nil {
		return err
	}

	forwardRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
		{
			// -A FORWARD -m comment --comment "kubernetes forwarding rules" -j KUBE-FORWARD
			Action: setActionVerdict(unix.NFT_JUMP, K8sFilterForward),
		},
		{
			// -A FORWARD -m conntrack --ctstate NEW -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
			Conntracks: []*nftableslib.Conntrack{
				{
					Key:   unix.NFT_CT_STATE,
					Value: binaryutil.BigEndian.PutUint32(nftableslib.CTStateNew),
				},
			},
			Action: setActionVerdict(unix.NFT_JUMP, K8sFilterServices),
		},
	}
	// Programming rules for Filter Chain Forward hook
	if _, err := programChainRules(ci, FilterForward, forwardRules, 0); err != nil {
		return err
	}

	outputRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
		{
			// -A OUTPUT -m conntrack --ctstate NEW -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
			Conntracks: []*nftableslib.Conntrack{
				{
					Key:   unix.NFT_CT_STATE,
					Value: binaryutil.BigEndian.PutUint32(nftableslib.CTStateNew),
				},
			},
			Action: setActionVerdict(unix.NFT_JUMP, K8sFilterServices),
		},
		{
			// -A OUTPUT -j KUBE-FIREWALL
			Action: setActionVerdict(unix.NFT_JUMP, K8sFilterFirewall),
		},
	}
	// Programming rules for Filter Chain Output hook
	if _, err := programChainRules(ci, FilterOutput, outputRules, 0); err != nil {
		return err
	}

	firewallRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
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
	if _, err := programChainRules(ci, K8sFilterFirewall, firewallRules, 0); err != nil {
		return err
	}

	k8sForwardRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
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
	if _, err := programChainRules(ci, K8sFilterForward, k8sForwardRules, 0); err != nil {
		return err
	}

	rejectAction, _ := nftableslib.SetReject(unix.NFT_REJECT_ICMP_UNREACH, unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED)
	k8sRejectRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
		{
			Action: rejectAction,
		},
	}
	// Programming rules for Filter Chain Firewall hook
	if _, err := programChainRules(ci, K8sFilterDoReject, k8sRejectRules, 0); err != nil {
		return err
	}

	return nil
}

func setupK8sFilterRules(sets map[string]*nftables.Set, ci nftableslib.ChainsInterface, ipv6 bool) error {
	var dataType nftables.SetDatatype
	dataType = nftables.TypeIPAddr
	if ipv6 {
		dataType = nftables.TypeIP6Addr
	}
	concatElements := []*nftableslib.ConcatElement{
		&nftableslib.ConcatElement{
			EType: nftables.TypeInetProto,
		},
		&nftableslib.ConcatElement{
			EType: dataType,
		},
		&nftableslib.ConcatElement{
			EType: nftables.TypeInetService,
		},
	}
	servicesRules := []nftableslib.Rule{
		{
			Counter: &nftableslib.Counter{},
		},
		{
			Concat: &nftableslib.Concat{
				VMap: true,
				SetRef: &nftableslib.SetRef{
					Name:  sets[K8sNoEndpointsSet].Name,
					ID:    sets[K8sNoEndpointsSet].ID,
					IsMap: true,
				},
				Elements: concatElements,
			},
		},
	}
	if _, err := programChainRules(ci, K8sFilterServices, servicesRules, 0); err != nil {
		return err
	}

	return nil
}

func setupCommonSets(sets map[string]*nftables.Set, si nftableslib.SetsInterface, ipv6 bool) error {
	var dataType nftables.SetDatatype
	dataType = nftables.TypeIPAddr
	if ipv6 {
		dataType = nftables.TypeIP6Addr
	}
	for _, setName := range []string{K8sNoEndpointsSet, K8sMarkMasqSet, K8sClusterIPSet, K8sExternalIPSet, K8sLoadbalancerIPSet} {
		s := nftableslib.SetAttributes{
			Name:     setName,
			Constant: false,
			IsMap:    true,
			KeyType:  nftableslib.GenSetKeyType(nftables.TypeInetProto, dataType, nftables.TypeInetService),
			DataType: nftables.TypeVerdict,
		}
		set, err := si.Sets().CreateSet(&s, nil)
		if err != nil {
			return fmt.Errorf("failed to create set %s with error: %+v", setName, err)
		}
		sets[setName] = set
	}
	// Create set for nodeports
	s := nftableslib.SetAttributes{
		Name:     K8sNodeportSet,
		Constant: false,
		IsMap:    true,
		KeyType:  nftableslib.GenSetKeyType(nftables.TypeInetProto, nftables.TypeInetService),
		DataType: nftables.TypeVerdict,
	}
	set, err := si.Sets().CreateSet(&s, nil)
	if err != nil {
		return fmt.Errorf("failed to create set %s with error: %+v", K8sNodeportSet, err)
	}
	sets[K8sNodeportSet] = set

	return nil
}

func programCommonChainsRules(nfti *NFTInterface, clusterCIDRIPv4, clusterCIDRIPv6 string) error {
	var clusterCIDR string
	var ipv6 bool
	var si nftableslib.SetsInterface
	for _, ci := range []nftableslib.ChainsInterface{nfti.CIv4, nfti.CIv6} {
		if ci == nfti.CIv4 {
			clusterCIDR = clusterCIDRIPv4
			ipv6 = false
			si = nfti.SIv4
		} else {
			clusterCIDR = clusterCIDRIPv6
			ipv6 = true
			si = nfti.SIv6
		}
		// Programming chains and initial rules only if clusterCIDR is specified
		if clusterCIDR != "" {
			if err := setupNFProxyChains(ci); err != nil {
				return err
			}
			if err := setupCommonSets(nfti.sets, si, ipv6); err != nil {
				return err
			}
			if err := setupStaticFilterRules(ci, clusterCIDR); err != nil {
				return err
			}
			if err := setupK8sFilterRules(nfti.sets, ci, ipv6); err != nil {
				return err
			}
			if err := setupStaticNATRules(nfti.sets, ci, clusterCIDR, ipv6); err != nil {
				return err
			}
		}
	}
	return nil
}
