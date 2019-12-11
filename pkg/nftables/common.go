package nftables

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
	"golang.org/x/sys/unix"
)

const (
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

func setupNATChains(ci nftableslib.ChainsInterface) error {
	// nat type chains
	natChains := []struct {
		name  string
		attrs *nftableslib.ChainAttributes
	}{
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

func programCommonChainsRules(nfti *NFTInterface) error {
	for _, ci := range []nftableslib.ChainsInterface{nfti.CIv4, nfti.CIv6} {
		if err := setupNATChains(ci); err != nil {
			return err
		}
		if err := setupInitialNATRules(ci); err != nil {
			return err
		}
	}
	return nil
}
