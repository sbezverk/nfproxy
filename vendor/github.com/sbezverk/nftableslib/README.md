[![Build Status](https://travis-ci.org/sbezverk/nftableslib.svg?branch=master)](https://travis-ci.org/sbezverk/nftableslib)
# **nftableslib** - a library for Golang to talk to Netfilter 

nftableslib is a library offering an interface to Netfilter tables. It is based on "github.com/google/nftables" and offers a higher level of abstraction. 
It allows to create tables, chains and rules. Once table is creates, a caller can request this table's Chains interface to create chains within this table.
Similarly, once chain is created, a caller can request this chain's Rules interface to create rules for this chain.

A caller defines netfilter rule by means of a Rule struct. 

Rule contains parameters for a rule to configure L3(ip/ipv6) and L4(tcp/udp/port) parameters. 

```
type Rule struct {
	Fib        *Fib
	L3         *L3Rule
	L4         *L4Rule
	Conntracks []*Conntrack
	Meta       *Meta
	Log        *Log
	RelOp      Operator
	Action     *RuleAction
	UserData   []byte
}
```
**Meta** Allows to specify additional matching criteria, for more details on supported keys, see [Meta Expressions section in nft man document](https://www.netfilter.org/projects/nftables/manpage.html)

**Log** Allows to trigger logging for a specific rule. The helper function *SetLog(key int, value []byte)* allows to customize certain logging parameters, below is the list of supported keys and values type: 

| Keyword                  |  Description                                                                  | Type                                                             |
|--------------------------|-------------------------------------------------------------------------------|------------------------------------------|
| unix.NFTA_LOG_PREFIX     | Log message prefix                                                            | string                                                           |
| unix.NFTA_LOG_LEVEL      | Syslog level of logging                                                       | emerg, alert, crit, err, warn [default], notice, info, debug |
| unix.NFTA_LOG_GROUP      | FLOG group to send messages to                                                | uint16                                                           |
| unix.NFTA_LOG_SNAPLEN    | Length of packet payload to include in netlink message                        | uint32                                                           |
| unix.NFTA_LOG_QTHRESHOLD | Number of packets to queue inside the kernel before sending them to userspace | uint32                                                           |

**Exclude** flag is true when the condition specified by the rules should be inverted. Example, L4 condition specifies match on tcp traffic for a range of ports 1025-1028, setting **Exclude** to *true* will match every tcp port with the exception of the ports specified in the range. 

**RuleAction** defines what action needs to be executed on the rule match. Currently, there are two choices, Verdict type and Redirect.

**SetVerdict(key int, chain ...string)** function defines the verdict based on passed arguments and returns *RuleActionan action. In some cases *Verdict* can be used without any conditions to be the last action in the chain. Example, when chain has default policy of Accept, but you want the traffic which did not match any condition to be dropped.

**SetRedirectport int, tproxy bool** function defines the redirection or where the traffic matching condition should be fowarded to. If transparent proxy is required, *tproxy* parameter should be set to *true*


A single rule can carry L3 and L4 parameteres. L3 and L4 can be combined in the same rule. 
Redirect requires either L3 or L4, if there is no condition to match some traffic validation of a rule will fail.

L4 parameters are defined by L4 type:
```
type L4Rule struct {
	L4Proto uint8
	Src     *Port
	Dst     *Port
	RelOp   Operator
}
```

L3 parameters are defined by L3 type:
```
type L3Rule struct {
	Src      *IPAddrSpec
	Dst      *IPAddrSpec
	Version  *byte
	Protocol *uint32
	RelOp    Operator
}
```
**Version** parameter is used to match against a particular IP protocol version. Example, all IPv4 or all IPv6 traffic.

**Protocol** parameter is used to match a specific L4 protocol, example all TCP or UDP or ICMP traffic

Rule type offers Validation method which checks all parameters provided in Rule structure for consistency.

Here is example of programming a simple L3 rule:

```
package main

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"

	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
)

func main() {
	// Initializing netlink connection for a global namespace,
    // if non-global namespace is needed, namespace id must be specified in InitConn
	conn := nftableslib.InitConn()
    // Initializing nftableslib
	ti := nftableslib.InitNFTables(conn)

	// Clean up previously defined nf tables
	conn.FlushRuleset()

    // Creating nf table for IPv4 family
	ti.Tables().Create("ipv4table", nftables.TableFamilyIPv4)

    // Alternatively ti.Tables().CreateImm("ipv4table", nftables.TableFamilyIPv4) could be 
    // used which does not require following conn.Flush()
    // There is CreateImm api call for tables, chains and rules following the same pattern, the result of calling them
    // would be immediate programming in kernel table,chain or a rule.

	// Pushing table config to nf tables module
    // Pushing config after each create is not mandatory, it is done for debugging purposes.
	if err := conn.Flush(); err != nil {
		fmt.Printf("Failed to programm nftable with error: %+v\n", err)
		os.Exit(1)
	}

    // Getting Chains Interface for just created table
	ci, err := ti.Tables().Table("ipv4table", nftables.TableFamilyIPv4)
	if err != nil {
		fmt.Printf("Failed to get chains interface for table ipv4table with error: %+v\n", err)
		os.Exit(1)
	}

    // Creating new chain
	ci.Chains().Create("ipv4chain-1", nftables.ChainHookPrerouting,
		nftables.ChainPriorityFirst, nftables.ChainTypeFilter)
	
	if err := conn.Flush(); err != nil {
		fmt.Printf("Failed to programm nftable with error: %+v\n", err)
		os.Exit(1)
	}
	// Specifying L3 rule if ipv4 traffic is source from one of these ip addresses
    // stiop processing.
    ruleAction, err := nftableslib.SetVerdict(unix.NFT_JUMP, "fake-chain-1")
	if err != nil {
		fmt.Printf("Failed to set the verdict with error: %+v\n", err)
		os.Exit(1)
	}
    ipv4addr1, _ := nftableslib.NewIPAddr("1.2.3.4")
    ipv4addr2, _ := nftableslib.NewIPAddr("2.3.4.5")
	rule1 := nftableslib.Rule{
		L3: &nftableslib.L3Rule{
			Src: &nftableslib.IPAddrSpec{
				List: []*nftableslib.IPAddr{ipv4addr1,ipv4addr2},
			},
		},
        Action: ruleAction,
		Exclude: false,
	}
    // Getting Rules interface from chain ipv4chain-1
	ri, err := ci.Chains().Chain("ipv4chain-1")
	if err != nil {
		fmt.Printf("Failed to get rules interface for chain ipv4chain-1 with error: %+v\n", err)
		os.Exit(1)
	}
    // Creating rule
	if err := ri.Rules().Create("ipv4rule-1", &rule1); err != nil {
		fmt.Printf("failed to create chain with error: %+v, exiting...\n", err)
		os.Exit(1)
	}
	// Final programming
	if err := conn.Flush(); err != nil {
		fmt.Printf("Failed to programm nftable with error: %+v\n", err)
		os.Exit(1)
	}
}

```

As a result of execution of this program, nft client displays the following configuration:

```
sudo nft list table ip ipv4table
table ip ipv4table {
	set ipv4rule-1 {
		type ipv4_addr
		flags constant
		elements = { 1.2.3.4, 2.3.4.5 }
	}

	chain ipv4chain-1 {
		type filter hook prerouting priority -2147483648; policy accept;
		ip saddr == @ipv4rule-1 jump fake-chain-1
	}
}

```