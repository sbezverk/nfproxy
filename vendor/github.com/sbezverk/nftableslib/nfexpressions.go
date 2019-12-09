package nftableslib

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/google/nftables"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}

func inputIntfByName(intf string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(intf),
		},
	}
}

func outputIntfByName(intf string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(intf),
		},
	}
}

// getExprForSingleIP returns expression to match a single IPv4 or IPv6 address
func getExprForSingleIP(l3proto nftables.TableFamily, offset uint32, addr *IPAddr, op Operator) ([]expr.Any, error) {
	re := []expr.Any{}
	addrLen := 4
	if l3proto == nftables.TableFamilyIPv6 {
		addrLen = 16
	}
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,          // Offset ipv4 address in network header
		Len:          uint32(addrLen), // length bytes for ipv4 address
	})
	var baddr, xor []byte
	if l3proto == nftables.TableFamilyIPv4 {
		baddr = []byte(addr.IP.To4())
	}
	if l3proto == nftables.TableFamilyIPv6 {
		baddr = []byte(addr.IP.To16())
	}
	if len(baddr) == 0 {
		return nil, fmt.Errorf("invalid ip %s", addr.IP.String())
	}
	xor = make([]byte, addrLen)
	re = append(re, &expr.Bitwise{
		SourceRegister: 1,
		DestRegister:   1,
		Len:            uint32(addrLen),
		Mask:           buildMask(addrLen, *addr.Mask),
		Xor:            xor,
	})
	cmpOp := expr.CmpOpEq
	if op == NEQ {
		cmpOp = expr.CmpOpNeq
	}
	re = append(re, &expr.Cmp{
		Op:       cmpOp,
		Register: 1,
		Data:     baddr,
	})

	return re, nil
}

// getExprForListIP returns expression to match a list of IPv4 or IPv6 addresses
func getExprForListIP(l3proto nftables.TableFamily, set *nftables.Set, offset uint32, op Operator) ([]expr.Any, error) {
	re := []expr.Any{}

	addrLen := 4
	if l3proto == nftables.TableFamilyIPv6 {
		addrLen = 16
	}
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,          // Offset ip address in network header
		Len:          uint32(addrLen), // length bytes for ip address
	})
	excl := false
	if op == NEQ {
		excl = true
	}
	re = append(re, &expr.Lookup{
		SourceRegister: 1,
		Invert:         excl,
		SetID:          set.ID,
		SetName:        set.Name,
	})

	return re, nil
}

// getExprForRangeIP returns expression to match a range of IPv4 or IPv6 addresses
func getExprForRangeIP(l3proto nftables.TableFamily, offset uint32, rng [2]*IPAddr, op Operator) ([]expr.Any, error) {
	re := []expr.Any{}

	addrLen := 4
	if l3proto == nftables.TableFamilyIPv6 {
		addrLen = 16
	}
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,          // Offset ipv4 address in network header
		Len:          uint32(addrLen), // length bytes for ipv4 address
	})
	var fromAddr, toAddr []byte
	if l3proto == nftables.TableFamilyIPv4 {
		fromAddr = []byte(rng[0].IP.To4())
		toAddr = []byte(rng[1].IP.To4())
	}
	if l3proto == nftables.TableFamilyIPv6 {
		fromAddr = []byte(rng[0].IP.To16())
		toAddr = []byte(rng[1].IP.To16())
	}
	if len(fromAddr) == 0 {
		return nil, fmt.Errorf("invalid ip %s", rng[0].IP.String())
	}
	if len(toAddr) == 0 {
		return nil, fmt.Errorf("invalid ip %s", rng[1].IP.String())
	}
	if op == NEQ {
		re = append(re, &expr.Range{
			Op:       expr.CmpOpNeq,
			Register: 1,
			FromData: fromAddr,
			ToData:   toAddr,
		})
		return re, nil
	}
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpGte,
		Register: 1,
		Data:     fromAddr,
	})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpLte,
		Register: 1,
		Data:     toAddr,
	})

	return re, nil
}

func getExprForRedirectPort(portToRedirect uint16) []expr.Any {
	// [ immediate reg 1 {port to Redirect} ]
	//  [ redir proto_min reg 1 ]
	re := []expr.Any{}
	re = append(re, &expr.Immediate{
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint16(portToRedirect),
	})

	re = append(re, &expr.Redir{
		RegisterProtoMin: 1,
	})

	return re
}

func getExprForListPort(l4proto uint8, offset uint32, port []*uint16, op Operator, set *nftables.Set) ([]expr.Any, error) {
	if l4proto == 0 {
		return nil, fmt.Errorf("l4 protocol is 0")
	}
	re := []expr.Any{}
	re = append(re, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     []byte{l4proto},
	})
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       offset, // Offset for a transport protocol header
		Len:          2,      // 2 bytes for port
	})
	excl := false
	if op == NEQ {
		excl = true
	}
	if len(port) > 1 {
		// Multi port is accomplished as a lookup
		re = append(re, &expr.Lookup{
			SourceRegister: 1,
			Invert:         excl,
			SetID:          set.ID,
			SetName:        set.Name,
		})
	} else {
		// Case for a single port list
		cmpOp := expr.CmpOpEq
		if excl {
			cmpOp = expr.CmpOpNeq
		}
		re = append(re, &expr.Cmp{
			Op:       cmpOp,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(*port[0]),
		})

	}
	return re, nil
}

func getExprForTProxyRedirect(port uint16, family nftables.TableFamily) []expr.Any {
	re := []expr.Any{}
	re = append(re, &expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(port)})
	re = append(re,
		&expr.TProxy{
			Family:      byte(family),
			TableFamily: byte(family),
			RegPort:     1,
		})

	return re
}

func getExprForRedirect(port uint16, family nftables.TableFamily) []expr.Any {
	re := []expr.Any{}
	re = append(re, &expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(port)})
	re = append(re,
		&expr.Redir{
			RegisterProtoMin: 1,
			RegisterProtoMax: 1,
		})

	return re
}

func getExprForRangePort(l4proto uint8, offset uint32, port [2]*uint16, op Operator) ([]expr.Any, error) {
	// [ meta load l4proto => reg 1 ]
	// [ cmp eq reg 1 0x00000006 ]
	// [ payload load 2b @ transport header + 0 => reg 1 ]
	// [ cmp gte reg 1 0x00003930 ]
	// [ cmp lte reg 1 0x000031d4 ]

	if l4proto == 0 {
		return nil, fmt.Errorf("l4 protocol is 0")
	}
	re := []expr.Any{}
	re = append(re, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     []byte{l4proto},
	})
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       offset, // Offset for a transport protocol header
		Len:          2,      // 2 bytes for port
	})
	if op == NEQ {
		re = append(re, &expr.Range{
			Op:       expr.CmpOpNeq,
			Register: 1,
			FromData: binaryutil.NativeEndian.PutUint16(*port[0]),
			ToData:   binaryutil.NativeEndian.PutUint16(*port[1]),
		})
		return re, nil
	}
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpGte,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint16(*port[0]),
	})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpLte,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint16(*port[1]),
	})

	return re, nil
}

func getExprForIPVersion(version byte, op Operator) ([]expr.Any, error) {
	re := []expr.Any{}
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       0, // Offset for a version of IP
		Len:          1, // 1 byte for IP version
	})
	if op != EQ {
		// TODO sbezverk
		return re, nil
	}
	re = append(re, &expr.Bitwise{
		SourceRegister: 1,
		DestRegister:   1,
		Len:            1,
		Mask:           []byte{0xf0},
		Xor:            []byte{0x0},
	})

	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     []byte{(version << 4)},
	})

	return re, nil
}

func getExprForProtocol(l3proto nftables.TableFamily, proto uint32, op Operator) ([]expr.Any, error) {
	re := []expr.Any{}
	if l3proto == nftables.TableFamilyIPv4 {
		// IPv4
		// [ payload load 1b @ network header + 9 => reg 1 ]
		re = append(re, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       9, // Offset for a L4 protocol
			Len:          1, // 1 byte for L4 protocol
		})
	} else {
		// IPv6
		//	[ payload load 1b @ network header + 6 => reg 1 ]
		re = append(re, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       6, // Offset for a L4 protocol
			Len:          1, // 1 byte for L4 protocol
		})
	}

	if op != EQ {
		// TODO sbezverk
		return re, nil
	}
	// [ cmp eq reg 1 0x00000006 ]
	protobyte := binaryutil.NativeEndian.PutUint32(proto)
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     protobyte[0:1],
	})

	return re, nil
}

func getExprForMetaMark(mark *MetaMark) []expr.Any {
	re := []expr.Any{}
	if mark.Set {
		// [ immediate reg 1 0x0000dead ]
		// [ meta set mark with reg 1 ]
		re = append(re, &expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(mark.Value))})
		re = append(re, &expr.Meta{Key: expr.MetaKey(unix.NFT_META_MARK), Register: 1, SourceRegister: true})
	} else {
		// [ meta load mark => reg 1 ]
		// [ cmp eq reg 1 0x0000dead ]
		re = append(re, &expr.Meta{Key: expr.MetaKey(unix.NFT_META_MARK), Register: 1, SourceRegister: false})
		re = append(re, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(uint32(mark.Value)),
		})
	}

	return re
}

func getExprForMetaExpr(meta []MetaExpr) []expr.Any {
	re := []expr.Any{}
	for _, m := range meta {
		op := expr.CmpOpEq
		if m.RelOp == NEQ {
			op = expr.CmpOpNeq
		}
		re = append(re, &expr.Meta{Key: expr.MetaKey(m.Key), Register: 1})
		re = append(re, &expr.Cmp{
			Op:       op,
			Register: 1,
			Data:     m.Value,
		})
	}
	return re
}

func getExprForMasq(masq *masquerade) []expr.Any {
	re := []expr.Any{}
	// Since masquerade flags and toPort are mutually exclusive, each case will generate different sequence of
	// expressions
	if masq.toPort[0] != nil {
		m := &expr.Masq{ToPorts: true}
		// Case  at least 1 toPort specified
		//  [ immediate reg 1 0x00000004 ]
		re = append(re, &expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint32(uint32(*masq.toPort[0]))})
		m.RegProtoMin = 1
		m.RegProtoMax = 0
		if masq.toPort[1] != nil {
			// If second port is specified, then range of ports will be used.
			// [ immediate reg 2 0x00000008 ]
			re = append(re, &expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint32(uint32(*masq.toPort[1]))})
			m.RegProtoMax = 2
		}
		// [ masq proto_min reg 1 proto_max reg 2 ]
		re = append(re, m)
	} else {
		// Since toPort[0] is nil, checking flags
		//  [ masq flags value ]
		var random, fullyRandom, persistent bool
		if masq.random != nil {
			random = *masq.random
		}
		if masq.fullyRandom != nil {
			fullyRandom = *masq.fullyRandom
		}
		if masq.persistent != nil {
			persistent = *masq.persistent
		}
		re = append(re, &expr.Masq{Random: random, FullyRandom: fullyRandom, Persistent: persistent, ToPorts: false})
	}

	return re
}

func getExprForLog(log *Log) []expr.Any {
	re := []expr.Any{}
	re = append(re, &expr.Log{Key: log.Key, Data: log.Value})

	return re
}

func getExprForReject(r *reject) []expr.Any {
	re := []expr.Any{}
	re = append(re, &expr.Reject{Type: r.rejectType, Code: r.rejectCode})

	return re
}

func getExprForFib(f *Fib) []expr.Any {
	// [ fib daddr type => reg 1 ]
	// [ cmp eq reg 1 0x00000002 ]
	re := []expr.Any{}
	re = append(re, &expr.Fib{Register: 1,
		ResultOIF:      f.ResultOIF,
		ResultOIFNAME:  f.ResultOIFNAME,
		ResultADDRTYPE: f.ResultADDRTYPE,
		FlagSADDR:      f.FlagSADDR,
		FlagDADDR:      f.FlagDADDR,
		FlagMARK:       f.FlagMARK,
		FlagIIF:        f.FlagIIF,
		FlagOIF:        f.FlagOIF,
		FlagPRESENT:    f.FlagPRESENT,
	})

	op := expr.CmpOpEq
	if f.RelOp == NEQ {
		op = expr.CmpOpNeq
	}
	l := len(f.Data) / 4
	if len(f.Data)%4 != 0 {
		l++
	}
	data := make([]byte, l*4)
	copy(data, f.Data)
	re = append(re, &expr.Cmp{
		Op:       op,
		Register: 1,
		Data:     data,
	})

	return re
}

func getExprForConntracks(cts []*Conntrack) []expr.Any {
	re := []expr.Any{}
	for _, ct := range cts {
		switch ct.Key {
		// List of supported conntrack keys
		case unix.NFT_CT_STATE:
			//	[ ct load state => reg 1 ]
			//	[ bitwise reg 1 = (reg=1 & 0x00000008 ) ^ 0x00000000 ]
			//	[ cmp neq reg 1 0x00000000 ]
			re = append(re, &expr.Ct{Key: unix.NFT_CT_STATE, Register: 1})
			re = append(re, &expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           ct.Value,
				Xor:            []byte{0x0, 0x0, 0x0, 0x0},
			})
			re = append(re, &expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x0, 0x0, 0x0, 0x0},
			})
		case unix.NFT_CT_DIRECTION:
		case unix.NFT_CT_STATUS:
		case unix.NFT_CT_LABELS:
		case unix.NFT_CT_EVENTMASK:
		}
	}

	return re
}

func getExprForPortSet(l4proto uint8, offset uint32, set *SetRef, op Operator) ([]expr.Any, error) {
	if l4proto == 0 {
		return nil, fmt.Errorf("l4 protocol is 0")
	}
	re := []expr.Any{}
	re = append(re, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     []byte{l4proto},
	})
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       offset, // Offset for a transport protocol header
		Len:          2,      // 2 bytes for port
	})
	excl := false
	if op == NEQ {
		excl = true
	}

	e := &expr.Lookup{
		SourceRegister: 1,
		Invert:         excl,
		SetID:          set.ID,
		SetName:        set.Name,
	}
	if set.IsMap {
		e.IsDestRegSet = true
		e.DestRegister = 0
	}
	re = append(re, e)

	return re, nil
}

// getExprForListIP returns expression to match a list of IPv4 or IPv6 addresses
func getExprForAddrSet(l3proto nftables.TableFamily, offset uint32, set *SetRef, op Operator) ([]expr.Any, error) {
	re := []expr.Any{}

	addrLen := 4
	if l3proto == nftables.TableFamilyIPv6 {
		addrLen = 16
	}
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,          // Offset ip address in network header
		Len:          uint32(addrLen), // length bytes for ip address
	})
	excl := false
	if op == NEQ {
		excl = true
	}
	e := &expr.Lookup{
		SourceRegister: 1,
		Invert:         excl,
		SetID:          set.ID,
		SetName:        set.Name,
	}
	if set.IsMap {
		e.DestRegister = 0
		e.IsDestRegSet = true
	}
	re = append(re, e)

	return re, nil
}

// getExprForSNAT returns expression for nat statement
func getExprForNAT(l3proto nftables.TableFamily, nat *nat) ([]expr.Any, error) {
	re := []expr.Any{}

	// TODO, move validation to Validation method
	if nat.address == nil && nat.port == nil {
		return nil, fmt.Errorf("either address or port must be specified")
	}

	var regAddrMin, regAddrMax, regProtoMin, regProtoMax uint32
	register := uint32(1)
	if nat.address != nil {
		var addr1, addr2 []byte
		// NAT does not support a list of addresses, it supports either a single address List[0]
		// or a range Range[0]-Range[1]
		switch {
		case nat.address.List != nil:
			if l3proto == nftables.TableFamilyIPv4 {
				addr1 = []byte(nat.address.List[0].IP.To4())
			} else {
				addr1 = []byte(nat.address.List[0].IP.To16())
			}
			re = append(re, &expr.Immediate{
				Register: register,
				Data:     addr1,
			})
			regAddrMin = register
			register++
		case nat.address.Range[0] != nil && nat.address.Range[1] != nil:
			if l3proto == nftables.TableFamilyIPv4 {
				addr1 = []byte(nat.address.Range[0].IP.To4())
				addr2 = []byte(nat.address.Range[1].IP.To4())
			} else {
				addr1 = []byte(nat.address.Range[0].IP.To16())
				addr2 = []byte(nat.address.Range[1].IP.To16())
			}
			re = append(re, &expr.Immediate{
				Register: register,
				Data:     addr1,
			})
			regAddrMin = register
			register++
			re = append(re, &expr.Immediate{
				Register: register,
				Data:     addr2,
			})
			regAddrMax = register
			register++
		}
	}
	if nat.port != nil {
		// NAT does not support a list of ports, it supports either a single port List[0]
		// or a range of ports Range[0]-Range[1]
		switch {
		case nat.port.List != nil:
			re = append(re, &expr.Immediate{
				Register: register,
				Data:     binaryutil.BigEndian.PutUint16(*nat.port.List[0]),
			})
			regProtoMin = register
			register++
		case nat.port.Range[0] != nil && nat.port.Range[1] != nil:
			re = append(re, &expr.Immediate{
				Register: register,
				Data:     binaryutil.BigEndian.PutUint16(*nat.port.Range[0]),
			})
			regProtoMin = register
			register++
			re = append(re, &expr.Immediate{
				Register: register,
				Data:     binaryutil.BigEndian.PutUint16(*nat.port.Range[1]),
			})
			regProtoMax = register
			register++
		}
	}
	e := &expr.NAT{
		Type:        nat.nattype,
		Family:      uint32(l3proto),
		RegAddrMin:  regAddrMin,
		RegAddrMax:  regAddrMax,
		RegProtoMin: regProtoMin,
		RegProtoMax: regProtoMax,
	}

	if nat.random != nil {
		e.Random = *nat.random
	}
	if nat.fullyRandom != nil {
		e.FullyRandom = *nat.fullyRandom
	}
	if nat.persistent != nil {
		e.Persistent = *nat.persistent
	}
	re = append(re, e)

	return re, nil
}

func getExprForLoadbalance(nfr *nfRules, l *loadbalance) ([]expr.Any, error) {
	var set *nftables.Set
	var elements []nftables.SetElement
	var exprs []expr.Any
	if len(l.chains) == 0 {
		return nil, fmt.Errorf("number of chains for loadbalancing cannot be 0")
	}
	set = &nftables.Set{
		Table:     nfr.table,
		Anonymous: true,
		Constant:  true,
		IsMap:     true,
		KeyType:   nftables.TypeInteger,
		DataType:  nftables.TypeVerdict,
	}

	for ind, chain := range l.chains {
		elements = append(elements, nftables.SetElement{
			Key: binaryutil.BigEndian.PutUint32(uint32(ind)),
			VerdictData: &expr.Verdict{
				Kind:  expr.VerdictKind(int64(unix.NFT_JUMP)),
				Chain: chain,
			},
		})
	}
	exprs = append(exprs, &expr.Numgen{
		Register: 1,
		Modulus:  uint32(len(l.chains)),
		Type:     uint32(unix.NFT_NG_RANDOM),
		Offset:   0,
	})

	if err := nfr.conn.AddSet(set, elements); err != nil {
		return nil, err
	}
	exprs = append(exprs, &expr.Lookup{
		SourceRegister: 1,
		DestRegister:   0,
		IsDestRegSet:   true,
		SetID:          set.ID,
		SetName:        set.Name,
	})

	return exprs, nil
}

func buildMask(length int, maskLength uint8) []byte {
	mask := make([]byte, length)
	fullBytes := maskLength / 8
	leftBits := maskLength % 8
	for i := 0; i < int(fullBytes); i++ {
		mask[i] = 0xff
	}
	if leftBits != 0 {
		m := uint8(0x80)
		v := uint8(0x00)
		for i := 0; i < int(leftBits); i++ {
			v += m
			m = (m >> 1)
		}
		mask[fullBytes] ^= v
	}
	return mask
}
