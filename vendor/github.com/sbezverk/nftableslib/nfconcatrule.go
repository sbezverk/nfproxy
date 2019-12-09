package nftableslib

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// ConcatElement defines 1 element of Concatination rule
type ConcatElement struct {
	// Etype defines an element type as defined in github.com/google/nftables
	// example nftables.InetService or nftables.IPAddr
	EType nftables.SetDatatype
	// EProto defines a protocol as defined in golang.org/x/sys/unix
	EProto byte
	// ESource defines a direction, if true then element is saddr or sport,
	// if false then daddr or dport
	ESource bool
	// EMask defines mask of the element, mostly used along with IPAddr
	EMask []byte
}

// Concat defines parameters of Concatination rule
type Concat struct {
	Elements []*ConcatElement
	// VMap defines if concatination is used with verdict map, if set to true
	// Rule's Action will be ignored as the action is stored in the verdict of the map.
	VMap bool
	// SetRef defines name and id of map for
	SetRef *SetRef
}

func getExprForConcat(l3proto nftables.TableFamily, concat *Concat) ([]expr.Any, error) {
	var l4OffsetSrc, l4OffsetDst, l3OffsetSrc, l3OffsetDst, l3AddrLen uint32
	re := []expr.Any{}
	switch l3proto {
	case nftables.TableFamilyIPv4:
		l3OffsetSrc = 12
		l3OffsetDst = 16
		l4OffsetSrc = 0
		l4OffsetDst = 2
		l3AddrLen = 4
	case nftables.TableFamilyIPv6:
		fallthrough
	default:
		return nil, fmt.Errorf("unsupported table family %d", l3proto)
	}
	// If any of the elements is inet_service, then "transport protocol cmp expression" must be added first
	for _, e := range concat.Elements {
		if e.EType == nftables.TypeInetService {
			// [ meta load l4proto => reg 1 ]
			// [ cmp eq reg 1 0x000000XX ]
			re = append(re, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
			re = append(re, &expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{e.EProto},
			})
			break
		}
	}
	register := uint32(1)
	for _, e := range concat.Elements {
		switch e.EType {
		case nftables.TypeIPAddr:
			fallthrough
		case nftables.TypeIP6Addr:
			// [ payload load length of address in bytes @ network header + l3OffsetSrc or l3OffsetDst => reg 1 ]
			var offset uint32
			if e.ESource {
				offset = l3OffsetSrc
			} else {
				offset = l3OffsetDst
			}
			re = append(re, &expr.Payload{
				DestRegister: register,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       offset,
				Len:          l3AddrLen,
			})
		case nftables.TypeEtherAddr:
		case nftables.TypeInetProto:
		case nftables.TypeInetService:
			// [ payload load 2b @ transport header + l4OffsetSrc or l4OffsetDst => reg X ]
			var offset uint32
			if e.ESource {
				offset = l4OffsetSrc
			} else {
				offset = l4OffsetDst
			}
			re = append(re, &expr.Payload{
				DestRegister: register,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       offset,
				Len:          2,
			})
		}
		if register == 1 {
			register = 9
		} else {
			register++
		}
	}
	// If Concat refers to map, add lookup expression
	if concat.SetRef != nil {
		re = append(re, &expr.Lookup{
			SourceRegister: 1,
			DestRegister:   0,
			IsDestRegSet:   true,
			SetID:          concat.SetRef.ID,
			SetName:        concat.SetRef.Name,
		})
	}

	return re, nil
}
