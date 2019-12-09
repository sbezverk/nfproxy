package nftableslib

import (
	"math/rand"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"

	"github.com/google/nftables"
)

func createL4(family nftables.TableFamily, rule *Rule) ([]expr.Any, []*nfSet, error) {
	re := []expr.Any{}
	sets := make([]*nfSet, 0)

	l4 := rule.L4
	if l4.Src != nil {
		// 0 bytes is offset for Source ports in L4 header
		e, set, err := processPort(l4.L4Proto, 0, l4.Src)
		if err != nil {
			return nil, nil, err
		}
		if set != nil {
			sets = append(sets, set)
		}
		re = append(re, e...)
	}
	if l4.Dst != nil {
		// 2 bytes is offset for Source ports in L4 header
		e, set, err := processPort(l4.L4Proto, 2, l4.Dst)
		if err != nil {
			return nil, nil, err
		}
		if set != nil {
			sets = append(sets, set)
		}
		re = append(re, e...)
	}

	return re, sets, nil
}

// processPort process one of the possible port sources and returns required expressions,
// dynamically generated set or error.
func processPort(proto uint8, offset uint32, port *Port) ([]expr.Any, *nfSet, error) {
	re := []expr.Any{}
	e := []expr.Any{}
	var set *nfSet
	var err error

	// Port has three possible sources: List, Range or a reference to already existing Set/Map or VMap
	switch {
	case len(port.List) != 0:
		e, set, err = processPortList(proto, offset, port.List, port.RelOp)
		if err != nil {
			return nil, nil, err
		}
	case port.Range[0] != nil && port.Range[1] != nil:
		e, set, err = processPortRange(proto, offset, port.Range, port.RelOp)
		if err != nil {
			return nil, nil, err
		}
	case port.SetRef != nil:
		e, err = getExprForPortSet(proto, offset, port.SetRef, port.RelOp)
		if err != nil {
			return nil, nil, err
		}
	}

	if set != nil {
		set.set.KeyType = nftables.TypeInetService
	}
	re = append(re, e...)

	return re, set, nil
}

func processPortList(l4proto uint8, offset uint32, port []*uint16, op Operator) ([]expr.Any, *nfSet, error) {
	// Processing multiple ports case
	re := []expr.Any{}
	var nfset *nfSet
	var set *nftables.Set
	if len(port) > 1 {
		nfset = &nfSet{}
		set = &nftables.Set{}
		set.Anonymous = false
		set.Constant = true
		set.Name = getSetName()
		set.ID = uint32(rand.Intn(0xffff))

		se := make([]nftables.SetElement, len(port))
		// Normal case, more than 1 entry in the port list need to build SetElement slice
		for i := 0; i < len(port); i++ {
			se[i].Key = binaryutil.BigEndian.PutUint16(*port[i])
		}
		nfset.set = set
		nfset.elements = se
	}
	re, err := getExprForListPort(l4proto, offset, port, op, set)
	if err != nil {
		return nil, nil, err
	}

	return re, nfset, nil
}

func processPortRange(l4proto uint8, offset uint32, port [2]*uint16, op Operator) ([]expr.Any, *nfSet, error) {
	re, err := getExprForRangePort(l4proto, offset, port, op)
	if err != nil {
		return nil, nil, err
	}
	return re, nil, nil
}
