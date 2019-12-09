package nftableslib

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// By some reason github.com/golang/unix does not define these constants but
// they can by used in a Verdict.
const (
	// NFT_DROP defines Drop action for a verdict
	NFT_DROP = 0x0
	// NFT_ACCEPT defines Accept action for a verdict
	NFT_ACCEPT = 0x1
)

// RulesInterface defines third level interface operating with nf Rules
type RulesInterface interface {
	Rules() RuleFuncs
}

// RuleFuncs defines funcations to operate with Rules
type RuleFuncs interface {
	Create(*Rule) (uint32, error)
	CreateImm(*Rule) (uint64, error)
	Delete(uint32) error
	DeleteImm(uint64) error
	Insert(*Rule, int) (uint32, error)
	InsertImm(*Rule, int) (uint64, error)
	Update(*Rule, uint64) error
	Dump() ([]byte, error)
	Sync() error
	UpdateRulesHandle() error
	GetRuleHandle(id uint32) (uint64, error)
	GetRulesUserData() (map[uint64][]byte, error)
}

type nfRules struct {
	conn  NetNS
	table *nftables.Table
	chain *nftables.Chain
	sync.Mutex
	currentID uint32
	rules     *nfRule
}

type nfSet struct {
	set      *nftables.Set
	elements []nftables.SetElement
}

type nfRule struct {
	id   uint32
	rule *nftables.Rule
	sets []*nfSet
	sync.Mutex
	next *nfRule
	prev *nfRule
}

type nfUserData struct {
	RuleID  uint32
	AppData []byte
}

func (nfr *nfRules) Rules() RuleFuncs {
	return nfr
}

func (nfr *nfRules) buildRule(rule *Rule) (*nfRule, error) {
	r := &nftables.Rule{}
	var err error
	var sets []*nfSet
	var set []*nfSet
	e := []expr.Any{}
	// Some Rule elements can request to skip processing of certain blocks
	var skipL3, skipL4, skipAction bool
	if rule.Concat != nil {
		if rule.Concat.VMap {
			skipL3, skipL4, skipAction = true, true, true
		}
	}
	if rule.Fib != nil {
		e := getExprForFib(rule.Fib)
		r.Exprs = append(r.Exprs, e...)
	}
	if rule.L3 != nil && !skipL3 {
		if e, set, err = createL3(nfr.table.Family, rule); err != nil {
			return nil, err
		}
		sets = append(sets, set...)
		r.Exprs = append(r.Exprs, e...)
	}

	if rule.L4 != nil && !skipL4 {
		if e, set, err = createL4(nfr.table.Family, rule); err != nil {
			return nil, err
		}
		sets = append(sets, set...)
		r.Exprs = append(r.Exprs, e...)
	}

	// If L3Rule or L4Rule did not produce a rule, initialize one to carry
	// Rule's Action expression
	if len(r.Exprs) == 0 {
		r.Exprs = []expr.Any{}
	}
	// Check if Meta is specified appending to rule's list of expressions
	if rule.Meta != nil {
		switch {
		case rule.Meta.Mark != nil:
			r.Exprs = append(r.Exprs, getExprForMetaMark(rule.Meta.Mark)...)
		case len(rule.Meta.Expr) != 0:
			r.Exprs = append(r.Exprs, getExprForMetaExpr(rule.Meta.Expr)...)
		}
	}
	// Check if Meta is specified appending to rule's list of expressions
	if rule.Log != nil {
		r.Exprs = append(r.Exprs, getExprForLog(rule.Log)...)
	}

	if len(rule.Conntracks) > 0 {
		r.Exprs = append(r.Exprs, getExprForConntracks(rule.Conntracks)...)
	}

	if rule.Action != nil && !skipAction {
		switch {
		case rule.Action.redirect != nil:
			if rule.Action.redirect.tproxy {
				r.Exprs = append(r.Exprs, getExprForTProxyRedirect(rule.Action.redirect.port, nfr.table.Family)...)
			} else {
				r.Exprs = append(r.Exprs, getExprForRedirect(rule.Action.redirect.port, nfr.table.Family)...)
			}
		case rule.Action.verdict != nil:
			r.Exprs = append(r.Exprs, rule.Action.verdict)
		case rule.Action.masq != nil:
			r.Exprs = append(r.Exprs, getExprForMasq(rule.Action.masq)...)
		case rule.Action.reject != nil:
			r.Exprs = append(r.Exprs, getExprForReject(rule.Action.reject)...)
		case rule.Action.loadbalance != nil:
			e, err := getExprForLoadbalance(nfr, rule.Action.loadbalance)
			if err != nil {
				return nil, err
			}
			// Adding generated loadbalancing expressions and anonymous set
			r.Exprs = append(r.Exprs, e...)
		case rule.Action.nat != nil:
			e, err = getExprForNAT(nfr.table.Family, rule.Action.nat)
			if err != nil {
				return nil, err
			}
			r.Exprs = append(r.Exprs, e...)
		}
	}
	if rule.Concat != nil {
		e, err = getExprForConcat(nfr.table.Family, rule.Concat)
		if err != nil {
			return nil, err
		}
		r.Exprs = append(r.Exprs, e...)
	}
	r.Table = nfr.table
	r.Chain = nfr.chain

	rr := &nfRule{}
	rr.rule = r
	for _, s := range sets {
		s.set.Table = nfr.table
		if err := nfr.conn.AddSet(s.set, s.elements); err != nil {
			return nil, err
		}
		//		s.set.DataLen = len(s.elements)
		rr.sets = append(rr.sets, s)
	}

	return rr, nil
}

func (nfr *nfRules) Create(rule *Rule) (uint32, error) {
	nfr.Lock()
	defer nfr.Unlock()

	return nfr.create(rule, 0)
}

func (nfr *nfRules) create(rule *Rule, position int) (uint32, error) {
	// Process all user specified expressions and return nfRule
	rr, err := nfr.buildRule(rule)
	if err != nil {
		return 0, err
	}
	// Adding nfRule to the list
	nfr.addRule(rr)
	if position != 0 {
		// Used by Insert call
		rr.rule.Position = uint64(position)
	}
	// Allocating UserData struct for ruleID
	userData := &nfUserData{
		// rule's ID is populated by fr.addRule(rr)
		RuleID: rr.id,
	}
	// If higher level app passes some arbitrary metadata for the rule, store it to nfUserData appData
	if rule.UserData != nil {
		userData.AppData = make([]byte, len(rule.UserData))
		copy(userData.AppData, rule.UserData)
	}
	// Encoding nfUserData into []byte to send as nftables.UserData
	buffer := new(bytes.Buffer)
	enc := gob.NewEncoder(buffer)
	enc.Encode(userData)
	rr.rule.UserData = buffer.Bytes()
	// Pushing rule to netlink library to be programmed by Fluhs()
	nfr.conn.AddRule(rr.rule)

	return rr.id, nil
}

func (nfr *nfRules) CreateImm(rule *Rule) (uint64, error) {
	nfr.Lock()
	defer nfr.Unlock()
	id, err := nfr.create(rule, 0)
	if err != nil {
		return 0, err
	}
	// Programming rule
	if err := nfr.conn.Flush(); err != nil {
		return 0, err
	}
	// Getting rule's handle allocated by the kernel
	handle, err := nfr.GetRuleHandle(id)
	if err != nil {
		return 0, err
	}
	if err := nfr.UpdateRuleHandleByID(id, handle); err != nil {
		return 0, err
	}

	return handle, nil
}

func (nfr *nfRules) delete(id uint32) error {
	r, err := getRuleByID(nfr.rules, id)
	if err != nil {
		return err
	}
	// If rule's handle is 0, it means it has not been already programmed
	// then no reason to call netfilter module
	if r.rule.Handle != 0 {
		if err := nfr.conn.DelRule(r.rule); err != nil {
			return err
		}
	}

	return nfr.removeRule(r.id)
}

func (nfr *nfRules) Delete(id uint32) error {
	nfr.Lock()
	defer nfr.Unlock()
	return nfr.delete(id)
}

func (nfr *nfRules) DeleteImm(rh uint64) error {
	nfr.Lock()
	defer nfr.Unlock()
	r, err := getRuleByHandle(nfr.rules, rh)
	if err != nil {
		return err
	}
	if err := nfr.delete(r.id); err != nil {
		return err
	}
	// Programming rule's deleteion
	if err := nfr.conn.Flush(); err != nil {
		return err
	}

	return nil
}

// Insert inserts a rule passed as a parameter before the rule which handle value matches
// the value of position passed as an argument.
// Example: rule1 has handle of 5, you want to insert rule2 before rule1, then position for rule2 will be 5
func (nfr *nfRules) Insert(rule *Rule, position int) (uint32, error) {
	return nfr.create(rule, position)
}

func (nfr *nfRules) InsertImm(rule *Rule, position int) (uint64, error) {
	id, err := nfr.Insert(rule, position)
	if err != nil {
		return 0, err
	}
	// Programming rule
	if err := nfr.conn.Flush(); err != nil {
		return 0, err
	}
	// Getting rule's handle allocated by the kernel
	handle, err := nfr.GetRuleHandle(id)
	if err != nil {
		return 0, err
	}
	if err := nfr.UpdateRuleHandleByID(id, handle); err != nil {
		return 0, err
	}

	return handle, nil
}

func (nfr *nfRules) Update(rule *Rule, handle uint64) error {
	nfrule, err := getRuleByHandle(nfr.rules, handle)
	if err != nil {
		return err
	}
	r, err := nfr.buildRule(rule)
	if err != nil {
		return err
	}
	r.rule.Handle = handle
	// If higher level app passes some arbitrary metadata for the rule, store it to nfUserData appData
	if rule.UserData != nil {
		userData := &nfUserData{}
		userData.AppData = make([]byte, len(rule.UserData))
		copy(userData.AppData, rule.UserData)
		// Encoding nfUserData into []byte to send as nftables.UserData
		buffer := new(bytes.Buffer)
		enc := gob.NewEncoder(buffer)
		enc.Encode(userData)
		r.rule.UserData = buffer.Bytes()
	}
	// Updating rule expressions and sets but preserving pointers to prev and next
	nfrule.rule = r.rule
	nfrule.sets = r.sets

	// Pushing rule to netlink library to be programmed by Flush()
	nfr.conn.AddRule(nfrule.rule)
	// Programming Update rule
	if err := nfr.conn.Flush(); err != nil {
		return err
	}

	return nil
}

func (nfr *nfRules) Dump() ([]byte, error) {
	nfr.Lock()
	defer nfr.Unlock()
	var data []byte

	for _, r := range nfr.dumpRules() {
		b, err := json.Marshal(&r)
		if err != nil {
			return nil, err
		}
		data = append(data, b...)
	}

	return data, nil
}

func (nfr *nfRules) Sync() error {
	rules, err := nfr.conn.GetRule(nfr.table, nfr.chain)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		sets := make([]*nfSet, 0)
		for _, e := range rule.Exprs {
			exp, ok := e.(*expr.Lookup)
			if !ok {
				continue
			}
			set, err := nfr.getSet(exp.SetName)
			if err != nil {
				return err
			}
			elements, err := nfr.getSetElements(set)
			if err != nil {
				return err
			}
			// set.DataLen = len(elements)
			sets = append(sets, &nfSet{set: set, elements: elements})

		}
		rr := &nfRule{}
		rr.rule = rule
		if len(sets) != 0 {
			rr.sets = sets
		}
		nfr.addRule(rr)
	}

	return nil
}

func (nfr *nfRules) getSet(name string) (*nftables.Set, error) {
	sets, err := nfr.conn.GetSets(nfr.table)
	if err != nil {
		return nil, err
	}
	for _, set := range sets {
		if set.Name == name {
			set.Table = nfr.table
			return set, nil
		}
	}

	return &nftables.Set{}, nil
}

func (nfr *nfRules) getSetElements(set *nftables.Set) ([]nftables.SetElement, error) {
	elements, err := nfr.conn.GetSetElements(set)
	if err != nil {
		return nil, err
	}

	return elements, nil
}

// UpdateRulesHandle populates rule's handle information with handle value allocated by the kernel.
// Handle information can be used for further rule's management.
func (nfr *nfRules) UpdateRulesHandle() error {
	r := nfr.rules
	for ; r != nil; r = r.next {
		handle, err := nfr.GetRuleHandle(r.id)
		if err != nil {
			return err
		}
		r.rule.Handle = handle
	}

	return nil
}

func (nfr *nfRules) UpdateRuleHandleByID(id uint32, handle uint64) error {
	r := nfr.rules
	for ; r != nil; r = r.next {
		if r.id == id {
			nfr.rules.Lock()
			defer nfr.rules.Unlock()
			r.rule.Handle = handle
			return nil
		}
	}

	return fmt.Errorf("rule id %d is not found", id)
}

// GetRuleHandle gets a handle of rule specified by its id
func (nfr *nfRules) GetRuleHandle(id uint32) (uint64, error) {
	rules, err := nfr.conn.GetRule(nfr.table, nfr.chain)
	if err != nil {
		return 0, err
	}
	for _, rule := range rules {
		if rule.UserData != nil {
			userData := nfUserData{}
			dr := bytes.NewReader(rule.UserData)
			dec := gob.NewDecoder(dr)
			if err := dec.Decode(&userData); err != nil {
				return 0, err
			}
			if userData.RuleID == id {
				return rule.Handle, nil
			}
		}
	}

	return 0, fmt.Errorf("rule with id %d is not found", id)
}

func (nfr *nfRules) GetRulesUserData() (map[uint64][]byte, error) {
	rules, err := nfr.conn.GetRule(nfr.table, nfr.chain)
	if err != nil {
		return nil, err
	}
	ud := make(map[uint64][]byte, 0)
	for _, rule := range rules {
		if rule.UserData != nil {
			userData := &nfUserData{}
			dr := bytes.NewReader(rule.UserData)
			dec := gob.NewDecoder(dr)
			if err := dec.Decode(userData); err != nil {
				return nil, err
			}
			// If rule has some application specific data, return it in the map with rule's
			// handle as a key
			if userData.AppData != nil {
				ud[rule.Handle] = userData.AppData
			}
		}
	}
	return ud, nil
}

func newRules(conn NetNS, t *nftables.Table, c *nftables.Chain) RulesInterface {
	return &nfRules{
		conn:      conn,
		table:     t,
		chain:     c,
		currentID: 10,
		rules:     nil,
	}
}

// IPAddr defines a type of ip address, if it is host address with mask of 32 for ipv4 and mask of 128 for ipv6
// then CIDR should be false, if it is a network address, then CIDR should be true and Mask set to a number of bits
// in the address' mask. Mask value is from 0 to 32 for ipv4 and from 0 to 128 for ipv6 addresses.
type IPAddr struct {
	*net.IPAddr
	CIDR bool
	Mask *uint8
}

// IsIPv6 is a helper function, it returns true if IPAddr struct holds IPv6 address, otherwise it returns false
func (ip *IPAddr) IsIPv6() bool {
	if ip.IP.To4() == nil {
		return true
	}
	return false
}

// Validate checks validity of ip address and its parameters
func (ip *IPAddr) Validate() error {
	// If CIDR is not specified, there is nothing to validate
	if !ip.CIDR {
		return nil
	}
	if ip.CIDR && ip.Mask == nil {
		return fmt.Errorf("mask length must be specified when CIDR is true")
	}

	return nil
}

// Operator defines type used for relational operations in the rule
type Operator byte

// List of supported relational operations, starts with 0. if not specified, default 0 inidcates eq operator
const (
	EQ Operator = iota
	NEQ
)

// IPAddrSpec lists possible flavours if specifying ip address, either List or Range can be specified
type IPAddrSpec struct {
	List   []*IPAddr
	Range  [2]*IPAddr
	SetRef *SetRef
	RelOp  Operator
}

// NewIPAddr is a helper function which converts ip address into IPAddr format
// required by IPAddrSpec. If CIDR format is specified, Mask will be set to address'
// subnet mask and CIDR will e set to true
func NewIPAddr(addr string) (*IPAddr, error) {
	if _, ipnet, err := net.ParseCIDR(addr); err == nil {
		// Found a valid CIDR address
		ones, _ := ipnet.Mask.Size()
		mask := uint8(ones)
		return &IPAddr{
			&net.IPAddr{
				IP: ipnet.IP,
			},
			true,
			&mask,
		}, nil
	}
	// Check if addr is just ip address in a non CIDR format
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("%s is invalid ip address", addr)
	}
	mask := uint8(32)
	if ip.To4() == nil {
		mask = uint8(128)
	}
	_, ipnet, err := net.ParseCIDR(addr + "/" + fmt.Sprintf("%d", mask))
	if err != nil {
		return nil, err
	}
	return &IPAddr{
		&net.IPAddr{
			IP: ipnet.IP,
		},
		true,
		&mask,
	}, nil
}

// Validate checks IPAddrSpec struct
func (ip *IPAddrSpec) Validate() error {
	if len(ip.List) != 0 && (ip.Range[0] != nil || ip.Range[1] != nil) {
		return fmt.Errorf("either List or Range but not both can be specified")
	}
	if len(ip.List) == 0 && (ip.Range[0] == nil || ip.Range[1] == nil) {
		return fmt.Errorf("neither List nor Range is specified")
	}
	if len(ip.List) != 0 {
		for i := 0; i < len(ip.List); i++ {
			if err := ip.List[i].Validate(); err != nil {
				return err
			}
		}
	}
	if ip.Range[0] != nil && ip.Range[1] != nil {
		for i := 0; i < len(ip.Range); i++ {
			if err := ip.Range[i].Validate(); err != nil {
				return err
			}
		}
	}

	return nil
}

// L3Rule contains parameters for L3 based rule, either Source or Destination can be specified
type L3Rule struct {
	Src      *IPAddrSpec
	Dst      *IPAddrSpec
	Version  *byte
	Protocol *uint32
	RelOp    Operator
}

// L3Protocol is a helper function to convert a value of L3 protocol
// to the type required by L3Rule *uint32
func L3Protocol(proto int) *uint32 {
	p := uint32(proto)
	return &p
}

// Validate checks parameters of L3Rule struct
func (l3 *L3Rule) Validate() error {
	switch {
	case l3.Src != nil:
		if err := l3.Src.Validate(); err != nil {
			return err
		}
	case l3.Dst != nil:
		if err := l3.Dst.Validate(); err != nil {
			return err
		}
	case l3.Version != nil:
	case l3.Protocol != nil:
	default:
		return fmt.Errorf("invalid L3 rule as none of L3 parameters are provided")
	}

	return nil
}

// SetRef defines a reference to a Set/Map/Vmap
type SetRef struct {
	Name  string
	ID    uint32
	IsMap bool
}

// Port lists possible flavours of specifying port information
type Port struct {
	List   []*uint16
	Range  [2]*uint16
	RelOp  Operator
	SetRef *SetRef
}

// SetPortList is a helper function which transforms a slice of int into
// a format required by Port struct
func SetPortList(ports []int) []*uint16 {
	p := make([]*uint16, len(ports))
	for i, port := range ports {
		pp := uint16(port)
		p[i] = &pp
	}
	return p
}

// SetPortRange is a helper function which transforms an 2 element array of int into
// a format required by Port struct
func SetPortRange(ports [2]int) [2]*uint16 {
	p := [2]*uint16{}
	for i, port := range ports {
		pp := uint16(port)
		p[i] = &pp
	}
	return p
}

// Validate check parameters of Port struct
func (p *Port) Validate() error {
	set := 0
	switch {
	case len(p.List) != 0:
		set++
	case p.Range[0] != nil || p.Range[1] != nil:
		if p.Range[0] == nil || p.Range[1] == nil {
			return fmt.Errorf("port range requires both ports of the range to be non nil")
		}
		set++
	case p.SetRef != nil:
		set++
	}
	if set > 1 {
		return fmt.Errorf("either List or Range or SetRef but not the combination of them can be specified")
	}
	if set == 0 {
		return fmt.Errorf("neither List nor Range nor SetRef is specified")
	}

	return nil
}

// L4Rule contains parameters for L4 based rule
type L4Rule struct {
	L4Proto uint8
	Src     *Port
	Dst     *Port
	RelOp   Operator
}

// Validate checks parameters of L4Rule struct
func (l4 *L4Rule) Validate() error {
	if l4.L4Proto == 0 {
		return fmt.Errorf("L4Proto cannot be 0")
	}
	if l4.Src != nil {
		if err := l4.Src.Validate(); err != nil {
			return err
		}
	}
	if l4.Dst != nil {
		if err := l4.Dst.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// redirect defines struct describing Redirection action, if Transparent Proxy is required
// TProxy should be set
type redirect struct {
	port   uint16
	tproxy bool
}

// masquarade defines a struct describing Masquerade action, flags cannot be combined with
// toPort
type masquerade struct {
	random      *bool
	fullyRandom *bool
	persistent  *bool
	toPort      [2]*uint16
}

// nat defines a struct describing nat action
type nat struct {
	nattype     expr.NATType
	random      *bool
	fullyRandom *bool
	persistent  *bool
	address     *IPAddrSpec
	port        *Port
}

// reject defines reject action
type reject struct {
	rejectType uint32
	rejectCode uint8
}

// loadbalance defines action to loadbalance between 1 or more chains
type loadbalance struct {
	chains []string
}

// MetaMark defines Mark keyword of Meta key
// Mark can be used either to Set or Match a mark.
// If Set is true, then the Value will be used to mark a packet,
// and if Set is false, then the Value will be used to match packet's mark against it.
type MetaMark struct {
	Set   bool
	Value int32
}

// MetaExpr allows specifing Meta expressions by meta key and its value,
// example Key: unix.NFT_META_SKGID and Value: 1024
type MetaExpr struct {
	Key   uint32
	Value []byte
	RelOp Operator
}

// Meta defines parameters used to build nft meta expression
type Meta struct {
	Mark *MetaMark
	Expr []MetaExpr
}

// RuleAction defines what action needs to be executed on the rule match
type RuleAction struct {
	verdict     *expr.Verdict
	redirect    *redirect
	masq        *masquerade
	nat         *nat
	reject      *reject
	loadbalance *loadbalance
}

// SetLoadbalance builds RuleAction struct for Verdict based actions
func SetLoadbalance(chains []string) (*RuleAction, error) {
	if len(chains) == 0 {
		return nil, fmt.Errorf("number of chains for loadbalancing cannot be 0")
	}
	ra := &RuleAction{
		loadbalance: &loadbalance{
			chains: chains,
		},
	}

	return ra, nil
}

// SetVerdict builds RuleAction struct for Verdict based actions
func SetVerdict(key int, chain ...string) (*RuleAction, error) {
	ra := &RuleAction{}
	if err := ra.setVerdict(key, chain...); err != nil {
		return nil, err
	}
	return ra, nil
}

// SetRedirect builds RuleAction struct for Redirect action
func SetRedirect(port int, tproxy bool) (*RuleAction, error) {
	ra := &RuleAction{}
	if err := ra.setRedirect(port, tproxy); err != nil {
		return nil, err
	}
	return ra, nil
}

// SetMasq builds RuleAction struct for Masquerade action
func SetMasq(random, fullyRandom, persistent bool) (*RuleAction, error) {
	ra := &RuleAction{}
	ra.masq = &masquerade{}
	ra.masq.random = &random
	ra.masq.fullyRandom = &fullyRandom
	ra.masq.persistent = &persistent

	return ra, nil
}

// SetMasqToPort builds RuleAction struct for Masquerade action
func SetMasqToPort(port ...int) (*RuleAction, error) {
	ra := &RuleAction{}
	ra.masq = &masquerade{}
	if len(port) == 0 {
		return nil, fmt.Errorf("no port provided")
	}
	if len(port) > 2 {
		return nil, fmt.Errorf("more than maximum of 2 ports provided")
	}
	ports := [2]*uint16{}
	p := uint16(port[0])
	ports[0] = &p
	if len(port) == 2 {
		p := uint16(port[1])
		ports[1] = &p
	}
	ra.masq.toPort = ports

	return ra, nil
}

// NATAttributes defines parameters used to generate nftables nat rule
// it is used as input parameter to two helper functions SetSNAT and SetDNAT
// Either L3Addr or Port must be defined.
// When 2 elements of array are specified, then the range of either ip addresses
// or ports will be specified in NAT rule.
type NATAttributes struct {
	L3Addr      [2]*IPAddr
	Port        [2]uint16
	FullyRandom bool
	Random      bool
	Persistent  bool
}

func setNat(nattype expr.NATType, natAttrs *NATAttributes) (*RuleAction, error) {
	if len(natAttrs.L3Addr) == 0 && len(natAttrs.Port) == 0 {
		return nil, fmt.Errorf("either ip address or port must be specified")
	}
	ra := &RuleAction{}
	ra.nat = &nat{
		nattype:     nattype,
		fullyRandom: &natAttrs.FullyRandom,
		random:      &natAttrs.Random,
		persistent:  &natAttrs.Persistent,
	}
	addr := &IPAddrSpec{}
	switch {
	case natAttrs.L3Addr[0] != nil && natAttrs.L3Addr[1] != nil:
		// Both IP addresses are not nil, then pass them as Range
		addr.Range = [2]*IPAddr{}
		addr.Range[0] = natAttrs.L3Addr[0]
		addr.Range[1] = natAttrs.L3Addr[1]

	case natAttrs.L3Addr[0] == nil && natAttrs.L3Addr[1] != nil:
		return nil, fmt.Errorf("first element of a range cannot be nil")
	case natAttrs.L3Addr[0] != nil:
		// Single IP is specified, then pass it as a single element of the list
		addr.List = make([]*IPAddr, 1)
		addr.List[0] = natAttrs.L3Addr[0]
	}
	ra.nat.address = addr
	// Process port if it is specified
	port := Port{}
	switch {
	case natAttrs.Port[0] != 0 && natAttrs.Port[1] != 0:
		// Both Ports are not 0, then pass them as Range
		port.Range = [2]*uint16{}
		port.Range[0] = &natAttrs.Port[0]
		port.Range[1] = &natAttrs.Port[1]

	case natAttrs.Port[0] == 0 && natAttrs.Port[1] != 0:
		return nil, fmt.Errorf("first element of a port range cannot be 0")
	case natAttrs.Port[0] != 0:
		// Single Port is specified, then pass it as a single element of the list
		port.List = make([]*uint16, 1)
		port.List[0] = &natAttrs.Port[0]
	}
	ra.nat.port = &port
	// Add NAT flags is any specified
	ra.nat.random = &natAttrs.Random
	ra.nat.fullyRandom = &natAttrs.FullyRandom
	ra.nat.persistent = &natAttrs.Persistent

	return ra, nil
}

// SetSNAT builds RuleAction struct for SNAT action
func SetSNAT(natAttrs *NATAttributes) (*RuleAction, error) {
	return setNat(expr.NATTypeSourceNAT, natAttrs)
}

// SetDNAT builds RuleAction struct for DNAT action
func SetDNAT(natAttrs *NATAttributes) (*RuleAction, error) {
	return setNat(expr.NATTypeDestNAT, natAttrs)
}

// SetReject builds RuleAction struct for Reject action, rt defines Reject type ICMP or TCP
// rc defines ICMP Reject Code
func SetReject(rt int, rc int) (*RuleAction, error) {
	ra := &RuleAction{
		reject: &reject{
			rejectType: uint32(rt),
			rejectCode: uint8(rc),
		},
	}

	return ra, nil
}

// Validate method validates RuleAction parameters and returns error if inconsistency if found
func (ra *RuleAction) Validate() error {
	if ra.verdict == nil && ra.redirect == nil {
		return fmt.Errorf("rule's action is not set")
	}
	if ra.verdict != nil && ra.redirect != nil {
		return fmt.Errorf("rule's action cannot have both redirect and verdict set")
	}
	return nil
}

func (ra *RuleAction) setRedirect(port int, tproxy bool) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("value of port %d is invalid", port)
	}
	ra.redirect = &redirect{
		port:   uint16(port),
		tproxy: tproxy,
	}

	return nil
}
func (ra *RuleAction) setVerdict(key int, chain ...string) error {
	ra.verdict = &expr.Verdict{}
	switch key {
	case unix.NFT_JUMP:
		fallthrough
	case unix.NFT_GOTO:
		if len(chain) > 1 {
			return fmt.Errorf("only a single chain name can be specified")
		}
		if len(chain) == 0 {
			return fmt.Errorf("jump or goto verdicts must have a chain name specified")
		}
		ra.verdict.Chain = chain[0]
	case unix.NFT_RETURN:
	case NFT_DROP:
	case NFT_ACCEPT:
	}
	ra.verdict.Kind = expr.VerdictKind(int64(key))

	return nil
}

// Log defines nftables logging parameters for a rule
type Log struct {
	Key   uint32
	Value []byte
}

// Fib defines nftables Fib expression. Results and Flags can have multiple selections.
// Data is a slice of bytes, its content depends up on Result and Flags combination.
// Example: if fib expression specifies a particular address type, then Data would carry one of
// constants defined in golang.org/x/sys/unix
// RTN_UNICAST             = 0x1
// RTN_LOCAL               = 0x2
// RTN_BROADCAST           = 0x3
// RTN_ANYCAST             = 0x4
// RTN_MULTICAST           = 0x5
// RTN_BLACKHOLE           = 0x6
// RTN_UNREACHABLE         = 0x7
// RTN_PROHIBIT            = 0x8
// RTN_THROW               = 0x9
// RTN_NAT                 = 0xa
// RTN_XRESOLVE            = 0xb
type Fib struct {
	ResultOIF      bool
	ResultOIFNAME  bool
	ResultADDRTYPE bool
	FlagSADDR      bool
	FlagDADDR      bool
	FlagMARK       bool
	FlagIIF        bool
	FlagOIF        bool
	FlagPRESENT    bool
	RelOp          Operator
	Data           []byte
}

// SetLog is a helper function returning Log struct with validated values
func SetLog(key int, value []byte) (*Log, error) {
	switch key {
	case unix.NFTA_LOG_PREFIX:
	case unix.NFTA_LOG_LEVEL:
	case unix.NFTA_LOG_GROUP:
	case unix.NFTA_LOG_SNAPLEN:
	case unix.NFTA_LOG_QTHRESHOLD:
	default:
		return nil, fmt.Errorf("%d is unsupported value for log's key", key)
	}
	return &Log{Key: uint32(key), Value: value}, nil
}

// Define States of Connection tracking State key
var (
	CTStateNew         uint32 = 0x08000000
	CTStateRelated     uint32 = 0x04000000
	CTStateEstablished uint32 = 0x02000000
	CTStateInvalid     uint32 = 0x01000000
)

// Conntrack defines a key and  value for Ccnnection tracking
type Conntrack struct {
	Key   uint32
	Value []byte
}

// Rule contains parameters for a rule to configure, only L3 OR L4 parameters can be specified
type Rule struct {
	Concat     *Concat
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

// Validate checks parameters passed in struct and returns error if inconsistency is found
func (r Rule) Validate() error {
	switch {
	case r.L3 != nil:
		if err := r.L3.Validate(); err != nil {
			return err
		}
	case r.L4 != nil:
		if err := r.L4.Validate(); err != nil {
			return err
		}
	}
	if r.Action == nil {
		return nil
	}
	if r.L3 == nil && r.L4 == nil && r.Action.redirect != nil {
		return fmt.Errorf("cannot redirect wihtout specifying L3 or L4 rule")
	}
	return nil
}

func getSetName() string {
	name := uuid.New().String()
	return name[len(name)-12:]
}
