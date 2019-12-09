package nftableslib

import "fmt"

const (
	initialRuleID   = 10
	ruleIDIncrement = 10
)

func (r *nfRules) addRule(e *nfRule) {
	if r.rules == nil {
		r.rules = e
		r.rules.next = nil
		r.rules.prev = nil
		r.currentID = initialRuleID
		r.rules.id = initialRuleID
		r.currentID += ruleIDIncrement
		return
	}
	last := getLast(r.rules)
	// Locking current last list's elelemnt.
	last.Lock()
	defer last.Unlock()
	last.next = e
	// Locking new list element while updating its fields.
	last.next.Lock()
	defer last.next.Unlock()
	last.next.next = nil
	last.next.prev = last
	last.next.id = r.currentID
	r.currentID += ruleIDIncrement

	return
}

func (r *nfRules) removeRule(id uint32) error {
	e := r.rules
	for ; e != nil; e = e.next {
		if e.id == id {
			if e.prev == nil {
				if e.next == nil {
					// Deleting first and the only element in the list
					r.rules = nil
					return nil
				}
				r.rules = e.next
			} else {
				e.prev.Lock()
				defer e.prev.Unlock()
				e.prev.next = e.next
			}
			if e.next != nil {
				e.next.Lock()
				defer e.next.Unlock()
				e.next.prev = e.prev
			}
			return nil
		}
	}

	return fmt.Errorf("id %d is not found", id)
}

func (r *nfRules) countRules() int {
	count := 0
	e := r.rules
	for ; e != nil; e = e.next {
		count++
	}
	return count
}

func (r *nfRules) dumpRules() []*nfRule {
	rr := []*nfRule{}
	e := r.rules
	for ; e != nil; e = e.next {
		rr = append(rr, e)
	}
	return rr
}

func getLast(e *nfRule) *nfRule {
	if e.next == nil {
		return e
	}
	return getLast(e.next)
}

func getRuleByID(e *nfRule, id uint32) (*nfRule, error) {
	if e == nil {
		return nil, fmt.Errorf("rule with id %d not found", id)
	}
	if e.id == id {
		return e, nil
	}
	return getRuleByID(e.next, id)
}

func getRuleByHandle(e *nfRule, handle uint64) (*nfRule, error) {
	if e == nil {
		return nil, fmt.Errorf("rule with handle %d not found", handle)
	}
	if e.rule.Handle == handle {
		return e, nil
	}
	return getRuleByHandle(e.next, handle)
}
