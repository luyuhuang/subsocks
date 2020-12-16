package client

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

const (
	ruleNone = iota
	ruleProxy
	ruleDirect
	ruleAuto
)

var ruleString2Rule = map[string]int{
	"proxy":  ruleProxy,
	"direct": ruleDirect,
	"auto":   ruleAuto,
	"P":      ruleProxy,
	"D":      ruleDirect,
	"A":      ruleAuto,
}

type domainNode struct {
	rule     int
	wild     bool
	children map[string]*domainNode
}

func newDomainNode() *domainNode {
	return &domainNode{children: make(map[string]*domainNode)}
}

// Rules represents proxy rules
type Rules struct {
	domainTree *domainNode
	ipMap      map[string]int
	cidrList   []struct {
		cidr *net.IPNet
		rule int
	}
	other int

	mu        sync.RWMutex
	isProxy   map[string]bool
	cacheFile *os.File
}

// NewRulesFromMap creates a Rules object from a map
func NewRulesFromMap(rules map[string]string) (*Rules, error) {
	r := &Rules{
		domainTree: newDomainNode(),
		ipMap:      make(map[string]int),
		isProxy:    make(map[string]bool),
		other:      ruleAuto,
	}
	r.loadCache()
	for addr, rules := range rules {
		rule, ok := ruleString2Rule[rules]
		if !ok {
			return nil, fmt.Errorf("Rule of %q got %s, want proxy|direct|auto|P|D|A", addr, rules)
		}

		if err := r.setRule(addr, rule); err != nil {
			return nil, fmt.Errorf("Set rule failed: %s", err)
		}
	}
	return r, nil
}

// NewRulesFromFile creates a Rules object from a rule file
func NewRulesFromFile(path string) (*Rules, error) {
	f, err := os.Open(path)
	defer f.Close()
	if err != nil {
		return nil, err
	}

	r := &Rules{
		domainTree: newDomainNode(),
		ipMap:      make(map[string]int),
		isProxy:    make(map[string]bool),
		other:      ruleAuto,
	}
	r.loadCache()

	ln := 1
	for s := bufio.NewScanner(f); s.Scan(); ln++ {
		line := strings.TrimSpace(s.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		i := strings.IndexAny(line, " \t")
		if i < 0 {
			return nil, fmt.Errorf("Illegal rule in line %d", ln)
		}

		addr := line[:i]
		rules := strings.TrimSpace(line[i+1:])
		rule, ok := ruleString2Rule[rules]
		if !ok {
			return nil, fmt.Errorf("Rule in line %d got %s, want proxy|direct|auto|P|D|A", ln, rules)
		}

		if err := r.setRule(addr, rule); err != nil {
			return nil, fmt.Errorf("Set rule failed: %s", err)
		}
	}
	return r, nil
}

func (r *Rules) loadCache() error {
	f, err := os.OpenFile(".proxy-cache", os.O_CREATE|os.O_RDWR, 0664)
	if err != nil {
		return err
	}
	s := bufio.NewScanner(f)
	for s.Scan() {
		r.isProxy[strings.TrimSpace(s.Text())] = true
	}
	r.cacheFile = f

	return nil
}

func (r *Rules) setRule(addr string, rule int) error {
	if addr == "*" {
		r.other = rule
	} else if ip := net.ParseIP(addr); ip != nil {
		r.ipMap[addr] = rule
	} else if _, cidr, err := net.ParseCIDR(addr); err == nil {
		r.cidrList = append(r.cidrList, struct {
			cidr *net.IPNet
			rule int
		}{cidr, rule})
	} else {
		if err := r.setDomainRule(addr, rule); err != nil {
			return err
		}
	}

	return nil
}

func (r *Rules) setDomainRule(domain string, rule int) error {
	if i := strings.IndexByte(domain, '*'); i != 0 && i != -1 ||
		strings.Count(domain, "*") > 1 {
		return fmt.Errorf("Domain %q contains illegal wildcards", domain)
	}

	parts := strings.Split(domain, ".")

	p := r.domainTree
	for i := len(parts) - 1; i > 0; i-- {
		part := parts[i]
		if p.children[part] == nil {
			p.children[part] = newDomainNode()
		}
		p = p.children[part]
	}

	if part := parts[0]; part == "*" {
		p.rule = rule
		p.wild = true
	} else {
		if p.children[part] == nil {
			p.children[part] = newDomainNode()
		}
		p.children[part].rule = rule
	}

	return nil
}

func (r *Rules) getRule(addr string) (rule int) {
	if r == nil {
		return ruleProxy
	}

	if ip := net.ParseIP(addr); ip != nil {
		if r, ok := r.ipMap[addr]; ok {
			rule = r
		}
		for _, pair := range r.cidrList {
			if pair.cidr.Contains(ip) {
				rule = pair.rule
				break
			}
		}
	} else {
		parts := strings.Split(addr, ".")
		p := r.domainTree
		for i := len(parts) - 1; i >= 0; i-- {
			part := parts[i]
			p = p.children[part]
			if p == nil {
				break
			}

			if p.rule != ruleNone && (p.wild || i == 0) {
				rule = p.rule
			}
		}
	}

	if rule == ruleNone {
		rule = r.other
	}

	if rule == ruleAuto {
		r.mu.RLock()
		if r.isProxy[addr] {
			rule = ruleProxy
		}
		r.mu.RUnlock()
	}
	return
}

func (r *Rules) setAsProxy(addr string) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.isProxy[addr] {
		r.isProxy[addr] = true
		r.cacheFile.WriteString(addr + "\n")
	}
}
