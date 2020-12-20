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

type ipNode struct {
	rule     int
	bits     []byte
	children [2]*ipNode
}

// Rules represents proxy rules
type Rules struct {
	domainTree *domainNode
	ipv4Tree   *ipNode
	ipv6Tree   *ipNode
	other      int

	mu        sync.RWMutex
	isProxy   map[string]bool
	cacheFile *os.File
}

func newRules() *Rules {
	return &Rules{
		domainTree: newDomainNode(),
		ipv4Tree:   new(ipNode),
		ipv6Tree:   new(ipNode),
		isProxy:    make(map[string]bool),
		other:      ruleAuto,
	}
}

// NewRulesFromMap creates a Rules object from a map
func NewRulesFromMap(rules map[string]string) (*Rules, error) {
	r := newRules()
	if err := r.loadCache(); err != nil {
		return nil, err
	}
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

	r := newRules()
	if err := r.loadCache(); err != nil {
		return nil, err
	}

	ln := 1
	var addr string
	var rule int
	for s := bufio.NewScanner(f); s.Scan(); ln++ {
		line := strings.TrimSpace(s.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		if i := strings.IndexAny(line, " \t"); i < 0 {
			if rule == ruleNone {
				return nil, fmt.Errorf("Illegal rule in line %d", ln)
			}
			addr = line
		} else {
			addr = line[:i]
			rules := strings.TrimSpace(line[i+1:])
			rule = ruleString2Rule[rules]
			if rule == ruleNone {
				return nil, fmt.Errorf("Rule in line %d got %s, want proxy|direct|auto|P|D|A", ln, rules)
			}
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
		if ipv4 := ip.To4(); ipv4 != nil {
			setIPRule(r.ipv4Tree, ipv4, 32, rule)
		} else {
			setIPRule(r.ipv6Tree, ip.To16(), 128, rule)
		}
	} else if _, cidr, err := net.ParseCIDR(addr); err == nil {
		ones, _ := cidr.Mask.Size()
		if ipv4 := cidr.IP.To4(); ipv4 != nil {
			setIPRule(r.ipv4Tree, ipv4, ones, rule)
		} else {
			setIPRule(r.ipv6Tree, cidr.IP.To16(), ones, rule)
		}
	} else {
		if err := r.setDomainRule(addr, rule); err != nil {
			return err
		}
	}

	return nil
}

func setIPRule(root *ipNode, ip []byte, length int, rule int) {
	var p, pp *ipNode
	p = root
	j := 0
	for i := 0; i < length; i++ {
		b := (ip[i/8] >> (8 - i%8 - 1)) & 1

		if j >= len(p.bits) {
			j = 0
			pp = p
			p = p.children[b]
		}

		var pnode, node *ipNode
		if p == nil {
			pnode = pp
		} else if p.bits[j] != b {
			// p: |------+---------|
			//           ^ j
			//    |--np--|----p----|

			np := new(ipNode)
			np.bits = make([]byte, j)
			copy(np.bits, p.bits[:j])

			pp.children[np.bits[0]] = np

			copy(p.bits, p.bits[j:])
			p.bits = p.bits[:len(p.bits)-j]

			np.children[p.bits[0]] = p
			pnode = np
		} else if i == length-1 {
			if j == len(p.bits)-1 {
				node = p
			} else {
				np := new(ipNode)
				np.bits = make([]byte, j+1)
				copy(np.bits, p.bits[:j+1])

				pp.children[np.bits[0]] = np
				node = np

				copy(p.bits, p.bits[j+1:])
				p.bits = p.bits[:len(p.bits)-j-1]

				np.children[p.bits[0]] = p
			}
		}

		if pnode != nil {
			node = new(ipNode)
			node.bits = make([]byte, length-i)
			for k := i; k < length; k++ {
				node.bits[k-i] = (ip[k/8] >> (8 - k%8 - 1)) & 1
			}
			pnode.children[node.bits[0]] = node
		}

		if node != nil {
			node.rule = rule
			break
		}

		j++
	}
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

func searchIPRule(root *ipNode, ip []byte) (rule int) {
	p := root
	j := 0
	for i := 0; i < len(ip)*8; i++ {
		b := (ip[i/8] >> (8 - i%8 - 1)) & 1

		if j >= len(p.bits) {
			j = 0
			p = p.children[b]
		}

		if p == nil || p.bits[j] != b {
			break
		}

		if j == len(p.bits)-1 && p.rule != ruleNone {
			rule = p.rule
		}

		j++
	}
	return
}

func (r *Rules) getRule(addr string) (rule int) {
	if r == nil {
		return ruleProxy
	}

	if ip := net.ParseIP(addr); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil { // IPv4
			rule = searchIPRule(r.ipv4Tree, ipv4)
		} else { // IPv6
			rule = searchIPRule(r.ipv6Tree, ip.To16())
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
