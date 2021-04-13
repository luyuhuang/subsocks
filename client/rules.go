package client

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
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

	watcher   *fsnotify.Watcher
	rulesPath string
	ruleMu    sync.RWMutex
}

func newRules() *Rules {
	return &Rules{
		isProxy: make(map[string]bool),
	}
}

// NewRulesFromMap creates a Rules object from a map
func NewRulesFromMap(rules map[string]string) (*Rules, error) {
	r := newRules()
	if err := r.loadCache(); err != nil {
		return nil, err
	}

	r.ipv4Tree = new(ipNode)
	r.ipv6Tree = new(ipNode)
	r.domainTree = newDomainNode()
	r.other = ruleAuto

	for addr, rules := range rules {
		rule, ok := ruleString2Rule[rules]
		if !ok {
			return nil, fmt.Errorf("Rule of %q got %s, want proxy|direct|auto|P|D|A", addr, rules)
		}

		if err := setRule(r.ipv4Tree, r.ipv6Tree, r.domainTree, &r.other, addr, rule); err != nil {
			return nil, fmt.Errorf("Set rule failed: %s", err)
		}
	}
	return r, nil
}

// NewRulesFromFile creates a Rules object from a rule file
func NewRulesFromFile(path string) (r *Rules, err error) {
	r = newRules()
	if err := r.loadCache(); err != nil {
		return nil, err
	}

	r.rulesPath = path
	r.ipv4Tree, r.ipv6Tree, r.domainTree, r.other, err = scanRules(path)
	if err != nil {
		return nil, err
	}

	r.watcher, err = fsnotify.NewWatcher()
	if err == nil {
		err = r.watcher.Add(path)
	}

	if err != nil {
		log.Printf("Watch %s failed", path)
	} else {
		go r.watchRules()
	}

	return r, nil
}

func scanRules(path string) (ipv4Tree, ipv6Tree *ipNode, domainTree *domainNode, other int, err error) {
	f, err := os.Open(path)
	defer f.Close()
	if err != nil {
		return
	}

	ipv4Tree = new(ipNode)
	ipv6Tree = new(ipNode)
	domainTree = newDomainNode()
	other = ruleAuto

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
				err = fmt.Errorf("Illegal rule in line %d", ln)
				return
			}
			addr = line
		} else {
			addr = line[:i]
			rules := strings.TrimSpace(line[i+1:])
			rule = ruleString2Rule[rules]
			if rule == ruleNone {
				err = fmt.Errorf("Rule in line %d got %s, want proxy|direct|auto|P|D|A", ln, rules)
				return
			}
		}

		if err = setRule(ipv4Tree, ipv6Tree, domainTree, &other, addr, rule); err != nil {
			err = fmt.Errorf("Set rule failed: %s", err)
			return
		}
	}

	return
}

func (r *Rules) watchRules() {
	for event := range r.watcher.Events {
		if event.Op&fsnotify.Write != 0 {
			log.Printf("Reload %s", r.rulesPath)
			r.ruleMu.Lock()
			ipv4Tree, ipv6Tree, domainTree, other, err := scanRules(r.rulesPath)
			if err == nil {
				r.ipv4Tree, r.ipv6Tree, r.domainTree, r.other = ipv4Tree, ipv6Tree, domainTree, other
			} else {
				log.Println(err)
			}
			r.ruleMu.Unlock()
		}
	}
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

func setRule(ipv4Tree, ipv6Tree *ipNode, domainTree *domainNode, other *int, addr string, rule int) error {
	if addr == "*" {
		*other = rule
	} else if ip := net.ParseIP(addr); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			setIPRule(ipv4Tree, ipv4, 32, rule)
		} else {
			setIPRule(ipv6Tree, ip.To16(), 128, rule)
		}
	} else if _, cidr, err := net.ParseCIDR(addr); err == nil {
		ones, _ := cidr.Mask.Size()
		if ipv4 := cidr.IP.To4(); ipv4 != nil {
			setIPRule(ipv4Tree, ipv4, ones, rule)
		} else {
			setIPRule(ipv6Tree, cidr.IP.To16(), ones, rule)
		}
	} else {
		if err := setDomainRule(domainTree, addr, rule); err != nil {
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

func setDomainRule(p *domainNode, domain string, rule int) error {
	if i := strings.IndexByte(domain, '*'); i != 0 && i != -1 ||
		strings.Count(domain, "*") > 1 {
		return fmt.Errorf("Domain %q contains illegal wildcards", domain)
	}

	parts := strings.Split(domain, ".")

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

	r.ruleMu.RLock()
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
	r.ruleMu.RUnlock()

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
