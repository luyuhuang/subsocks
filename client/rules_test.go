package client

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

func TestRulesDomain(t *testing.T) {
	rule, err := NewRulesFromMap(map[string]string{
		"*.google.com":   "P",
		"www.google.com": "D",
		"github.com":     "D",
		"www.github.com": "P",
		"*.tech":         "D",

		"*.d":   "P",
		"*.c.d": "D",
		"b.c.d": "A",
	})
	if err != nil {
		t.Fatalf("Create rules failed: %s", err)
	}

	cases := []struct {
		addr string
		rule int
	}{
		{"www.google.com", ruleDirect},
		{"google.com", ruleProxy},
		{"mail.google.com", ruleProxy},
		{"github.com", ruleDirect},
		{"www.github.com", ruleProxy},
		{"raw.github.com", ruleAuto},
		{"bing.com", ruleAuto},
		{"luyuhuang.tech", ruleDirect},
		{"admin.luyuhuang.tech", ruleDirect},

		{"d", ruleProxy},
		{"c.d", ruleDirect},
		{"b.c.d", ruleAuto},
		{"x.c.d", ruleDirect},
		{"x.y.c.d", ruleDirect},
		{"x.y.z.d", ruleProxy},
	}

	for _, c := range cases {
		if r := rule.getRule(c.addr); r != c.rule {
			t.Fatalf("%q rule got %d, want %d", c.addr, r, c.rule)
		}
	}
}

func TestRulesIPv4(t *testing.T) {
	rule, err := NewRulesFromMap(map[string]string{
		"10.1.0.0/16": "D",
		"10.1.1.0/24": "P",
		"10.1.1.123":  "D",
		"10.2.0.0/16": "D",
		"127.0.0.1":   "D",
	})
	if err != nil {
		t.Fatalf("Create rules failed: %s", err)
	}

	cases := []struct {
		addr string
		rule int
	}{
		{"10.1.1.1", ruleProxy},
		{"10.1.1.2", ruleProxy},
		{"10.1.1.224", ruleProxy},
		{"10.1.2.1", ruleDirect},
		{"10.1.1.123", ruleDirect},
		{"10.2.1.1", ruleDirect},
		{"10.2.2.1", ruleDirect},
		{"10.2.1.224", ruleDirect},
		{"10.2.224.224", ruleDirect},
		{"10.3.2.1", ruleAuto},
		{"127.0.0.1", ruleDirect},
	}

	for _, c := range cases {
		if r := rule.getRule(c.addr); r != c.rule {
			t.Fatalf("%q rule got %d, want %d", c.addr, r, c.rule)
		}
	}
}

func TestRulesIPv6(t *testing.T) {
	rule, err := NewRulesFromMap(map[string]string{
		"1234:5678:abcd::1":         "D",
		"1234:5678:abcd::/48":       "P",
		"1234:5678::/32":            "D",
		"fe80::75ba:83df:b394:2e60": "P",
	})
	if err != nil {
		t.Fatalf("Create rules failed: %s", err)
	}

	cases := []struct {
		addr string
		rule int
	}{
		{"1234:5678:abcd::1", ruleDirect},
		{"1234:5678:abcd::2", ruleProxy},
		{"1234:5678:bbcd::2", ruleDirect},
		{"fe80::75ba:83df:b394:2e60", ruleProxy},
		{"10.1.1.1", ruleAuto},
	}

	for _, c := range cases {
		if r := rule.getRule(c.addr); r != c.rule {
			t.Fatalf("%q rule got %d, want %d", c.addr, r, c.rule)
		}
	}
}

func TestIPRulesOrder(t *testing.T) {
	rule, err := NewRulesFromMap(nil)
	if err != nil {
		t.Fatalf("Create rules failed: %s", err)
	}

	rules := []struct {
		ip   string
		l    int
		rule int
	}{
		{"10.1.1.123", 32, ruleDirect},
		{"10.1.1.0", 24, ruleProxy},
		{"10.1.0.0", 16, ruleDirect},
		{"127.0.0.1", 32, ruleDirect},
		{"127.0.0.1", 32, ruleProxy},
	}
	for _, c := range rules {
		setIPRule(rule.ipv4Tree, net.ParseIP(c.ip).To4(), c.l, c.rule)
	}

	cases := []struct {
		addr string
		rule int
	}{
		{"10.1.1.123", ruleDirect},
		{"10.1.1.1", ruleProxy},
		{"10.1.2.1", ruleDirect},
		{"127.0.0.1", ruleProxy},
	}

	for _, c := range cases {
		if r := rule.getRule(c.addr); r != c.rule {
			t.Fatalf("%q rule got %d, want %d", c.addr, r, c.rule)
		}
	}
}

func TestRulesOther(t *testing.T) {
	rule, err := NewRulesFromMap(map[string]string{
		"*.google.com":   "P",
		"www.google.com": "P",

		"10.1.1.0/24": "P",
		"10.2.0.0/16": "P",

		"*": "D",
	})
	if err != nil {
		t.Fatalf("Create rules failed: %s", err)
	}

	cases := []struct {
		addr string
		rule int
	}{
		{"google.com", ruleProxy},
		{"www.google.com", ruleProxy},
		{"mail.google.com", ruleProxy},
		{"10.1.1.1", ruleProxy},
		{"10.1.1.2", ruleProxy},
		{"10.2.1.1", ruleProxy},
		{"10.2.2.1", ruleProxy},

		{"www.github.com", ruleDirect},
		{"luyuhuang.tech", ruleDirect},
		{"127.0.0.1", ruleDirect},
		{"10.1.2.1", ruleDirect},
		{"10.3.2.1", ruleDirect},
	}

	for _, c := range cases {
		if r := rule.getRule(c.addr); r != c.rule {
			t.Fatalf("%q rule got %d, want %d", c.addr, r, c.rule)
		}
	}
}

func TestRulesIllegal(t *testing.T) {
	cases := []struct {
		addr string
		rule string
		err  string
	}{
		{"www.*.com", "P", "contains illegal wildcards"},
		{"www*.google.com", "P", "contains illegal wildcards"},
		{"**", "P", "contains illegal wildcards"},
		{"www.google.com", "proyx", "want proxy|direct|auto|P|D|A"},
	}

	for _, c := range cases {
		_, err := NewRulesFromMap(map[string]string{c.addr: c.rule})
		if err == nil || !strings.Contains(err.Error(), c.err) {
			t.Fatalf("Error %q does not contain %q", err, c.err)
		}
	}
}

func TestRulesFile(t *testing.T) {
	path := fmt.Sprintf("%s%crule.txt", t.TempDir(), os.PathSeparator)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0664)
	if err != nil {
		t.Fatalf("Create file %q failed %q", path, err)
	}

	f.WriteString("# comment\n")
	f.WriteString("*.google.com P\n")
	f.WriteString("mail.google.com    D\n")
	f.WriteString("\n")
	f.WriteString("github.com\tP\n")
	f.WriteString("raw.github.com\t\tD\n")
	f.WriteString(" \t# twitter\n")
	f.WriteString("twitter.com\t P\n")
	f.WriteString("facebook.com \tD\n")
	f.WriteString("*.bing.com\n")
	f.WriteString("*.apple.com  \n")
	f.Close()

	rule, err := NewRulesFromFile(path)
	if err != nil {
		t.Fatalf("Create rules failed: %s", err)
	}

	cases := []struct {
		addr string
		rule int
	}{
		{"google.com", ruleProxy},
		{"www.google.com", ruleProxy},
		{"mail.google.com", ruleDirect},
		{"github.com", ruleProxy},
		{"raw.github.com", ruleDirect},
		{"twitter.com", ruleProxy},
		{"facebook.com", ruleDirect},
		{"bing.com", ruleDirect},
		{"cn.bing.com", ruleDirect},
		{"apple.com", ruleDirect},
	}

	for _, c := range cases {
		if r := rule.getRule(c.addr); r != c.rule {
			t.Fatalf("%q rule got %d, want %d", c.addr, r, c.rule)
		}
	}

	rule.watcher.Close()
}

func TestRulesFileIllegal(t *testing.T) {
	path := fmt.Sprintf("%s%crule1.txt", t.TempDir(), os.PathSeparator)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0664)
	if err != nil {
		t.Fatalf("Create file %q failed %q", path, err)
	}

	f.WriteString("*.google.com  \n")
	f.WriteString("mail.google.com    D\n")
	f.Close()

	_, err = NewRulesFromFile(path)
	if err == nil || !strings.Contains(err.Error(), "Illegal rule") {
		t.Fatalf("Error %q does not contain 'Illegal rule'", err)
	}

	path = fmt.Sprintf("%s%crule2.txt", t.TempDir(), os.PathSeparator)
	f, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0664)
	if err != nil {
		t.Fatalf("Create file %q failed %q", path, err)
	}

	f.WriteString("*.google.com  x\n")
	f.Close()

	_, err = NewRulesFromFile(path)
	if err == nil || !strings.Contains(err.Error(), "want proxy|direct|auto|P|D|A") {
		t.Fatalf("Error %q does not contain 'want proxy|direct|auto|P|D|A'", err)
	}
}

func printIPTree(n *ipNode, k int) {
	fmt.Printf(strings.Repeat("  ", k))
	if n == nil || len(n.bits) <= 0 {
		fmt.Printf("-")
	} else {
		for _, b := range n.bits {
			fmt.Printf("%d", b)
		}
		fmt.Printf(" (%d)", len(n.bits))
	}
	fmt.Println()

	if n != nil {
		printIPTree(n.children[0], k+1)
		printIPTree(n.children[1], k+1)
	}
}

// func TestIP(t *testing.T) {
// 	cases := []struct {
// 		ip string
// 		l  int
// 	}{
// 		{"10.1.1.123", 32},
// 		{"10.1.1.0", 24},
// 		{"10.1.0.0", 16},
// 		{"10.2.0.0", 16},
// 		{"127.0.0.1", 32},
// 	}

// 	root := &ipNode{}

// 	for _, c := range cases {
// 		fmt.Printf("%s\t", c.ip)
// 		ip := net.ParseIP(c.ip).To4()
// 		for i := 0; i < c.l; i++ {
// 			b := (ip[i/8] >> (8 - i%8 - 1)) & 1
// 			fmt.Printf("%d", b)
// 		}
// 		fmt.Printf(" (%d)\n", c.l)

// 		setIPRule(root, ip, c.l, ruleDirect)
// 	}
// 	printIPTree(root, 0)

// }
