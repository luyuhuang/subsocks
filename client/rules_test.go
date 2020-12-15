package client

import "testing"

func TestRulesDomain(t *testing.T) {
	rule, err := NewRulesFromMap(map[string]string{
		"*.google.com":   "P",
		"www.google.com": "D",
		"github.com":     "D",
		"www.github.com": "P",
		"*.tech":         "D",

		"c.d":     "A",
		"b.c.d":   "D",
		"a.b.c.d": "P",
	})
	if err != nil {
		t.Fatalf("Create rules failed: %s", err)
	}

	cases := []struct {
		addr string
		rule int
	}{
		{"www.google.com", ruleProxy},
		{"google.com", ruleProxy},
		{"mail.google.com", ruleProxy},
		{"github.com", ruleDirect},
		{"www.github.com", ruleProxy},
		{"raw.github.com", ruleAuto},
		{"bing.com", ruleAuto},
		{"luyuhuang.tech", ruleDirect},
		{"admin.luyuhuang.tech", ruleDirect},

		{"c.d", ruleAuto},
		{"b.c.d", ruleDirect},
		{"a.b.c.d", ruleProxy},
	}

	for _, c := range cases {
		if r := rule.getRule(c.addr); r != c.rule {
			t.Fatalf("%q rule got %d, want %d", c.addr, r, c.rule)
		}
	}
}

func TestRulesIPv4(t *testing.T) {
	rule, err := NewRulesFromMap(map[string]string{
		"10.1.1.0/24": "P",
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
		{"10.2.1.1", ruleDirect},
		{"10.2.2.1", ruleDirect},
		{"10.2.1.224", ruleDirect},
		{"10.2.224.224", ruleDirect},
		{"10.1.2.1", ruleAuto},
		{"10.3.2.1", ruleAuto},
		{"127.0.0.1", ruleDirect},
	}

	for _, c := range cases {
		if r := rule.getRule(c.addr); r != c.rule {
			t.Fatalf("%q rule got %d, want %d", c.addr, r, c.rule)
		}
	}
}
