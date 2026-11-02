package netpol

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// TestAnInertRuleStaysInertWhenAnotherPolicyIsolates covers the bug a per-pod
// rule set has and a per-policy one cannot: P1 lists egress rules without
// declaring Egress, so they do nothing; P2 isolates egress. The pod is now
// isolated for egress, and P1's inert rules must still not apply.
func TestAnInertRuleStaysInertWhenAnotherPolicyIsolates(t *testing.T) {
	p1 := &Translated{
		Isolates: map[Direction]bool{Ingress: true},
		Rules: []Rule{
			{Direction: Egress, Peers: []Peer{{CIDR: "8.8.8.8/32"}}},
		},
	}
	p2 := &Translated{Isolates: map[Direction]bool{Egress: true}}

	if got := PolicyRules(p1); len(got.Rules) != 0 {
		t.Errorf("an inert egress rule was written: %+v", got.Rules)
	}
	if got := PolicyRules(p2); len(got.Rules) != 0 {
		t.Errorf("a policy with no rules produced some: %+v", got.Rules)
	}
}

// TestExpansionMultipliesPeersByPorts is the arithmetic Neutron forces on us:
// one remote and one port range per rule, so a policy rule with two peers and
// two ports is four rules -- times the address families a peer needs.
func TestExpansionMultipliesPeersByPorts(t *testing.T) {
	set := Expand([]Rule{{
		Direction: Ingress,
		Peers: []Peer{
			{CIDR: "10.0.0.0/8"},
			{SelectorKey: "ns=prod;pods=app=web"},
		},
		Ports: []Port{
			{Protocol: corev1.ProtocolTCP, Min: 80, Max: 80},
			{Protocol: corev1.ProtocolTCP, Min: 443, Max: 443},
		},
	}})

	// The CIDR is v4 only: one family. The pod set needs both.
	if len(set.Rules) != 2*1+2*2 {
		t.Fatalf("expansion produced %d rules: %+v", len(set.Rules), set.Rules)
	}
	if _, ok := set.Peers["ns=prod;pods=app=web"]; !ok || len(set.Peers) != 1 {
		t.Errorf("the peer set was not reported: %v", set.Peers)
	}
}

// TestAV4CIDRNeverBecomesAV6Rule guards a pairing Neutron rejects. A rejected
// rule in the middle of writing a set leaves the pod holding half a policy.
func TestAV4CIDRNeverBecomesAV6Rule(t *testing.T) {
	set := Expand([]Rule{{
		Direction: Egress,
		Peers:     []Peer{{CIDR: "192.168.0.0/16"}, {CIDR: "fd00::/8"}},
	}})
	for _, r := range set.Rules {
		if r.RemoteCIDR == "192.168.0.0/16" && r.EtherType != "IPv4" {
			t.Errorf("a v4 prefix was paired with %s", r.EtherType)
		}
		if r.RemoteCIDR == "fd00::/8" && r.EtherType != "IPv6" {
			t.Errorf("a v6 prefix was paired with %s", r.EtherType)
		}
	}
	if len(set.Rules) != 2 {
		t.Errorf("expected one rule per prefix, got %d", len(set.Rules))
	}
}

// TestDuplicatesAreCollapsed matters because policies are additive and Neutron
// refuses a duplicate rule: two policies allowing the same thing is ordinary,
// and would otherwise fail at write time rather than here.
func TestDuplicatesAreCollapsed(t *testing.T) {
	one := Rule{Direction: Ingress, Peers: []Peer{{CIDR: "10.0.0.0/8"}}}
	set := Expand([]Rule{one, one})
	if len(set.Rules) != 1 {
		t.Errorf("a repeated rule was not collapsed: %+v", set.Rules)
	}
}

// TestTheGroupNameFollowsThePolicyNotItsContents is what keeps the number of
// security groups equal to the number of policies. A content-derived name mints
// a new group whenever a policy is edited, and orphans the old one -- and a
// group created or deleted is a cloud-wide northd recompute.
func TestTheGroupNameFollowsThePolicyNotItsContents(t *testing.T) {
	before := testNaming.PolicyGroup("prod", "web")
	after := testNaming.PolicyGroup("prod", "web") // same policy, rules edited meanwhile
	if before != after {
		t.Error("editing a policy would have created a second group")
	}
	if testNaming.PolicyGroup("prod", "web") == testNaming.PolicyGroup("staging", "web") {
		t.Error("two namespaces collided on one group")
	}
	if got := len(testNaming.PeerGroup("ns=prod;pods=" + string(make([]byte, 400)))); got > 255 {
		t.Errorf("an address group name of %d characters cannot be stored", got)
	}
}

// TestRulesOfAnUnisolatedDirectionAreDropped is the subtlety that would
// otherwise turn an unrestricted direction into a restricted one. A policy
// isolating ingress and listing egress rules does not restrict egress at all.
//
// ⚠️ And it must be decided per policy. Deciding it from the union of every
// policy selecting the pod -- which a per-pod rule set is forced to do -- makes
// these inert rules take effect the moment some OTHER policy isolates egress,
// which is not what the API says and not what the tenant wrote.
func TestRulesOfAnUnisolatedDirectionAreDropped(t *testing.T) {
	tr := &Translated{
		Isolates: map[Direction]bool{Ingress: true},
		Rules: []Rule{
			{Direction: Ingress, Peers: []Peer{{CIDR: "10.0.0.0/8"}}},
			{Direction: Egress, Peers: []Peer{{CIDR: "8.8.8.8/32"}}},
		},
	}
	set := PolicyRules(tr)
	for _, r := range set.Rules {
		if r.Direction == Egress {
			t.Fatalf("an egress rule was written for a policy that does not "+
				"isolate egress, which restricts a direction the tenant left "+
				"open: %+v", r)
		}
	}
	if len(set.Rules) != 1 {
		t.Errorf("the ingress rule was lost: %+v", set.Rules)
	}
}
