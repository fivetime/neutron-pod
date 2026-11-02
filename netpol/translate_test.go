package netpol

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func policy(ns, name string, spec networkingv1.NetworkPolicySpec) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       spec,
	}
}

func selector(kv map[string]string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: kv}
}

// TestDenyAllIsolatesWithNoRules is the policy everyone writes first, and the
// one a rules-based shortcut silently turns into a no-op.
func TestDenyAllIsolatesWithNoRules(t *testing.T) {
	p := policy("app", "deny-all", networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
	})
	got, err := Translate(p)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Isolates[Ingress] {
		t.Error("a deny-all policy did not isolate ingress")
	}
	if got.Isolates[Egress] {
		t.Error("it isolated egress, which it did not ask for")
	}
	if len(got.Rules) != 0 {
		t.Errorf("it allowed something: %+v", got.Rules)
	}
}

// TestPolicyTypesDecideIsolationNotRules guards the same trap from the other
// side: naming both types isolates both even when only one has rules.
func TestPolicyTypesDecideIsolationNotRules(t *testing.T) {
	p := policy("app", "both", networkingv1.NetworkPolicySpec{
		PolicyTypes: []networkingv1.PolicyType{
			networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{{
			From: []networkingv1.NetworkPolicyPeer{{PodSelector: selector(map[string]string{"app": "web"})}},
		}},
	})
	got, _ := Translate(p)
	if !got.Isolates[Ingress] || !got.Isolates[Egress] {
		t.Errorf("both directions should be isolated: %+v", got.Isolates)
	}
}

// TestExceptIsNeverDropped is the refusal that matters most: keeping the block
// and dropping the exception hands out exactly the addresses that were excluded.
func TestExceptIsNeverDropped(t *testing.T) {
	p := policy("app", "block", networkingv1.NetworkPolicySpec{
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{{
			From: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{
				CIDR:   "10.0.0.0/8",
				Except: []string{"10.1.0.0/16"},
			}}},
		}},
	})
	got, _ := Translate(p)
	for _, r := range got.Rules {
		for _, peer := range r.Peers {
			if peer.CIDR == "10.0.0.0/8" {
				t.Fatal("the block was allowed with its exception dropped -- " +
					"that allows exactly what the tenant excluded")
			}
		}
	}
	if len(got.Refused) == 0 {
		t.Fatal("the exception was neither honoured nor reported")
	}
	if !strings.Contains(RefusalMessage(got.Refused), "except") {
		t.Errorf("the refusal does not name the field: %q", RefusalMessage(got.Refused))
	}
}

// TestNamedPortDoesNotWidenToTheProtocol is the ovn-kubernetes bug, asserted
// against: an unresolvable name must not become "all of tcp".
func TestNamedPortDoesNotWidenToTheProtocol(t *testing.T) {
	named := intstr.FromString("http")
	p := policy("app", "named", networkingv1.NetworkPolicySpec{
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{{
			From:  []networkingv1.NetworkPolicyPeer{{PodSelector: selector(map[string]string{"a": "b"})}},
			Ports: []networkingv1.NetworkPolicyPort{{Port: &named}},
		}},
	})
	got, _ := Translate(p)
	if len(got.Rules) != 0 {
		t.Fatalf("a rule survived with no usable port, which allows the whole "+
			"protocol: %+v", got.Rules)
	}
	if len(got.Refused) != 1 {
		t.Fatalf("expected one refusal, got %+v", got.Refused)
	}
}

// TestPortsAndRangesSurvive covers the ordinary case the refusals must not eat.
func TestPortsAndRangesSurvive(t *testing.T) {
	port := intstr.FromInt32(8080)
	end := int32(8090)
	udp := corev1.ProtocolUDP
	p := policy("app", "ports", networkingv1.NetworkPolicySpec{
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{{
			From: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "192.168.0.0/16"}}},
			Ports: []networkingv1.NetworkPolicyPort{
				{Port: &port, EndPort: &end},
				{Protocol: &udp},
			},
		}},
	})
	got, _ := Translate(p)
	if len(got.Refused) != 0 {
		t.Fatalf("nothing here is unsupported: %+v", got.Refused)
	}
	if len(got.Rules) != 1 || len(got.Rules[0].Ports) != 2 {
		t.Fatalf("ports were lost: %+v", got.Rules)
	}
	if got.Rules[0].Ports[0].Min != 8080 || got.Rules[0].Ports[0].Max != 8090 {
		t.Errorf("the range is wrong: %+v", got.Rules[0].Ports[0])
	}
	// A protocol with no port means every port of that protocol, which is what
	// leaving Min and Max at zero says downstream.
	if got.Rules[0].Ports[1].Protocol != corev1.ProtocolUDP {
		t.Errorf("the protocol was lost: %+v", got.Rules[0].Ports[1])
	}
}

// TestEmptyPeerListMeansEverywhere keeps a rule with no `from` from being read
// as "nothing", which would deny traffic the policy explicitly allows.
func TestEmptyPeerListMeansEverywhere(t *testing.T) {
	p := policy("app", "open", networkingv1.NetworkPolicySpec{
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress:     []networkingv1.NetworkPolicyIngressRule{{}},
	})
	got, _ := Translate(p)
	if len(got.Rules) != 1 {
		t.Fatalf("an empty peer list should allow everywhere: %+v", got.Rules)
	}
	// ⚠️ Both families. Naming only 0.0.0.0/0 allows everywhere over IPv4 and
	// nowhere over IPv6 -- narrower than written, and invisible until someone
	// turns IPv6 on.
	var families []string
	for _, peer := range got.Rules[0].Peers {
		families = append(families, peer.CIDR)
	}
	if len(families) != 2 || families[0] != "0.0.0.0/0" || families[1] != "::/0" {
		t.Errorf("everywhere covered only %v", families)
	}
}

// TestNilNamespaceSelectorMeansThisNamespace is the distinction that decides
// whether an app talks to its own front end or to every front end the tenant
// runs. All of a tenant's namespaces share one network here, so getting it
// wrong is not academic.
func TestNilNamespaceSelectorMeansThisNamespace(t *testing.T) {
	pods := selector(map[string]string{"app": "web"})
	own, err := SelectorKey("prod", nil, pods)
	if err != nil {
		t.Fatal(err)
	}
	every, err := SelectorKey("prod", &metav1.LabelSelector{}, pods)
	if err != nil {
		t.Fatal(err)
	}
	if own == every {
		t.Fatalf("a nil namespace selector was treated as every namespace: %q", own)
	}
	if !strings.Contains(own, "ns=prod") {
		t.Errorf("the policy's own namespace is not in the key: %q", own)
	}
	// The same set asked for twice must land on one address group.
	again, _ := SelectorKey("prod", nil, selector(map[string]string{"app": "web"}))
	if own != again {
		t.Errorf("the same selector produced two keys: %q vs %q", own, again)
	}
}

// TestIsolationFollowsLabels checks the switch that actually changes a pod's
// security groups.
func TestIsolationFollowsLabels(t *testing.T) {
	pods := []*corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "web", Labels: map[string]string{"app": "web"}}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "db", Labels: map[string]string{"app": "db"}}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "staging", Name: "web", Labels: map[string]string{"app": "web"}}},
	}
	policies := []*networkingv1.NetworkPolicy{
		policy("prod", "web-deny", networkingv1.NetworkPolicySpec{
			PodSelector: *selector(map[string]string{"app": "web"}),
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		}),
	}

	got, err := IsolationOf(pods[0], policies)
	if err != nil {
		t.Fatal(err)
	}
	if len(got[Ingress]) != 1 || got[Ingress][0] != "web-deny" {
		t.Errorf("the selected pod is not isolated: %+v", got)
	}
	if len(got[Egress]) != 0 {
		t.Errorf("egress was isolated without being asked: %+v", got)
	}
	if got, _ := IsolationOf(pods[1], policies); len(got) != 0 {
		t.Errorf("a pod the selector does not match was isolated: %+v", got)
	}
	// ⚠️ Same labels, different namespace. All of a tenant's namespaces share
	// one Neutron network, so a policy leaking across namespaces would be
	// invisible in the substrate and wrong in exactly the case namespaces are
	// created for.
	if got, _ := IsolationOf(pods[2], policies); len(got) != 0 {
		t.Errorf("a policy reached into another namespace: %+v", got)
	}
}
