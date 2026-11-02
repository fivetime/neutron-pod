// Package netpol turns Kubernetes NetworkPolicy into what a Neutron port can
// carry, and refuses — loudly — the parts it cannot carry.
//
// The shape of the answer comes from one fact about OVN: an ACL attaches to a
// Logical_Switch or a Port_Group, and there is no Address_Set.acls column. An
// address set is what a rule MATCHES; a port group is where a rule HANGS. So a
// policy's subject — which pods it isolates — rides the port's security group
// list, and a policy's peers ride address groups.
//
// The refusals are the important half. A policy this cannot express must never
// come out wider than what was asked for: a dropped `except` turns a narrowing
// into a widening, and an unresolved named port turns "port 8080" into "all of
// tcp". Where something cannot be expressed, the traffic it would have allowed
// stays denied and the reason is reported. Narrower than asked is a visible
// failure; wider than asked is a silent one.
package netpol

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Direction is which way a rule applies. Kubernetes isolates a pod
// per-direction; a Neutron security group has no direction of its own, so the
// two are kept apart everywhere in this package.
type Direction string

const (
	Ingress Direction = "ingress"
	Egress  Direction = "egress"
)

// Peer is one source or destination a rule allows, already reduced to
// something Neutron can be told.
type Peer struct {
	// CIDR is set for an ipBlock peer.
	CIDR string
	// SelectorKey identifies a pod set, whose addresses live in an address
	// group. Empty when CIDR is set.
	SelectorKey string
	// Selector is that same pod set, resolved. ⚠️ Carried rather than derived
	// later: the key is a hash, and nothing can be recovered from it. A
	// pipeline that keeps only the key discovers this at the point where it
	// has to list the pods and cannot.
	Selector PeerSelector
}

// Port is one allowed port range and protocol.
type Port struct {
	Protocol corev1.Protocol
	Min      int32
	Max      int32
}

// PeerSelector is a resolved peer: which namespaces, and which pods in them.
type PeerSelector struct {
	// Namespace is the one namespace to look in, set when the policy named no
	// namespace selector at all. ⚠️ That case means the policy's OWN namespace,
	// not every namespace, and the two are only distinguishable here.
	Namespace string
	// Namespaces selects namespaces when the policy gave a selector. Only
	// consulted when Namespace is empty.
	Namespaces labels.Selector
	Pods       labels.Selector
}

// Rule is one allowance: these peers, on these ports, in this direction.
type Rule struct {
	Direction Direction
	Peers     []Peer
	Ports     []Port
}

// Refusal is something asked for that this cannot express. It is not an error:
// the rest of the policy still applies. It is the part that stays denied, and
// the reason, so it can be reported on the policy object.
type Refusal struct {
	Field  string
	Reason string
}

// Translated is a policy reduced to what the substrate can carry.
type Translated struct {
	// Isolates says which directions this policy puts its subjects into
	// default-deny. This is the half that is always expressible.
	Isolates map[Direction]bool
	// Subject selects the pods the policy applies to, within its namespace.
	Subject labels.Selector
	Rules   []Rule
	Refused []Refusal
}

// Translate reduces one NetworkPolicy.
//
// ⚠️ Isolation is computed from policyTypes, and policyTypes is not optional to
// read: a policy with no `ingress` key still isolates ingress, and a policy
// naming both types isolates both even where one rule list is empty. Deriving
// isolation from the presence of rules instead — the obvious shortcut — makes
// `policyTypes: [Ingress], ingress: []`, the canonical deny-all, do nothing at
// all.
func Translate(p *networkingv1.NetworkPolicy) (*Translated, error) {
	subject, err := metav1.LabelSelectorAsSelector(&p.Spec.PodSelector)
	if err != nil {
		return nil, fmt.Errorf("the pod selector of %s/%s: %w", p.Namespace, p.Name, err)
	}
	out := &Translated{
		Isolates: map[Direction]bool{},
		Subject:  subject,
	}

	types := p.Spec.PolicyTypes
	if len(types) == 0 {
		// The API server defaults this, but a policy can reach us without it.
		// Kubernetes' own rule: ingress always, egress only if egress rules
		// were written.
		types = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
		if len(p.Spec.Egress) > 0 {
			types = append(types, networkingv1.PolicyTypeEgress)
		}
	}
	for _, t := range types {
		switch t {
		case networkingv1.PolicyTypeIngress:
			out.Isolates[Ingress] = true
		case networkingv1.PolicyTypeEgress:
			out.Isolates[Egress] = true
		}
	}

	for i, r := range p.Spec.Ingress {
		rule, refusals := translateRule(p.Namespace, Ingress, i, r.From, r.Ports)
		out.Refused = append(out.Refused, refusals...)
		if rule != nil {
			out.Rules = append(out.Rules, *rule)
		}
	}
	for i, r := range p.Spec.Egress {
		rule, refusals := translateRule(p.Namespace, Egress, i, r.To, r.Ports)
		out.Refused = append(out.Refused, refusals...)
		if rule != nil {
			out.Rules = append(out.Rules, *rule)
		}
	}
	return out, nil
}

func translateRule(ns string, dir Direction, index int, peers []networkingv1.NetworkPolicyPeer, ports []networkingv1.NetworkPolicyPort) (*Rule, []Refusal) {
	where := fmt.Sprintf("spec.%s[%d]", dir, index)
	rule := &Rule{Direction: dir}
	var refused []Refusal

	// No peers means every source. ⚠️ Both families: a rule saying "from
	// anywhere" that only names 0.0.0.0/0 allows anywhere reachable over IPv4
	// and nothing over IPv6, which is narrower than what was written and
	// invisible on a tenant that has not turned IPv6 on yet.
	if len(peers) == 0 {
		rule.Peers = []Peer{{CIDR: "0.0.0.0/0"}, {CIDR: "::/0"}}
	}
	for i, peer := range peers {
		at := fmt.Sprintf("%s.%s[%d]", where, peerField(dir), i)
		switch {
		case peer.IPBlock != nil:
			if len(peer.IPBlock.Except) > 0 {
				// A security group rule has no negation: Neutron's match
				// builder emits only equality. The complement can be expanded
				// into a set of CIDRs, but until that exists the exception is
				// honoured the only safe way -- by not allowing the block at
				// all. Dropping the `except` and keeping the block would hand
				// out exactly the addresses the tenant excluded.
				refused = append(refused, Refusal{
					Field: at + ".ipBlock.except",
					Reason: "this platform cannot express an exception inside " +
						"an allowed range yet, so the whole range stays denied " +
						"rather than allowing the addresses you excluded",
				})
				continue
			}
			rule.Peers = append(rule.Peers, Peer{CIDR: peer.IPBlock.CIDR})
		case peer.PodSelector != nil || peer.NamespaceSelector != nil:
			key, err := SelectorKey(ns, peer.NamespaceSelector, peer.PodSelector)
			if err != nil {
				refused = append(refused, Refusal{Field: at, Reason: err.Error()})
				continue
			}
			sel, err := resolvePeer(ns, peer.NamespaceSelector, peer.PodSelector)
			if err != nil {
				refused = append(refused, Refusal{Field: at, Reason: err.Error()})
				continue
			}
			rule.Peers = append(rule.Peers, Peer{SelectorKey: key, Selector: sel})
		default:
			refused = append(refused, Refusal{
				Field:  at,
				Reason: "a peer with nothing in it selects nothing",
			})
		}
	}

	// No ports means every port, which a rule can say by leaving them out.
	for i, p := range ports {
		at := fmt.Sprintf("%s.ports[%d]", where, i)
		if p.Port != nil && p.Port.Type != 0 {
			// A named port resolves per pod -- two pods can give the same name
			// different numbers -- while a security group rule belongs to a
			// group, not to a target. ⚠️ ovn-kubernetes gets this wrong in the
			// dangerous direction: an unresolved name becomes a bare protocol
			// match, widening "port http" to all of tcp
			// (go-controller/pkg/ovn/gress_policy.go:118-122). Refusing keeps
			// the traffic denied instead.
			refused = append(refused, Refusal{
				Field: at + ".port",
				Reason: fmt.Sprintf("named port %q is not supported yet; give "+
					"the number instead", p.Port.StrVal),
			})
			continue
		}
		proto := corev1.ProtocolTCP
		if p.Protocol != nil {
			proto = *p.Protocol
		}
		if proto == corev1.ProtocolSCTP {
			refused = append(refused, Refusal{
				Field:  at + ".protocol",
				Reason: "SCTP is not supported by this platform",
			})
			continue
		}
		port := Port{Protocol: proto}
		if p.Port != nil {
			port.Min, port.Max = p.Port.IntVal, p.Port.IntVal
		}
		if p.EndPort != nil {
			port.Max = *p.EndPort
		}
		rule.Ports = append(rule.Ports, port)
	}

	// Every peer was refused: there is nothing left to allow, and emitting a
	// rule with no peers would mean "from anywhere" -- the widening this whole
	// package exists to prevent.
	if len(rule.Peers) == 0 {
		return nil, refused
	}
	// Every port was refused, but ports were asked for. Same reasoning: a rule
	// with no ports means every port.
	if len(ports) > 0 && len(rule.Ports) == 0 {
		return nil, refused
	}
	return rule, refused
}

func peerField(dir Direction) string {
	if dir == Ingress {
		return "from"
	}
	return "to"
}

// SelectorKey names a pod set, so that two rules asking for the same set share
// one address group instead of each maintaining its own.
//
// ⚠️ A nil namespaceSelector does NOT mean "every namespace" -- it means the
// policy's own namespace, and that is the difference between an app talking to
// its own front end and an app talking to every front end in the tenant. An
// empty (non-nil) selector is what means every namespace.
func SelectorKey(policyNamespace string, nsSel, podSel *metav1.LabelSelector) (string, error) {
	scope := "ns=" + policyNamespace
	if nsSel != nil {
		s, err := metav1.LabelSelectorAsSelector(nsSel)
		if err != nil {
			return "", fmt.Errorf("namespace selector: %w", err)
		}
		scope = "nsSelector=" + s.String()
	}
	pods := "all"
	if podSel != nil {
		s, err := metav1.LabelSelectorAsSelector(podSel)
		if err != nil {
			return "", fmt.Errorf("pod selector: %w", err)
		}
		pods = s.String()
	}
	return scope + ";pods=" + pods, nil
}

// resolvePeer turns a peer's two selectors into something that can list pods.
func resolvePeer(policyNamespace string, nsSel, podSel *metav1.LabelSelector) (PeerSelector, error) {
	out := PeerSelector{Pods: labels.Everything()}
	if podSel != nil {
		s, err := metav1.LabelSelectorAsSelector(podSel)
		if err != nil {
			return out, err
		}
		out.Pods = s
	}
	if nsSel == nil {
		// ⚠️ The policy's own namespace, not every namespace.
		out.Namespace = policyNamespace
		return out, nil
	}
	s, err := metav1.LabelSelectorAsSelector(nsSel)
	if err != nil {
		return out, err
	}
	out.Namespaces = s
	return out, nil
}

// IsolationOf reports which directions a pod is put into default-deny by the
// policies given, and which policies did it.
//
// This is the whole of what the first increment enforces on its own, and it is
// the expensive half to get wrong in either direction: a pod isolated when it
// should not be loses traffic visibly, and a pod left open when it should be
// isolated is the silent failure this replaces.
func IsolationOf(pod *corev1.Pod, policies []*networkingv1.NetworkPolicy) (map[Direction][]string, error) {
	by := map[Direction][]string{}
	for _, p := range policies {
		if p.Namespace != pod.Namespace {
			continue
		}
		t, err := Translate(p)
		if err != nil {
			return nil, err
		}
		if !t.Subject.Matches(labels.Set(pod.Labels)) {
			continue
		}
		for dir, yes := range t.Isolates {
			if yes {
				by[dir] = append(by[dir], p.Name)
			}
		}
	}
	for dir := range by {
		sort.Strings(by[dir])
	}
	return by, nil
}

// String renders a refusal for an event message.
func (r Refusal) String() string { return r.Field + ": " + r.Reason }

// RefusalMessage joins refusals into one line for a Kubernetes event.
func RefusalMessage(refused []Refusal) string {
	parts := make([]string, 0, len(refused))
	for _, r := range refused {
		parts = append(parts, r.String())
	}
	return strings.Join(parts, "; ")
}
