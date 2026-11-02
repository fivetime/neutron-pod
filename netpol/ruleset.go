package netpol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// SGRule is one Neutron security group rule: the unit Neutron actually stores.
//
// ⚠️ One Kubernetes rule is many of these. Neutron permits exactly one remote
// and one port range per rule, so a policy rule with F peers and P ports
// becomes F × P × (address families) rules. ovn-kubernetes folds all of that
// into a single ACL match; that folding is not reachable through this API, and
// pretending otherwise is how a rule set quietly comes out wrong.
type SGRule struct {
	Direction Direction
	EtherType string // IPv4 or IPv6
	Protocol  string // empty means every protocol
	PortMin   int32
	PortMax   int32
	// RemoteCIDR and RemoteAddressGroup are exclusive; exactly one is set.
	RemoteCIDR         string
	RemoteAddressGroup string // the peer's selector key, not yet an id
}

// RuleSet is everything the policies selecting one pod allow it to do.
type RuleSet struct {
	Rules []SGRule
	// Peers is every pod set this set references, keyed by selector key, so
	// the caller can build the address groups the rules point at.
	Peers map[string]PeerSelector
}

// Expand turns translated policy rules into the rules Neutron stores.
func Expand(rules []Rule) RuleSet {
	var out RuleSet
	seen := map[string]struct{}{}
	peers := map[string]PeerSelector{}

	for _, r := range rules {
		ports := r.Ports
		if len(ports) == 0 {
			// No ports named means every port, which Neutron says by leaving
			// the protocol and range unset.
			ports = []Port{{}}
		}
		for _, peer := range r.Peers {
			for _, port := range ports {
				for _, family := range familiesFor(peer) {
					rule := SGRule{
						Direction: r.Direction,
						EtherType: family,
						Protocol:  protocolOf(port),
						PortMin:   port.Min,
						PortMax:   port.Max,
					}
					if peer.CIDR != "" {
						// ⚠️ A v4 CIDR cannot be the remote of a v6 rule and
						// the reverse; Neutron rejects the pair, and a rule
						// rejected in the middle of writing a set leaves the
						// pod holding half a policy.
						if family != familyOfCIDR(peer.CIDR) {
							continue
						}
						rule.RemoteCIDR = peer.CIDR
					} else {
						rule.RemoteAddressGroup = peer.SelectorKey
						peers[peer.SelectorKey] = peer.Selector
					}
					key := rule.key()
					if _, dup := seen[key]; dup {
						// Two policies allowing the same thing is ordinary --
						// they are additive -- and Neutron refuses a duplicate
						// rule, so the set has to be deduplicated here rather
						// than discovered at write time.
						continue
					}
					seen[key] = struct{}{}
					out.Rules = append(out.Rules, rule)
				}
			}
		}
	}

	out.Peers = peers
	sort.Slice(out.Rules, func(i, j int) bool {
		return out.Rules[i].key() < out.Rules[j].key()
	})
	return out
}

// familiesFor is which address families a peer needs rules for. A CIDR needs
// only its own; a pod set needs both, because a pod can have either.
func familiesFor(p Peer) []string {
	if p.CIDR != "" {
		return []string{familyOfCIDR(p.CIDR)}
	}
	return []string{"IPv4", "IPv6"}
}

func familyOfCIDR(cidr string) string {
	if strings.Contains(cidr, ":") {
		return "IPv6"
	}
	return "IPv4"
}

func protocolOf(p Port) string {
	if p.Protocol == "" {
		return ""
	}
	return strings.ToLower(string(p.Protocol))
}

func (r SGRule) key() string {
	return fmt.Sprintf("%s|%s|%s|%d|%d|%s|%s", r.Direction, r.EtherType,
		r.Protocol, r.PortMin, r.PortMax, r.RemoteCIDR, r.RemoteAddressGroup)
}

// GroupNameFor is the security group one policy's allowances live in.
//
// Named after the policy, not after its contents. ⚠️ A content hash looks
// tidier and is worse in the one dimension that matters: a security group
// OBJECT created or deleted makes ovn-northd rebuild every port group in the
// cloud, so the count must follow something that changes rarely. Named by
// content, editing a policy mints a new group and orphans the old one, and a
// pod selected by a new combination of policies mints another -- the number of
// groups then follows the number of distinct COMBINATIONS, which is
// exponential in the number of policies. Named by policy it is exactly one
// group per policy, editing one rewrites rules inside it, and a pod's changing
// membership is only a port update.
func (n Naming) PolicyGroup(namespace, name string) string {
	h := sha256.Sum256([]byte(namespace + "/" + name))
	return n.policyPrefix() + hex.EncodeToString(h[:])[:16]
}

// Empty reports whether this set allows nothing at all.
func (s RuleSet) Empty() bool { return len(s.Rules) == 0 }

// AddressGroupName is what a peer set is called in Neutron.
//
// ⚠️ Hashed rather than spelled out. A selector key carries label expressions
// that can be longer than Neutron's 255-character name limit, and a name
// truncated to fit is a name two different selectors can share -- which would
// have one policy's peers silently answering for another's.
func (n Naming) PeerGroup(selectorKey string) string {
	h := sha256.Sum256([]byte(selectorKey))
	return n.peerPrefix() + hex.EncodeToString(h[:])[:16]
}

// PolicyRules is what one policy allows: its own rules, in the directions that
// same policy isolates.
//
// ⚠️ Its own directions, not the pod's. Kubernetes ignores the rules of a
// direction a policy does not declare in policyTypes -- an `egress:` section
// under `policyTypes: [Ingress]` has no effect at all. Deciding this from the
// union across every policy selecting the pod, which is what a per-pod rule set
// has to do, brings those inert rules back to life as soon as some other policy
// isolates that direction. Per policy the question does not arise.
func PolicyRules(t *Translated) RuleSet {
	var keep []Rule
	for _, r := range t.Rules {
		if t.Isolates[r.Direction] {
			keep = append(keep, r)
		}
	}
	return Expand(keep)
}
