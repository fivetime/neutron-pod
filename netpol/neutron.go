package netpol

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/addressgroups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/pagination"
	"golang.org/x/time/rate"
)

// The two groups that carry the baseline. They exist for the life of the
// tenant and never change, which is deliberate: creating or deleting a
// security group OBJECT makes ovn-northd rebuild every port group in the
// cloud -- every other tenant's, nova's, Octavia's. Adding
// rules to an existing group does not.
const (
	allowIngressName = "allow-ingress"
	allowEgressName  = "allow-egress"

	// DenyAll exists so that a port's group list is never empty, and allows
	// nothing but the tenant's resolver (see SyncResolvers).
	//
	// ⚠️ Empty and absent are opposite meanings and one API cannot tell them
	// apart. Neutron injects the project's default group -- which is
	// permissive -- when a port names no groups, so a pod isolated in both
	// directions, whose correct group list is empty, would come up reachable
	// by everything. Naming a group that allows next to nothing says deny-all
	// in a way that survives the round trip.
	denyAllName = "deny-all"
)

// managedBy marks what this controller owns, so a sweep can tell our objects
// from a tenant's own and from another tool's.
func (n Naming) managedBy() string { return n.Product + "-networkpolicy" }

// Neutron is the part of the network API this package uses.
type Neutron struct {
	// peerSets serialises finding-or-creating an address group.
	peerSets sync.Mutex

	Client *gophercloud.ServiceClient

	// Naming says whose groups these are. Required: the sweep deletes by these
	// names, so two controllers in one project must not share them.
	Naming Naming

	// Log, if set, receives what a tenant cannot act on but an operator can.
	Log func(ctx context.Context, msg string, keysAndValues ...any)

	// Churn paces the creation and deletion of security groups. Each one
	// makes ovn-northd recompute every logical flow in the region -- measured
	// once per group, whether sent in one bulk request, back to back, or a
	// second apart; batching moves the cost and never merges it -- and the
	// recomputes do not overlap, they queue. At a hundred thousand flows a
	// wave of tenants creating a dozen groups each keeps northd busy for
	// hours. Nil paces nothing. Shared by every tenant one process serves,
	// because northd's time is shared by every tenant in the region.
	Churn *rate.Limiter

	// Pool turns released groups into a pool for reuse instead of deleting
	// them. ⚠️ Off unless the region's ovn-northd is 25.09 or newer. Before
	// that release every ACL change is a full recompute too (measured on
	// 24.03: a rule added +1, a rule deleted +1, a rename +0), and a release
	// deletes a policy's rules one by one -- N recomputes where deleting the
	// group cost one. The pool is a loss there, not a saving. From 25.09
	// ACL changes on an existing port group are handled incrementally
	// (northd_handle_pgs_acl_changes), which is the premise this rests on.
	Pool bool

	// PoolCap bounds how many released groups a project keeps for reuse,
	// which is also the number of full recomputes a tenant can ever cause:
	// a group pays its recompute once, at creation, and never again while it
	// is reused. Zero means the default.
	PoolCap int
}

// freePrefix names a released group waiting to be claimed. Not the policy
// prefix, so the sweep's "whose policy is gone" walk never sees it, and not a
// name any policy can hash to.
func (n Naming) freePrefix() string { return n.Prefix + "-free-" }

// freeDescription is what a released group says about itself. policyOf reads ""
// out of it, which is right: it belongs to no policy.
func (n Naming) freeDescription() string {
	return n.Product + ": free [" + n.managedBy() + "]"
}

const defaultPoolCap = 16

// EnsureBaseline makes sure the two allow-everything groups exist, and returns
// their ids.
//
// ⚠️ Two groups, not one. A Neutron security group has no direction of its own
// -- direction lives on the rule -- while Kubernetes isolates a pod per
// direction. One combined group, detached from a pod whose policy names only
// Ingress, would take that pod's egress with it.
func (n *Neutron) EnsureBaseline(ctx context.Context) (ingressID, egressID string, err error) {
	if _, err := n.EnsureDenyAll(ctx); err != nil {
		return "", "", err
	}
	ingressID, err = n.ensureGroup(ctx, n.Naming.AllowIngress(),
		n.Naming.Product+": a pod no policy has isolated for ingress")
	if err != nil {
		return "", "", err
	}
	egressID, err = n.ensureGroup(ctx, n.Naming.AllowEgress(),
		n.Naming.Product+": a pod no policy has isolated for egress")
	if err != nil {
		return "", "", err
	}
	if err := n.ensureBaselineRules(ctx, ingressID, "ingress"); err != nil {
		return "", "", err
	}
	if err := n.ensureBaselineRules(ctx, egressID, "egress"); err != nil {
		return "", "", err
	}
	return ingressID, egressID, nil
}

// ensureBaselineRules opens one direction completely, for both address
// families, and closes the other.
//
// The opening is needed because Neutron's baseline is the opposite of
// Kubernetes': a port carrying security groups is denied whatever no rule
// allows, while a pod no policy selects must be able to talk. So "no policy
// applies" has to be stated rather than left unsaid.
//
// ⚠️ The closing is needed because Neutron adds two egress allow-all rules to
// every security group it creates, which nobody asked for and which the API
// does not mention at creation time. Left in place they make the ingress group
// allow all egress as well -- so detaching the egress group from an isolated
// pod changes nothing, and egress policy is enforced in appearance only. That
// is the failure this whole package exists to remove, so a group here carries
// rules for its own direction and nothing else.
func (n *Neutron) ensureBaselineRules(ctx context.Context, groupID, direction string) error {
	want := []rules.CreateOpts{
		{SecGroupID: groupID, Direction: rules.RuleDirection(direction),
			EtherType: rules.EtherType4, RemoteIPPrefix: "0.0.0.0/0"},
		{SecGroupID: groupID, Direction: rules.RuleDirection(direction),
			EtherType: rules.EtherType6, RemoteIPPrefix: "::/0"},
	}
	have, err := n.rulesOf(ctx, groupID)
	if err != nil {
		return err
	}
	for _, w := range want {
		if hasRule(have, w) {
			continue
		}
		if _, err := rules.Create(ctx, n.Client, w).Extract(); err != nil {
			// Another process of the same tenant may have written it between
			// the read and the write, and Neutron reads a rule with no remote
			// prefix as the same rule as one naming the whole address space.
			// Either way the state we wanted is the state that exists.
			if !isConflict(err) {
				return fmt.Errorf("opening %s on %s: %w", direction, groupID, err)
			}
		}
	}
	for _, r := range have {
		if r.Direction == direction {
			continue
		}
		if err := rules.Delete(ctx, n.Client, r.ID).ExtractErr(); err != nil && !isGone(err) {
			return fmt.Errorf("removing a %s rule from the %s group: %w",
				r.Direction, direction, err)
		}
	}
	return nil
}

// EnsureDenyAll makes sure the anchor group exists and allows nothing it should
// not.
//
// ⚠️ Emptying it is the work. Neutron adds two egress allow-all rules to every
// group it creates, so a group made to allow nothing arrives allowing all
// egress -- and a pod isolated in both directions would keep talking outward
// while appearing to be fully isolated.
//
// Resolver rules are left in place. This runs on every start, and removing them
// here would cut every isolated pod off from DNS until SyncResolvers next ran.
func (n *Neutron) EnsureDenyAll(ctx context.Context) (string, error) {
	id, err := n.ensureGroup(ctx, n.Naming.DenyAll(),
		n.Naming.Product+": allows only the tenant's resolver; carried so a port's group list is never empty")
	if err != nil {
		return "", err
	}
	have, err := n.rulesOf(ctx, id)
	if err != nil {
		return "", err
	}
	for _, r := range have {
		if isResolverRule(r) {
			continue
		}
		if err := rules.Delete(ctx, n.Client, r.ID).ExtractErr(); err != nil && !isGone(err) {
			return "", fmt.Errorf("emptying the deny-all group: %w", err)
		}
	}
	return id, nil
}

// SyncResolvers makes the anchor group allow DNS to exactly these addresses.
//
// A tenant's default-deny must not take away its own resolver. The anchor is the place for it because every port carries
// the anchor whatever selects it. The rule names the resolver's Service address
// because that is what a security group sees: it judges a packet before the load
// balancer rewrites its destination, which is also why a policy
// allowing the resolver's pods does not help.
//
// New rules go in before old ones come out, so moving the resolver to another
// address never leaves a moment with neither.
//
// ⚠️ Given the anchor rather than ensuring it. Neutron does not refuse a second
// group of the same name, so a find-then-create running beside EnsureBaseline can
// make two anchors, and rules written into one do nothing for ports on the other:
// DNS silently stays cut off. Seen live.
func (n *Neutron) SyncResolvers(ctx context.Context, id string, addrs []string) error {
	want := make([]rules.CreateOpts, 0, 2*len(addrs))
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return fmt.Errorf("resolver address %q: %w", a, err)
		}
		ether := rules.EtherType4
		if ip.Is6() {
			ether = rules.EtherType6
		}
		prefix := netip.PrefixFrom(ip, ip.BitLen()).String()
		for _, proto := range []rules.RuleProtocol{rules.ProtocolUDP, rules.ProtocolTCP} {
			want = append(want, rules.CreateOpts{
				SecGroupID: id, Direction: rules.DirEgress, EtherType: ether, Protocol: proto,
				PortRangeMin: 53, PortRangeMax: 53, RemoteIPPrefix: prefix,
			})
		}
	}
	have, err := n.rulesOf(ctx, id)
	if err != nil {
		return err
	}
	for _, w := range want {
		if hasRule(have, w) {
			continue
		}
		if _, err := rules.Create(ctx, n.Client, w).Extract(); err != nil && !isConflict(err) {
			return fmt.Errorf("allowing the resolver at %s: %w", w.RemoteIPPrefix, err)
		}
	}
	for _, r := range have {
		if !isResolverRule(r) || wantedResolver(want, r) {
			continue
		}
		if err := rules.Delete(ctx, n.Client, r.ID).ExtractErr(); err != nil && !isGone(err) {
			return fmt.Errorf("removing the old resolver %s: %w", r.RemoteIPPrefix, err)
		}
	}
	return nil
}

// isResolverRule recognises what SyncResolvers writes: outbound DNS to one host.
// Neutron's default rules have no port and no single-host remote, so nothing it
// adds by itself can pass for one.
func isResolverRule(r rules.SecGroupRule) bool {
	if r.Direction != string(rules.DirEgress) || r.PortRangeMin != 53 || r.PortRangeMax != 53 ||
		(r.Protocol != string(rules.ProtocolUDP) && r.Protocol != string(rules.ProtocolTCP)) {
		return false
	}
	prefix, err := netip.ParsePrefix(r.RemoteIPPrefix)
	return err == nil && prefix.IsSingleIP()
}

func wantedResolver(want []rules.CreateOpts, r rules.SecGroupRule) bool {
	for _, w := range want {
		if hasRule([]rules.SecGroupRule{r}, w) {
			return true
		}
	}
	return false
}

// findGroup returns a security group's id and description, or "" when the
// project has none by that name.
func (n *Neutron) findGroup(ctx context.Context, name string) (string, string, error) {
	var found, description string
	err := groups.List(n.Client, groups.ListOpts{Name: name}).EachPage(ctx,
		func(_ context.Context, page pagination.Page) (bool, error) {
			list, err := groups.ExtractGroups(page)
			if err != nil {
				return false, err
			}
			// Neutron allows two groups of one name. Every reader settles on the
			// smallest id, so a port and the rules meant for it cannot disagree.
			for _, g := range list {
				if found == "" || g.ID < found {
					found, description = g.ID, g.Description
				}
			}
			return true, nil
		})
	if err != nil {
		return "", "", fmt.Errorf("looking for security group %s: %w", name, err)
	}
	return found, description, nil
}

func (n *Neutron) ensureGroup(ctx context.Context, name, description string) (string, error) {
	found, have, err := n.findGroup(ctx, name)
	if err != nil {
		return "", err
	}
	if found != "" {
		if have != description {
			// ⚠️ Rewritten when it differs, because the description is not
			// decoration: the sweep reads which policy a group belongs to out
			// of it, and a group left carrying an older wording is one the
			// sweep can never identify and so can never collect.
			if _, err := groups.Update(ctx, n.Client, found,
				groups.UpdateOpts{Description: &description}).Extract(); err != nil {
				return "", fmt.Errorf("correcting the description of %s: %w", name, err)
			}
		}
		return found, nil
	}
	// A released group first: renaming one is a change northd handles
	// incrementally, where creating one recomputes the region.
	if n.Pool {
		if id, err := n.claimFree(ctx, name, description); err != nil || id != "" {
			return id, err
		}
	}
	if err := n.churn(ctx); err != nil {
		return "", err
	}
	g, err := groups.Create(ctx, n.Client, groups.CreateOpts{
		// ⚠️ Exactly the description, nothing appended: the sweep reads the policy
		// back out of it, and a group created with a suffix was unidentifiable
		// until a later ensureGroup rewrote it. A policy deleted before that left
		// a group the sweep could never collect.
		Name: name, Description: description,
	}).Extract()
	if err != nil {
		return "", fmt.Errorf("creating security group %s: %w", name, err)
	}
	return g.ID, nil
}

// churn takes one token from the region's budget of full recomputes.
func (n *Neutron) churn(ctx context.Context) error {
	if n.Churn == nil {
		return nil
	}
	return n.Churn.Wait(ctx)
}

func (n *Neutron) poolCap() int {
	if n.PoolCap > 0 {
		return n.PoolCap
	}
	return defaultPoolCap
}

// claimFree takes a released group for a policy, or returns "" when there is
// none to take.
//
// The claim is a rename conditioned on the group's revision number, which
// Neutron bumps on any change to the group or its rules. Two claimants of one
// group therefore get one success and one 412; the loser moves to the next.
// ⚠️ Winning proves nobody touched the group since it was listed, not that it
// was released correctly, so the winner checks that before writing a rule
// into it: a group still on a port, or still holding rules, would hand that
// port whatever this policy allows. Such a group is given back and never
// used, and a fresh one is created instead -- a recompute is cheaper than a
// wrong allow.
func (n *Neutron) claimFree(ctx context.Context, name, description string) (string, error) {
	free, err := n.freeGroups(ctx)
	if err != nil {
		return "", err
	}
	for _, g := range free {
		if err := n.casRename(ctx, g.ID, g.RevisionNumber, name, description); err != nil {
			if isPreconditionFailed(err) {
				continue // claimed by someone else between the list and now
			}
			return "", fmt.Errorf("claiming free group %s: %w", g.ID, err)
		}
		clean, err := n.isClean(ctx, g.ID)
		if err != nil {
			return "", err
		}
		if !clean {
			n.logf(ctx, g.ID, "a free security group still held rules or ports; "+
				"releasing it again and not using it")
			// Unconditional: this process holds the claim.
			_, _ = groups.Update(ctx, n.Client, g.ID, groups.UpdateOpts{
				Name: n.Naming.freePrefix() + short(g.ID), Description: strPtr(n.Naming.freeDescription()),
			}).Extract()
			continue
		}
		return g.ID, nil
	}
	return "", nil
}

// freeGroups lists the released groups of this project, oldest name first so
// every claimant tries them in the same order and the race is decided by the
// revision check, not by luck.
func (n *Neutron) freeGroups(ctx context.Context) ([]groups.SecGroup, error) {
	var out []groups.SecGroup
	err := groups.List(n.Client, groups.ListOpts{}).EachPage(ctx,
		func(_ context.Context, page pagination.Page) (bool, error) {
			list, err := groups.ExtractGroups(page)
			if err != nil {
				return false, err
			}
			for _, g := range list {
				if strings.HasPrefix(g.Name, n.Naming.freePrefix()) {
					out = append(out, g)
				}
			}
			return true, nil
		})
	if err != nil {
		return nil, fmt.Errorf("listing free security groups: %w", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// casRename changes a group's name and description only if its revision is
// still the one the caller read. Neutron's revision-if-match extension turns
// a stale revision into a 412 rather than a lost update.
func (n *Neutron) casRename(ctx context.Context, id string, revision int, name, description string) error {
	body := map[string]any{"security_group": map[string]any{
		"name": name, "description": description,
	}}
	_, err := n.Client.Put(ctx, n.Client.ServiceURL("security-groups", id), body, nil,
		&gophercloud.RequestOpts{
			MoreHeaders: map[string]string{"If-Match": fmt.Sprintf("revision_number=%d", revision)},
			OkCodes:     []int{200},
		})
	return err
}

// isClean is the invariant a free group must satisfy before it carries a
// policy's rules: nothing in it, and nothing on it.
func (n *Neutron) isClean(ctx context.Context, id string) (bool, error) {
	have, err := n.rulesOf(ctx, id)
	if err != nil {
		return false, err
	}
	if len(have) > 0 {
		return false, nil
	}
	using, err := n.portsUsing(ctx, id)
	if err != nil {
		return false, err
	}
	return using == 0, nil
}

// portsUsing counts the ports that carry a group.
func (n *Neutron) portsUsing(ctx context.Context, id string) (int, error) {
	count := 0
	err := ports.List(n.Client, ports.ListOpts{SecurityGroups: []string{id}}).EachPage(ctx,
		func(_ context.Context, page pagination.Page) (bool, error) {
			list, err := ports.ExtractPorts(page)
			if err != nil {
				return false, err
			}
			count += len(list)
			return count == 0, nil
		})
	if err != nil {
		return 0, fmt.Errorf("listing ports carrying %s: %w", id, err)
	}
	return count, nil
}

// release turns a group whose policy is gone back into a free one: empties
// it, then renames it -- in that order, so a group that reads as free never
// holds a rule. It reports whether the group was released this time.
//
// Not touched while a port still carries it: the pods of a deleted policy
// are re-reconciled to drop its group, and until they have, the group must
// keep its rules -- emptying it first would change what those pods allow
// before their ports are rewritten. The sweep comes round again.
func (n *Neutron) release(ctx context.Context, g groups.SecGroup) (bool, error) {
	using, err := n.portsUsing(ctx, g.ID)
	if err != nil {
		return false, err
	}
	if using > 0 {
		return false, nil
	}
	have, err := n.rulesOf(ctx, g.ID)
	if err != nil {
		return false, err
	}
	for _, r := range have {
		if err := rules.Delete(ctx, n.Client, r.ID).ExtractErr(); err != nil && !isGone(err) {
			return false, fmt.Errorf("emptying %s: %w", g.Name, err)
		}
	}
	// The rules just removed bumped the revision; read it back before the
	// conditional rename, or the rename refuses its own work.
	fresh, err := groups.Get(ctx, n.Client, g.ID).Extract()
	if err != nil {
		return false, fmt.Errorf("re-reading %s before release: %w", g.Name, err)
	}
	if err := n.casRename(ctx, g.ID, fresh.RevisionNumber, n.Naming.freePrefix()+short(g.ID), n.Naming.freeDescription()); err != nil {
		if isPreconditionFailed(err) {
			// Something changed a group whose policy is gone and which no
			// port carries. That is not a state this design produces.
			n.logf(ctx, g.ID, "a group changed under the sweep while being released; leaving it for the next round")
			return false, nil
		}
		return false, fmt.Errorf("releasing %s: %w", g.Name, err)
	}
	return true, nil
}

// trimPool deletes released groups beyond the cap, paced like any other
// deletion: each costs the region a recompute, spent here only to give
// quota back.
func (n *Neutron) trimPool(ctx context.Context, free []groups.SecGroup) (int, error) {
	excess := len(free) - n.poolCap()
	if excess <= 0 {
		return 0, nil
	}
	removed := 0
	// Newest names last; trim from the end so the oldest, best-known free
	// groups stay.
	for i := len(free) - 1; i >= 0 && removed < excess; i-- {
		if err := n.churn(ctx); err != nil {
			return removed, err
		}
		if err := groups.Delete(ctx, n.Client, free[i].ID).ExtractErr(); err != nil {
			if isConflict(err) || isGone(err) {
				continue
			}
			return removed, fmt.Errorf("trimming free group %s: %w", free[i].Name, err)
		}
		removed++
	}
	return removed, nil
}

func (n *Neutron) logf(ctx context.Context, group, msg string) {
	if n.Log != nil {
		n.Log(ctx, msg, "group", group)
	}
}

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func strPtr(s string) *string { return &s }

// isPreconditionFailed is Neutron refusing a conditional update because the
// revision moved: the caller lost a race, which is an answer, not an error.
func isPreconditionFailed(err error) bool {
	var code gophercloud.ErrUnexpectedResponseCode
	return errors.As(err, &code) && code.Actual == 412
}

func (n *Neutron) rulesOf(ctx context.Context, groupID string) ([]rules.SecGroupRule, error) {
	var out []rules.SecGroupRule
	err := rules.List(n.Client, rules.ListOpts{SecGroupID: groupID}).EachPage(ctx,
		func(_ context.Context, page pagination.Page) (bool, error) {
			list, err := rules.ExtractRules(page)
			if err != nil {
				return false, err
			}
			out = append(out, list...)
			return true, nil
		})
	return out, err
}

// EnsureRuleSet makes a security group hold exactly these rules.
//
// The peers map turns a selector key into the address group id the rule refers
// to; every key in the set must be present, because a rule naming a group that
// does not exist is refused and leaves the set half written.
func (n *Neutron) EnsureRuleSet(ctx context.Context, name, policyRef string, set RuleSet, peers map[string]string) (string, error) {
	// ⚠️ The policy this belongs to goes in the description, because the name
	// is a hash and nothing can be read back out of it. Without it the sweep
	// cannot tell a group whose policy is gone from one belonging to a
	// namespace this process does not serve -- and it would have to choose
	// between leaking groups forever and deleting another process's.
	id, err := n.ensureGroup(ctx, name,
		n.Naming.Product+": what NetworkPolicy "+policyRef+" allows")
	if err != nil {
		return "", err
	}
	have, err := n.rulesOf(ctx, id)
	if err != nil {
		return "", err
	}

	want := make([]rules.CreateOpts, 0, len(set.Rules))
	for _, r := range set.Rules {
		opts := rules.CreateOpts{
			SecGroupID:   id,
			Direction:    rules.RuleDirection(r.Direction),
			EtherType:    rules.RuleEtherType(r.EtherType),
			Protocol:     rules.RuleProtocol(r.Protocol),
			PortRangeMin: int(r.PortMin),
			PortRangeMax: int(r.PortMax),
		}
		switch {
		case r.RemoteCIDR != "":
			opts.RemoteIPPrefix = r.RemoteCIDR
		case r.RemoteAddressGroup != "":
			gid, ok := peers[r.RemoteAddressGroup]
			if !ok || gid == "" {
				return "", fmt.Errorf(
					"the peer set %q has no address group yet", r.RemoteAddressGroup)
			}
			opts.RemoteAddressGroupID = gid
		}
		want = append(want, opts)
	}

	if err := n.writeRules(ctx, name, id, want, have); err != nil {
		return "", err
	}
	// ⚠️ And remove what is no longer wanted, including the two egress
	// allow-all rules Neutron adds to every group it creates. A rule set that
	// only ever grows is a rule set that keeps allowing what a tenant has
	// already taken out of its policy.
	for _, h := range have {
		if wantsRule(want, h) {
			continue
		}
		if err := rules.Delete(ctx, n.Client, h.ID).ExtractErr(); err != nil && !isGone(err) {
			return "", fmt.Errorf("removing a stale rule from %s: %w", name, err)
		}
	}
	return id, nil
}

// writeRules adds the rules a group lacks, in one request.
//
// A policy of P peers and F ports is P×F×2 rules, and written one at a time
// that was as many round trips to Neutron and as many transactions in the OVN
// northbound database -- a hundred for a modest policy, and the policy's
// sync time was the sum of them. Neutron takes them all in one request and
// writes them in one transaction, which is one round trip and one NB commit
// whatever the size of the policy.
//
// ⚠️ A conflict fails the whole batch. Neutron checks every rule against the
// group before writing any of them, so one rule that another writer added
// since `have` was read refuses all of them at once. That is the case the
// per-rule path handled by tolerating a conflict on each rule; it is kept
// as the fallback, entered only after re-reading the group, so the common
// case stays one request and the race stays correct.
func (n *Neutron) writeRules(ctx context.Context, name, id string, want []rules.CreateOpts, have []rules.SecGroupRule) error {
	missing := make([]rules.CreateOpts, 0, len(want))
	for _, w := range want {
		if !hasRule(have, w) {
			missing = append(missing, w)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if len(missing) > 1 {
		_, err := rules.CreateBulk(ctx, n.Client, missing).Extract()
		if err == nil {
			return nil
		}
		if !isConflict(err) {
			return fmt.Errorf("writing %d rules into %s: %w", len(missing), name, err)
		}
		if have, err = n.rulesOf(ctx, id); err != nil {
			return err
		}
	}
	for _, w := range missing {
		if hasRule(have, w) {
			continue
		}
		if _, err := rules.Create(ctx, n.Client, w).Extract(); err != nil && !isConflict(err) {
			return fmt.Errorf("writing a rule into %s: %w", name, err)
		}
	}
	return nil
}

// policyOf reads back which policy a group was made for, or "" if it was not
// made by this.
func (n Naming) policyOf(description string) string {
	prefix := n.Product + ": what NetworkPolicy "
	const suffix = " allows"
	if !strings.HasPrefix(description, prefix) || !strings.HasSuffix(description, suffix) {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(description, prefix), suffix)
}

// Sweep removes the groups no live policy needs any more.
//
// ⚠️ Deliberately not driven by policy deletion. Deleting a security group
// object makes ovn-northd rebuild every port group in the cloud -- other
// tenants', nova's, Octavia's -- so the cost of removing one is paid by
// everybody. Doing it on a slow timer, in a batch, spends that once for
// whatever has accumulated instead of once per policy a tenant edits.
//
// live is the set of policy references ("namespace/name") that still exist.
// A group is removed only when this process serves its namespace and the
// policy is gone: a group whose policy exists but whose pods have all left is
// kept, because the pods will come back and rebuilding it costs more than
// leaving it.
func (n *Neutron) Sweep(ctx context.Context, live map[string]bool, serves func(string) bool) (removed int, err error) {
	var all []groups.SecGroup
	err = groups.List(n.Client, groups.ListOpts{}).EachPage(ctx,
		func(_ context.Context, page pagination.Page) (bool, error) {
			got, err := groups.ExtractGroups(page)
			if err != nil {
				return false, err
			}
			all = append(all, got...)
			return true, nil
		})
	if err != nil {
		return 0, fmt.Errorf("listing security groups: %w", err)
	}

	// ⚠️ Decide what goes before working out what is still referenced. A peer
	// set pointed at only by a group that is about to be deleted is not
	// referenced by anything, and computing that from the list as read leaves
	// it behind for a whole sweep interval -- correct in the end, and a
	// needlessly long end.
	doomed := map[string]struct{}{}
	for _, g := range all {
		if !strings.HasPrefix(g.Name, n.Naming.policyPrefix()) {
			continue
		}
		ref := n.Naming.policyOf(g.Description)
		if ref == "" {
			// Not identifiable, so not ours to judge: it may belong to a
			// namespace this process does not serve.
			continue
		}
		namespace, _, ok := strings.Cut(ref, "/")
		if !ok || !serves(namespace) || live[ref] {
			continue
		}
		doomed[g.ID] = struct{}{}
	}

	// Which peer sets the survivors still point at -- including groups
	// belonging to namespaces this process does not serve, whose rules are
	// just as real.
	referenced := map[string]struct{}{}
	for _, g := range all {
		if !strings.HasPrefix(g.Name, n.Naming.policyPrefix()) {
			continue
		}
		if _, going := doomed[g.ID]; going {
			continue
		}
		for _, r := range g.Rules {
			if r.RemoteAddressGroupID != "" {
				referenced[r.RemoteAddressGroupID] = struct{}{}
			}
		}
	}

	// Released, not deleted: deleting a security group makes northd
	// recompute the region, renaming one does not, and a released group is
	// reused by the next policy at the price of a rename. A group still on
	// a port is left for the next round, as before.
	var free []groups.SecGroup
	for _, g := range all {
		if strings.HasPrefix(g.Name, n.Naming.freePrefix()) {
			free = append(free, g)
			continue
		}
		if _, going := doomed[g.ID]; !going {
			continue
		}
		if !n.Pool {
			// Deleting is the right call below OVN 25.09: one recompute,
			// against one per rule for a release.
			if err := n.churn(ctx); err != nil {
				return removed, err
			}
			if err := groups.Delete(ctx, n.Client, g.ID).ExtractErr(); err != nil {
				if isConflict(err) || isGone(err) {
					// Still on a port somewhere: a pod this process has
					// not finished reconciling. It will come round again.
					continue
				}
				return removed, fmt.Errorf("removing %s: %w", g.Name, err)
			}
			removed++
			continue
		}
		released, err := n.release(ctx, g)
		if err != nil {
			return removed, err
		}
		if released {
			removed++
			free = append(free, g)
		}
	}
	if n.Pool {
		sort.Slice(free, func(i, j int) bool { return free[i].Name < free[j].Name })
		if trimmed, err := n.trimPool(ctx, free); err != nil {
			return removed + trimmed, err
		}
	}

	// Peer sets are named by prefix and referenced by id, so an unreferenced
	// one is unreferenced for everybody.
	var peers []addressgroups.AddressGroup
	err = addressgroups.List(n.Client, addressgroups.ListOpts{}).EachPage(ctx,
		func(_ context.Context, page pagination.Page) (bool, error) {
			got, err := addressgroups.ExtractGroups(page)
			if err != nil {
				return false, err
			}
			peers = append(peers, got...)
			return true, nil
		})
	if err != nil {
		return removed, fmt.Errorf("listing address groups: %w", err)
	}
	for _, p := range peers {
		if !strings.HasPrefix(p.Name, n.Naming.peerPrefix()) {
			continue
		}
		if _, still := referenced[p.ID]; still {
			continue
		}
		if err := addressgroups.Delete(ctx, n.Client, p.ID).ExtractErr(); err != nil {
			if isConflict(err) || isGone(err) {
				continue
			}
			return removed, fmt.Errorf("removing peer set %s: %w", p.Name, err)
		}
		removed++
	}
	return removed, nil
}

// EnsureAddressGroup makes sure a peer set exists under a stable name.
//
// ⚠️ Neutron does not refuse a second group of the same name, and two policies
// sharing a peer selector reach here from different workers. Two groups would mean
// rules pointing at one while the other is kept up to date, so the find and the
// create are one step within this process (one Neutron per project).
// Where duplicates already exist every reader picks the smallest id, so all agree.
func (n *Neutron) EnsureAddressGroup(ctx context.Context, name string) (string, error) {
	n.peerSets.Lock()
	defer n.peerSets.Unlock()
	var found string
	err := addressgroups.List(n.Client, addressgroups.ListOpts{Name: name}).EachPage(ctx,
		func(_ context.Context, page pagination.Page) (bool, error) {
			list, err := addressgroups.ExtractGroups(page)
			if err != nil {
				return false, err
			}
			for _, g := range list {
				if found == "" || g.ID < found {
					found = g.ID
				}
			}
			return true, nil
		})
	if err != nil {
		return "", fmt.Errorf("looking for address group %s: %w", name, err)
	}
	if found != "" {
		return found, nil
	}
	// ⚠️ Posted directly rather than through addressgroups.CreateOpts, whose
	// Addresses field is marked required by the client while the service
	// accepts an empty group and answers 201 (measured). An empty peer set is
	// an ordinary state -- a selector that matches no pod yet -- so inventing
	// a placeholder address to satisfy a client-side rule would put an address
	// in a group that nothing asked to be there.
	var created struct {
		Group struct {
			ID string `json:"id"`
		} `json:"address_group"`
	}
	body := map[string]any{"address_group": map[string]any{
		"name":        name,
		"description": n.Naming.managedBy(),
		"addresses":   []string{},
	}}
	if _, err := n.Client.Post(ctx, n.Client.ServiceURL("address-groups"),
		body, &created, &gophercloud.RequestOpts{
			OkCodes: []int{200, 201}}); err != nil {
		return "", fmt.Errorf("creating address group %s: %w", name, err)
	}
	if created.Group.ID == "" {
		return "", fmt.Errorf("creating address group %s: no id was returned", name)
	}
	return created.Group.ID, nil
}

// SyncAddresses makes an address group hold exactly these addresses.
//
// ⚠️ Read, diff, then write. The add and remove calls are not idempotent --
// adding an address that is already there answers 400 AddressesAlreadyExist,
// and removing one that is not there answers 400 AddressesNotFound (measured,
// not assumed). A reconciler that retries must therefore never send the whole
// desired set and hope; it sends the difference, and treats those two answers
// as agreement rather than failure when a concurrent write got there first.
func (n *Neutron) SyncAddresses(ctx context.Context, groupID string, want []string) error {
	current, err := addressgroups.Get(ctx, n.Client, groupID).Extract()
	if err != nil {
		return fmt.Errorf("reading address group %s: %w", groupID, err)
	}
	add, remove := diffAddresses(current.Addresses, want)
	if len(add) > 0 {
		if _, err := addressgroups.AddAddresses(ctx, n.Client, groupID,
			addressgroups.UpdateAddressesOpts{Addresses: add}).Extract(); err != nil {
			if !isConflict(err) {
				return fmt.Errorf("adding %d addresses to %s: %w", len(add), groupID, err)
			}
		}
	}
	if len(remove) > 0 {
		if _, err := addressgroups.RemoveAddresses(ctx, n.Client, groupID,
			addressgroups.UpdateAddressesOpts{Addresses: remove}).Extract(); err != nil {
			if !isConflict(err) {
				return fmt.Errorf("removing %d addresses from %s: %w", len(remove), groupID, err)
			}
		}
	}
	return nil
}

// diffAddresses says what to add and what to remove to get from have to want.
//
// Addresses are compared in the form Neutron stores them, which is a CIDR: a
// bare address handed in as "10.0.0.5" comes back as "10.0.0.5/32", and
// comparing the two forms directly would re-add every address on every pass.
func diffAddresses(have, want []string) (add, remove []string) {
	h := make(map[string]struct{}, len(have))
	for _, a := range have {
		h[normalizeCIDR(a)] = struct{}{}
	}
	w := make(map[string]struct{}, len(want))
	for _, a := range want {
		w[normalizeCIDR(a)] = struct{}{}
	}
	for a := range w {
		if _, ok := h[a]; !ok {
			add = append(add, a)
		}
	}
	for a := range h {
		if _, ok := w[a]; !ok {
			remove = append(remove, a)
		}
	}
	sort.Strings(add)
	sort.Strings(remove)
	return add, remove
}

func normalizeCIDR(a string) string {
	a = strings.TrimSpace(a)
	if a == "" || strings.Contains(a, "/") {
		return a
	}
	if strings.Contains(a, ":") {
		return a + "/128"
	}
	return a + "/32"
}

// isConflict reports whether the service is saying "already so", which for an
// operation whose goal is a state rather than a change is agreement.
func isConflict(err error) bool {
	var conflict gophercloud.ErrUnexpectedResponseCode
	if errors.As(err, &conflict) {
		if conflict.Actual == 409 {
			return true
		}
		if conflict.Actual == 400 {
			body := string(conflict.Body)
			return strings.Contains(body, "AddressesAlreadyExist") ||
				strings.Contains(body, "AddressesNotFound") ||
				strings.Contains(body, "already exists")
		}
	}
	return false
}

// isGone reports whether the thing we were removing is already absent, which
// is the outcome the caller wanted.
func isGone(err error) bool {
	var code gophercloud.ErrUnexpectedResponseCode
	return errors.As(err, &code) && code.Actual == 404
}

// wantsRule reports whether an existing rule is one of the wanted ones.
func wantsRule(want []rules.CreateOpts, have rules.SecGroupRule) bool {
	for _, w := range want {
		if hasRule([]rules.SecGroupRule{have}, w) {
			return true
		}
	}
	return false
}

func hasRule(have []rules.SecGroupRule, want rules.CreateOpts) bool {
	for _, r := range have {
		if r.Direction == string(want.Direction) &&
			r.EtherType == string(want.EtherType) &&
			r.Protocol == string(want.Protocol) &&
			r.PortRangeMin == want.PortRangeMin &&
			r.PortRangeMax == want.PortRangeMax &&
			r.RemoteIPPrefix == want.RemoteIPPrefix &&
			r.RemoteGroupID == want.RemoteGroupID &&
			r.RemoteAddressGroupID == want.RemoteAddressGroupID {
			return true
		}
	}
	return false
}

// PruneDuplicates removes other groups carrying a constant group's name, which a
// race can leave behind. A duplicate still on a port is refused by Neutron and
// stays for the next pass; nothing else refers to these by name.
func (n *Neutron) PruneDuplicates(ctx context.Context, name, keep string) error {
	var extra []string
	err := groups.List(n.Client, groups.ListOpts{Name: name}).EachPage(ctx,
		func(_ context.Context, page pagination.Page) (bool, error) {
			list, err := groups.ExtractGroups(page)
			if err != nil {
				return false, err
			}
			for _, g := range list {
				if g.ID != keep {
					extra = append(extra, g.ID)
				}
			}
			return true, nil
		})
	if err != nil {
		return fmt.Errorf("listing duplicates of %s: %w", name, err)
	}
	for _, id := range extra {
		if err := groups.Delete(ctx, n.Client, id).ExtractErr(); err != nil && !isConflict(err) && !isGone(err) {
			return fmt.Errorf("removing a duplicate of %s: %w", name, err)
		}
	}
	return nil
}

// EvictAddress removes one address from every peer set of this project.
//
// ⚠️ For a port that outlives its pod: an address still sitting in another
// policy's peer set is that policy ALLOWING whoever holds the address next. Run it
// before a port is deleted (Neutron may hand the address to a new port) and before
// a fixed port changes holder (the new pod may have different labels). Failure must
// stop the caller: deleting the port or admitting the new holder anyway is the hole
// this closes. The periodic peer resync re-adds the address wherever the current
// holder really belongs.
func (n *Neutron) EvictAddress(ctx context.Context, address string) (removed int, err error) {
	want := normalizeCIDR(address)
	if want == "" {
		return 0, nil
	}
	var all []addressgroups.AddressGroup
	err = addressgroups.List(n.Client, addressgroups.ListOpts{}).EachPage(ctx,
		func(_ context.Context, page pagination.Page) (bool, error) {
			got, err := addressgroups.ExtractGroups(page)
			if err != nil {
				return false, err
			}
			all = append(all, got...)
			return true, nil
		})
	if err != nil {
		return 0, fmt.Errorf("listing address groups: %w", err)
	}
	for _, g := range all {
		if !strings.HasPrefix(g.Name, n.Naming.peerPrefix()) {
			continue
		}
		held := false
		for _, a := range g.Addresses {
			if normalizeCIDR(a) == want {
				held = true
				break
			}
		}
		if !held {
			continue
		}
		if _, err := addressgroups.RemoveAddresses(ctx, n.Client, g.ID,
			addressgroups.UpdateAddressesOpts{Addresses: []string{want}}).Extract(); err != nil && !isConflict(err) {
			return removed, fmt.Errorf("removing %s from %s: %w", want, g.Name, err)
		}
		removed++
	}
	return removed, nil
}
