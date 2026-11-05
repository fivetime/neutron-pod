package l7

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/l7policies"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/monitors"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/pools"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

// Backend identifies one Ingress backend (Service + port), the unit that maps to
// one Octavia pool.
type Backend struct {
	Service string
	Port    networkingv1.ServiceBackendPort
}

func (b Backend) portKey() string {
	if b.Port.Name != "" {
		return b.Port.Name
	}
	return fmt.Sprintf("%d", b.Port.Number)
}

// CollectBackends returns every distinct backend the Ingress references: the
// default backend (if any) plus each rule path's.
func CollectBackends(ing *networkingv1.Ingress) (defaultBackend *Backend, all []Backend) {
	seen := map[string]bool{}
	add := func(b *networkingv1.IngressBackend) *Backend {
		if b == nil || b.Service == nil {
			return nil
		}
		ref := Backend{Service: b.Service.Name, Port: b.Service.Port}
		key := ref.Service + "|" + ref.portKey()
		if !seen[key] {
			seen[key] = true
			all = append(all, ref)
		}
		return &ref
	}
	defaultBackend = add(ing.Spec.DefaultBackend)
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for i := range rule.HTTP.Paths {
			add(&rule.HTTP.Paths[i].Backend)
		}
	}
	return defaultBackend, all
}

// PoolName derives the stable pool name for one backend. It is in production, and
// a changed name creates a new pool for every backend of every Ingress.
func PoolName(lbname string, b Backend) string {
	return fmt.Sprintf("%s_%s_%s", lbname, b.Service, b.portKey())
}

// ResolveServicePort maps an Ingress backend port (name or number) onto the backing
// Service's ServicePort, through which members then resolve the endpoint port.
func ResolveServicePort(svc *corev1.Service, port networkingv1.ServiceBackendPort) (corev1.ServicePort, error) {
	for _, sp := range svc.Spec.Ports {
		if port.Name != "" && sp.Name == port.Name {
			return sp, nil
		}
		if port.Name == "" && sp.Port == port.Number {
			return sp, nil
		}
	}
	return corev1.ServicePort{}, fmt.Errorf("service %s has no port %q/%d", svc.Name, port.Name, port.Number)
}

// EnsureBackendPool reconciles one backend into a pool + HTTP health monitor. Pools
// hang off the load balancer, not a listener: the listener reaches them through
// default_pool_id or l7policies.
//
// Members are the caller's, and deliberately after EnsureListener. Member churn
// flips the load balancer to PENDING_UPDATE, and if it ran first, a listener whose
// TLS ref needs repair could never be repaired: the provider fails converging on the
// dangling ref, the load balancer never returns to ACTIVE, and the repairing update
// is refused as immutable.
func EnsureBackendPool(ctx context.Context, oct Octavia, lbID, lbname string, b Backend) (*pools.Pool, error) {
	name := PoolName(lbname, b)
	pool, err := oct.GetPoolByName(ctx, lbID, name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("looking up pool %q: %w", name, err)
	}
	if err != nil {
		pool, err = oct.CreatePool(ctx, lbID, pools.CreateOpts{
			Name:           name,
			Protocol:       pools.ProtocolHTTP,
			LBMethod:       pools.LBMethodRoundRobin,
			LoadbalancerID: lbID,
		})
		if err != nil {
			return nil, fmt.Errorf("creating pool %q: %w", name, err)
		}
	}

	// An HTTP health monitor is the L7 layer's real gain over the L4 tier: "port
	// open but the application answers 500" is invisible to a TCP check.
	if pool.MonitorID == "" {
		if err := oct.CreateHealthMonitor(ctx, lbID, monitors.CreateOpts{
			Name:           name,
			PoolID:         pool.ID,
			Type:           "HTTP",
			URLPath:        "/",
			Delay:          5,
			Timeout:        3,
			MaxRetries:     2,
			MaxRetriesDown: 2,
		}); err != nil {
			return nil, fmt.Errorf("creating HTTP health monitor for pool %q: %w", name, err)
		}
	}
	return pool, nil
}

// Policy is one host/path rule as an Octavia l7policy + its rules.
type Policy struct {
	Name     string
	PoolID   string
	Host     string
	Path     string
	PathType networkingv1.PathType
}

// signature flattens a policy (desired or existing) for drift comparison.
func (d Policy) signature() string {
	return fmt.Sprintf("%s|%s|%s|%s|%s", d.Name, d.PoolID, d.Host, d.Path, d.PathType)
}

// BuildPolicies orders the Ingress rules into l7policies. poolIDs is keyed by
// PoolName. Octavia evaluates policies by position and Kubernetes wants the most
// specific path first, so longer paths sort ahead: "/api" wins over "/" no matter how
// the manifest ordered them.
func BuildPolicies(ing *networkingv1.Ingress, lbname string, poolIDs map[string]string) []Policy {
	var out []Policy
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for i := range rule.HTTP.Paths {
			p := &rule.HTTP.Paths[i]
			if p.Backend.Service == nil {
				continue
			}
			ref := Backend{Service: p.Backend.Service.Name, Port: p.Backend.Service.Port}
			poolID := poolIDs[PoolName(lbname, ref)]
			if poolID == "" {
				continue // no pool: skip rather than mis-route
			}
			pathType := networkingv1.PathTypePrefix
			if p.PathType != nil {
				pathType = *p.PathType
			}
			out = append(out, Policy{
				PoolID:   poolID,
				Host:     rule.Host,
				Path:     p.Path,
				PathType: pathType,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i].Path) > len(out[j].Path) })
	for i := range out {
		out[i].Name = fmt.Sprintf("%s_l7_%d", lbname, i)
	}
	return out
}

// SyncPolicies converges the listener's l7policies onto desired. Drift detection is
// whole-set: policies are ordered and few, so on any difference the set is torn down
// and recreated in order, which is simpler and safer than in-place position surgery.
func SyncPolicies(ctx context.Context, oct Octavia, lbID, listenerID, lbname string, desired []Policy) error {
	existing, err := oct.ListL7Policies(ctx, listenerID)
	if err != nil {
		return fmt.Errorf("listing l7policies: %w", err)
	}
	sort.SliceStable(existing, func(i, j int) bool { return existing[i].Position < existing[j].Position })

	match := len(existing) == len(desired)
	if match {
		for i := range existing {
			got, err := existingSignature(ctx, oct, &existing[i])
			if err != nil {
				return err
			}
			if got != desired[i].signature() {
				match = false
				break
			}
		}
	}
	if match {
		return nil
	}

	for i := range existing {
		// Only our own policies are ours to delete; anything else on the listener
		// was made out-of-band and is left alone.
		if !strings.HasPrefix(existing[i].Name, lbname+"_l7_") {
			continue
		}
		if err := oct.DeleteL7Policy(ctx, lbID, existing[i].ID); err != nil {
			return fmt.Errorf("deleting stale l7policy %s: %w", existing[i].Name, err)
		}
	}
	for i := range desired {
		d := &desired[i]
		pol, err := oct.CreateL7Policy(ctx, lbID, l7policies.CreateOpts{
			Name:           d.Name,
			ListenerID:     listenerID,
			Action:         l7policies.ActionRedirectToPool,
			RedirectPoolID: d.PoolID,
			Position:       int32(i + 1),
		})
		if err != nil {
			return fmt.Errorf("creating l7policy %s: %w", d.Name, err)
		}
		for _, rule := range rulesFor(*d) {
			if err := oct.CreateL7Rule(ctx, lbID, pol.ID, rule); err != nil {
				return fmt.Errorf("creating l7rule for %s: %w", d.Name, err)
			}
		}
	}
	return nil
}

// rulesFor renders the host/path of one policy as Octavia l7rules. All rules of a
// policy AND together, exactly the Ingress "host AND path" semantics.
func rulesFor(d Policy) []l7policies.CreateRuleOpts {
	var rules []l7policies.CreateRuleOpts
	if d.Host != "" {
		rules = append(rules, l7policies.CreateRuleOpts{
			RuleType:    l7policies.TypeHostName,
			CompareType: l7policies.CompareTypeEqual,
			Value:       d.Host,
		})
	}
	// "/" gets a rule of its own like any other path. Skipping it leaves a hostless
	// policy with no rules, and a policy with no rules matches nothing: requests to
	// "/" fall through to the listener and come back 503 while longer paths serve.
	// STARTS_WITH "/" matches every path, and policies are ordered longest-path-first,
	// so it catches only what nothing more specific claimed.
	if d.Path != "" {
		compare := l7policies.CompareTypeStartWith
		if d.PathType == networkingv1.PathTypeExact {
			compare = l7policies.CompareTypeEqual
		}
		rules = append(rules, l7policies.CreateRuleOpts{
			RuleType:    l7policies.TypePath,
			CompareType: compare,
			Value:       d.Path,
		})
	}
	return rules
}

// existingSignature reconstructs a Policy signature from a live policy + its rules,
// so drift comparison sees through Octavia's data model.
func existingSignature(ctx context.Context, oct Octavia, pol *l7policies.L7Policy) (string, error) {
	rules, err := oct.ListL7Rules(ctx, pol.ID)
	if err != nil {
		return "", fmt.Errorf("listing rules of l7policy %s: %w", pol.Name, err)
	}
	got := Policy{Name: pol.Name, PoolID: pol.RedirectPoolID}
	for i := range rules {
		switch rules[i].RuleType {
		case string(l7policies.TypeHostName):
			got.Host = rules[i].Value
		case string(l7policies.TypePath):
			got.Path = rules[i].Value
			got.PathType = networkingv1.PathTypePrefix
			if rules[i].CompareType == string(l7policies.CompareTypeEqual) {
				got.PathType = networkingv1.PathTypeExact
			}
		}
	}
	// No compensation for a missing path rule: a live policy without one differs from
	// a desired "/" and is rebuilt. Reading it back as "/" would make the drift check
	// agree with a policy that matches nothing, and nothing would repair it.
	return got.signature(), nil
}

// listenerNames returns the listener this Ingress wants and the one it supersedes.
// An Ingress serves exactly one listener, :443 TERMINATED_HTTPS when it declares TLS
// and :80 HTTP otherwise, so the other name is always garbage to collect, in both
// directions (adding TLS and removing it).
func listenerNames(lbname string, tls bool) (want, stale string, proto listeners.Protocol, port int) {
	httpName, httpsName := fmt.Sprintf("%s_http_80", lbname), fmt.Sprintf("%s_https_443", lbname)
	if tls {
		return httpsName, httpName, listeners.ProtocolTerminatedHTTPS, 443
	}
	return httpName, httpsName, listeners.ProtocolHTTP, 80
}

// deleteListenerByName removes a listener if it exists, and is a no-op when it does
// not, the ordinary case on every reconcile after the first.
func deleteListenerByName(ctx context.Context, oct Octavia, lbID, name string) error {
	listener, err := oct.GetListenerByName(ctx, lbID, name)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("looking up superseded listener %q: %w", name, err)
	}
	if err := oct.DeleteListener(ctx, lbID, listener.ID); err != nil {
		return fmt.Errorf("deleting superseded listener %q: %w", name, err)
	}
	return nil
}

// GCStalePools removes pools of ours that no current backend references. Run it after
// SyncPolicies, so no policy still points at one; the listener default pool is skipped
// (EnsureListener has re-pointed it already).
func GCStalePools(ctx context.Context, oct Octavia, lbID, lbname string, keep map[string]bool, defaultPoolID string) error {
	all, err := oct.ListPools(ctx, lbID)
	if err != nil {
		return fmt.Errorf("listing pools: %w", err)
	}
	for i := range all {
		p := &all[i]
		if !strings.HasPrefix(p.Name, lbname+"_") || keep[p.ID] || p.ID == defaultPoolID {
			continue
		}
		if err := oct.DeletePool(ctx, lbID, p.ID); err != nil {
			return fmt.Errorf("deleting stale pool %s: %w", p.Name, err)
		}
	}
	return nil
}

// EnsureListener reconciles THE listener of the Ingress load balancer: TERMINATED_HTTPS
// :443 with Barbican refs when tlsRefs is set, plain HTTP :80 otherwise. Existing drift
// (rotated certificate, changed default pool, tuning annotations) is applied in place.
func EnsureListener(ctx context.Context, oct Octavia, lbID, lbname string, tlsRefs []string, defaultPoolID string, tuning *Tuning) (*listeners.Listener, error) {
	name, stale, proto, port := listenerNames(lbname, len(tlsRefs) > 0)

	// The listener of the other protocol must go, or adding TLS to a live Ingress leaves
	// the :80 listener (and its l7policies) serving a port the spec no longer declares,
	// frozen at whatever config it had when TLS arrived and never reconciled again. It
	// hides well because :80 keeps answering. Deleting the listener cascades its policies.
	if err := deleteListenerByName(ctx, oct, lbID, stale); err != nil {
		return nil, err
	}

	listener, err := oct.GetListenerByName(ctx, lbID, name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("looking up listener %q: %w", name, err)
	}
	if err != nil {
		opts := listeners.CreateOpts{
			Name:           name,
			Protocol:       proto,
			ProtocolPort:   port,
			LoadbalancerID: lbID,
		}
		if len(tlsRefs) > 0 {
			opts.DefaultTlsContainerRef = tlsRefs[0]
			if len(tlsRefs) > 1 {
				opts.SniContainerRefs = tlsRefs[1:]
			}
		}
		if defaultPoolID != "" {
			opts.DefaultPoolID = defaultPoolID
		}
		if len(tuning.AllowedCIDRs) > 0 {
			opts.AllowedCIDRs = tuning.AllowedCIDRs
		}
		opts.TimeoutClientData = tuning.TimeoutClientData
		opts.TimeoutMemberData = tuning.TimeoutMemberData
		opts.TimeoutMemberConnect = tuning.TimeoutMemberConnect
		opts.TimeoutTCPInspect = tuning.TimeoutTCPInspect
		listener, err = oct.CreateListener(ctx, lbID, opts)
		if err != nil {
			return nil, fmt.Errorf("creating listener %q: %w", name, err)
		}
		return listener, nil
	}

	var update listeners.UpdateOpts
	dirty := false
	if len(tlsRefs) > 0 && listener.DefaultTlsContainerRef != tlsRefs[0] {
		update.DefaultTlsContainerRef = &tlsRefs[0]
		dirty = true
	}
	if listener.DefaultPoolID != defaultPoolID {
		update.DefaultPoolID = &defaultPoolID
		dirty = true
	}
	// Whitelist: always enforced, including back to empty (see Tuning).
	if !cidrsEqual(listener.AllowedCIDRs, tuning.AllowedCIDRs) {
		cidrs := tuning.AllowedCIDRs
		update.AllowedCIDRs = &cidrs
		dirty = true
	}
	// Timeouts: enforced only while their annotation manages them.
	if timeoutDrift(tuning.TimeoutClientData, listener.TimeoutClientData) {
		update.TimeoutClientData = tuning.TimeoutClientData
		dirty = true
	}
	if timeoutDrift(tuning.TimeoutMemberData, listener.TimeoutMemberData) {
		update.TimeoutMemberData = tuning.TimeoutMemberData
		dirty = true
	}
	if timeoutDrift(tuning.TimeoutMemberConnect, listener.TimeoutMemberConnect) {
		update.TimeoutMemberConnect = tuning.TimeoutMemberConnect
		dirty = true
	}
	if timeoutDrift(tuning.TimeoutTCPInspect, listener.TimeoutTCPInspect) {
		update.TimeoutTCPInspect = tuning.TimeoutTCPInspect
		dirty = true
	}
	if dirty {
		if err := oct.UpdateListener(ctx, lbID, listener.ID, update); err != nil {
			return nil, fmt.Errorf("updating listener %q: %w", name, err)
		}
		listener, err = oct.GetListenerByName(ctx, lbID, name)
		if err != nil {
			return nil, err
		}
	}
	return listener, nil
}
