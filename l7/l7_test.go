package l7

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/l7policies"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/monitors"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/pools"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testLB = "ctl_ing_t1_web"

func prefixType() *networkingv1.PathType { p := networkingv1.PathTypePrefix; return &p }
func exactType() *networkingv1.PathType  { p := networkingv1.PathTypeExact; return &p }

func ingWith(rules []networkingv1.IngressRule, def *networkingv1.IngressBackend) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "t1", Name: "web"},
		Spec:       networkingv1.IngressSpec{Rules: rules, DefaultBackend: def},
	}
}

func backend(svc string, port int32) networkingv1.IngressBackend {
	return networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
		Name: svc, Port: networkingv1.ServiceBackendPort{Number: port}}}
}

func paths(host string, p ...networkingv1.HTTPIngressPath) networkingv1.IngressRule {
	return networkingv1.IngressRule{
		Host:             host,
		IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: p}},
	}
}

// Two paths on one backend are one pool, and the default backend counts.
func TestCollectBackends(t *testing.T) {
	def := backend("fallback", 80)
	api := backend("api", 8080)
	web := backend("web", 80)
	ing := ingWith([]networkingv1.IngressRule{paths("www.example.com",
		networkingv1.HTTPIngressPath{Path: "/api", PathType: prefixType(), Backend: api},
		networkingv1.HTTPIngressPath{Path: "/api/v2", PathType: prefixType(), Backend: api},
		networkingv1.HTTPIngressPath{Path: "/", PathType: prefixType(), Backend: web},
	)}, &def)

	d, all := CollectBackends(ing)
	if d == nil || d.Service != "fallback" {
		t.Fatalf("default backend = %+v", d)
	}
	if len(all) != 3 {
		t.Fatalf("want 3 distinct backends, got %d: %+v", len(all), all)
	}
}

// Longer paths sort ahead so "/api" wins over "/" regardless of manifest order, and
// each policy carries host+path rules per Ingress semantics.
func TestBuildPoliciesOrderAndRules(t *testing.T) {
	api := backend("api", 8080)
	web := backend("web", 80)
	ing := ingWith([]networkingv1.IngressRule{paths("www.example.com",
		networkingv1.HTTPIngressPath{Path: "/", PathType: prefixType(), Backend: web},
		networkingv1.HTTPIngressPath{Path: "/api", PathType: prefixType(), Backend: api},
	)}, nil)
	poolIDs := map[string]string{
		PoolName(testLB, Backend{Service: "api", Port: api.Service.Port}): "pool-api",
		PoolName(testLB, Backend{Service: "web", Port: web.Service.Port}): "pool-web",
	}

	got := BuildPolicies(ing, testLB, poolIDs)
	if len(got) != 2 {
		t.Fatalf("want 2 policies, got %d", len(got))
	}
	if got[0].Path != "/api" || got[0].PoolID != "pool-api" {
		t.Fatalf("longest path must come first, got %+v", got[0])
	}
	if got[1].Path != "/" || got[1].PoolID != "pool-web" {
		t.Fatalf("catch-all last, got %+v", got[1])
	}

	r0 := rulesFor(got[0])
	if len(r0) != 2 || r0[0].Value != "www.example.com" || r0[1].Value != "/api" {
		t.Fatalf("rules for /api = %+v", r0)
	}
	r1 := rulesFor(got[1])
	if len(r1) != 2 || r1[0].Value != "www.example.com" || r1[1].Value != "/" {
		t.Fatalf("rules for / = %+v", r1)
	}
}

// A policy with no rules matches nothing in Octavia, so a hostless "/" must still
// render one, or requests to "/" come back 503 while longer paths serve.
func TestRootPathWithoutHostHasARule(t *testing.T) {
	rules := rulesFor(Policy{Path: "/", PathType: networkingv1.PathTypePrefix})
	if len(rules) != 1 || rules[0].Value != "/" || string(rules[0].CompareType) != "STARTS_WITH" {
		t.Fatalf("rules for a hostless / = %+v", rules)
	}
}

func TestRulesForExactPath(t *testing.T) {
	rules := rulesFor(Policy{Path: "/healthz", PathType: networkingv1.PathTypeExact})
	if len(rules) != 1 || string(rules[0].CompareType) != "EQUAL_TO" {
		t.Fatalf("exact path must render EQUAL_TO, got %+v", rules)
	}
}

// A backend whose pool failed to materialize is skipped, not routed to "".
func TestBuildPoliciesSkipsMissingPool(t *testing.T) {
	api := backend("api", 8080)
	ing := ingWith([]networkingv1.IngressRule{paths("",
		networkingv1.HTTPIngressPath{Path: "/api", PathType: prefixType(), Backend: api},
	)}, nil)
	if got := BuildPolicies(ing, testLB, map[string]string{}); len(got) != 0 {
		t.Fatalf("missing pool must be skipped, got %+v", got)
	}
}

// Object names are in production. A changed one recreates the pool, listener or
// policies of every Ingress, so changing one is a migration.
func TestExistingObjectsKeepTheirNames(t *testing.T) {
	lb := "kubetron_ing_t1_web"
	if got := PoolName(lb, Backend{Service: "api", Port: networkingv1.ServiceBackendPort{Number: 8080}}); got != "kubetron_ing_t1_web_api_8080" {
		t.Fatalf("pool by number = %q", got)
	}
	if got := PoolName(lb, Backend{Service: "api", Port: networkingv1.ServiceBackendPort{Name: "http"}}); got != "kubetron_ing_t1_web_api_http" {
		t.Fatalf("pool by name = %q", got)
	}
	api := backend("api", 8080)
	ing := ingWith([]networkingv1.IngressRule{paths("",
		networkingv1.HTTPIngressPath{Path: "/api", PathType: prefixType(), Backend: api},
	)}, nil)
	got := BuildPolicies(ing, lb, map[string]string{"kubetron_ing_t1_web_api_8080": "p"})
	if len(got) != 1 || got[0].Name != "kubetron_ing_t1_web_l7_0" {
		t.Fatalf("policies = %+v", got)
	}
}

// Adding TLS to a live Ingress must supersede its :80 listener, and removing TLS the
// :443 one, or the abandoned listener keeps serving a port the spec no longer declares.
func TestListenerNamesIdentifyTheSupersededOne(t *testing.T) {
	want, stale, proto, port := listenerNames(testLB, true)
	if want != testLB+"_https_443" || stale != testLB+"_http_80" {
		t.Fatalf("with TLS: want=%q stale=%q", want, stale)
	}
	if string(proto) != "TERMINATED_HTTPS" || port != 443 {
		t.Fatalf("with TLS: proto=%s port=%d", proto, port)
	}
	want, stale, proto, port = listenerNames(testLB, false)
	if want != testLB+"_http_80" || stale != testLB+"_https_443" {
		t.Fatalf("without TLS: want=%q stale=%q", want, stale)
	}
	if string(proto) != "HTTP" || port != 80 {
		t.Fatalf("without TLS: proto=%s port=%d", proto, port)
	}
}

func TestResolveServicePort(t *testing.T) {
	svc := &corev1.Service{Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{
		{Name: "http", Port: 80}, {Name: "admin", Port: 9000},
	}}}
	if sp, err := ResolveServicePort(svc, networkingv1.ServiceBackendPort{Name: "admin"}); err != nil || sp.Port != 9000 {
		t.Fatalf("by name: %+v %v", sp, err)
	}
	if sp, err := ResolveServicePort(svc, networkingv1.ServiceBackendPort{Number: 80}); err != nil || sp.Name != "http" {
		t.Fatalf("by number: %+v %v", sp, err)
	}
	if _, err := ResolveServicePort(svc, networkingv1.ServiceBackendPort{Number: 81}); err == nil {
		t.Fatal("a port the Service lacks must be an error")
	}
}

// fakeOctavia records every write, so a test can tell "nothing changed" from
// "rebuilt to the same thing": a needless write parks a live load balancer in
// PENDING_UPDATE.
type fakeOctavia struct {
	pools     map[string]*pools.Pool
	listeners map[string]*listeners.Listener
	policies  []l7policies.L7Policy
	rules     map[string][]l7policies.Rule
	writes    []string
	failList  error
	seq       int
	watch     []string // paths observe() records after every policy or rule write
	seen      []string
}

func newFake() *fakeOctavia {
	return &fakeOctavia{
		pools:     map[string]*pools.Pool{},
		listeners: map[string]*listeners.Listener{},
		rules:     map[string][]l7policies.Rule{},
	}
}

func (f *fakeOctavia) id(prefix string) string {
	f.seq++
	return fmt.Sprintf("%s-%d", prefix, f.seq)
}

func (f *fakeOctavia) GetPoolByName(_ context.Context, _, name string) (*pools.Pool, error) {
	if p, ok := f.pools[name]; ok {
		return p, nil
	}
	return nil, ErrNotFound
}

func (f *fakeOctavia) ListPools(context.Context, string) ([]pools.Pool, error) {
	var out []pools.Pool
	for _, p := range f.pools {
		out = append(out, *p)
	}
	return out, nil
}

func (f *fakeOctavia) CreatePool(_ context.Context, _ string, o pools.CreateOpts) (*pools.Pool, error) {
	f.writes = append(f.writes, "create-pool "+o.Name)
	p := &pools.Pool{ID: f.id("pool"), Name: o.Name}
	f.pools[o.Name] = p
	return p, nil
}

func (f *fakeOctavia) DeletePool(_ context.Context, _, id string) error {
	f.writes = append(f.writes, "delete-pool "+id)
	for name, p := range f.pools {
		if p.ID == id {
			delete(f.pools, name)
		}
	}
	return nil
}

func (f *fakeOctavia) CreateHealthMonitor(_ context.Context, _ string, o monitors.CreateOpts) error {
	f.writes = append(f.writes, fmt.Sprintf("create-monitor %s %s", o.Name, o.Type))
	for _, p := range f.pools {
		if p.ID == o.PoolID {
			p.MonitorID = "mon"
		}
	}
	return nil
}

func (f *fakeOctavia) GetListenerByName(_ context.Context, _, name string) (*listeners.Listener, error) {
	if l, ok := f.listeners[name]; ok {
		return l, nil
	}
	return nil, ErrNotFound
}

func (f *fakeOctavia) CreateListener(_ context.Context, _ string, o listeners.CreateOpts) (*listeners.Listener, error) {
	f.writes = append(f.writes, "create-listener "+o.Name)
	l := &listeners.Listener{
		ID: f.id("listener"), Name: o.Name, DefaultPoolID: o.DefaultPoolID,
		DefaultTlsContainerRef: o.DefaultTlsContainerRef, SniContainerRefs: o.SniContainerRefs, AllowedCIDRs: o.AllowedCIDRs,
	}
	f.listeners[o.Name] = l
	return l, nil
}

func (f *fakeOctavia) UpdateListener(_ context.Context, _, id string, o listeners.UpdateOpts) error {
	f.writes = append(f.writes, "update-listener "+id)
	for _, l := range f.listeners {
		if l.ID != id {
			continue
		}
		if o.DefaultTlsContainerRef != nil {
			l.DefaultTlsContainerRef = *o.DefaultTlsContainerRef
		}
		if o.SniContainerRefs != nil {
			l.SniContainerRefs = *o.SniContainerRefs
		}
		if o.DefaultPoolID != nil {
			l.DefaultPoolID = *o.DefaultPoolID
		}
		if o.AllowedCIDRs != nil {
			l.AllowedCIDRs = *o.AllowedCIDRs
		}
		if o.TimeoutClientData != nil {
			l.TimeoutClientData = *o.TimeoutClientData
		}
	}
	return nil
}

func (f *fakeOctavia) DeleteListener(_ context.Context, _, id string) error {
	f.writes = append(f.writes, "delete-listener "+id)
	for name, l := range f.listeners {
		if l.ID == id {
			delete(f.listeners, name)
		}
	}
	return nil
}

func (f *fakeOctavia) ListL7Policies(context.Context, string) ([]l7policies.L7Policy, error) {
	if f.failList != nil {
		return nil, f.failList
	}
	return append([]l7policies.L7Policy(nil), f.policies...), nil
}

func (f *fakeOctavia) ListL7Rules(_ context.Context, id string) ([]l7policies.Rule, error) {
	return f.rules[id], nil
}

// CreateL7Policy inserts at the requested position and shifts the rest down, as Octavia's
// ordering list does (octavia/db/repositories.py, L7PolicyRepository.create).
func (f *fakeOctavia) CreateL7Policy(_ context.Context, _ string, o l7policies.CreateOpts) (*l7policies.L7Policy, error) {
	f.writes = append(f.writes, "create-policy "+o.Name)
	p := l7policies.L7Policy{ID: f.id("policy"), Name: o.Name, RedirectPoolID: o.RedirectPoolID}
	at := int(o.Position) - 1
	if o.Position == 0 || at > len(f.policies) {
		at = len(f.policies)
	}
	f.policies = append(f.policies[:at], append([]l7policies.L7Policy{p}, f.policies[at:]...)...)
	f.renumber()
	f.observe()
	return &f.policies[at], nil
}

func (f *fakeOctavia) renumber() {
	for i := range f.policies {
		f.policies[i].Position = int32(i + 1)
	}
}

// route is what the listener does with a request path: the pool of the first policy, by
// position, whose rules all match, or "" when none does. A policy without rules matches
// nothing.
func (f *fakeOctavia) route(path string) string {
	for _, p := range f.policies {
		rules := f.rules[p.ID]
		if len(rules) == 0 {
			continue
		}
		ok := true
		for _, r := range rules {
			if r.RuleType != string(l7policies.TypePath) {
				continue
			}
			if r.CompareType == string(l7policies.CompareTypeEqual) && path != r.Value ||
				r.CompareType == string(l7policies.CompareTypeStartWith) && !strings.HasPrefix(path, r.Value) {
				ok = false
			}
		}
		if ok {
			return p.RedirectPoolID
		}
	}
	return ""
}

// observe records, after a write, where each watched path goes.
func (f *fakeOctavia) observe() {
	for _, path := range f.watch {
		f.seen = append(f.seen, path+"->"+f.route(path))
	}
}

func (f *fakeOctavia) CreateL7Rule(_ context.Context, _, id string, o l7policies.CreateRuleOpts) error {
	f.writes = append(f.writes, "create-rule "+o.Value)
	f.rules[id] = append(f.rules[id], l7policies.Rule{
		RuleType: string(o.RuleType), CompareType: string(o.CompareType), Value: o.Value,
	})
	f.observe()
	return nil
}

func (f *fakeOctavia) DeleteL7Policy(_ context.Context, _, id string) error {
	f.writes = append(f.writes, "delete-policy "+id)
	for i := range f.policies {
		if f.policies[i].ID == id {
			f.policies = append(f.policies[:i], f.policies[i+1:]...)
			break
		}
	}
	delete(f.rules, id)
	f.renumber()
	f.observe()
	return nil
}

func desiredRootAndAPI() []Policy {
	return []Policy{
		{Name: testLB + "_l7_0", PoolID: "pool-api", Path: "/api", PathType: networkingv1.PathTypePrefix},
		{Name: testLB + "_l7_1", PoolID: "pool-web", Path: "/", PathType: networkingv1.PathTypePrefix},
	}
}

// An unchanged Ingress must write nothing, or every reconcile parks the load balancer
// in PENDING_UPDATE and drops the connections a rebuild takes with it.
func TestSyncPoliciesWritesNothingWhenConverged(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	if err := SyncPolicies(ctx, f, "lb", "l", testLB, desiredRootAndAPI()); err != nil {
		t.Fatal(err)
	}
	if len(f.policies) != 2 || f.policies[0].Position != 1 || f.policies[1].Position != 2 {
		t.Fatalf("policies = %+v", f.policies)
	}
	f.writes = nil
	if err := SyncPolicies(ctx, f, "lb", "l", testLB, desiredRootAndAPI()); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("a converged listener was written: %v", f.writes)
	}
}

// A live "/" policy without its rule (what older code created) matches nothing. It
// must count as drift, or nothing ever repairs it.
func TestSyncPoliciesRebuildsARulelessRootPolicy(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	desired := []Policy{{Name: testLB + "_l7_0", PoolID: "pool-web", Path: "/", PathType: networkingv1.PathTypePrefix}}
	f.policies = []l7policies.L7Policy{{ID: "old", Name: desired[0].Name, RedirectPoolID: "pool-web", Position: 1}}

	if err := SyncPolicies(ctx, f, "lb", "l", testLB, desired); err != nil {
		t.Fatal(err)
	}
	if len(f.policies) != 1 || f.policies[0].ID == "old" {
		t.Fatalf("policy not rebuilt: %+v", f.policies)
	}
	if rules := f.rules[f.policies[0].ID]; len(rules) != 1 || rules[0].Value != "/" {
		t.Fatalf("rules = %+v", rules)
	}
}

// A policy someone made by hand on the listener is not ours to delete.
func TestSyncPoliciesLeavesForeignPoliciesAlone(t *testing.T) {
	f := newFake()
	f.policies = []l7policies.L7Policy{{ID: "theirs", Name: "by-hand", Position: 1}}
	if err := SyncPolicies(context.Background(), f, "lb", "l", testLB, desiredRootAndAPI()); err != nil {
		t.Fatal(err)
	}
	for _, w := range f.writes {
		if strings.HasPrefix(w, "delete-policy") {
			t.Fatalf("deleted a policy that is not ours: %v", f.writes)
		}
	}
}

func TestSyncPoliciesReportsAListFailure(t *testing.T) {
	f := newFake()
	f.failList = errors.New("octavia is down")
	if err := SyncPolicies(context.Background(), f, "lb", "l", testLB, nil); err == nil {
		t.Fatal("a failed list must not read as nothing to do")
	}
	if len(f.writes) != 0 {
		t.Fatalf("wrote after a failed list: %v", f.writes)
	}
}

func TestEnsureBackendPool(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	b := Backend{Service: "api", Port: networkingv1.ServiceBackendPort{Number: 8080}}
	if _, err := EnsureBackendPool(ctx, f, "lb", testLB, b); err != nil {
		t.Fatal(err)
	}
	want := []string{"create-pool " + testLB + "_api_8080", "create-monitor " + testLB + "_api_8080 HTTP"}
	if strings.Join(f.writes, ",") != strings.Join(want, ",") {
		t.Fatalf("writes = %v", f.writes)
	}
	f.writes = nil
	if _, err := EnsureBackendPool(ctx, f, "lb", testLB, b); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("an existing pool was written: %v", f.writes)
	}
}

// A pool that lost its monitor gets one back.
func TestEnsureBackendPoolRestoresAMissingMonitor(t *testing.T) {
	f := newFake()
	b := Backend{Service: "api", Port: networkingv1.ServiceBackendPort{Number: 8080}}
	f.pools[PoolName(testLB, b)] = &pools.Pool{ID: "p", Name: PoolName(testLB, b)}
	if _, err := EnsureBackendPool(context.Background(), f, "lb", testLB, b); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 1 || !strings.HasPrefix(f.writes[0], "create-monitor") {
		t.Fatalf("writes = %v", f.writes)
	}
}

func TestGCStalePoolsKeepsWhatIsInUseAndWhatIsNotOurs(t *testing.T) {
	f := newFake()
	f.pools["kept"] = &pools.Pool{ID: "kept", Name: testLB + "_web_80"}
	f.pools["default"] = &pools.Pool{ID: "default", Name: testLB + "_fallback_80"}
	f.pools["stale"] = &pools.Pool{ID: "stale", Name: testLB + "_old_80"}
	f.pools["foreign"] = &pools.Pool{ID: "foreign", Name: "by-hand"}

	if err := GCStalePools(context.Background(), f, "lb", testLB, map[string]bool{"kept": true}, "default"); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 1 || f.writes[0] != "delete-pool stale" {
		t.Fatalf("writes = %v", f.writes)
	}
}

func TestEnsureListenerSupersedesTheOtherProtocol(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.listeners[testLB+"_http_80"] = &listeners.Listener{ID: "plain", Name: testLB + "_http_80"}

	l, err := EnsureListener(ctx, f, "lb", testLB, []string{"ref-1"}, "", &Tuning{AllowedCIDRs: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if l.Name != testLB+"_https_443" || l.DefaultTlsContainerRef != "ref-1" {
		t.Fatalf("listener = %+v", l)
	}
	if _, stillThere := f.listeners[testLB+"_http_80"]; stillThere {
		t.Fatal("the :80 listener survived adding TLS")
	}
}

func TestEnsureListenerAppliesDriftOnlyWhenThereIsSome(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	timeout := 50000
	tuning := &Tuning{AllowedCIDRs: []string{"10.0.0.0/8"}, TimeoutClientData: &timeout}
	if _, err := EnsureListener(ctx, f, "lb", testLB, []string{"ref-1"}, "pool", tuning); err != nil {
		t.Fatal(err)
	}
	// The fake keeps what a create was given; apply the timeout as Octavia would.
	f.listeners[testLB+"_https_443"].TimeoutClientData = timeout

	f.writes = nil
	if _, err := EnsureListener(ctx, f, "lb", testLB, []string{"ref-1"}, "pool", tuning); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("a converged listener was written: %v", f.writes)
	}

	// A rotated certificate re-points the live listener in place.
	l, err := EnsureListener(ctx, f, "lb", testLB, []string{"ref-2"}, "pool", tuning)
	if err != nil {
		t.Fatal(err)
	}
	if l.DefaultTlsContainerRef != "ref-2" || len(f.writes) != 1 {
		t.Fatalf("listener = %+v, writes = %v", l, f.writes)
	}

	// A removed whitelist must not silently stay.
	if l, err = EnsureListener(ctx, f, "lb", testLB, []string{"ref-2"}, "pool", &Tuning{AllowedCIDRs: []string{}}); err != nil {
		t.Fatal(err)
	}
	if len(l.AllowedCIDRs) != 0 {
		t.Fatalf("whitelist stayed: %v", l.AllowedCIDRs)
	}
}

// An exact path reads back as exact, not as drift.
func TestExactPathRoundTripsThroughDriftCheck(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	ing := ingWith([]networkingv1.IngressRule{paths("",
		networkingv1.HTTPIngressPath{Path: "/healthz", PathType: exactType(), Backend: backend("web", 80)},
	)}, nil)
	desired := BuildPolicies(ing, testLB, map[string]string{testLB + "_web_80": "pool-web"})
	if err := SyncPolicies(ctx, f, "lb", "l", testLB, desired); err != nil {
		t.Fatal(err)
	}
	f.writes = nil
	if err := SyncPolicies(ctx, f, "lb", "l", testLB, desired); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("an exact path read back as drift: %v", f.writes)
	}
}

// CleanupBarbicanSecrets removes every bundle not in tlsRefs. A listener left holding an
// SNI ref outside tlsRefs points at a deleted secret, and its next update leaves the load
// balancer stuck in PENDING_UPDATE, undeletable (seen live on incus).
func TestEnsureListenerKeepsSNIRefsInStepWithTLSRefs(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	open := &Tuning{AllowedCIDRs: []string{}}
	ensure := func(refs ...string) *listeners.Listener {
		t.Helper()
		l, err := EnsureListener(ctx, f, "lb", testLB, refs, "", open)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	wantSNI := func(l *listeners.Listener, want ...string) {
		t.Helper()
		if !sameSet(l.SniContainerRefs, want) {
			t.Fatalf("sni = %v, want %v", l.SniContainerRefs, want)
		}
	}

	wantSNI(ensure("default", "s2"), "s2")

	// Rotating an SNI certificate is a new ref.
	wantSNI(ensure("default", "s2-new"), "s2-new")
	// So is adding one.
	wantSNI(ensure("default", "s2-new", "s3"), "s2-new", "s3")
	// And dropping one, down to none: an empty list has to be sent, not omitted.
	wantSNI(ensure("default", "s3"), "s3")
	f.writes = nil
	l := ensure("default")
	wantSNI(l)
	if len(f.writes) != 1 {
		t.Fatalf("writes = %v", f.writes)
	}

	// Octavia does not promise an order back, and order is not drift.
	ensure("default", "a", "b")
	f.listeners[testLB+"_https_443"].SniContainerRefs = []string{"b", "a"}
	f.writes = nil
	ensure("default", "a", "b")
	if len(f.writes) != 0 {
		t.Fatalf("a reordered SNI list was written: %v", f.writes)
	}
}

// A rule change must not leave a path unrouted while it is written: each write waits for
// the load balancer to settle, and tearing the set down first answered 503 on every path
// for 47 seconds with two rules, over two minutes with six.
func TestSyncPoliciesKeepsServingWhileReplacing(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	old := []Policy{
		{Name: testLB + "_l7_0", PoolID: "pool-web", Path: "/web", PathType: networkingv1.PathTypePrefix},
		{Name: testLB + "_l7_1", PoolID: "pool-root", Path: "/", PathType: networkingv1.PathTypePrefix},
	}
	if err := SyncPolicies(ctx, f, "lb", "l", testLB, old); err != nil {
		t.Fatal(err)
	}

	f.watch = []string{"/", "/web/x", "/web2/x"}
	f.seen = nil
	desired := []Policy{
		{Name: testLB + "_l7_0", PoolID: "pool-web", Path: "/web2", PathType: networkingv1.PathTypePrefix},
		{Name: testLB + "_l7_1", PoolID: "pool-root", Path: "/", PathType: networkingv1.PathTypePrefix},
	}
	if err := SyncPolicies(ctx, f, "lb", "l", testLB, desired); err != nil {
		t.Fatal(err)
	}
	for _, s := range f.seen {
		if strings.HasSuffix(s, "->") {
			t.Fatalf("a path went unrouted during the change: %s (all: %v)", s, f.seen)
		}
	}
	if f.route("/web2/x") != "pool-web" || f.route("/web/x") != "pool-root" || f.route("/") != "pool-root" {
		t.Fatalf("after the change: /web2/x->%s /web/x->%s /->%s", f.route("/web2/x"), f.route("/web/x"), f.route("/"))
	}
	if len(f.policies) != 2 {
		t.Fatalf("old policies left behind: %+v", f.policies)
	}

	// Converged: names and positions are what the drift check expects, so nothing is written.
	f.writes = nil
	if err := SyncPolicies(ctx, f, "lb", "l", testLB, desired); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("a converged listener was written: %v", f.writes)
	}
}

// A policy made by hand on the listener is neither ours to compare nor to delete. Counting
// it made every reconcile see drift and rebuild the whole set.
func TestSyncPoliciesConvergesBesideAForeignPolicy(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.policies = []l7policies.L7Policy{{ID: "theirs", Name: "by-hand", Position: 1}}
	if err := SyncPolicies(ctx, f, "lb", "l", testLB, desiredRootAndAPI()); err != nil {
		t.Fatal(err)
	}
	f.writes = nil
	if err := SyncPolicies(ctx, f, "lb", "l", testLB, desiredRootAndAPI()); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("a foreign policy made a converged listener look drifted: %v", f.writes)
	}
	if f.policies[len(f.policies)-1].ID != "theirs" {
		t.Fatalf("the foreign policy is not behind ours: %+v", f.policies)
	}
}

// A replacement that failed half-way leaves both sets. The next sync replaces both.
func TestSyncPoliciesRecoversFromAHalfWrittenReplacement(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	if err := SyncPolicies(ctx, f, "lb", "l", testLB, desiredRootAndAPI()); err != nil {
		t.Fatal(err)
	}
	// One stray new policy at the front, as if the process died after creating it.
	if _, err := f.CreateL7Policy(ctx, "lb", l7policies.CreateOpts{Name: testLB + "_l7_0", RedirectPoolID: "pool-new", Position: 1}); err != nil {
		t.Fatal(err)
	}
	if err := SyncPolicies(ctx, f, "lb", "l", testLB, desiredRootAndAPI()); err != nil {
		t.Fatal(err)
	}
	if len(f.policies) != 2 {
		t.Fatalf("policies = %+v", f.policies)
	}
	f.writes = nil
	if err := SyncPolicies(ctx, f, "lb", "l", testLB, desiredRootAndAPI()); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("not converged: %v", f.writes)
	}
}
