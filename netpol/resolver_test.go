package netpol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/rules"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
	"github.com/gophercloud/gophercloud/v2/testhelper/client"
	"golang.org/x/time/rate"
)

// anchorRules is the deny-all group with real rule contents: what is created
// shows up in the next listing and what is deleted does not.
type anchorRules struct {
	mu    sync.Mutex
	rules map[string]rules.SecGroupRule
	next  int

	// writes counts rule creates and deletes, reads rule listings.
	writes, reads int
	// metadata is the addresses of the metadata port, by network.
	metadata  map[string][]string
	portsDown bool
}

func (a *anchorRules) add(r rules.SecGroupRule) string {
	a.next++
	r.ID = fmt.Sprintf("r%d", a.next)
	a.rules[r.ID] = r
	return r.ID
}

func (a *anchorRules) prefixes() []string {
	out := []string{}
	for _, r := range a.rules {
		out = append(out, r.Protocol+":"+r.RemoteIPPrefix)
	}
	return out
}

func newAnchor(t *testing.T) (*Neutron, *anchorRules) {
	t.Helper()
	fs := th.SetupHTTP()
	t.Cleanup(fs.Teardown)
	a := &anchorRules{rules: map[string]rules.SecGroupRule{}, metadata: map[string][]string{}}
	enc := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	desc := "test: allows only the tenant's resolver; carried so a port's group list is never empty"
	fs.Mux.HandleFunc("/security-groups", func(w http.ResponseWriter, r *http.Request) {
		enc(w, 200, map[string]any{"security_groups": []any{map[string]any{
			"id": "anchor", "name": testNaming.DenyAll(), "description": desc, "security_group_rules": []any{},
		}}})
	})
	fs.Mux.HandleFunc("/security-group-rules", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if r.Method == http.MethodGet {
			a.reads++
			out := []rules.SecGroupRule{}
			for _, v := range a.rules {
				out = append(out, v)
			}
			enc(w, 200, map[string]any{"security_group_rules": out})
			return
		}
		a.writes++
		var body struct {
			R struct {
				Direction      string `json:"direction"`
				EtherType      string `json:"ethertype"`
				Protocol       string `json:"protocol"`
				PortRangeMin   int    `json:"port_range_min"`
				PortRangeMax   int    `json:"port_range_max"`
				RemoteIPPrefix string `json:"remote_ip_prefix"`
			} `json:"security_group_rule"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		id := a.add(rules.SecGroupRule{
			Direction: body.R.Direction, EtherType: body.R.EtherType, Protocol: body.R.Protocol,
			PortRangeMin: body.R.PortRangeMin, PortRangeMax: body.R.PortRangeMax,
			RemoteIPPrefix: body.R.RemoteIPPrefix,
		})
		enc(w, 201, map[string]any{"security_group_rule": map[string]any{"id": id}})
	})
	fs.Mux.HandleFunc("/security-group-rules/", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.writes++
		delete(a.rules, strings.TrimPrefix(r.URL.Path, "/security-group-rules/"))
		w.WriteHeader(204)
	})
	fs.Mux.HandleFunc("/ports", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.portsDown {
			w.WriteHeader(503)
			return
		}
		q := r.URL.Query()
		net := q.Get("network_id")
		found := []any{}
		// Filtered as Neutron would: asking for anything but the metadata port
		// of this network finds nothing.
		if addrs, ok := a.metadata[net]; ok && q.Get("device_owner") == "network:distributed" &&
			q.Get("device_id") == "ovnmeta-"+net {
			ips := []any{}
			for _, ip := range addrs {
				ips = append(ips, map[string]any{"ip_address": ip, "subnet_id": "s"})
			}
			found = append(found, map[string]any{"id": "m", "network_id": net, "fixed_ips": ips})
		}
		enc(w, 200, map[string]any{"ports": found})
	})
	return &Neutron{Naming: testNaming, Client: client.ServiceClient(fs)}, a
}

func TestAnchorAllowsOnlyTheResolver(t *testing.T) {
	n, a := newAnchor(t)
	// What Neutron puts in every group it creates: all egress, both families.
	a.add(rules.SecGroupRule{Direction: "egress", EtherType: "IPv4"})
	a.add(rules.SecGroupRule{Direction: "egress", EtherType: "IPv6"})

	if _, err := n.EnsureDenyAll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := n.SyncResolvers(t.Context(), "anchor", []string{"192.168.200.244"}); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(sortedStrings(a.prefixes()), ",")
	if want := "tcp:192.168.200.244/32,udp:192.168.200.244/32"; got != want {
		t.Fatalf("anchor holds %q, want %q", got, want)
	}
}

// Every start runs this. Taking the rules out here would cut every isolated pod
// off from DNS until the next sync came round.
func TestEnsureDenyAllKeepsTheResolver(t *testing.T) {
	n, a := newAnchor(t)
	if err := n.SyncResolvers(t.Context(), "anchor", []string{"192.168.200.244"}); err != nil {
		t.Fatal(err)
	}
	if _, err := n.EnsureDenyAll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(a.rules) != 2 {
		t.Fatalf("a restart left %v", a.prefixes())
	}
}

func TestResolverMovingReplacesTheRules(t *testing.T) {
	n, a := newAnchor(t)
	for _, addr := range []string{"192.168.200.244", "192.168.200.7"} {
		if err := n.SyncResolvers(t.Context(), "anchor", []string{addr}); err != nil {
			t.Fatal(err)
		}
	}
	got := strings.Join(sortedStrings(a.prefixes()), ",")
	if want := "tcp:192.168.200.7/32,udp:192.168.200.7/32"; got != want {
		t.Fatalf("anchor holds %q, want %q", got, want)
	}
}

// An IPv6 resolver gets rules of its own family; Neutron refuses a v6 remote on
// a v4 rule.
func TestResolverFamily(t *testing.T) {
	n, a := newAnchor(t)
	if err := n.SyncResolvers(t.Context(), "anchor", []string{"fd00::35"}); err != nil {
		t.Fatal(err)
	}
	for _, r := range a.rules {
		if r.EtherType != "IPv6" || r.RemoteIPPrefix != "fd00::35/128" {
			t.Errorf("got %s %s", r.EtherType, r.RemoteIPPrefix)
		}
	}
}

func sortedStrings(in []string) []string {
	slices.Sort(in)
	return in
}

// Two policies sharing a peer selector reach this from different workers. Neutron
// would accept both creates, and rules would then point at one group while the
// other is kept up to date.
func TestConcurrentAddressGroupsMakeOne(t *testing.T) {
	fs := th.SetupHTTP()
	defer fs.Teardown()
	var mu sync.Mutex
	made := []string{}
	fs.Mux.HandleFunc("/address-groups", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			list := []map[string]string{}
			for _, id := range made {
				list = append(list, map[string]string{"id": id, "name": "tst-peers-x"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"address_groups": list})
			return
		}
		id := fmt.Sprintf("g%d", len(made))
		made = append(made, id)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"address_group": map[string]string{"id": id}})
	})
	n := &Neutron{Naming: testNaming, Client: client.ServiceClient(fs)}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := n.EnsureAddressGroup(t.Context(), "tst-peers-x"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if len(made) != 1 {
		t.Errorf("made %d groups of one name", len(made))
	}
}

// Duplicates that already exist: every reader has to settle on the same one.
func TestDuplicateAddressGroupsResolveToTheSmallestID(t *testing.T) {
	fs := th.SetupHTTP()
	defer fs.Teardown()
	fs.Mux.HandleFunc("/address-groups", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"address_groups": []map[string]string{
			{"id": "b", "name": "tst-peers-x"}, {"id": "a", "name": "tst-peers-x"},
		}})
	})
	n := &Neutron{Naming: testNaming, Client: client.ServiceClient(fs)}
	got, err := n.EnsureAddressGroup(t.Context(), "tst-peers-x")
	if err != nil || got != "a" {
		t.Errorf("got %q, %v", got, err)
	}
}

// Knowing part of the answer must not cost the rule for the rest.
func TestAddResolversRemovesNothing(t *testing.T) {
	n, a := newAnchor(t)
	if err := n.SyncResolvers(t.Context(), "anchor", []string{"192.168.200.244"}); err != nil {
		t.Fatal(err)
	}
	if err := n.AddResolvers(t.Context(), "anchor", []string{"192.168.100.2"}); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(sortedStrings(a.prefixes()), ",")
	want := "tcp:192.168.100.2/32,tcp:192.168.200.244/32,udp:192.168.100.2/32,udp:192.168.200.244/32"
	if got != want {
		t.Fatalf("anchor holds %q, want %q", got, want)
	}
}

// This runs for every tenant on a timer: an unchanged answer must not write,
// because below ovn-northd 25.09 each write is a recompute for the whole region.
func TestUnchangedResolversWriteNothing(t *testing.T) {
	n, a := newAnchor(t)
	addrs := []string{"192.168.200.244", "fd79:c::2"}
	if err := n.SyncResolvers(t.Context(), "anchor", addrs); err != nil {
		t.Fatal(err)
	}
	if a.writes != 4 {
		t.Fatalf("first sync made %d writes, want 4", a.writes)
	}
	a.writes = 0
	if err := n.SyncResolvers(t.Context(), "anchor", addrs); err != nil {
		t.Fatal(err)
	}
	if err := n.AddResolvers(t.Context(), "anchor", addrs); err != nil {
		t.Fatal(err)
	}
	if a.writes != 0 {
		t.Fatalf("unchanged answer made %d writes", a.writes)
	}
}

// A caller joining two sources can name an address twice.
func TestRepeatedAddressIsWrittenOnce(t *testing.T) {
	n, a := newAnchor(t)
	if err := n.AddResolvers(t.Context(), "anchor", []string{"192.168.100.2", "192.168.100.2"}); err != nil {
		t.Fatal(err)
	}
	if a.writes != 2 {
		t.Fatalf("%d writes, want 2", a.writes)
	}
}

func TestAddingNothingAsksNothing(t *testing.T) {
	n, a := newAnchor(t)
	if err := n.AddResolvers(t.Context(), "anchor", nil); err != nil {
		t.Fatal(err)
	}
	if a.reads != 0 || a.writes != 0 {
		t.Fatalf("%d reads, %d writes", a.reads, a.writes)
	}
}

// Every resolver write spends the region's budget, and a caller out of budget
// leaves what is there.
func TestResolverWritesTakeAChurnToken(t *testing.T) {
	n, a := newAnchor(t)
	if err := n.SyncResolvers(t.Context(), "anchor", []string{"192.168.200.244"}); err != nil {
		t.Fatal(err)
	}
	a.writes = 0
	// One token: the first create, then nothing for an hour.
	n.Churn = rate.NewLimiter(rate.Every(time.Hour), 1)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	err := n.SyncResolvers(ctx, "anchor", []string{"192.168.100.2"})
	if err == nil {
		t.Fatal("ran past the budget")
	}
	if a.writes != 1 {
		t.Fatalf("%d writes, want 1", a.writes)
	}
	// New rules go in first, so the old resolver is still allowed.
	got := strings.Join(sortedStrings(a.prefixes()), ",")
	if !strings.Contains(got, "udp:192.168.200.244/32") || !strings.Contains(got, "tcp:192.168.200.244/32") {
		t.Fatalf("anchor holds %q", got)
	}
	// Nothing to do takes no token.
	n.Churn = rate.NewLimiter(rate.Every(time.Hour), 0)
	if err := n.AddResolvers(ctx, "anchor", []string{"192.168.200.244"}); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataAddresses(t *testing.T) {
	n, a := newAnchor(t)
	a.metadata["net"] = []string{"192.168.100.2", "fd79:c::2"}
	a.metadata["other"] = []string{"192.168.110.2"}
	got, err := n.MetadataAddresses(t.Context(), "net")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "192.168.100.2,fd79:c::2" {
		t.Fatalf("got %v", got)
	}
	// A network without the port is no error, and a failed read is not "none".
	if got, err := n.MetadataAddresses(t.Context(), "bare"); err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
	a.portsDown = true
	if _, err := n.MetadataAddresses(t.Context(), "net"); err == nil {
		t.Fatal("the failure went unreported")
	}
}
