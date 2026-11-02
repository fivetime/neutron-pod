package netpol

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/rules"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
	"github.com/gophercloud/gophercloud/v2/testhelper/client"
)

// anchorRules is the deny-all group with real rule contents: what is created
// shows up in the next listing and what is deleted does not.
type anchorRules struct {
	mu    sync.Mutex
	rules map[string]rules.SecGroupRule
	next  int
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
	a := &anchorRules{rules: map[string]rules.SecGroupRule{}}
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
			out := []rules.SecGroupRule{}
			for _, v := range a.rules {
				out = append(out, v)
			}
			enc(w, 200, map[string]any{"security_group_rules": out})
			return
		}
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
		delete(a.rules, strings.TrimPrefix(r.URL.Path, "/security-group-rules/"))
		w.WriteHeader(204)
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
