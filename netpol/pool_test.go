package netpol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
	"github.com/gophercloud/gophercloud/v2/testhelper/client"
)

// fakeNeutron models the two things the pool's safety rests on and nothing
// else: a group's revision_number, bumped by any change to it or its rules,
// and a PUT that refuses a stale If-Match with 412. Ports are a count per
// group -- how many carry it -- because that is the only question asked.
type fakeNeutron struct {
	mu     sync.Mutex
	groups map[string]*fakeGroup
	rules  map[string]string // rule id -> group id
	next   int
	// bumpBeforePut simulates another claimant winning between the list
	// and the conditional update: the named group's revision moves once,
	// the first time a PUT reaches it.
	bumpBeforePut map[string]bool

	creates, deletes, puts, ruleDeletes int
}

type fakeGroup struct {
	ID, Name, Description string
	Revision              int
	Ports                 int
}

func newFakeNeutron() *fakeNeutron {
	return &fakeNeutron{groups: map[string]*fakeGroup{}, rules: map[string]string{}, bumpBeforePut: map[string]bool{}}
}

func (f *fakeNeutron) add(name, desc string, nrules, ports int) *fakeGroup {
	f.next++
	g := &fakeGroup{ID: fmt.Sprintf("%08d-0000-0000-0000-000000000000", f.next), Name: name, Description: desc, Revision: 1, Ports: ports}
	f.groups[g.ID] = g
	for i := 0; i < nrules; i++ {
		f.next++
		f.rules[fmt.Sprintf("rule-%d", f.next)] = g.ID
	}
	return g
}

func (f *fakeNeutron) view(g *fakeGroup) map[string]any {
	return map[string]any{"id": g.ID, "name": g.Name, "description": g.Description, "revision_number": g.Revision, "security_group_rules": []any{}}
}

func (f *fakeNeutron) mount(mux *http.ServeMux) {
	enc := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/security-groups", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			name := r.URL.Query().Get("name")
			out := []any{}
			for _, g := range f.groups {
				if name == "" || g.Name == name {
					out = append(out, f.view(g))
				}
			}
			enc(w, 200, map[string]any{"security_groups": out})
		case http.MethodPost:
			var body struct {
				G struct{ Name, Description string } `json:"security_group"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.creates++
			g := f.add(body.G.Name, body.G.Description, 0, 0)
			enc(w, 201, map[string]any{"security_group": f.view(g)})
		}
	})
	mux.HandleFunc("/security-groups/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		id := strings.TrimPrefix(r.URL.Path, "/security-groups/")
		g, ok := f.groups[id]
		if !ok {
			w.WriteHeader(404)
			return
		}
		switch r.Method {
		case http.MethodGet:
			enc(w, 200, map[string]any{"security_group": f.view(g)})
		case http.MethodPut:
			f.puts++
			if f.bumpBeforePut[id] {
				g.Revision++
				delete(f.bumpBeforePut, id)
			}
			if im := r.Header.Get("If-Match"); im != "" && im != fmt.Sprintf("revision_number=%d", g.Revision) {
				w.WriteHeader(412)
				return
			}
			var body struct {
				G struct{ Name, Description *string } `json:"security_group"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.G.Name != nil {
				g.Name = *body.G.Name
			}
			if body.G.Description != nil {
				g.Description = *body.G.Description
			}
			g.Revision++
			enc(w, 200, map[string]any{"security_group": f.view(g)})
		case http.MethodDelete:
			if g.Ports > 0 {
				w.WriteHeader(409)
				return
			}
			f.deletes++
			delete(f.groups, id)
			w.WriteHeader(204)
		}
	})
	mux.HandleFunc("/security-group-rules", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		gid := r.URL.Query().Get("security_group_id")
		out := []any{}
		for rid, owner := range f.rules {
			if owner == gid {
				out = append(out, map[string]any{"id": rid, "security_group_id": gid, "direction": "ingress", "ethertype": "IPv4"})
			}
		}
		enc(w, 200, map[string]any{"security_group_rules": out})
	})
	mux.HandleFunc("/security-group-rules/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		rid := strings.TrimPrefix(r.URL.Path, "/security-group-rules/")
		if gid, ok := f.rules[rid]; ok {
			delete(f.rules, rid)
			f.groups[gid].Revision++ // rules revise their group
			f.ruleDeletes++
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("/ports", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		out := []any{}
		for _, gid := range r.URL.Query()["security_groups"] {
			if g, ok := f.groups[gid]; ok {
				for i := 0; i < g.Ports; i++ {
					out = append(out, map[string]any{"id": fmt.Sprintf("port-%s-%d", gid[:4], i)})
				}
			}
		}
		enc(w, 200, map[string]any{"ports": out})
	})
	mux.HandleFunc("/address-groups", func(w http.ResponseWriter, r *http.Request) {
		enc(w, 200, map[string]any{"address_groups": []any{}})
	})
}

func poolFixture(t *testing.T) (*fakeNeutron, *Neutron) {
	t.Helper()
	fs := th.SetupHTTP()
	t.Cleanup(fs.Teardown)
	f := newFakeNeutron()
	f.mount(fs.Mux)
	return f, &Neutron{Naming: testNaming, Client: client.ServiceClient(fs), Pool: true, PoolCap: 16}
}

func (f *fakeNeutron) byID(id string) *fakeGroup {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.groups[id]
}

// TestClaimReusesAFreeGroup is the point: a policy that finds a released
// group takes it by rename and creates nothing -- the create is the event
// that recomputes the region.
func TestClaimReusesAFreeGroup(t *testing.T) {
	f, n := poolFixture(t)
	free := f.add(testNaming.freePrefix()+"aaaa", testNaming.freeDescription(), 0, 0)

	id, err := n.ensureGroup(context.Background(), "tst-policy-1234", "test: what NetworkPolicy ns/p allows")
	if err != nil {
		t.Fatal(err)
	}
	if id != free.ID {
		t.Fatalf("claimed %s, want the free group %s", id, free.ID)
	}
	if f.creates != 0 {
		t.Fatalf("a free group was available and %d groups were still created", f.creates)
	}
	if g := f.byID(id); g.Name != "tst-policy-1234" || !strings.Contains(g.Description, "ns/p") {
		t.Fatalf("claimed group not renamed for the policy: %+v", g)
	}
}

// TestLostClaimRaceMovesOn is invariant I2 under contention: the group's
// revision moved after it was listed, so the conditional rename is refused
// and the claimant takes the next free group rather than the contested one.
func TestLostClaimRaceMovesOn(t *testing.T) {
	f, n := poolFixture(t)
	contested := f.add(testNaming.freePrefix()+"aaaa", testNaming.freeDescription(), 0, 0)
	other := f.add(testNaming.freePrefix()+"bbbb", testNaming.freeDescription(), 0, 0)
	f.bumpBeforePut[contested.ID] = true

	id, err := n.ensureGroup(context.Background(), "tst-policy-1", "test: what NetworkPolicy ns/p allows")
	if err != nil {
		t.Fatal(err)
	}
	if id == contested.ID {
		t.Fatal("a group whose revision moved was claimed anyway; two policies could now share it")
	}
	if id != other.ID {
		t.Fatalf("claimed %s, want the uncontested free group %s", id, other.ID)
	}
	if f.creates != 0 {
		t.Fatal("losing one race created a group instead of trying the next free one")
	}
}

// TestDirtyFreeGroupIsAbandoned is invariant I1 as a check, not an
// assumption: a group that reads as free but still sits on a port would hand
// that port this policy's allows. It is given back and a new group is
// created -- a recompute rather than a wrong allow.
func TestDirtyFreeGroupIsAbandoned(t *testing.T) {
	f, n := poolFixture(t)
	dirty := f.add(testNaming.freePrefix()+"aaaa", testNaming.freeDescription(), 0, 1)

	id, err := n.ensureGroup(context.Background(), "tst-policy-1", "test: what NetworkPolicy ns/p allows")
	if err != nil {
		t.Fatal(err)
	}
	if id == dirty.ID {
		t.Fatal("a free group still carried by a port was used for a policy")
	}
	if f.creates != 1 {
		t.Fatalf("expected one fresh group after abandoning the dirty one, created %d", f.creates)
	}
	if g := f.byID(dirty.ID); !strings.HasPrefix(g.Name, testNaming.freePrefix()) {
		t.Fatalf("the abandoned group kept the policy's name: %s", g.Name)
	}
}

// TestReleaseWaitsForPorts: a deleted policy's group keeps its rules until no
// port carries it. Emptying it first would change what those pods allow
// before their ports are rewritten.
func TestReleaseWaitsForPorts(t *testing.T) {
	f, n := poolFixture(t)
	g := f.add("tst-policy-dead", "test: what NetworkPolicy ns/gone allows", 3, 1)

	if _, err := n.Sweep(context.Background(), map[string]bool{}, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if f.ruleDeletes != 0 {
		t.Fatalf("%d rules were removed from a group still on a port", f.ruleDeletes)
	}
	if got := f.byID(g.ID); got.Name != "tst-policy-dead" {
		t.Fatalf("a group still on a port was released: %s", got.Name)
	}
}

// TestReleaseEmptiesThenRenames pins the order inside a release: rules go
// first, the name last, so a group that reads as free never holds a rule.
// The rename is conditional on the revision the rule deletions produced.
func TestReleaseEmptiesThenRenames(t *testing.T) {
	f, n := poolFixture(t)
	g := f.add("tst-policy-dead", "test: what NetworkPolicy ns/gone allows", 3, 0)

	removed, err := n.Sweep(context.Background(), map[string]bool{}, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("released %d groups, want 1", removed)
	}
	if f.ruleDeletes != 3 {
		t.Fatalf("%d rules removed, want all 3", f.ruleDeletes)
	}
	got := f.byID(g.ID)
	if !strings.HasPrefix(got.Name, testNaming.freePrefix()) || got.Description != testNaming.freeDescription() {
		t.Fatalf("released group not marked free: %+v", got)
	}
	if f.deletes != 0 {
		t.Fatal("the sweep deleted a group it should have released; that is the recompute the pool exists to avoid")
	}
}

// TestPoolCapTrims: released groups beyond the cap are deleted, because each
// one held is quota, and each one deleted is a recompute -- the cap is where
// the trade is made, and nowhere else.
func TestPoolCapTrims(t *testing.T) {
	f, n := poolFixture(t)
	n.PoolCap = 1
	for i := 0; i < 3; i++ {
		f.add(fmt.Sprintf("%s%04d", testNaming.freePrefix(), i), testNaming.freeDescription(), 0, 0)
	}
	if _, err := n.Sweep(context.Background(), map[string]bool{}, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if f.deletes != 2 {
		t.Fatalf("trimmed %d free groups, want 2 above a cap of 1", f.deletes)
	}
	left := 0
	for _, g := range f.groups {
		if strings.HasPrefix(g.Name, testNaming.freePrefix()) {
			left++
		}
	}
	if left != 1 {
		t.Fatalf("%d free groups left, want the cap of 1", left)
	}
}

var _ = groups.SecGroup{} // keep the import honest if the fake grows a typed view

// TestPoolOffDeletesAsBefore is the gate: below OVN 25.09 a release costs a
// recompute per rule where a delete costs one, so with the pool off the
// sweep must delete, and a policy must create rather than claim.
func TestPoolOffDeletesAsBefore(t *testing.T) {
	f, n := poolFixture(t)
	n.Pool = false
	f.add("tst-policy-dead", "test: what NetworkPolicy ns/gone allows", 3, 0)
	free := f.add(testNaming.freePrefix()+"aaaa", testNaming.freeDescription(), 0, 0)

	if _, err := n.Sweep(context.Background(), map[string]bool{}, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if f.deletes != 1 || f.ruleDeletes != 0 {
		t.Fatalf("pool off: deletes=%d ruleDeletes=%d, want the group deleted whole (1, 0)", f.deletes, f.ruleDeletes)
	}
	id, err := n.ensureGroup(context.Background(), "tst-policy-new", "test: what NetworkPolicy ns/p allows")
	if err != nil {
		t.Fatal(err)
	}
	if id == free.ID {
		t.Fatal("pool off, yet a free group was claimed")
	}
	if f.creates != 1 {
		t.Fatalf("pool off: created %d groups, want 1", f.creates)
	}
}
