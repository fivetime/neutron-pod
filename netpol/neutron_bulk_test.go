package netpol

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/rules"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
	"github.com/gophercloud/gophercloud/v2/testhelper/client"
)

// fakeRules is Neutron's security-group-rules collection: it counts what it
// receives, so the test can judge "how many requests" rather than "did it
// work" -- the whole point of the change is the count.
type fakeRules struct {
	bulkPosts   atomic.Int32
	singlePosts atomic.Int32
	// existing is what a listing answers; the conflict case fills it after
	// refusing the batch, the way another writer would have.
	existing []rules.SecGroupRule
	// refuseBulk makes the first batch a 409, as Neutron answers when any one
	// rule of the batch already exists.
	refuseBulk bool
}

func (f *fakeRules) serve(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"security_group_rules": f.existing})
	case http.MethodPost:
		var body map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		if raw, ok := body["security_group_rules"]; ok {
			f.bulkPosts.Add(1)
			if f.refuseBulk {
				f.refuseBulk = false
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"NeutronError":{"type":"SecurityGroupRuleExists","message":"already exists"}}`)
				return
			}
			var in []rules.CreateOpts
			_ = json.Unmarshal(raw, &in)
			out := make([]rules.SecGroupRule, len(in))
			for i := range in {
				out[i] = rules.SecGroupRule{ID: fmt.Sprintf("r%d", i)}
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"security_group_rules": out})
			return
		}
		f.singlePosts.Add(1)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"security_group_rule":{"id":"single"}}`)
	}
}

func tenRules(group string) []rules.CreateOpts {
	out := make([]rules.CreateOpts, 0, 10)
	for port := 80; port < 90; port++ {
		out = append(out, rules.CreateOpts{
			SecGroupID: group, Direction: rules.DirIngress, EtherType: rules.EtherType4,
			Protocol: rules.ProtocolTCP, PortRangeMin: port, PortRangeMax: port,
			RemoteIPPrefix: "10.0.0.0/8",
		})
	}
	return out
}

// TestRulesAreWrittenInOneRequest is the number this change exists for: ten
// rules a group lacks reach Neutron as one request, not ten.
func TestRulesAreWrittenInOneRequest(t *testing.T) {
	fs := th.SetupHTTP()
	defer fs.Teardown()
	f := &fakeRules{}
	fs.Mux.HandleFunc("/security-group-rules", f.serve)
	n := &Neutron{Naming: testNaming, Client: client.ServiceClient(fs)}

	if err := n.writeRules(t.Context(), "g", "gid", tenRules("gid"), nil); err != nil {
		t.Fatal(err)
	}
	if got := f.bulkPosts.Load(); got != 1 {
		t.Fatalf("ten missing rules took %d bulk requests, want 1", got)
	}
	if got := f.singlePosts.Load(); got != 0 {
		t.Fatalf("ten missing rules also took %d single requests; the batch was not trusted", got)
	}
}

// TestBulkConflictFallsBackToWhatIsStillMissing is the race the batch cannot
// tolerate on its own. ⚠️ One rule added by another writer between the read
// and the batch refuses the whole batch with a conflict; the driver must then
// re-read and write only what is still missing, one at a time, rather than
// fail the policy or re-send the batch into the same refusal.
func TestBulkConflictFallsBackToWhatIsStillMissing(t *testing.T) {
	fs := th.SetupHTTP()
	defer fs.Teardown()
	want := tenRules("gid")
	f := &fakeRules{refuseBulk: true}
	// After the refusal the listing shows the rule that caused it: the first.
	f.existing = []rules.SecGroupRule{{
		ID: "theirs", SecGroupID: "gid", Direction: "ingress", EtherType: "IPv4",
		Protocol: "tcp", PortRangeMin: 80, PortRangeMax: 80, RemoteIPPrefix: "10.0.0.0/8",
	}}
	fs.Mux.HandleFunc("/security-group-rules", f.serve)
	n := &Neutron{Naming: testNaming, Client: client.ServiceClient(fs)}

	if err := n.writeRules(t.Context(), "g", "gid", want, nil); err != nil {
		t.Fatalf("a conflict on one rule failed the whole policy: %v", err)
	}
	if got := f.bulkPosts.Load(); got != 1 {
		t.Fatalf("the batch was retried %d times into the same refusal", got-1)
	}
	if got := f.singlePosts.Load(); got != 9 {
		t.Fatalf("after the re-read %d rules were written singly, want the 9 still missing", got)
	}
}

// TestNothingMissingWritesNothing keeps the steady state silent: a resync of a
// group that already holds its rules must not touch Neutron at all.
func TestNothingMissingWritesNothing(t *testing.T) {
	fs := th.SetupHTTP()
	defer fs.Teardown()
	f := &fakeRules{}
	fs.Mux.HandleFunc("/security-group-rules", f.serve)
	n := &Neutron{Naming: testNaming, Client: client.ServiceClient(fs)}
	want := tenRules("gid")
	have := make([]rules.SecGroupRule, 0, len(want))
	for i, w := range want {
		have = append(have, rules.SecGroupRule{
			ID: fmt.Sprint(i), SecGroupID: "gid", Direction: "ingress", EtherType: "IPv4",
			Protocol: "tcp", PortRangeMin: w.PortRangeMin, PortRangeMax: w.PortRangeMax,
			RemoteIPPrefix: "10.0.0.0/8",
		})
	}
	if err := n.writeRules(t.Context(), "g", "gid", want, have); err != nil {
		t.Fatal(err)
	}
	if f.bulkPosts.Load()+f.singlePosts.Load() != 0 {
		t.Fatal("a steady state wrote to Neutron")
	}
}
