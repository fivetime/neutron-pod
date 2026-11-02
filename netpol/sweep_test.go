package netpol

import (
	"net/http"
	"testing"

	th "github.com/gophercloud/gophercloud/v2/testhelper"
	"github.com/gophercloud/gophercloud/v2/testhelper/client"
)

// TestPolicyOfReadsBackWhatEnsureWrote keeps the sweep's only means of
// identification working. The group name is a hash, so the description is the
// only thing that says whose it is -- and a sweep that cannot tell is a sweep
// that must either leak forever or delete another process's groups.
func TestPolicyOfReadsBackWhatEnsureWrote(t *testing.T) {
	written := "test: what NetworkPolicy prod/web-deny allows"
	if got := testNaming.policyOf(written); got != "prod/web-deny" {
		t.Errorf("testNaming.policyOf(%q) = %q", written, got)
	}
	// Anything not written by this must be left alone, not misparsed into a
	// name that happens to look sweepable.
	for _, other := range []string{
		"", "default", "test: allows nothing",
		"some other tool's group", "test: what NetworkPolicy prod/web",
	} {
		if got := testNaming.policyOf(other); got != "" {
			t.Errorf("testNaming.policyOf(%q) claimed %q", other, got)
		}
	}
}

// A group has to be identifiable from the moment it is created, not from the
// next time something rewrites it: a policy deleted before then left a group
// the sweep could never collect. The test above reads a string it wrote itself,
// which is how this went unnoticed.
func TestACreatedGroupIsIdentifiable(t *testing.T) {
	fs := th.SetupHTTP()
	defer fs.Teardown()
	f := newFakeNeutron()
	f.mount(fs.Mux)
	var _ http.Handler = fs.Mux
	n := &Neutron{Naming: testNaming, Client: client.ServiceClient(fs)}

	const want = "test: what NetworkPolicy prod/web-deny allows"
	id, err := n.ensureGroup(t.Context(), "tst-policy-x", want)
	if err != nil {
		t.Fatal(err)
	}
	if got := testNaming.policyOf(f.byID(id).Description); got != "prod/web-deny" {
		t.Errorf("a new group's description %q reads back as policy %q",
			f.byID(id).Description, got)
	}
}
