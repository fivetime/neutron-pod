package netpol

import (
	"errors"
	"strings"
	"testing"
)

var testNaming = Naming{Prefix: "tst", Product: "test"}

// Two controllers in one project must never collect each other's groups.
func TestNamingKeepsControllersApart(t *testing.T) {
	a, b := Naming{Prefix: "abc", Product: "one"}, Naming{Prefix: "xyz", Product: "two"}
	if a.DenyAll() != "abc-deny-all" || b.DenyAll() != "xyz-deny-all" {
		t.Fatal(a.DenyAll(), b.DenyAll())
	}
	if a.PolicyGroup("ns", "p") == b.PolicyGroup("ns", "p") {
		t.Fatal("same policy group name for two controllers")
	}
	written := "one: what NetworkPolicy ns/p allows"
	if a.policyOf(written) != "ns/p" || b.policyOf(written) != "" {
		t.Fatalf("%q %q", a.policyOf(written), b.policyOf(written))
	}
}

func TestMessagesNameBothHalvesAndLeakNoEndpoint(t *testing.T) {
	for err, want := range map[error]string{
		errors.New("Expected HTTP response code ... OverQuota ..."): "quota is exhausted",
		errors.New("dial http://192.0.2.10/ refused"):               "retried",
	} {
		got := NotPreparedMessage(err, "")
		if !strings.Contains(got, want) || !strings.Contains(got, "pods already running keep their current access") || strings.Contains(got, "192.0.2.10") {
			t.Fatal(got)
		}
	}
	if got := NotPreparedMessage(errors.New("x"), "not provisioned here"); !strings.HasSuffix(got, "; not provisioned here") {
		t.Fatal(got)
	}
	got := RefusedMessage([]Refusal{{Field: "spec.ingress[0]", Reason: "no"}})
	if !strings.Contains(got, "stays denied") || !strings.Contains(got, "spec.ingress[0]: no") {
		t.Fatal(got)
	}
}

// A controller moving onto this module must find the groups it already has. A name
// that changed would mint a new group for every policy of every tenant, and creating
// a security group object is what ovn-northd recomputes the whole region for. A
// description that changed rewrites every group and orphans it from the sweep.
// These strings are in production: changing one is a migration, not a refactor.
func TestExistingGroupsKeepTheirNames(t *testing.T) {
	kubezun := Naming{Prefix: "knp", Product: "kubezun"}
	kubetron := Naming{Prefix: "ktn", Product: "kubetron"}
	for got, want := range map[string]string{
		kubezun.AllowIngress():          "knp-allow-ingress",
		kubezun.AllowEgress():           "knp-allow-egress",
		kubezun.DenyAll():               "knp-deny-all",
		kubezun.PolicyGroup("ns", "p"):  "knp-policy-75fe947f4ed54540",
		kubezun.PeerGroup("key"):        "knp-peers-2c70e12b7a0646f9",
		kubezun.freePrefix():            "knp-free-",
		kubezun.managedBy():             "kubezun-networkpolicy",
		kubezun.freeDescription():       "kubezun: free [kubezun-networkpolicy]",
		kubetron.AllowIngress():         "ktn-allow-ingress",
		kubetron.AllowEgress():          "ktn-allow-egress",
		kubetron.DenyAll():              "ktn-deny-all",
		kubetron.PolicyGroup("ns", "p"): "ktn-policy-75fe947f4ed54540",
		kubetron.PeerGroup("key"):       "ktn-peers-2c70e12b7a0646f9",
		kubetron.managedBy():            "kubetron-networkpolicy",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if got := kubezun.policyOf("kubezun: what NetworkPolicy ns/p allows"); got != "ns/p" {
		t.Errorf("a kubezun group reads back as %q", got)
	}
	if got := kubetron.policyOf("kubetron: what NetworkPolicy ns/p allows"); got != "ns/p" {
		t.Errorf("a kubetron group reads back as %q", got)
	}
}
