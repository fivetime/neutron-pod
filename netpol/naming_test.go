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
