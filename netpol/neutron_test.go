package netpol

import (
	"reflect"
	"testing"
)

// TestDiffAddressesComparesInTheStoredForm guards the loop this would
// otherwise become. Neutron stores an address as a CIDR, so a bare address
// sent in comes back with a prefix; comparing the two forms literally makes
// every pass believe every address is missing, re-adding all of them, and
// every add of an existing address is a 400.
func TestDiffAddressesComparesInTheStoredForm(t *testing.T) {
	add, remove := diffAddresses(
		[]string{"10.0.0.1/32", "10.0.0.2/32"},
		[]string{"10.0.0.1", "10.0.0.3"})
	if !reflect.DeepEqual(add, []string{"10.0.0.3/32"}) {
		t.Errorf("add = %v, want [10.0.0.3/32]", add)
	}
	if !reflect.DeepEqual(remove, []string{"10.0.0.2/32"}) {
		t.Errorf("remove = %v, want [10.0.0.2/32]", remove)
	}

	// Nothing to do must produce nothing to send: an empty diff is what keeps
	// a steady state from writing to Neutron on every resync.
	add, remove = diffAddresses([]string{"10.0.0.1/32"}, []string{"10.0.0.1"})
	if len(add) != 0 || len(remove) != 0 {
		t.Errorf("a steady state produced work: add=%v remove=%v", add, remove)
	}

	if got := normalizeCIDR("fd00::5"); got != "fd00::5/128" {
		t.Errorf("v6 host address normalised to %q", got)
	}
}
