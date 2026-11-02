package netpol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	th "github.com/gophercloud/gophercloud/v2/testhelper"
	"github.com/gophercloud/gophercloud/v2/testhelper/client"
)

// An address leaves every peer set of ours, in stored (CIDR) form, and groups
// that are not ours are left alone even when they hold it.
func TestEvictAddressLeavesEveryPeerSet(t *testing.T) {
	srv := th.SetupHTTP()
	defer srv.Teardown()
	var removals []string
	fail := false
	srv.Mux.HandleFunc("/address-groups", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"address_groups":[
		  {"id":"a","name":"tst-peers-1","addresses":["192.168.1.5/32","192.168.1.6/32"]},
		  {"id":"b","name":"tst-peers-2","addresses":["192.168.1.6/32"]},
		  {"id":"c","name":"tst-peers-3","addresses":["192.168.1.5/32"]},
		  {"id":"d","name":"tenant-own","addresses":["192.168.1.5/32"]}]}`)
	})
	srv.Mux.HandleFunc("/address-groups/", func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var body struct {
			Addresses []string `json:"addresses"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		id := strings.Split(strings.TrimPrefix(r.URL.Path, "/address-groups/"), "/")[0]
		removals = append(removals, id+"="+strings.Join(body.Addresses, ","))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"address_group":{"id":%q}}`, id)
	})
	n := &Neutron{Naming: testNaming, Client: client.ServiceClient(srv)}

	got, err := n.EvictAddress(context.Background(), "192.168.1.5")
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 || strings.Join(removals, " ") != "a=192.168.1.5/32 c=192.168.1.5/32" {
		t.Fatalf("removed %d: %v", got, removals)
	}

	// A failed removal must surface: the caller may not delete the port.
	fail = true
	if _, err := n.EvictAddress(context.Background(), "192.168.1.5"); err == nil {
		t.Fatal("a failed removal must be reported")
	}
}

// A just-created group must be identifiable by the sweep from its first write.
func TestCreatedGroupIsIdentifiableBySweep(t *testing.T) {
	srv := th.SetupHTTP()
	defer srv.Teardown()
	var created string
	srv.Mux.HandleFunc("/security-groups", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `{"security_groups":[]}`)
			return
		}
		var body struct {
			Group struct {
				Description string `json:"description"`
			} `json:"security_group"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		created = body.Group.Description
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"security_group":{"id":"g"}}`)
	})
	n := &Neutron{Naming: testNaming, Client: client.ServiceClient(srv)}
	const description = "test: what NetworkPolicy prod/web allows"
	if _, err := n.ensureGroup(context.Background(), "tst-policy-x", description); err != nil {
		t.Fatal(err)
	}
	if got := testNaming.policyOf(created); got != "prod/web" {
		t.Fatalf("testNaming.policyOf(%q) = %q: the sweep could never collect this group", created, got)
	}
}

// Duplicate names exist (Neutron does not refuse them, and a race made one live):
// every reader must pick the same group, and the others can be removed, except one
// still on a port.
func TestDuplicateGroupNames(t *testing.T) {
	srv := th.SetupHTTP()
	defer srv.Teardown()
	var deleted []string
	srv.Mux.HandleFunc("/security-groups", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"security_groups":[{"id":"z","name":"tst-deny-all"},{"id":"a","name":"tst-deny-all","description":"d"},{"id":"m","name":"tst-deny-all"}]}`)
	})
	srv.Mux.HandleFunc("/security-groups/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/security-groups/")
		if id == "m" {
			w.WriteHeader(http.StatusConflict) // still on a port
			return
		}
		deleted = append(deleted, id)
		w.WriteHeader(http.StatusNoContent)
	})
	n := &Neutron{Naming: testNaming, Client: client.ServiceClient(srv)}
	id, _, err := n.findGroup(context.Background(), "tst-deny-all")
	if err != nil || id != "a" {
		t.Fatalf("readers must agree on the lowest id, got %q %v", id, err)
	}
	if err := n.PruneDuplicates(context.Background(), "tst-deny-all", "a"); err != nil {
		t.Fatalf("a duplicate on a port must not be an error: %v", err)
	}
	if strings.Join(deleted, ",") != "z" {
		t.Fatalf("deleted = %v", deleted)
	}
}
