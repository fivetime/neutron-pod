// Package l7 turns an Ingress into Octavia L7 objects: pools and their HTTP
// health monitors, the listener, l7policies and l7rules, and the TLS bundles in
// Barbican.
//
// It holds what does not depend on how a controller is built. Watching Ingresses,
// finding credentials, creating the load balancer, resolving members and exposing
// a floating IP stay in the controller using it.
package l7

import (
	"context"
	"errors"

	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/l7policies"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/monitors"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/pools"
)

// ErrNotFound is what Octavia lookups by name return when nothing matches.
var ErrNotFound = errors.New("not found")

// Octavia is the part of the load balancer API this package calls. A controller
// implements it over its own client, so how it waits for a load balancer to settle
// and what it records about each call stay its own.
//
// Every write returns only after the load balancer is settled: Octavia refuses to
// touch one that is still provisioning, and the next call here would fail. Deleting
// what is already gone is not an error.
type Octavia interface {
	// GetPoolByName and GetListenerByName return ErrNotFound when nothing matches.
	GetPoolByName(ctx context.Context, lbID, name string) (*pools.Pool, error)
	ListPools(ctx context.Context, lbID string) ([]pools.Pool, error)
	CreatePool(ctx context.Context, lbID string, opts pools.CreateOpts) (*pools.Pool, error)
	DeletePool(ctx context.Context, lbID, poolID string) error

	CreateHealthMonitor(ctx context.Context, lbID string, opts monitors.CreateOpts) error

	GetListenerByName(ctx context.Context, lbID, name string) (*listeners.Listener, error)
	CreateListener(ctx context.Context, lbID string, opts listeners.CreateOpts) (*listeners.Listener, error)
	UpdateListener(ctx context.Context, lbID, listenerID string, opts listeners.UpdateOpts) error
	DeleteListener(ctx context.Context, lbID, listenerID string) error

	ListL7Policies(ctx context.Context, listenerID string) ([]l7policies.L7Policy, error)
	ListL7Rules(ctx context.Context, policyID string) ([]l7policies.Rule, error)
	CreateL7Policy(ctx context.Context, lbID string, opts l7policies.CreateOpts) (*l7policies.L7Policy, error)
	CreateL7Rule(ctx context.Context, lbID, policyID string, opts l7policies.CreateRuleOpts) error
	DeleteL7Policy(ctx context.Context, lbID, policyID string) error
}
