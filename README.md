# neutron-pod

Shared parts of controllers that attach pods to OpenStack tenant networks.

| Package | |
|---|---|
| `netpol` | Kubernetes NetworkPolicy on Neutron ports |
| `l7` | Kubernetes Ingress on Octavia L7 load balancers |

Each holds what does not depend on how a pod reaches its port. Watching objects, finding
credentials and deciding when to apply stay in the controller using it.

## netpol

### What is here

| | |
|---|---|
| `Translate` | NetworkPolicy to rules, and a `Refusal` for what cannot be expressed |
| `PolicyRules`, `IsolationOf` | Rule sets and which directions a policy isolates |
| `Neutron` | Baseline, anchor and policy groups, resolver rules, address groups, sweep, optional reuse pool |
| `Naming` | Whose groups these are; two controllers in a project never touch each other's |
| `RefusedMessage`, `NotPreparedMessage` | What to tell the tenant, under `EventReason` |

### Semantics to keep in mind

- A security group is additive and has no deny. Anything not expressible stays denied:
  `ipBlock.except`, named ports and SCTP are refused, never widened.
- On OVN, a security group judges a connection's first packet before the load balancer
  rewrites its destination, and the packets after it by the address they are rewritten to.
  So egress through a load balancer has to allow both. Allowing only the VIP connects and
  then hangs waiting for a response; allowing only the backend pods times out on connect.
  An Octavia L7 provider's backends are its workers, which the tenant cannot see: allow the
  VIP subnet on the listener port.
- Creating or deleting a security group makes ovn-northd recompute. Pace it with
  `Churn`, and leave `Pool` off below ovn-northd 25.09.
- Group names and descriptions are in production. A changed name mints a new group for
  every policy of every tenant, so `TestExistingGroupsKeepTheirNames` pins them; changing
  one is a migration.
- The anchor's resolver rules are on every port of a tenant, and reconciled for every
  tenant on a timer. An unchanged answer writes nothing, and writes take a `Churn` token.

## l7

### What is here

| | |
|---|---|
| `Octavia` | The load balancer calls this package makes. The controller implements it, so how it waits for a load balancer to settle stays its own |
| `CollectBackends`, `ResolveServicePort`, `PoolName` | Ingress backends and the pools they map to |
| `EnsureBackendPool`, `GCStalePools` | Pools with their HTTP health monitors, and removing the ones no backend references |
| `EnsureListener` | The one listener of an Ingress, and removing the protocol it no longer serves |
| `BuildPolicies`, `SyncPolicies` | Host and path rules as ordered l7policies |
| `TuningFromAnnotations` | The upstream `octavia.ingress.kubernetes.io/*` listener annotations |
| `EnsureBarbicanSecret`, `CleanupBarbicanSecrets` | TLS Secrets as PKCS12 bundles in Barbican |

The load balancer itself, members and the floating IP stay in the controller.

### Semantics to keep in mind

- Order within a reconcile: pools, `EnsureListener`, members, `SyncPolicies`, `GCStalePools`.
  Member changes flip a load balancer to PENDING_UPDATE, and a listener whose TLS ref needs
  repair cannot wait behind them.
- Clean up Barbican only after `EnsureListener` holds the new refs. Secrets are immutable and
  named by content, so rotation creates a new one and re-points the listener first.
- A policy with no rules matches nothing. `SyncPolicies` treats a live one as drift and rebuilds it.
- `SyncPolicies` replaces the whole set on any difference, new set in front before the old one
  goes, so a rule change does not stop the listener serving. Each write waits for the load
  balancer to settle, about 8 seconds on incus, so the change itself takes that long per object.
  An unchanged Ingress writes nothing, and `TestSyncPoliciesWritesNothingWhenConverged` holds
  it to that. Policies not named after the Ingress are left alone and end up behind ours.
- Object names are in production. A changed name recreates the objects of every Ingress, so
  `TestExistingObjectsKeepTheirNames` pins them; changing one is a migration.
