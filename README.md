# neutron-pod

Kubernetes NetworkPolicy on Neutron ports: translation, rule sets and the Neutron
calls, for controllers that attach pods to OpenStack tenant networks.

It holds what does not depend on how a pod reaches its port. Watching policies,
finding the port and deciding when to apply stay in the controller using it.

## What is here

| | |
|---|---|
| `Translate` | NetworkPolicy to rules, and a `Refusal` for what cannot be expressed |
| `PolicyRules`, `IsolationOf` | Rule sets and which directions a policy isolates |
| `Neutron` | Baseline, anchor and policy groups, address groups, sweep, optional reuse pool |
| `Naming` | Whose groups these are; two controllers in a project never touch each other's |
| `RefusedMessage`, `NotPreparedMessage` | What to tell the tenant, under `EventReason` |

## Semantics to keep in mind

- A security group is additive and has no deny. Anything not expressible stays denied:
  `ipBlock.except`, named ports and SCTP are refused, never widened.
- On OVN, a security group judges a connection's first packet before the load balancer
  rewrites its destination. Egress to a Service needs the Service address, and a policy
  naming the backend pods does not admit their Service.
- Creating or deleting a security group makes ovn-northd recompute. Pace it with
  `Churn`, and leave `Pool` off below ovn-northd 25.09.
