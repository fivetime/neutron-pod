package netpol

// Naming is what makes these groups one controller's own. Everything this package
// creates, finds or sweeps goes through it, so a controller keeps the names it
// already has in a project when it moves onto this module.
type Naming struct {
	// Prefix starts every group name, without the dash ("abc" gives "abc-deny-all").
	Prefix string
	// Product starts every group description ("abc: what NetworkPolicy ...").
	// The sweep reads the description back, so changing it orphans existing groups.
	Product string
}

// AllowIngress names the baseline for a pod no policy has isolated for ingress.
func (n Naming) AllowIngress() string { return n.Prefix + "-" + allowIngressName }

// AllowEgress names the baseline for a pod no policy has isolated for egress.
func (n Naming) AllowEgress() string { return n.Prefix + "-" + allowEgressName }

// DenyAll names the anchor every port carries.
func (n Naming) DenyAll() string { return n.Prefix + "-" + denyAllName }

func (n Naming) policyPrefix() string { return n.Prefix + "-policy-" }
func (n Naming) peerPrefix() string   { return n.Prefix + "-peers-" }
