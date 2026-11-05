package l7

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
)

// Upstream octavia-ingress-controller listener-tuning annotations, kept verbatim:
// source whitelist and the four HAProxy timeouts, all applied at the listener.
const (
	SourceRangesAnnotation         = "octavia.ingress.kubernetes.io/whitelist-source-range"
	TimeoutClientDataAnnotation    = "octavia.ingress.kubernetes.io/timeout-client-data"
	TimeoutMemberDataAnnotation    = "octavia.ingress.kubernetes.io/timeout-member-data"
	TimeoutMemberConnectAnnotation = "octavia.ingress.kubernetes.io/timeout-member-connect"
	TimeoutTCPInspectAnnotation    = "octavia.ingress.kubernetes.io/timeout-tcp-inspect"
)

// Tuning is the parsed listener-level tuning of one Ingress.
//
// Asymmetric management, on purpose:
//   - AllowedCIDRs is ALWAYS enforced — an empty list when the annotation is
//     absent. A whitelist is a security control; "annotation removed but the
//     old whitelist silently stays" would keep locking clients out with
//     nothing left in the spec to explain why.
//   - Timeouts are enforced only while their annotation is present (nil =
//     unmanaged): their defaults are the provider's business, and resetting
//     them to hardcoded values on annotation removal would surprise more than
//     it helps.
type Tuning struct {
	AllowedCIDRs         []string
	TimeoutClientData    *int
	TimeoutMemberData    *int
	TimeoutMemberConnect *int
	TimeoutTCPInspect    *int
}

// TuningFromAnnotations parses the tuning annotations. Malformed values are
// ERRORS (failing the reconcile visibly), never silently ignored: a whitelist
// typo that quietly applied nothing would expose a listener its operator
// believes is restricted.
func TuningFromAnnotations(ing *networkingv1.Ingress) (*Tuning, error) {
	t := &Tuning{AllowedCIDRs: []string{}}
	if raw := strings.TrimSpace(ing.Annotations[SourceRangesAnnotation]); raw != "" {
		for _, part := range strings.Split(raw, ",") {
			cidr := strings.TrimSpace(part)
			if cidr == "" {
				continue
			}
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return nil, fmt.Errorf("%s: %q is not a CIDR: %w", SourceRangesAnnotation, cidr, err)
			}
			t.AllowedCIDRs = append(t.AllowedCIDRs, cidr)
		}
		if len(t.AllowedCIDRs) == 0 {
			return nil, fmt.Errorf("%s is set but contains no CIDR", SourceRangesAnnotation)
		}
	}
	for _, spec := range []struct {
		key  string
		dest **int
	}{
		{TimeoutClientDataAnnotation, &t.TimeoutClientData},
		{TimeoutMemberDataAnnotation, &t.TimeoutMemberData},
		{TimeoutMemberConnectAnnotation, &t.TimeoutMemberConnect},
		{TimeoutTCPInspectAnnotation, &t.TimeoutTCPInspect},
	} {
		raw := strings.TrimSpace(ing.Annotations[spec.key])
		if raw == "" {
			continue
		}
		v, err := strconv.Atoi(raw)
		if err != nil || v < 0 {
			return nil, fmt.Errorf("%s: %q is not a non-negative integer (milliseconds)", spec.key, raw)
		}
		*spec.dest = &v
	}
	return t, nil
}

// cidrsEqual compares two CIDR sets order-insensitively.
func cidrsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as, bs := slices.Clone(a), slices.Clone(b)
	slices.Sort(as)
	slices.Sort(bs)
	return slices.Equal(as, bs)
}

// timeoutDrift reports whether a MANAGED timeout (non-nil desired) differs
// from the live value.
func timeoutDrift(desired *int, live int) bool {
	return desired != nil && *desired != live
}
