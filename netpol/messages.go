package netpol

import "strings"

// EventReason is the reason on every Warning this package's messages go out under.
const EventReason = "NotEnforced"

// RefusedMessage says which parts of a policy were refused. Send it as a Warning
// on the policy: a tenant has the Kubernetes API and nothing else, a NetworkPolicy
// has no status, and a refused part looks exactly like a policy that works and
// traffic that does not.
func RefusedMessage(refused []Refusal) string {
	return "parts of this NetworkPolicy are not enforced, and the traffic they " +
		"would have allowed stays denied: " + RefusalMessage(refused)
}

// NotPreparedMessage says a policy could not be prepared. Send it as a Warning on
// the policy.
//
// ⚠️ Both halves matter. A new pod the policy selects waits for it, but a running
// pod's port keeps its groups: it is NOT yet isolated, and its access is wider than
// the policy asks. "Pods are waiting" alone would let the tenant believe otherwise.
//
// ⚠️ Not the raw error, which carries internal endpoints: a tenant reads Events.
// detail, if not empty, is a sentence the caller vouches is safe to show.
func NotPreparedMessage(err error, detail string) string {
	message := "this NetworkPolicy has not taken effect yet: new pods it selects wait " +
		"for it, and pods already running keep their current access until it does"
	switch {
	case detail != "":
		return message + "; " + detail
	case err != nil && strings.Contains(err.Error(), "OverQuota"):
		return message + "; the project's security group quota is exhausted, ask the platform to raise it"
	}
	return message + "; it will be retried"
}
