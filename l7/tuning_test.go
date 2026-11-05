package l7

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ingAnnotated(ann map[string]string) *networkingv1.Ingress {
	return &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
		Namespace: "t1", Name: "web", Annotations: ann}}
}

func TestTuningDefaults(t *testing.T) {
	got, err := TuningFromAnnotations(ingAnnotated(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.AllowedCIDRs) != 0 {
		t.Fatalf("no annotation must mean empty (enforced-open) whitelist, got %v", got.AllowedCIDRs)
	}
	if got.TimeoutClientData != nil || got.TimeoutMemberData != nil ||
		got.TimeoutMemberConnect != nil || got.TimeoutTCPInspect != nil {
		t.Fatal("absent timeout annotations must stay unmanaged (nil)")
	}
}

func TestTuningParsesWhitelistAndTimeouts(t *testing.T) {
	got, err := TuningFromAnnotations(ingAnnotated(map[string]string{
		SourceRangesAnnotation:         "10.0.0.0/8, 192.168.1.0/24",
		TimeoutClientDataAnnotation:    "50000",
		TimeoutMemberConnectAnnotation: "5000",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !cidrsEqual(got.AllowedCIDRs, []string{"192.168.1.0/24", "10.0.0.0/8"}) {
		t.Fatalf("whitelist = %v", got.AllowedCIDRs)
	}
	if got.TimeoutClientData == nil || *got.TimeoutClientData != 50000 {
		t.Fatalf("timeout-client-data = %v", got.TimeoutClientData)
	}
	if got.TimeoutMemberConnect == nil || *got.TimeoutMemberConnect != 5000 {
		t.Fatalf("timeout-member-connect = %v", got.TimeoutMemberConnect)
	}
	if got.TimeoutMemberData != nil {
		t.Fatal("unset timeout must stay nil")
	}
}

// A malformed whitelist must FAIL the reconcile — silently applying nothing
// would leave a listener open that the operator believes is restricted.
func TestTuningRejectsGarbage(t *testing.T) {
	for _, ann := range []map[string]string{
		{SourceRangesAnnotation: "10.0.0.0/8, not-a-cidr"},
		{SourceRangesAnnotation: "10.0.0.1"}, // bare IP is not a CIDR
		{SourceRangesAnnotation: " , "},      // set but empty
		{TimeoutClientDataAnnotation: "fast"},
		{TimeoutMemberDataAnnotation: "-1"},
	} {
		if _, err := TuningFromAnnotations(ingAnnotated(ann)); err == nil {
			t.Fatalf("annotation %v must be rejected", ann)
		}
	}
}

func TestTimeoutDrift(t *testing.T) {
	v := 50000
	if timeoutDrift(nil, 123) {
		t.Fatal("unmanaged timeout must never drift")
	}
	if !timeoutDrift(&v, 123) {
		t.Fatal("managed timeout with different live value must drift")
	}
	if timeoutDrift(&v, 50000) {
		t.Fatal("managed timeout equal to live value must not drift")
	}
}
