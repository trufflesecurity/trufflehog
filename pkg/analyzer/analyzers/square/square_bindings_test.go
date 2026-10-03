package square

import "testing"

func TestGetBindingsAndUnboundedResources(t *testing.T) {
	scopes := []string{"PAYMENTS_READ", "PAYMENTS_WRITE", "MERCHANT_PROFILE_READ"}
	bindings, unbounded := getBindingsAndUnboundedResources(scopes)

	if len(bindings) == 0 {
		t.Fatal("expected bindings for known scopes, got none")
	}

	foundPaymentRead := false
	for _, binding := range bindings {
		if binding.Permission.Value == "PAYMENTS_READ" {
			foundPaymentRead = true
			break
		}
	}
	if !foundPaymentRead {
		t.Fatalf("expected a PAYMENTS_READ binding, got %d bindings", len(bindings))
	}

	if len(unbounded) == 0 {
		t.Fatal("expected some categories without matching scopes to be unbounded")
	}
}
