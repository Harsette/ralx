package logins

import "testing"

func TestClerkTestEmailScope(t *testing.T) {
	for _, address := range []string{"test+clerk_test@example.com", "unique+clerk_test@example.invalid"} {
		if !ClerkTestEmail(address) {
			t.Fatalf("reserved test address rejected: %s", address)
		}
	}
	for _, address := range []string{"ordinary@example.com", "test+clerk_test_spoof@example.com", "clerk_test@example.com", "Test <test+clerk_test@example.com>", "test+clerk_test@example.com\n", "test+clerk_test@example.com.extra@elsewhere.invalid"} {
		if ClerkTestEmail(address) {
			t.Fatalf("ordinary/malformed address accepted: %s", address)
		}
	}
}
