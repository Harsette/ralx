package daemon

import (
	"strings"
	"testing"
	"time"
)

func TestEnrollmentOwnerCopy(t *testing.T) {
	s := &Server{port: "17347"}
	t.Setenv("RALX_OWNER_NAME", "")
	prompt := s.enrollPrompt("synthetic-code", time.Now().Add(time.Minute))
	if !strings.Contains(prompt, "Tell the owner:") || strings.Contains(prompt, "Hamza") {
		t.Fatal(prompt)
	}
	t.Setenv("RALX_OWNER_NAME", "  Taylor  ")
	prompt = s.enrollPrompt("synthetic-code", time.Now().Add(time.Minute))
	if !strings.Contains(prompt, "Tell Taylor:") || !strings.Contains(prompt, "approval from Taylor") {
		t.Fatal(prompt)
	}
}
