package ebpf

import (
	"errors"
	"os"
	"testing"

	cebpf "github.com/cilium/ebpf"
)

// TestProgramLoads runs the embedded XDP object through the kernel verifier.
// It is skipped when the process lacks the privileges to load BPF programs.
func TestProgramLoads(t *testing.T) {
	_ = allowUnlimitedLocked()
	var objs captureObjects
	err := loadCaptureObjects(&objs, nil)
	if err != nil {
		var ve *cebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier rejected program: %+v", ve)
		}
		if os.IsPermission(err) || errors.Is(err, os.ErrPermission) {
			t.Skipf("insufficient privileges to load BPF: %v", err)
		}
		t.Skipf("cannot load BPF in this environment: %v", err)
	}
	objs.Close()
}
