//go:build linux

package ebpf

import (
	"golang.org/x/sys/unix"
)

// allowUnlimitedLocked raises the RLIMIT_MEMLOCK resource limit to unlimited.
// This is required on kernels < 5.11 to allow eBPF map allocation.
// On kernels >= 5.11 the memlock limit for BPF objects was replaced by
// the cgroup memory controller, so this call is a no-op on modern kernels
// but harmless to call regardless.
func allowUnlimitedLocked() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
}
