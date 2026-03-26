//go:build !linux

package ebpf

// allowUnlimitedLocked is a no-op on non-Linux platforms.
// RLIMIT_MEMLOCK is a Linux-only concept; eBPF itself only runs on Linux.
func allowUnlimitedLocked() error { return nil }
