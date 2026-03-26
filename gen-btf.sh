#!/bin/bash
# /usr/local/lib/webtraffik/gen-btf.sh
#
# Generates /sys/kernel/btf/vmlinux from DWARF debug info using pahole.
# Called as ExecStartPre (root) by webtraffik.service on each boot.
# Exits 0 always — failure is non-fatal; app falls back to go-only mode.

BTF_PATH="/sys/kernel/btf/vmlinux"

# Already present (another service generated it, or kernel shipped it).
if [[ -f "$BTF_PATH" ]]; then
    echo "gen-btf: $BTF_PATH already exists, skipping"
    exit 0
fi

# pahole is required to extract BTF from DWARF.
if ! command -v pahole &>/dev/null; then
    echo "gen-btf: pahole not found — install with: apt install pahole"
    exit 0
fi

# Find the debug vmlinux matching the running kernel.
KVER=$(uname -r)
DBG="/usr/lib/debug/boot/vmlinux-${KVER}"

if [[ ! -f "$DBG" ]]; then
    # Fallback: pick the newest debug image available.
    DBG=$(ls /usr/lib/debug/boot/vmlinux-* 2>/dev/null | sort -V | tail -1)
fi

if [[ -z "$DBG" || ! -f "$DBG" ]]; then
    echo "gen-btf: no debug vmlinux found (install linux-image-$(uname -r | sed 's/-[^-]*$//')-dbg)"
    exit 0
fi

echo "gen-btf: generating BTF from $DBG"
if pahole --btf_encode_detached "$BTF_PATH" "$DBG"; then
    echo "gen-btf: wrote $BTF_PATH"
else
    echo "gen-btf: pahole failed — eBPF will fall back to go-only mode"
    rm -f "$BTF_PATH"
fi

exit 0
