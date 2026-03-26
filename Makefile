BINARY  := webtraffik
GOFLAGS := -ldflags="-s -w"
OUTDIR  := dist
MAIN    := ./cmd/webtraffik

PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64

.PHONY: build run cap cap-dist install uninstall clean dist remote-install firewall ebpf-gen ebpf-clean $(PLATFORMS) linux/armv6 linux/armv7

# Regenerate eBPF Go bindings from C source via bpf2go.
# Requires: clang >= 10, llvm-strip, linux-libc-dev, bpftool (for vmlinux.h)
# Run after editing internal/ebpf/bpf/programs/capture.bpf.c
ebpf-gen:
	go generate ./internal/ebpf/...

# Remove generated eBPF artifacts (force regeneration on next build)
ebpf-clean:
	rm -f internal/ebpf/capture_bpfel.go internal/ebpf/capture_bpfeb.go
	rm -f internal/ebpf/capture_bpfel.o  internal/ebpf/capture_bpfeb.o

# Build for the current host OS/arch
build:
	go build $(GOFLAGS) -o $(BINARY) $(MAIN)

# Cross-compile for all platforms into dist/
dist: $(PLATFORMS) linux/armv6 linux/armv7

$(PLATFORMS):
	$(eval OS   := $(word 1,$(subst /, ,$@)))
	$(eval ARCH := $(word 2,$(subst /, ,$@)))
	$(eval EXT  := $(if $(filter windows,$(OS)),.exe,))
	$(eval OUT  := $(OUTDIR)/$(BINARY)_$(OS)_$(ARCH)$(EXT))
	@mkdir -p $(OUTDIR)
	@echo "  building $(OUT)"
	@GOOS=$(OS) GOARCH=$(ARCH) go build $(GOFLAGS) -o $(OUT) $(MAIN)

# Pi Zero / Pi 1 (ARMv6, hard-float)
linux/armv6:
	@mkdir -p $(OUTDIR)
	@echo "  building $(OUTDIR)/$(BINARY)_linux_armv6  (Pi Zero / Pi 1)"
	@GOOS=linux GOARCH=arm GOARM=6 go build $(GOFLAGS) -o $(OUTDIR)/$(BINARY)_linux_armv6 $(MAIN)

# Pi 2 / Pi 3 / Pi Zero 2 W 32-bit (ARMv7)
linux/armv7:
	@mkdir -p $(OUTDIR)
	@echo "  building $(OUTDIR)/$(BINARY)_linux_armv7  (Pi 2 / Pi 3 / Pi Zero 2 W 32-bit)"
	@GOOS=linux GOARCH=arm GOARM=7 go build $(GOFLAGS) -o $(OUTDIR)/$(BINARY)_linux_armv7 $(MAIN)

run: build
	./$(BINARY)

# Grant cap_net_bind_service so the binary can bind ports <1024 without sudo.
# Run once after each build, then use 'make run' normally.
cap: build
	sudo setcap 'cap_net_bind_service=+ep' ./$(BINARY)
	@echo "Capability set — running $(BINARY)"
	./$(BINARY)

# Set cap_net_bind_service on all Linux dist binaries after 'make dist'.
# Must be re-run after every 'make dist' since setcap clears on file replace.
# On the target machine: sudo setcap 'cap_net_bind_service=+ep' ./webtraffik_linux_*
cap-dist: dist
	@sudo -v
	@for b in \
		$(OUTDIR)/$(BINARY)_linux_amd64 \
		$(OUTDIR)/$(BINARY)_linux_arm64 \
		$(OUTDIR)/$(BINARY)_linux_armv6 \
		$(OUTDIR)/$(BINARY)_linux_armv7; do \
		echo "  setting cap on $$b"; \
		sudo setcap 'cap_net_bind_service=+ep' $$b; \
	done
	@echo "Done — capabilities set on all Linux dist binaries"

clean: ebpf-clean
	rm -f $(BINARY)
	rm -rf $(OUTDIR)
	rm -f GeoLite2-City.mmdb

# Install binary + systemd service (run on the target Linux machine)
install: build
	sudo install -d /var/lib/webtraffik
	sudo useradd --system --no-create-home --home /var/lib/webtraffik \
	             --shell /usr/sbin/nologin webtraffik 2>/dev/null || true
	sudo chown webtraffik:webtraffik /var/lib/webtraffik
	sudo install -m 755 $(BINARY) /usr/local/bin/$(BINARY)
	sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/$(BINARY)
	sudo install -m 644 $(BINARY).service /etc/systemd/system/$(BINARY).service
	sudo systemctl daemon-reload
	sudo systemctl enable --now $(BINARY).service
	@echo "Service installed and started — check with: journalctl -u $(BINARY) -f"

# Deploy to a remote Linux host over SSH.
# Usage: make remote-install IP=1.2.3.4
#
# Detects the remote arch, cross-compiles the matching binary, copies it along
# with install.sh, then runs install.sh as root over SSH.
# SSH connects as $(USER) (your current local username) and assumes a key is
# already available in your ssh-agent or ~/.ssh/config.
remote-install:
	@if [ -z "$(IP)" ]; then \
		echo "error: IP is required — usage: make remote-install IP=1.2.3.4"; \
		exit 1; \
	fi
	$(eval REMOTE_ARCH := $(shell ssh $(USER)@$(IP) 'uname -m'))
	@echo "remote arch: $(REMOTE_ARCH)"
	$(eval REMOTE_GOARCH := $(shell \
		echo "$(REMOTE_ARCH)" | sed \
			-e 's/x86_64/linux\/amd64/' \
			-e 's/aarch64/linux\/arm64/' \
			-e 's/armv7.*/linux\/armv7/' \
			-e 's/armv6.*/linux\/armv6/' \
	))
	@if [ -z "$(REMOTE_GOARCH)" ]; then \
		echo "error: unsupported remote arch '$(REMOTE_ARCH)'"; \
		exit 1; \
	fi
	@echo "building for $(REMOTE_GOARCH)..."
	@$(MAKE) $(REMOTE_GOARCH)
	$(eval REMOTE_BIN := $(OUTDIR)/$(BINARY)_$(subst /,_,$(REMOTE_GOARCH)))
	@echo "copying $(REMOTE_BIN), install.sh, firewall.sh, nftables.conf, and gen-btf.sh to $(USER)@$(IP)..."
	@scp $(REMOTE_BIN)  $(USER)@$(IP):~/webtraffik
	@scp install.sh     $(USER)@$(IP):~/install.sh
	@scp firewall.sh    $(USER)@$(IP):~/firewall.sh
	@scp nftables.conf  $(USER)@$(IP):~/nftables.conf
	@scp gen-btf.sh     $(USER)@$(IP):~/gen-btf.sh
	@echo "running install.sh on remote..."
	@ssh -t $(USER)@$(IP) 'sudo bash ~/install.sh ~/webtraffik && rm ~/webtraffik ~/install.sh ~/firewall.sh ~/nftables.conf ~/gen-btf.sh'

# Remove binary, service, and data directory
uninstall:
	sudo systemctl disable --now $(BINARY).service 2>/dev/null || true
	sudo rm -f /etc/systemd/system/$(BINARY).service
	sudo systemctl daemon-reload
	sudo rm -f /usr/local/bin/$(BINARY)
	sudo rm -rf /var/lib/webtraffik
	sudo userdel webtraffik 2>/dev/null || true
	sudo rm -f /etc/nftables.d/webtraffik.conf
	sudo systemctl restart nftables.service 2>/dev/null || true
	@echo "$(BINARY) uninstalled"

# Apply the nftables firewall ruleset on the local machine (must be root / sudo).
# Useful for re-applying after editing nftables.conf without a full reinstall.
firewall:
	sudo bash firewall.sh
