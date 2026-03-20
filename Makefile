BINARY  := webtraffik
GOFLAGS := -ldflags="-s -w"
OUTDIR  := dist

PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64

.PHONY: build run cap cap-dist install uninstall clean dist $(PLATFORMS) linux/armv6 linux/armv7

# Build for the current host OS/arch
build:
	go build $(GOFLAGS) -o $(BINARY) .

# Cross-compile for all platforms into dist/
dist: $(PLATFORMS) linux/armv6 linux/armv7

$(PLATFORMS):
	$(eval OS   := $(word 1,$(subst /, ,$@)))
	$(eval ARCH := $(word 2,$(subst /, ,$@)))
	$(eval EXT  := $(if $(filter windows,$(OS)),.exe,))
	$(eval OUT  := $(OUTDIR)/$(BINARY)_$(OS)_$(ARCH)$(EXT))
	@mkdir -p $(OUTDIR)
	@echo "  building $(OUT)"
	@GOOS=$(OS) GOARCH=$(ARCH) go build $(GOFLAGS) -o $(OUT) .

# Pi Zero / Pi 1 (ARMv6, hard-float)
linux/armv6:
	@mkdir -p $(OUTDIR)
	@echo "  building $(OUTDIR)/$(BINARY)_linux_armv6  (Pi Zero / Pi 1)"
	@GOOS=linux GOARCH=arm GOARM=6 go build $(GOFLAGS) -o $(OUTDIR)/$(BINARY)_linux_armv6 .

# Pi 2 / Pi 3 / Pi Zero 2 W 32-bit (ARMv7)
linux/armv7:
	@mkdir -p $(OUTDIR)
	@echo "  building $(OUTDIR)/$(BINARY)_linux_armv7  (Pi 2 / Pi 3 / Pi Zero 2 W 32-bit)"
	@GOOS=linux GOARCH=arm GOARM=7 go build $(GOFLAGS) -o $(OUTDIR)/$(BINARY)_linux_armv7 .

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

clean:
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

# Remove binary, service, and data directory
uninstall:
	sudo systemctl disable --now $(BINARY).service 2>/dev/null || true
	sudo rm -f /etc/systemd/system/$(BINARY).service
	sudo systemctl daemon-reload
	sudo rm -f /usr/local/bin/$(BINARY)
	sudo rm -rf /var/lib/webtraffik
	sudo userdel webtraffik 2>/dev/null || true
	@echo "$(BINARY) uninstalled"
