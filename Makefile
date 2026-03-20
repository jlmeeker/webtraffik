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

.PHONY: build run cap clean dist $(PLATFORMS) linux/armv6 linux/armv7

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

clean:
	rm -f $(BINARY)
	rm -rf $(OUTDIR)
	rm -f GeoLite2-City.mmdb
