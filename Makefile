BINARY  := webtraffik
GOFLAGS := -ldflags="-s -w"
OUTDIR  := dist

PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	linux/arm \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64

.PHONY: build run clean dist $(PLATFORMS)

# Build for the current host OS/arch
build:
	go build $(GOFLAGS) -o $(BINARY) .

# Cross-compile for all platforms into dist/
dist: $(PLATFORMS)

$(PLATFORMS):
	$(eval OS   := $(word 1,$(subst /, ,$@)))
	$(eval ARCH := $(word 2,$(subst /, ,$@)))
	$(eval EXT  := $(if $(filter windows,$(OS)),.exe,))
	$(eval OUT  := $(OUTDIR)/$(BINARY)_$(OS)_$(ARCH)$(EXT))
	@mkdir -p $(OUTDIR)
	@echo "  building $(OUT)"
	@GOOS=$(OS) GOARCH=$(ARCH) go build $(GOFLAGS) -o $(OUT) .

run: build
	sudo ./$(BINARY)

clean:
	rm -f $(BINARY)
	rm -rf $(OUTDIR)
	rm -f GeoLite2-City.mmdb

# Install setcap so the binary can bind port 80 without sudo (Linux only)
cap:
	sudo setcap 'cap_net_bind_service=+ep' ./$(BINARY)
	./$(BINARY)
