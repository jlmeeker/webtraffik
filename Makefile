BINARY  := webtraffik
GOFLAGS := -ldflags="-s -w"

.PHONY: build run clean

build:
	go build $(GOFLAGS) -o $(BINARY) .

run: build
	sudo ./$(BINARY)

clean:
	rm -f $(BINARY) GeoLite2-City.mmdb

# Install setcap so the binary can bind port 80 without sudo
cap:
	sudo setcap 'cap_net_bind_service=+ep' ./$(BINARY)
	./$(BINARY)
