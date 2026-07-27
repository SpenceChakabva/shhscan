VERSION ?= dev

.PHONY: build test vet demo release clean
build:
	go build -ldflags "-X main.version=$(VERSION)" -o shhscan .
test:
	go test ./...
vet:
	go vet ./...
demo:
	@bash scripts/demo.sh
release:            ## cross-build every platform into dist/
	@bash scripts/build-all.sh $(VERSION)
clean:
	rm -rf shhscan shhscan.exe shhscan-bin .demo dist
