SOURCES := $(shell find . -name '*.go')
BINARY := scanner-adapter
IMAGE_TAG := dev
IMAGE := aquasec/harbor-scanner-aqua:$(IMAGE_TAG)

build: $(BINARY)

test: build
	GO111MODULE=on go test -v -short -race -coverprofile=coverage.txt -covermode=atomic ./...

$(BINARY): $(SOURCES)
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o $(BINARY) cmd/scanner-adapter/main.go

container: build
	docker build --no-cache -t $(IMAGE) .
