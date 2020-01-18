REGISTRY_NAME?=docker.io/sbezverk
IMAGE_VERSION?=0.0.0

.PHONY: all nfproxy container push clean test

ifdef V
TESTARGS = -v -args -alsologtostderr -v 5
else
TESTARGS =
endif

all: nfproxy

nfproxy:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GO111MODULE=on go build -a -ldflags '-extldflags "-static"' -o ./bin/nfproxy ./cmd/nfproxy.go

container: nfproxy
	docker build -t $(REGISTRY_NAME)/nfproxy-debug:$(IMAGE_VERSION) -f ./build/Dockerfile.nfproxy .

push: container
	docker push $(REGISTRY_NAME)/nfproxy-debug:$(IMAGE_VERSION)

clean:
	rm -rf bin

test:
	GO111MODULE=on go test `go list ./... | grep -v 'vendor'` $(TESTARGS)
	GO111MODULE=on go vet `go list ./... | grep -v vendor`
