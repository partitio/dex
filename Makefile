PROJ=dex
ORG_PATH=github.com/dexidp
REPO_PATH=$(ORG_PATH)/$(PROJ)
export PATH := $(PWD)/bin:$(PATH)
THIS_DIRECTORY:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

VERSION ?= $(shell ./scripts/git-version)

DOCKER_REPO=quay.io/dexidp/dex
DOCKER_IMAGE=$(DOCKER_REPO):$(VERSION)

user=$(shell id -u -n)
group=$(shell id -g -n)
export GOBIN=$(PWD)/bin


LD_FLAGS="-w -X $(REPO_PATH)/version.Version=$(VERSION)"

build: bin/dex bin/example-app bin/grpc-client

bin:
	@mkdir -p bin

bin/dex: bin
	@go install -v -ldflags $(LD_FLAGS) $(REPO_PATH)/cmd/dex

bin/example-app: bin
	@go install -v -ldflags $(LD_FLAGS) $(REPO_PATH)/cmd/example-app

bin/grpc-client: bin
	@go install -v -ldflags $(LD_FLAGS) $(REPO_PATH)/examples/grpc-client

.PHONY: release-binary
release-binary:
	@go build -o /go/bin/dex -v -ldflags $(LD_FLAGS) $(REPO_PATH)/cmd/dex

.PHONY: revendor
revendor:
	@go mod tidy -v
	@go mod vendor -v
	@go mod verify

test:
	@go test -v ./...

testrace:
	@go test -v --race ./...

vet:
	@go vet ./...

fmt:
	@./scripts/gofmt ./...

lint: bin/golint
	@./bin/golint -set_exit_status $(shell go list ./...)

.PHONY: docker-image
docker-image:
	@sudo docker build -t $(DOCKER_IMAGE) .

LDAP_AGGREGATOR_PROTOS := ./connector/ldap-aggregator
.PHONY: proto
proto: bin/protoc bin/protoc-gen-go bin/protoc-gen-validate bin/protoc-gen-gorm
	@./bin/protoc --go_out=plugins=grpc:. --plugin=protoc-gen-go=./bin/protoc-gen-go api/*.proto
	@./bin/protoc --go_out=. --plugin=protoc-gen-go=./bin/protoc-gen-go server/internal/*.proto
	@./bin/protoc -I./vendor -I./include -I$(LDAP_AGGREGATOR_PROTOS) \
		-I./vendor/github.com/envoyproxy/protoc-gen-validate \
		--plugin=protoc-gen-go=./bin/protoc-gen-go \
		--plugin=protoc-gen-validate=./bin/protoc-gen-validate \
		--plugin=protoc-gen-gorm=./bin/protoc-gen-gorm \
		--go_out=plugins=grpc:$(LDAP_AGGREGATOR_PROTOS) \
		--gorm_out=$(LDAP_AGGREGATOR_PROTOS) \
		--validate_out="lang=go:$(LDAP_AGGREGATOR_PROTOS)" \
		$(LDAP_AGGREGATOR_PROTOS)/*.proto

.PHONY: verify-proto
verify-proto: proto
	@./scripts/git-diff

bin/protoc: bin scripts/get-protoc
	@./scripts/get-protoc bin/protoc .

bin/protoc-gen-gorm: bin
	@go install -v $(THIS_DIRECTORY)/vendor/github.com/infobloxopen/protoc-gen-gorm

bin/protoc-gen-validate: bin
	@go install -v $(THIS_DIRECTORY)/vendor/github.com/envoyproxy/protoc-gen-validate

bin/protoc-gen-go: bin
	@go install -v $(REPO_PATH)/vendor/github.com/golang/protobuf/protoc-gen-go

bin/golint: bin
	@go install -v $(THIS_DIRECTORY)/vendor/golang.org/x/lint/golint

clean:
	@rm -rf bin/

testall: testrace vet fmt lint

FORCE:

.PHONY: test testrace vet fmt lint testall
