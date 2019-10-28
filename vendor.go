// +build vendor

package main

// This file exists to trick "go mod vendor" to include "main" packages.
// It is not expected to build, the build tag above is only to prevent this
// file from being included in builds.

import (
	_ "github.com/golang/protobuf/protoc-gen-go"
	_ "github.com/infobloxopen/protoc-gen-gorm"
	_ "github.com/infobloxopen/protoc-gen-gorm/types"
	_ "golang.org/x/lint/golint"
)

func main() {}
