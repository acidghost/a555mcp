build_dir := 'build'

version := 'SNAPSHOT-'+`git describe --tags --always --dirty`
commit_sha := `git rev-parse HEAD`
build_time := `date -u '+%Y-%m-%d_%H:%M:%S'`

ldflags := '-s -w -X main.buildVersion='+version \
        +' -X main.buildCommit='+commit_sha \
        +' -X main.buildDate='+build_time

default:
    @just --list

build:
    CGO_ENABLED=0 go build -ldflags '{{ldflags}}' -o '{{build_dir}}/' ./...

run *args:
    CGO_ENABLED=0 go run -ldflags '{{ldflags}}' ./... {{args}}

vendor:
    go mod tidy
    go mod vendor

fmt:
    go fmt ./...

lint:
    golangci-lint run ./...

clean:
    rm -rf {{build_dir}}