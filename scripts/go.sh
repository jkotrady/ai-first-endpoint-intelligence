#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
ROOT_DIR=$(pwd)
export GOCACHE="$ROOT_DIR/work/go-cache"
export GOPATH="$ROOT_DIR/work/go-path"
export GOTOOLCHAIN=local
export GOPROXY=off
export GOSUMDB=off
exec "$ROOT_DIR/work/toolchains/go/bin/go" "$@"
