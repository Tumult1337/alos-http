#!/bin/bash
set -euo pipefail

HARNESS=${HARNESS:-/root/alos-perf/harness}
BIN=${BIN:-$HARNESS/bin}
RUST_TOOLCHAIN=${RUST_TOOLCHAIN:-1.99.1}
export GOTOOLCHAIN=go1.26.9 GOFLAGS=-buildvcs=false PATH=$PATH:/root/go/bin:/root/.cargo/bin

usage() {
  echo "usage: build.sh [-tree <alos tree> ...] [-competitors] [-tools]"
  echo "  -tree      build the ALOS server against that tree, output bin/alos-<tree basename>"
  echo "  -competitors  build xitca, ntex, fiber, gin"
  echo "  -tools     build wsload, report and idleconn"
  exit 2
}

TREES=()
COMPETITORS=0
TOOLS=0
while [ $# -gt 0 ]; do
  case "$1" in
    -tree) TREES+=("$2"); shift 2 ;;
    -competitors) COMPETITORS=1; shift ;;
    -tools) TOOLS=1; shift ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

mkdir -p "$BIN"

build_alos() {
  local tree=$1 name
  name=$(basename "$tree")
  mkdir -p "$tree/tests/perfcompare/servers"
  local src="$HARNESS/servers/alos" dir="$tree/tests/perfcompare/servers/alos"
  if [ -d "$tree/tests/perfcompare/servers/alos-lab" ]; then
    dir="$tree/tests/perfcompare/servers/alos-lab"
    echo "using the tree's own servers/alos-lab"
  else
    rm -rf "$dir"
    cp -r "$src" "$dir"
  fi
  (cd "$dir" && go mod tidy >/dev/null 2>&1 || true; go build -o "$BIN/alos-$name" .)
  echo "built $BIN/alos-$name"
}

build_go() {
  local dir=$1 out=$2
  (cd "$dir" && go build -o "$BIN/$out" .)
  echo "built $BIN/$out"
}

build_rust() {
  local dir=$1 out=$2 pkg
  pkg=$(grep -m1 '^name' "$dir/Cargo.toml" | sed -E 's/name *= *"([^"]+)"/\1/')
  (cd "$dir" && cargo "+$RUST_TOOLCHAIN" build --release --quiet)
  cp "$dir/target/release/$pkg" "$BIN/$out"
  echo "built $BIN/$out"
}

for t in "${TREES[@]}"; do build_alos "$t"; done

if [ "$COMPETITORS" = 1 ]; then
  build_go "$HARNESS/servers/fiber" fiber
  build_go "$HARNESS/servers/gin" gin
  build_rust "$HARNESS/rust/xitca" xitca
  build_rust "$HARNESS/rust/ntex" ntex
fi

if [ "$TOOLS" = 1 ]; then
  build_go "$HARNESS/tools/wsload" wsload
  build_go "$HARNESS/tools/report" report
  build_go "$HARNESS/tools/idleconn" idleconn
fi
