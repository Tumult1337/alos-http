#!/bin/bash
set -uo pipefail

ROOT=${ROOT:-/root/alos-perf}
HARNESS=$ROOT/harness
BASE=${BASE:-$ROOT/final}
BASE_FW=alos-$(basename "$BASE")
BENCHTIME=125ms
LOAD_DUR=1500ms
LOAD_WARM=500ms
LOCK=$ROOT/bench.lock
export GOTOOLCHAIN=go1.26.9 PATH=$PATH:/root/go/bin GOFLAGS=-buildvcs=false

usage() {
  cat <<EOF
usage: perfq.sh <tree> micro <bench regex> [rounds=3]
       perfq.sh <tree> gate [rounds=3] [pattern=^BenchmarkGate]
       perfq.sh <tree> load <workloads> <protos> [rounds=2]
  every mode takes the exclusive bench lock, compares <tree> against $BASE, and logs to $ROOT/logs/
  micro: interleaved base/tree runs at $BENCHTIME + benchstat + perf instructions:u per op for each matched benchmark
  gate:  interleaved gate rows + benchstat
  load:  builds alos-<tree> (and the baseline $BASE_FW if missing), runs the quick matrix at -dur $LOAD_DUR -warm $LOAD_WARM for the baseline vs alos-<tree>
EOF
  exit 2
}

[ $# -ge 2 ] || usage
TREE=$(cd "$1" && pwd) || usage
CMD=$2
shift 2
NAME=$(basename "$TREE")
STAMP=$(date +%Y%m%d-%H%M%S)
LOG=$ROOT/logs/$NAME-$CMD-$STAMP
mkdir -p "$ROOT/logs"

exec 9>"$LOCK"
flock -x 9

prepare_against() {
  if [ -n "${AGAINST:-}" ]; then
    BASE=$(cd "$AGAINST" && pwd) || exit 1
    return
  fi
  local overlay=$ROOT/pqbase-$NAME
  rm -rf "$overlay"
  mkdir -p "$overlay"
  cp -a "$BASE/go.mod" "$BASE/go.sum" "$overlay/"
  cp -a "$BASE/core" "$overlay/core"
  find "$overlay/core" -name '*_test.go' -delete
  cp -a "$TREE"/core/*_test.go "$overlay/core/"
  BASE=$overlay
}

build_tests() {
  prepare_against
  if ! (cd "$BASE" && go test -c -o "/tmp/pq_base.test" ./core 2> "$LOG.basebuild.txt"); then
    echo "base build with this tree's test files failed (tests use APIs base lacks). Re-run with AGAINST=<your pre-change tree>:"
    head -5 "$LOG.basebuild.txt"
    exit 1
  fi
  (cd "$TREE" && go test -c -o "/tmp/pq_$NAME.test" ./core) || exit 1
  echo "comparing $TREE against $BASE"
}

run_bench() {
  local bin=$1 dir=$2 pat=$3 bt=$4
  (cd "$dir/core" && "$bin" -test.run '^$' -test.bench "$pat" -test.benchmem -test.count 1 -test.benchtime "$bt" 2>/dev/null \
    | grep -E '^(Benchmark|goos|goarch|pkg|cpu)')
}

instr_per_op() {
  local bin=$1 dir=$2 name=$3 iters=$4 ins
  ins=$(cd "$dir/core" && perf stat -x, -e instructions:u "$bin" -test.run '^$' -test.bench "^${name}\$" -test.benchtime "${iters}x" -test.count 1 2>&1 >/dev/null \
    | awk -F, '/instructions/{print $1}')
  awk -v i="${ins:-0}" -v n="$iters" 'BEGIN{ if (n > 0) printf "%.1f", i / n }'
}

case "$CMD" in
  micro)
    [ $# -ge 1 ] || usage
    PAT=$1
    ROUNDS=${2:-3}
    build_tests
    : > "$LOG.base.txt"
    : > "$LOG.tree.txt"
    for _ in $(seq "$ROUNDS"); do
      run_bench /tmp/pq_base.test "$BASE" "$PAT" "$BENCHTIME" >> "$LOG.base.txt"
      run_bench "/tmp/pq_$NAME.test" "$TREE" "$PAT" "$BENCHTIME" >> "$LOG.tree.txt"
    done
    benchstat "$LOG.base.txt" "$LOG.tree.txt" | tee "$LOG.benchstat.txt"
    echo
    echo "instructions:u per op (base -> tree)"
    awk '/^Benchmark/{n=$1; sub(/-[0-9]+$/,"",n); if (!(n in it)) { it[n]=$2; order[++k]=n } } END{ for (i=1;i<=k;i++) print order[i], it[order[i]] }' "$LOG.base.txt" |
    while read -r name iters; do
      b=$(instr_per_op /tmp/pq_base.test "$BASE" "$name" "$iters")
      t=$(instr_per_op "/tmp/pq_$NAME.test" "$TREE" "$name" "$iters")
      awk -v n="$name" -v b="$b" -v t="$t" 'BEGIN{ d = (b > 0) ? (t / b - 1) * 100 : 0; printf "%-60s %12s %12s %+7.2f%%\n", n, b, t, d }'
    done | tee "$LOG.instr.txt"
    ;;
  gate)
    ROUNDS=${1:-3}
    PAT=${2:-^BenchmarkGate}
    build_tests
    : > "$LOG.base.txt"
    : > "$LOG.tree.txt"
    for _ in $(seq "$ROUNDS"); do
      run_bench /tmp/pq_base.test "$BASE" "$PAT" "$BENCHTIME" >> "$LOG.base.txt"
      run_bench "/tmp/pq_$NAME.test" "$TREE" "$PAT" "$BENCHTIME" >> "$LOG.tree.txt"
    done
    benchstat "$LOG.base.txt" "$LOG.tree.txt" | tee "$LOG.benchstat.txt"
    ;;
  load)
    [ $# -ge 2 ] || usage
    WLS=$1
    PROTOS=$2
    ROUNDS=${3:-2}
    if [ ! -x "$HARNESS/bin/$BASE_FW" ]; then
      "$HARNESS/build.sh" -tree "$BASE" > "$LOG.basebuild.txt" 2>&1 || { cat "$LOG.basebuild.txt"; exit 1; }
    fi
    "$HARNESS/build.sh" -tree "$TREE" > "$LOG.build.txt" 2>&1 || { cat "$LOG.build.txt"; exit 1; }
    PERF_NO_LOCK=1 "$HARNESS/run.sh" -tier quick -rounds "$ROUNDS" -dur "$LOAD_DUR" -warm "$LOAD_WARM" -fw "$BASE_FW,alos-$NAME" -wl "$WLS" -proto "$PROTOS" \
      -out "$LOG.csv" > "$LOG.run.txt" 2>&1
    "$HARNESS/bin/report" -base "$BASE_FW" -lab "alos-$NAME" "$LOG.csv" | tee "$LOG.report.txt"
    grep -E 'valid=0|skipped' "$LOG.run.txt" | head -20
    ;;
  *) usage ;;
esac
echo "logs: $LOG.*"
