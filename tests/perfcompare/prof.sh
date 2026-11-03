#!/bin/bash
set -uo pipefail

HARNESS=${HARNESS:-/root/alos-perf/harness}
LOCK=${LOCK:-/root/alos-perf/bench.lock}
FW=${1:?usage: prof.sh <alos-name> <out dir> [protos] [workloads]}
OUT=${2:?usage: prof.sh <alos-name> <out dir> [protos] [workloads]}
PROTOS=${3:-h1,tls,h2c,h2}
WLS=${4:-W1,W1r,W2,W3,W4,W5a,W5b,W6,W7g,W7b,W8,W9,W10,W11,W12a,W12b}

exec 9>"$LOCK"
flock -x 9
mkdir -p "$OUT"
IFS=, read -r -a protoarr <<< "$PROTOS"
IFS=, read -r -a wlarr <<< "$WLS"
for proto in "${protoarr[@]}"; do
  for wl in "${wlarr[@]}"; do
    PERF_NO_LOCK=1 PROFILE_DIR="$OUT" PROFILE_TAG="$wl" "$HARNESS/run.sh" -tier quick -rounds 1 -dur 5 \
      -fw "$FW" -proto "$proto" -wl "$wl" -out "$OUT/$proto-$wl.csv" 2>&1 | grep -E 'valid=|skipped' || true
  done
done
ls "$OUT"/*.cpu 2>/dev/null | wc -l
