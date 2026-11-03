#!/bin/bash
set -uo pipefail

HARNESS=${HARNESS:-/root/alos-perf/harness}
BIN=$HARNESS/bin
LOCK=${LOCK:-/root/alos-perf/bench.lock}
ADDR=127.0.0.1:18080
FWS=alos-base,xitca,ntex,fiber,gin
PROTOS=h1,tls
CONNS=10000
OUT=""

usage() {
  cat <<EOF
usage: idle.sh [-fw list] [-proto h1,tls] [-n conns] [-out file]
  opens -n keep-alive connections (one GET /plaintext each) and records the server's RSS before and after
EOF
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    -fw) FWS=$2; shift 2 ;;
    -proto) PROTOS=$2; shift 2 ;;
    -n) CONNS=$2; shift 2 ;;
    -out) OUT=$2; shift 2 ;;
    *) usage ;;
  esac
done

mkdir -p "$HARNESS/results"
[ -n "$OUT" ] || OUT=$HARNESS/results/$(date +%Y%m%d-%H%M%S)-idle.csv
TMP=$(mktemp -d /tmp/perfidle.XXXXXX)
SPID=""
CPID=""

group_rss_kb() {
  local total=0 p v
  for p in $(pgrep -g "$1" 2>/dev/null); do
    v=$(awk '/^VmRSS/{print $2}' "/proc/$p/status" 2>/dev/null)
    total=$((total + ${v:-0}))
  done
  echo "$total"
}

cleanup() {
  [ -n "$CPID" ] && kill -TERM "$CPID" 2>/dev/null && wait "$CPID" 2>/dev/null
  [ -n "$SPID" ] && kill -TERM -- "-$SPID" 2>/dev/null && sleep 1 && kill -KILL -- "-$SPID" 2>/dev/null
  CPID=""; SPID=""
}
trap 'cleanup; rm -rf "$TMP"' EXIT

fw_bin() { case "$1" in fiber-pf) echo "$BIN/fiber" ;; *) echo "$BIN/$1" ;; esac; }
fw_extra() { case "$1" in fiber-pf) echo "-prefork" ;; esac; }

measure() {
  local fw=$1 proto=$2 i before after open tlsflag=""
  [ "$proto" = tls ] && tlsflag="-tls"
  setsid "$(fw_bin "$fw")" -proto "$proto" -mode app -addr "$ADDR" -cert "$HARNESS/certs/cert.pem" -key "$HARNESS/certs/key.pem" \
    -static "$HARNESS/static" -origin 127.0.0.1:18090 $(fw_extra "$fw") > "$TMP/srv.out" 2> "$TMP/srv.err" < /dev/null &
  SPID=$!
  for i in $(seq 1 200); do grep -q '^READY' "$TMP/srv.out" 2>/dev/null && break; sleep 0.1; done
  if ! grep -q '^READY' "$TMP/srv.out"; then
    echo "$fw,$proto,$CONNS,,,,,start failed" >> "$OUT"
    cleanup
    return
  fi
  sleep 2
  before=$(group_rss_kb "$SPID")
  "$BIN/idleconn" -addr "$ADDR" -n "$CONNS" $tlsflag > "$TMP/cli.out" 2>&1 &
  CPID=$!
  for i in $(seq 1 1200); do grep -q '^open=' "$TMP/cli.out" 2>/dev/null && break; sleep 0.1; done
  open=$(grep -o 'open=[0-9]*' "$TMP/cli.out" | cut -d= -f2)
  sleep 3
  after=$(group_rss_kb "$SPID")
  local per
  per=$(awk -v a="$after" -v b="$before" -v n="${open:-0}" 'BEGIN{ if(n>0) printf "%.2f", (a-b)/n }')
  echo "$fw,$proto,$CONNS,${open:-0},$before,$after,$per," >> "$OUT"
  printf '%-9s %-4s open=%s rss_before=%sKB rss_after=%sKB per_conn=%sKB\n' "$fw" "$proto" "${open:-0}" "$before" "$after" "$per"
  cleanup
  sleep 1
}

main() {
  echo "fw,proto,requested,open,rss_before_kb,rss_after_kb,kb_per_conn,note" > "$OUT"
  IFS=, read -r -a fwarr <<< "$FWS"
  IFS=, read -r -a protoarr <<< "$PROTOS"
  local fw proto
  for fw in "${fwarr[@]}"; do
    for proto in "${protoarr[@]}"; do measure "$fw" "$proto"; done
  done
  echo "done: $OUT"
}

if [ -z "${PERF_NO_LOCK:-}" ]; then
  exec 9>"$LOCK"
  flock -x 9
fi
main
