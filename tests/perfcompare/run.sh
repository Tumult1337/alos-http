#!/bin/bash
set -uo pipefail

HARNESS=${HARNESS:-/root/alos-perf/harness}
BIN=$HARNESS/bin
CERT=$HARNESS/certs/cert.pem
KEY=$HARNESS/certs/key.pem
STATIC=$HARNESS/static
EXPECT=$HARNESS/expect
LOCK=${LOCK:-/root/alos-perf/bench.lock}
ADDR=127.0.0.1:18080
ORIGIN=127.0.0.1:18090

TIER=quick
FWS=alos-base,xitca,ntex,fiber,gin
PROTOS=h1,tls,h2c,h2
WLS=all
ROUNDS=2
DUR=1500ms
WARM=500ms
WRK=${WRK:-$BIN/wrk}
THREADS=4
STREAMS=100
ORIGIN_FW=alos-base
OUT=""

usage() {
  cat <<EOF
usage: run.sh [options]
  -tier quick|full     quick: c=256 everywhere; full: W1 W1r W2 W3 at c=64,256,1024,4096, others c=256 (default quick)
  -fw list             comma list of alos-<tree>, xitca, ntex, fiber, fiber-pf, gin (default $FWS)
  -proto list          comma list of h1,tls,h2c,h2 (default $PROTOS)
  -wl list             comma list of W1,W1r,W2,W3,W4,W5a,W5b,W6,W7g,W7b,W8,W9,W10,W11,W12a,W12b or all (default all)
  -rounds n            interleaved rounds (default $ROUNDS)
  -dur duration        length of each run, e.g. 1500ms or 2s; a bare number is seconds (default $DUR)
  -warm duration       warm-up per server start, same format as -dur (default $WARM)
  -origin fw           ALOS binary used as the proxy origin (default $ORIGIN_FW)
  -out file            CSV output (default $HARNESS/results/<timestamp>.csv)
exit codes: 0 ok, 2 bad usage, 3 at least one cell failed a validity rule
EOF
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    -tier) TIER=$2; shift 2 ;;
    -fw) FWS=$2; shift 2 ;;
    -proto) PROTOS=$2; shift 2 ;;
    -wl) WLS=$2; shift 2 ;;
    -rounds) ROUNDS=$2; shift 2 ;;
    -dur) DUR=$2; shift 2 ;;
    -warm) WARM=$2; shift 2 ;;
    -origin) ORIGIN_FW=$2; shift 2 ;;
    -out) OUT=$2; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done
case "$TIER" in quick|full) ;; *) usage ;; esac
duration_ms() {
  local v=$1 mult=1000
  case "$v" in
    *ms) v=${v%ms}; mult=1 ;;
    *s) v=${v%s} ;;
  esac
  case "$v" in ''|*[!0-9]*) return 1 ;; esac
  v=$((10#$v * mult))
  [ "$v" -gt 0 ] || return 1
  echo "$v"
}

load_timeout_secs() {
  echo $(( ($1 * 4 + 999) / 1000 + 30 ))
}

DUR_MS=$(duration_ms "$DUR") || usage
WARM_MS=$(duration_ms "$WARM") || usage
DUR=${DUR_MS}ms
WARM=${WARM_MS}ms

mkdir -p "$HARNESS/results"
[ -n "$OUT" ] || OUT=$HARNESS/results/$(date +%Y%m%d-%H%M%S)-$TIER.csv
LOAD_TIMEOUT=$(load_timeout_secs "$DUR_MS")
TMP=$(mktemp -d /tmp/perfrun.XXXXXX)
trap 'stop_server; stop_origin; rm -rf "$TMP"' EXIT
FAILED=0
CLK=$(getconf CLK_TCK)

ALL_WLS="W1 W1r W2 W3 W4 W5a W5b W6 W7g W7b W8 W9 W10 W11 W12a W12b"
CORE_WLS=" W1 W1r W2 W3 "
LATE_WLS="W10"
PHASE=main
TW_PORTS="${ADDR##*:} ${ORIGIN##*:}"
TW_WAIT_MAX_MS=61000
TW_POLL_S=0.2
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'
AL='en-US,en;q=0.9'
SID=abc123def456

prepare_expect() {
  mkdir -p "$EXPECT"
  printf 'Hello, World!' > "$EXPECT/W1"
  cp "$EXPECT/W1" "$EXPECT/W1r"
  printf '{"message":"Hello, World!"}' > "$EXPECT/W2"
  printf '12345' > "$EXPECT/W3"
  printf '1024' > "$EXPECT/W4"
  head -c 65536 /dev/zero | tr '\0' 'x' > "$EXPECT/W5a"
  head -c 1048576 /dev/zero | tr '\0' 'x' > "$EXPECT/W5b"
  cp "$STATIC/file-64k.bin" "$EXPECT/W6"
  yes 'The quick brown fox jumps over the lazy dog. ' | tr -d '\n' | head -c 16384 > "$EXPECT/W7g"
  cp "$EXPECT/W7g" "$EXPECT/W7b"
  printf '%s|%s|%s' "$UA" "$AL" "$SID" > "$EXPECT/W8"
  printf 'ok' > "$EXPECT/W9"
  cp "$EXPECT/W1" "$EXPECT/W10"
  cp "$EXPECT/W1" "$EXPECT/W11"
  head -c 1024 /dev/zero | tr '\0' 'a' > "$EXPECT/body1k"
  cat > "$TMP/post.lua" <<EOF
wrk.method = "POST"
wrk.body = string.rep("a", 1024)
wrk.headers["Content-Type"] = "application/octet-stream"
EOF
}

wl_path() {
  case "$1" in
    W1|W10|W11) echo /plaintext ;;
    W1r) echo / ;;
    W2) echo /json ;;
    W3) echo /user/12345 ;;
    W4) echo /echo ;;
    W5a) echo /bytes/64k ;;
    W5b) echo /bytes/1m ;;
    W6) echo /static/file-64k.bin ;;
    W7g|W7b) echo /text16k ;;
    W8) echo /browser ;;
    W9) echo /mw ;;
    W12a|W12b) echo /ws ;;
  esac
}

wl_protos() {
  case "$1" in
    W10|W11|W12a|W12b) echo " h1 tls " ;;
    *) echo " h1 tls h2c h2 " ;;
  esac
}

wl_conns() {
  if [ "$TIER" = full ] && [[ "$CORE_WLS" == *" $1 "* ]]; then echo "64 256 1024 4096"; else echo 256; fi
}

wl_streams() {
  case "$1" in
    W5a|W5b|W6|W7g|W7b) echo 1 ;;
    *) echo "$STREAMS" ;;
  esac
}

wl_headers() {
  case "$1" in
    W7g) printf '%s\n' 'Accept-Encoding: gzip' ;;
    W7b) printf '%s\n' 'Accept-Encoding: br' ;;
    W10) printf '%s\n' 'Connection: close' ;;
    W8) printf '%s\n' \
      "User-Agent: $UA" \
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
      "Accept-Language: $AL" \
      'Accept-Encoding: identity' \
      'Cache-Control: no-cache' \
      'Pragma: no-cache' \
      'Referer: https://example.com/' \
      'Sec-Fetch-Dest: document' \
      'Sec-Fetch-Mode: navigate' \
      'Sec-Fetch-Site: none' \
      'Sec-Fetch-User: ?1' \
      'Upgrade-Insecure-Requests: 1' \
      'sec-ch-ua: "Chromium";v="141", "Not?A_Brand";v="8"' \
      'sec-ch-ua-mobile: ?0' \
      'sec-ch-ua-platform: "Windows"' \
      "Cookie: sid=$SID; theme=dark; lang=en" ;;
  esac
}

scheme() { case "$1" in tls|h2) echo https ;; *) echo http ;; esac; }

fw_bin() {
  case "$1" in
    fiber-pf) echo "$BIN/fiber" ;;
    *) echo "$BIN/$1" ;;
  esac
}

fw_extra() { case "$1" in fiber-pf) echo "-prefork" ;; esac; }

fw_is_go() { case "$1" in alos-*|fiber|gin) return 0 ;; *) return 1 ;; esac; }

SPID=""
OPID=""

launch() {
  local bin=$1 log=$2; shift 2
  setsid "$bin" "$@" >"$log.out" 2>"$log.err" < /dev/null &
  local pid=$! i
  for i in $(seq 1 200); do
    if grep -q '^READY' "$log.out" 2>/dev/null; then echo "$pid"; return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null
      echo "EXIT:$?"
      return 1
    fi
    sleep 0.1
  done
  kill -KILL -- "-$pid" 2>/dev/null
  echo "TIMEOUT"
  return 1
}

kill_group() {
  local pid=$1 i
  [ -n "$pid" ] || return 0
  kill -TERM -- "-$pid" 2>/dev/null
  for i in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  kill -KILL -- "-$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  sleep 0.3
}

stop_server() { kill_group "$SPID"; SPID=""; }
stop_origin() { kill_group "$OPID"; OPID=""; }

profile_flags() {
  local fw=$1 proto=$2 mode=$3
  [ -n "${PROFILE_DIR:-}" ] || return 0
  [[ "$fw" == alos-* ]] || return 0
  mkdir -p "$PROFILE_DIR"
  echo "-cpuprofile $PROFILE_DIR/$fw-$proto-$mode-${PROFILE_TAG:-all}.cpu -memprofile $PROFILE_DIR/$fw-$proto-$mode-${PROFILE_TAG:-all}.mem"
}

start_server() {
  local fw=$1 proto=$2 mode=$3 r
  r=$(launch "$(fw_bin "$fw")" "$TMP/srv" -proto "$proto" -mode "$mode" -addr "$ADDR" \
      -cert "$CERT" -key "$KEY" -static "$STATIC" -origin "$ORIGIN" $(fw_extra "$fw") $(profile_flags "$fw" "$proto" "$mode"))
  case "$r" in
    EXIT:64) SPID=""; START_NOTE="unsupported: $(grep -m1 UNSUPPORTED "$TMP/srv.out" | tr ',' ';')"; return 1 ;;
    EXIT:*|TIMEOUT) SPID=""; START_NOTE="start failed $r: $(tail -n 3 "$TMP/srv.err" | tr '\n,' '  ')"; return 1 ;;
  esac
  SPID=$r
  START_NOTE=""
  return 0
}

start_origin() {
  local r
  r=$(launch "$(fw_bin "$ORIGIN_FW")" "$TMP/origin" -proto h1 -mode app -addr "$ORIGIN" \
      -cert "$CERT" -key "$KEY" -static "$STATIC" -origin "$ORIGIN")
  case "$r" in EXIT:*|TIMEOUT) echo "origin failed to start: $r" >&2; return 1 ;; esac
  OPID=$r
}

curl_proto() {
  case "$1" in
    h1) echo "--http1.1" ;;
    tls) echo "-k --http1.1" ;;
    h2c) echo "--http2-prior-knowledge" ;;
    h2) echo "-k --http2" ;;
  esac
}

smoke() {
  local wl=$1 proto=$2 url hdrs=() line
  url="$(scheme "$proto")://$ADDR$(wl_path "$wl")"
  while IFS= read -r line; do [ -n "$line" ] && [ "$wl" != W10 ] && hdrs+=(-H "$line"); done < <(wl_headers "$wl")
  local args=(-s -o "$TMP/body" -D "$TMP/hdr" -w '%{http_code} %{http_version}' --max-time 10 $(curl_proto "$proto"))
  case "$wl" in
    W4) args+=(-X POST --data-binary "@$EXPECT/body1k" -H 'Content-Type: application/octet-stream') ;;
    W7g|W7b) args+=(--compressed) ;;
  esac
  local res
  res=$(curl "${args[@]}" "${hdrs[@]}" "$url" 2>/dev/null) || { SMOKE_NOTE="curl failed"; return 1; }
  case "$res" in 200\ *) ;; *) SMOKE_NOTE="status $res"; return 1 ;; esac
  if [ "$proto" = h2 ] || [ "$proto" = h2c ]; then
    case "$res" in *\ 2) ;; *) SMOKE_NOTE="not http2 ($res)"; return 1 ;; esac
  fi
  if ! cmp -s "$TMP/body" "$EXPECT/$wl"; then SMOKE_NOTE="body mismatch ($(wc -c < "$TMP/body") bytes)"; return 1; fi
  case "$wl" in
    W7g) grep -qi '^content-encoding: *gzip' "$TMP/hdr" || { SMOKE_NOTE="no gzip encoding"; return 1; } ;;
    W7b) grep -qi '^content-encoding: *br' "$TMP/hdr" || { SMOKE_NOTE="no br encoding"; return 1; } ;;
  esac
  SMOKE_NOTE=""
  return 0
}

group_cpu_ticks() {
  local pg=$1 total=0 p v
  for p in $(pgrep -g "$pg" 2>/dev/null); do
    v=$(awk '{print $14+$15}' "/proc/$p/stat" 2>/dev/null) || continue
    total=$((total + ${v:-0}))
  done
  echo "$total"
}

group_rss_kb() {
  local pg=$1 total=0 p v
  for p in $(pgrep -g "$pg" 2>/dev/null); do
    v=$(awk '/^VmRSS/{print $2}' "/proc/$p/status" 2>/dev/null)
    total=$((total + ${v:-0}))
  done
  echo "$total"
}

group_hwm_kb() {
  local pg=$1 total=0 p v
  for p in $(pgrep -g "$pg" 2>/dev/null); do
    v=$(awk '/^VmHWM/{print $2}' "/proc/$p/status" 2>/dev/null)
    total=$((total + ${v:-0}))
  done
  echo "$total"
}

rss_sampler() {
  local pg=$1 out=$2 max=0 s
  while [ -e "$TMP/sampling" ]; do
    s=$(group_rss_kb "$pg")
    [ "$s" -gt "$max" ] && max=$s
    sleep 0.25
  done
  echo "$max" > "$out"
}

mallocs_mark() {
  local fw=$1
  fw_is_go "$fw" || return 0
  [ "$fw" = fiber-pf ] && return 0
  kill -USR1 "$SPID" 2>/dev/null
  sleep 0.3
}

mallocs_read() {
  local fw=$1 line
  MALLOCS=""; MBYTES=""
  fw_is_go "$fw" || return 0
  [ "$fw" = fiber-pf ] && return 0
  kill -USR1 "$SPID" 2>/dev/null
  sleep 0.3
  line=$(grep -o 'mallocs=[0-9]* bytes=[0-9]*' "$TMP/srv.err" | tail -n 1)
  MALLOCS=$(echo "$line" | sed -E 's/mallocs=([0-9]+).*/\1/')
  MBYTES=$(echo "$line" | sed -E 's/.*bytes=([0-9]+)/\1/')
}

to_us() {
  awk -v v="$1" 'BEGIN{
    n=v; sub(/[a-z]+$/,"",n); u=v; sub(/^[0-9.]+/,"",u);
    if(u=="us") m=1; else if(u=="ms") m=1000; else if(u=="s") m=1000000; else if(u=="m") m=60000000; else m=1;
    printf "%.1f", n*m }'
}

load_cmd() {
  local wl=$1 proto=$2 conns=$3 dur=$4 url line
  url="$(scheme "$proto")://$ADDR$(wl_path "$wl")"
  LOAD=()
  case "$proto" in
    h1|tls)
      LOAD=("$WRK" -t"$THREADS" -c"$conns" -d"$dur" --latency)
      [ "$wl" = W4 ] && LOAD+=(-s "$TMP/post.lua")
      while IFS= read -r line; do [ -n "$line" ] && LOAD+=(-H "$line"); done < <(wl_headers "$wl")
      LOAD+=("$url") ;;
    h2c|h2)
      LOAD=(h2load -t"$THREADS" -c"$conns" -m"$(wl_streams "$wl")" -D"$dur")
      [ "$wl" = W4 ] && LOAD+=(-d "$EXPECT/body1k" -H 'content-type: application/octet-stream')
      while IFS= read -r line; do [ -n "$line" ] && LOAD+=(-H "$line"); done < <(wl_headers "$wl")
      LOAD+=("$url") ;;
  esac
}

parse_wrk() {
  local f=$1
  REQS=$(awk '/requests in/{print $1}' "$f")
  RPS=$(awk '/^Requests\/sec:/{print $2}' "$f")
  NON2XX=$(awk '/Non-2xx or 3xx responses:/{print $NF}' "$f")
  ERRS=$(awk '/Socket errors:/{gsub(/,/,""); print $4+$6+$8+$10}' "$f")
  P50=$(to_us "$(awk '$1=="50%"{print $2}' "$f")")
  P99=$(to_us "$(awk '$1=="99%"{print $2}' "$f")")
  MEAN=$(to_us "$(awk '$1=="Latency"{print $2; exit}' "$f")")
  SD=$(to_us "$(awk '$1=="Latency"{print $3; exit}' "$f")")
}

parse_h2load() {
  local f=$1
  RPS=$(awk '/^finished in/{print $4}' "$f")
  REQS=$(awk '/^requests:/{print $8}' "$f")
  ERRS=$(awk '/^requests:/{print $10+$12+$14}' "$f")
  NON2XX=$(awk '/^status codes:/{print $5+$7+$9}' "$f")
  P50=""; P99=""
  MEAN=$(to_us "$(awk '/^time for request:/{print $6}' "$f")")
  SD=$(to_us "$(awk '/^time for request:/{print $7}' "$f")")
}

parse_ws() {
  local f=$1
  REQS=$(grep -o 'msgs=[0-9]*' "$f" | cut -d= -f2)
  RPS=$(grep -o 'rate=[0-9.]*' "$f" | cut -d= -f2)
  P50=$(grep -o 'p50=[0-9.]*' "$f" | cut -d= -f2)
  P99=$(grep -o 'p99=[0-9.]*' "$f" | cut -d= -f2)
  ERRS=$(grep -o 'errors=[0-9]*' "$f" | cut -d= -f2)
  NON2XX=0; MEAN=""; SD=""
}

csv_header() {
  echo "round,fw,proto,mode,wl,conns,streams,reqs,rps,p50_us,p99_us,mean_us,sd_us,non2xx,errors,client_cpu_pct,server_cpu_pct,server_rss_max_kb,server_hwm_kb,mallocs_per_req,bytes_per_req,client_bound,valid,note" > "$OUT"
}

csv_row() {
  local note
  note=$(printf '%s' "$9" | tr ',"\n' ";' ")
  echo "$1,$2,$3,$4,$5,$6,$7,${REQS:-},${RPS:-},${P50:-},${P99:-},${MEAN:-},${SD:-},${NON2XX:-},${ERRS:-},${CCPU:-},${SCPU:-},${RSSMAX:-},${HWM:-},${MPR:-},${BPR:-},${CBOUND:-},$8,$note" >> "$OUT"
}

measure() {
  local round=$1 fw=$2 proto=$3 mode=$4 wl=$5 conns=$6 streams=$7 out=$TMP/load.txt t0 t1 cu cs ce
  REQS=""; RPS=""; P50=""; P99=""; MEAN=""; SD=""; NON2XX=""; ERRS=""; CCPU=""; SCPU=""; RSSMAX=""; HWM=""; MPR=""; BPR=""; CBOUND=""
  mallocs_mark "$fw"
  touch "$TMP/sampling"
  rss_sampler "$SPID" "$TMP/rssmax" &
  local sampler=$!
  t0=$(group_cpu_ticks "$SPID")
  if [[ "$wl" == W12* ]]; then
    local size=64
    [ "$wl" = W12b ] && size=16384
    local wsurl="ws://$ADDR/ws"
    [ "$proto" = tls ] && wsurl="wss://$ADDR/ws"
    timeout -k 5 "$LOAD_TIMEOUT" /usr/bin/time -f '%U %S %e' -o "$TMP/time" "$BIN/wsload" -url "$wsurl" -c "$conns" -d "$DUR" -size "$size" -insecure > "$out" 2>&1
  else
    load_cmd "$wl" "$proto" "$conns" "$DUR"
    timeout -k 5 "$LOAD_TIMEOUT" /usr/bin/time -f '%U %S %e' -o "$TMP/time" "${LOAD[@]}" > "$out" 2>&1
  fi
  [ $? = 124 ] && echo "load tool timed out after ${LOAD_TIMEOUT}s" >> "$out"
  t1=$(group_cpu_ticks "$SPID")
  rm -f "$TMP/sampling"
  wait "$sampler" 2>/dev/null
  RSSMAX=$(cat "$TMP/rssmax" 2>/dev/null)
  HWM=$(group_hwm_kb "$SPID")
  read -r cu cs ce < <(tail -n 1 "$TMP/time")
  CCPU=$(awk -v u="$cu" -v s="$cs" -v e="$ce" 'BEGIN{ if(e>0) printf "%.0f", (u+s)/e*100 }')
  SCPU=$(awk -v d=$((t1 - t0)) -v hz="$CLK" -v e="$ce" 'BEGIN{ if(e>0) printf "%.0f", d/hz/e*100 }')
  CBOUND=$(awk -v c="${CCPU:-0}" -v t="$THREADS" 'BEGIN{ print (c >= t*95) ? 1 : 0 }')
  case "$wl" in
    W12*) parse_ws "$out" ;;
    *) case "$proto" in h1|tls) parse_wrk "$out" ;; *) parse_h2load "$out" ;; esac ;;
  esac
  mallocs_read "$fw"
  if [ -n "${MALLOCS:-}" ] && [ "${REQS:-0}" -gt 0 ] 2>/dev/null; then
    MPR=$(awk -v m="$MALLOCS" -v r="$REQS" 'BEGIN{ printf "%.3f", m/r }')
    BPR=$(awk -v b="$MBYTES" -v r="$REQS" 'BEGIN{ printf "%.1f", b/r }')
  fi
  local valid=1 note=""
  if [ -z "${RPS:-}" ] || [ "${REQS:-0}" = 0 ]; then valid=0; note="no result: $(head -c 120 "$out" | tr '\n,' '  ')"; fi
  [ "${NON2XX:-0}" != 0 ] && { valid=0; note="non2xx=$NON2XX"; }
  [ "${ERRS:-0}" != 0 ] && { valid=0; note="${note:+$note; }errors=$ERRS"; }
  [ "$valid" = 1 ] || FAILED=1
  csv_row "$round" "$fw" "$proto" "$mode" "$wl" "$conns" "$streams" "$valid" "$note"
  printf '%s %-9s %-4s %-5s %-5s c=%-5s rps=%-12s p99=%-9s cpu(c/s)=%s/%s valid=%s %s\n' \
    "$round" "$fw" "$proto" "$mode" "$wl" "$conns" "${RPS:-}" "${P99:-${MEAN:-}}" "${CCPU:-}" "${SCPU:-}" "$valid" "$note"
}

warmup() {
  local proto=$1
  [ -n "${PROFILE_DIR:-}" ] && return 0
  load_cmd W1 "$proto" 256 "$WARM"
  timeout -k 5 "$(load_timeout_secs "$WARM_MS")" "${LOAD[@]}" > /dev/null 2>&1
}

selected() { [ "$WLS" = all ] || [[ ",$WLS," == *",$1,"* ]]; }
proto_selected() { [[ ",$PROTOS," == *",$1,"* ]]; }
in_phase() { if [ "$PHASE" = late ]; then [[ " $LATE_WLS " == *" $1 "* ]]; else [[ " $LATE_WLS " != *" $1 "* ]]; fi; }

skip_row() {
  local c conns=256
  REQS=""; RPS=""; P50=""; P99=""; MEAN=""; SD=""; NON2XX=""; ERRS=""; CCPU=""; SCPU=""; RSSMAX=""; HWM=""; MPR=""; BPR=""; CBOUND=""
  [ "$4" = app ] && conns=$(wl_conns "$5")
  for c in $conns; do csv_row "$1" "$2" "$3" "$4" "$5" "$c" "" "$6" "$7"; done
  printf '%s %-9s %-4s %-5s %-5s skipped: %s\n' "$1" "$2" "$3" "$4" "$5" "$7"
}

run_app() {
  local round=$1 fw=$2 proto=$3 wl conns streams
  local wls=()
  for wl in $ALL_WLS; do
    [ "$wl" = W11 ] && continue
    selected "$wl" || continue
    in_phase "$wl" || continue
    [[ "$(wl_protos "$wl")" == *" $proto "* ]] || continue
    wls+=("$wl")
  done
  [ ${#wls[@]} -gt 0 ] || return 0
  if ! start_server "$fw" "$proto" app; then
    for wl in "${wls[@]}"; do skip_row "$round" "$fw" "$proto" app "$wl" 0 "$START_NOTE"; done
    case "$START_NOTE" in unsupported*) ;; *) FAILED=1 ;; esac
    return 0
  fi
  warmup "$proto"
  for wl in "${wls[@]}"; do
    streams=""
    case "$proto" in h2c|h2) streams=$(wl_streams "$wl") ;; esac
    if ! kill -0 "$SPID" 2>/dev/null; then
      local died
      died=$(tail -n 2 "$TMP/srv.err" | tr '\n,' '  ')
      SPID=""
      if ! start_server "$fw" "$proto" app; then
        skip_row "$round" "$fw" "$proto" app "$wl" 0 "server died and restart failed: $died"
        FAILED=1
        continue
      fi
      echo "restarted $fw $proto after crash: $died"
      warmup "$proto"
    fi
    if [[ "$wl" != W12* ]] && ! smoke "$wl" "$proto"; then
      skip_row "$round" "$fw" "$proto" app "$wl" 0 "smoke: $SMOKE_NOTE"
      FAILED=1
      continue
    fi
    for conns in $(wl_conns "$wl"); do
      measure "$round" "$fw" "$proto" app "$wl" "$conns" "$streams"
    done
  done
  stop_server
}

run_proxy() {
  local round=$1 fw=$2 proto=$3
  selected W11 || return 0
  [[ " h1 tls " == *" $proto "* ]] || return 0
  if ! start_server "$fw" "$proto" proxy; then
    skip_row "$round" "$fw" "$proto" proxy W11 0 "$START_NOTE"
    case "$START_NOTE" in unsupported*) ;; *) FAILED=1 ;; esac
    return 0
  fi
  warmup "$proto"
  if smoke W11 "$proto"; then
    measure "$round" "$fw" "$proto" proxy W11 256 ""
  else
    skip_row "$round" "$fw" "$proto" proxy W11 0 "smoke: $SMOKE_NOTE"
    FAILED=1
  fi
  stop_server
}

phase_rounds() {
  local wl
  for wl in $ALL_WLS; do
    if selected "$wl" && in_phase "$wl"; then seq 1 "$ROUNDS"; return; fi
  done
}

time_wait_count() {
  local side=$1 filter="" p
  for p in $TW_PORTS; do filter+="${filter:+ or }$side = :$p"; done
  ss -Htan state time-wait "( $filter )" | wc -l
}

now_ms() { echo $(($(date +%s%N) / 1000000)); }

wait_time_wait() {
  local start left
  start=$(now_ms)
  left=$(time_wait_count sport)
  while [ "$left" -gt 0 ] && [ $(($(now_ms) - start)) -lt "$TW_WAIT_MAX_MS" ]; do
    sleep "$TW_POLL_S"
    left=$(time_wait_count sport)
  done
  printf 'tw-wait %s: %d ms, %d server-side TIME_WAIT left on ports %s (client-side, not waited for: %d)\n' \
    "$1" $(($(now_ms) - start)) "$left" "$TW_PORTS" "$(time_wait_count dport)"
}

rotate() {
  local n=$1; shift
  local arr=("$@") len=$# i
  for i in $(seq 0 $((len - 1))); do echo "${arr[$(((i + n) % len))]}"; done
}

main() {
  for t in "$WRK" h2load curl /usr/bin/time; do command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 2; }; done
  IFS=, read -r -a fwarr <<< "$FWS"
  IFS=, read -r -a protoarr <<< "$PROTOS"
  for fw in "${fwarr[@]}"; do [ -x "$(fw_bin "$fw")" ] || { echo "missing binary for $fw: $(fw_bin "$fw")" >&2; exit 2; }; done
  prepare_expect
  csv_header
  echo "tier=$TIER fws=$FWS protos=$PROTOS wls=$WLS rounds=$ROUNDS dur=$DUR warm=$WARM out=$OUT"
  if selected W11; then
    [ -x "$(fw_bin "$ORIGIN_FW")" ] || { echo "missing origin binary: $(fw_bin "$ORIGIN_FW")" >&2; exit 2; }
    start_origin || exit 3
  fi
  local round fw proto
  PHASE=main
  for round in $(phase_rounds); do
    while read -r fw; do
      wait_time_wait "$PHASE r$round $fw"
      for proto in "${protoarr[@]}"; do
        run_app "$round" "$fw" "$proto"
        run_proxy "$round" "$fw" "$proto"
      done
    done < <(rotate $((round - 1)) "${fwarr[@]}")
  done
  stop_origin
  PHASE=late
  for round in $(phase_rounds); do
    while read -r fw; do
      wait_time_wait "$PHASE r$round $fw"
      for proto in "${protoarr[@]}"; do
        run_app "$round" "$fw" "$proto"
      done
    done < <(rotate $((round - 1)) "${fwarr[@]}")
  done
  echo "done: $OUT"
  [ "$FAILED" = 0 ] || exit 3
}

if [ "${PERF_NO_LOCK:-0}" = 1 ]; then
  main
else
  exec 9>"$LOCK"
  flock -x 9
  main
fi
