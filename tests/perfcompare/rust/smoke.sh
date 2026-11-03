#!/bin/bash
BIN="$1"
PROTO="$2"
PORT="$3"
MODE="${4:-app}"
ORIGIN="${5:-127.0.0.1:18209}"
H=/root/alos-perf/harness
DIR=$(dirname "$0")
LOG=$(mktemp)
FAILS=0

"$BIN" -proto "$PROTO" -mode "$MODE" -addr 127.0.0.1:$PORT -cert $H/certs/cert.pem -key $H/certs/key.pem -static $H/static -origin "$ORIGIN" >"$LOG" 2>&1 &
PID=$!
for i in $(seq 1 100); do
  grep -q '^READY$' "$LOG" && break
  if ! kill -0 $PID 2>/dev/null; then break; fi
  sleep 0.05
done
if ! grep -q '^READY$' "$LOG"; then
  wait $PID 2>/dev/null
  echo "[$PROTO/$MODE] not ready, exit=$? output: $(head -c 400 "$LOG")"
  rm -f "$LOG"
  exit 0
fi
echo "[$PROTO/$MODE] READY pid=$PID threads=$(ls /proc/$PID/task | wc -l)"

case "$PROTO" in
  h1) BASE=http://127.0.0.1:$PORT; CURLS=("--http1.1") ;;
  h2c) BASE=http://127.0.0.1:$PORT; CURLS=("--http2-prior-knowledge") ;;
  tls) BASE=https://127.0.0.1:$PORT; CURLS=("-k --http1.1" "-k --http2") ;;
  h2) BASE=https://127.0.0.1:$PORT; CURLS=("-k --http2") ;;
esac

check() {
  local name="$1" got="$2" want="$3"
  if [ "$got" == "$want" ]; then echo "  ok   $name"; else echo "  FAIL $name got=[$(echo "$got" | head -c 120)] want=[$(echo "$want" | head -c 120)]"; FAILS=$((FAILS+1)); fi
}

if [ "$MODE" == "proxy" ]; then
  for C in "${CURLS[@]}"; do
    check "proxy /plaintext ($C)" "$(curl -s $C $BASE/plaintext)" "Hello, World!"
  done
  kill $PID; wait $PID 2>/dev/null; rm -f "$LOG"; echo "[$PROTO/$MODE] fails=$FAILS"; exit 0
fi

python3 -c "import sys;sys.stdout.buffer.write(b'x'*65536)" > /tmp/smk-64k
python3 -c "import sys;sys.stdout.buffer.write(b'x'*1048576)" > /tmp/smk-1m
python3 -c "import sys;p=b'The quick brown fox jumps over the lazy dog. ';sys.stdout.buffer.write((p*400)[:16384])" > /tmp/smk-16k
head -c 1024 /dev/zero | tr '\0' 'a' > /tmp/smk-post

for C in "${CURLS[@]}"; do
  echo " curl $C"
  V=$(curl -s $C -o /dev/null -w '%{http_version}' $BASE/plaintext); echo "  http_version=$V"
  check "W1 body" "$(curl -s $C $BASE/plaintext)" "Hello, World!"
  check "W1 ctype" "$(curl -s $C -o /dev/null -w '%{content_type}' $BASE/plaintext)" "text/plain"
  check "W1r body" "$(curl -s $C $BASE/)" "Hello, World!"
  check "W2 body" "$(curl -s $C $BASE/json)" '{"message":"Hello, World!"}'
  check "W2 ctype" "$(curl -s $C -o /dev/null -w '%{content_type}' $BASE/json)" "application/json"
  check "W3 body" "$(curl -s $C $BASE/user/12345)" "12345"
  check "W4 body" "$(curl -s $C -X POST --data-binary @/tmp/smk-post $BASE/echo)" "1024"
  check "W5a body" "$(curl -s $C $BASE/bytes/64k | cmp - /tmp/smk-64k && echo same)" "same"
  check "W5a ctype" "$(curl -s $C -o /dev/null -w '%{content_type}' $BASE/bytes/64k)" "application/octet-stream"
  check "W5b body" "$(curl -s $C $BASE/bytes/1m | cmp - /tmp/smk-1m && echo same)" "same"
  check "W6 body" "$(curl -s $C $BASE/static/file-64k.bin | cmp - $H/static/file-64k.bin && echo same)" "same"
  check "W7 gzip body" "$(curl -s $C -H 'Accept-Encoding: gzip' --compressed $BASE/text16k | cmp - /tmp/smk-16k && echo same)" "same"
  check "W7 gzip header" "$(curl -s $C -H 'Accept-Encoding: gzip' -D - -o /dev/null $BASE/text16k | tr -d '\r' | grep -i '^content-encoding:' | tr 'A-Z' 'a-z')" "content-encoding: gzip"
  check "W7 gzip wire<16k" "$(test $(curl -s $C -H 'Accept-Encoding: gzip' $BASE/text16k | wc -c) -lt 16384 && echo smaller)" "smaller"
  check "W7 br header" "$(curl -s $C -H 'Accept-Encoding: br' -D - -o /dev/null $BASE/text16k | tr -d '\r' | grep -i '^content-encoding:' | tr 'A-Z' 'a-z')" "content-encoding: br"
  check "W7 identity" "$(curl -s $C -D /tmp/smk-h $BASE/text16k | cmp - /tmp/smk-16k && echo same; grep -ci '^content-encoding:' /tmp/smk-h)" "same
0"
  check "W8 body" "$(curl -s $C -A 'Mozilla/5.0 smoke' -H 'Accept-Language: en-US,en;q=0.9' -b 'a=1; sid=abc123; z=9' $BASE/browser)" "Mozilla/5.0 smoke|en-US,en;q=0.9|abc123"
  check "W9 body" "$(curl -s $C -H 'Origin: http://example.com' $BASE/mw)" "ok"
  check "W9 cors" "$(curl -s $C -H 'Origin: http://example.com' -D - -o /dev/null $BASE/mw | tr -d '\r' | grep -i '^access-control-allow-origin:' | tr 'A-Z' 'a-z')" "access-control-allow-origin: *"
  check "404" "$(curl -s $C -o /dev/null -w '%{http_code}' $BASE/nope)" "404"
done

case "$PROTO" in
  h1|tls)
    W=$(wrk -t2 -c16 -d2s $BASE/plaintext 2>&1)
    echo "$W" | grep -E 'Requests/sec|Non-2xx|Socket errors|requests in' | sed 's/^/  wrk: /'
    if echo "$W" | grep -qE 'Non-2xx|Socket errors'; then FAILS=$((FAILS+1)); echo "  FAIL wrk errors"; else echo "  ok   wrk 0 non-2xx 0 errors"; fi
    S=ws; [ "$PROTO" == "tls" ] && S=wss
    python3 -I $DIR/wsecho.py $S 127.0.0.1 $PORT | sed 's/^/  /' || { FAILS=$((FAILS+1)); echo "  FAIL ws"; }
    ;;
  h2c|h2)
    O=$(h2load -n2000 -c8 -m10 $BASE/plaintext 2>&1)
    echo "$O" | grep -E '^requests:|^status codes:|Application protocol' | sed 's/^/  h2load: /'
    if echo "$O" | grep -qE '2000 succeeded'; then echo "  ok   h2load 2000 succeeded"; else FAILS=$((FAILS+1)); echo "  FAIL h2load"; fi
    ;;
esac

kill $PID; wait $PID 2>/dev/null
kill -0 $PID 2>/dev/null && kill -9 $PID
rm -f "$LOG"
echo "[$PROTO/$MODE] fails=$FAILS"
