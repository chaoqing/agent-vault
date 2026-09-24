#!/usr/bin/env bash
# End-to-end demo of instance-level upstream (egress) proxies.
#
# Everything runs on loopback — no internet access, no third-party services,
# and no changes to your machine beyond a temporary directory. The demo proves:
#
#   1. With no profile configured, brokered requests dial their target directly.
#   2. An instance default profile routes the same request through the proxy.
#   3. no_proxy lets matching targets bypass that proxy again.
#   4. fail_closed refuses the request when the proxy is unreachable.
#   5. fail_open lets the same request through (directly) once flipped.
#   6. Services reference profiles by name, and a referenced profile cannot be
#      deleted out from under them.
#
# Usage: ./run.sh
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DEMO_DIR/../.." && pwd)"

API_PORT=14331
MITM_PORT=14332
TARGET_PORT=18099
PROXY_PORT=13128

OWNER_EMAIL="owner@example.com"
OWNER_PASSWORD="demo-password-123"
PROFILE_NAME="corp-egress"
TARGET_HOST="127.0.0.1:${TARGET_PORT}"
PROXY_HOST="127.0.0.1:${PROXY_PORT}"

WORK_DIR="$(mktemp -d)"
LOG_DIR="$WORK_DIR/logs"
mkdir -p "$LOG_DIR"
PROXY_LOG="$LOG_DIR/egress-proxy.log"

TARGET_PID=""
PROXY_PID=""
BROKER_PID=""

step() { printf '\n\033[1m%s\033[0m\n' "$1"; }
info() { printf '  %s\n' "$1"; }
ok() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() {
  printf '  \033[31m✗\033[0m %s\n' "$1"
  exit 1
}
cleanup() {
  for pid in "$TARGET_PID" "$PROXY_PID" "$BROKER_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

json_field() { python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }

api() { # api <method> <path> [json-body]
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -X "$method" -H "Authorization: Bearer ${OWNER_TOKEN:-}" -H "Content-Type: application/json")
  [ -n "$body" ] && args+=(-d "$body")
  curl "${args[@]}" "http://127.0.0.1:${API_PORT}${path}"
}

proxy_log_lines() { wc -l < "$PROXY_LOG" | tr -d ' '; }

wait_for() { # wait_for <curl-expr...>
  for _ in $(seq 1 60); do
    "$@" >/dev/null 2>&1 && return 0 || sleep 0.25
  done
  return 1
}

# wait_requests waits until the resolver's short cache window has passed so a
# policy edit is guaranteed to apply to the next request rather than being
# served from a stale resolution.
wait_policy() { sleep 6; }

# request_status performs one brokered request and prints its HTTP status.
request_status() {
  curl -s -o /dev/null -w '%{http_code}' \
    -x "http://127.0.0.1:${MITM_PORT}" \
    -U "${AGENT_TOKEN}:default" \
    --max-time 15 "http://${TARGET_HOST}/"
}

# --- 0. Build ------------------------------------------------------------

step "0. Building the broker"
if command -v agent-vault >/dev/null 2>&1; then
  BIN="$(command -v agent-vault)"
  ok "using agent-vault from PATH ($BIN)"
else
  BIN="$WORK_DIR/agent-vault"
  (cd "$REPO_ROOT" && go build -o "$BIN" .)
  ok "built from source ($BIN)"
fi

# --- 1. Fake upstream target --------------------------------------------

step "1. Starting a stand-in upstream target on ${TARGET_HOST}"
echo '<html><body>hello from the demo target</body></html>' > "$WORK_DIR/index.html"
(cd "$WORK_DIR" && python3 -m http.server "$TARGET_PORT" --bind 127.0.0.1 >"$LOG_DIR/target.log" 2>&1 & echo $! >"$LOG_DIR/target.pid")
TARGET_PID="$(cat "$LOG_DIR/target.pid")"
wait_for curl -sf "http://${TARGET_HOST}/" || fail "target did not come up"
ok "target serves GET / (200)"

# --- 2. Stand-in egress proxy -------------------------------------------

step "2. Starting the logging egress proxy on ${PROXY_HOST}"
python3 "$DEMO_DIR/egress_proxy.py" "$PROXY_PORT" "$PROXY_LOG" >"$LOG_DIR/egress-proxy.stderr" 2>&1 &
PROXY_PID=$!
wait_for curl -sf -x "http://${PROXY_HOST}" "http://${TARGET_HOST}/" || fail "egress proxy did not come up"
ok "proxy forwards requests and logs them to $(basename "$PROXY_LOG")"

# --- 3. Broker ----------------------------------------------------------

step "3. Starting the broker (ports ${API_PORT} / ${MITM_PORT})"
HOME="$WORK_DIR" \
AGENT_VAULT_ALLOW_PRIVATE_RANGES=true \
AGENT_VAULT_NO_TELEMETRY=1 \
AGENT_VAULT_LOG_LEVEL=debug \
  "$BIN" server --host 127.0.0.1 --port "$API_PORT" --mitm-port "$MITM_PORT" \
  --password-stdin <<< "" >"$LOG_DIR/broker.log" 2>&1 &
BROKER_PID=$!
wait_for curl -sf "http://127.0.0.1:${API_PORT}/v1/status" || fail "broker did not come up"
ok "broker ready (isolated HOME=$WORK_DIR)"

# --- 4. Owner + agent session -------------------------------------------

step "4. Registering the owner and minting an agent token"
OWNER_TOKEN="$(curl -sS -X POST -H 'Content-Type: application/json' \
  -d "{\"email\":\"$OWNER_EMAIL\",\"password\":\"$OWNER_PASSWORD\"}" \
  "http://127.0.0.1:${API_PORT}/v1/auth/register" | json_field token)"
[ -n "$OWNER_TOKEN" ] || fail "owner registration returned no token"
ok "owner registered (first user becomes instance owner)"

AGENT_TOKEN="$(api POST /v1/sessions \
  "{\"vault\":\"default\",\"vault_role\":\"proxy\",\"ttl_seconds\":3600,\"label\":\"demo-agent\"}" | json_field token)"
[ -n "$AGENT_TOKEN" ] || fail "session minting returned no token"
ok "vault-scoped agent token minted"

# --- 5. Baseline: no profile --------------------------------------------

step "5. Baseline: with no profile, requests dial the target directly"
BEFORE="$(proxy_log_lines)"
STATUS="$(request_status)"
AFTER="$(proxy_log_lines)"
[ "$STATUS" = "200" ] || fail "expected 200, got $STATUS"
[ "$BEFORE" = "$AFTER" ] || fail "proxy saw traffic it should not have"
ok "brokered request succeeded (200) without touching the egress proxy"

# --- 6. Instance default profile ----------------------------------------

step "6. Creating the instance default profile '${PROFILE_NAME}'"
api POST /v1/admin/upstream-proxies \
  "{\"name\":\"$PROFILE_NAME\",\"scheme\":\"http\",\"host\":\"$PROXY_HOST\",\"on_failure\":\"fail_closed\",\"is_default\":true,\"enabled\":true}" \
  >/dev/null
ok "profile created (scheme=http, host=$PROXY_HOST, on_failure=fail_closed, is_default=true)"

wait_policy
BEFORE="$(proxy_log_lines)"
STATUS="$(request_status)"
AFTER="$(proxy_log_lines)"
[ "$STATUS" = "200" ] || fail "expected 200, got $STATUS"
[ "$AFTER" -gt "$BEFORE" ] || fail "the request did not transit the egress proxy"
ok "request succeeded (200) and the proxy logged $((AFTER - BEFORE)) new request(s)"
info "proxy log: $(tail -n 1 "$PROXY_LOG")"

# --- 7. no_proxy bypass -------------------------------------------------

step "7. no_proxy lets a target bypass the profile"
api PATCH "/v1/admin/upstream-proxies/$PROFILE_NAME" "{\"no_proxy\":\"127.0.0.1\"}" >/dev/null
wait_policy
BEFORE="$(proxy_log_lines)"
STATUS="$(request_status)"
AFTER="$(proxy_log_lines)"
[ "$STATUS" = "200" ] || fail "expected 200, got $STATUS"
[ "$BEFORE" = "$AFTER" ] || fail "no_proxy was ignored — the proxy still saw the request"
ok "request succeeded (200) while bypassing the proxy"
api PATCH "/v1/admin/upstream-proxies/$PROFILE_NAME" '{"no_proxy":""}' >/dev/null
ok "bypass cleared"

# --- 8. fail_closed -----------------------------------------------------

step "8. fail_closed when the proxy is unreachable"
kill "$PROXY_PID"; PROXY_PID=""
wait_policy
STATUS="$(request_status)"
[ "$STATUS" != "200" ] || fail "request succeeded with the proxy down — traffic leaked"
ok "proxy down: broker returned ${STATUS} (no silent fallback to a direct dial)"

# --- 9. fail_open -------------------------------------------------------

step "9. fail_open lets the same request through"
api PATCH "/v1/admin/upstream-proxies/$PROFILE_NAME" '{"on_failure":"fail_open"}' >/dev/null
wait_policy
STATUS="$(request_status)"
[ "$STATUS" = "200" ] || fail "expected 200 under fail_open, got $STATUS"
ok "request succeeded (200) by falling back to a direct dial"
api PATCH "/v1/admin/upstream-proxies/$PROFILE_NAME" '{"on_failure":"fail_closed"}' >/dev/null
info "policy restored to fail_closed"

# --- 10. Per-service references -----------------------------------------

step "10. Services reference profiles by name"
SERVICE_HOST="example.test"

# A reference to a profile that does not exist is rejected before it can be
# persisted — otherwise a service would silently dial directly.
REJECTION="$(api PUT /v1/vaults/default/services \
  "{\"services\":[{\"name\":\"demo-api\",\"host\":\"$SERVICE_HOST\",\"auth\":{\"type\":\"passthrough\"},\"upstream_proxy\":\"does-not-exist\"}]}")"
echo "$REJECTION" | grep -q 'unknown upstream proxy' || fail "expected a rejection, got: $REJECTION"
ok "unknown profile reference rejected: $REJECTION"

api PUT /v1/vaults/default/services \
  "{\"services\":[{\"name\":\"demo-api\",\"host\":\"$SERVICE_HOST\",\"auth\":{\"type\":\"passthrough\"},\"upstream_proxy\":\"$PROFILE_NAME\"}]}" \
  >/dev/null
ok "service 'demo-api' now references ${PROFILE_NAME}"

REFUSAL="$(api DELETE "/v1/admin/upstream-proxies/$PROFILE_NAME")"
echo "$REFUSAL" | grep -q 'referenced by' || fail "expected a 409 refusal, got: $REFUSAL"
ok "delete refused while referenced: $REFUSAL"

api PUT /v1/vaults/default/services \
  "{\"services\":[{\"name\":\"demo-api\",\"host\":\"$SERVICE_HOST\",\"auth\":{\"type\":\"passthrough\"}}]}" \
  >/dev/null
DELETED="$(api DELETE "/v1/admin/upstream-proxies/$PROFILE_NAME")"
echo "$DELETED" | grep -q 'deleted' || fail "expected the delete to succeed, got: $DELETED"
ok "once unreferenced, the profile deletes cleanly"

# --- Summary ------------------------------------------------------------

step "Demo complete"
cat <<EOF
  profile ......... ${PROFILE_NAME} (${PROXY_HOST})
  target .......... http://${TARGET_HOST}/  (python3 -m http.server)
  egress proxy .... ${PROXY_HOST} (logging proxy, $(basename "$DEMO_DIR")/egress_proxy.py)
  broker .......... api :${API_PORT} / mitm :${MITM_PORT}
  evidence ........ ${PROXY_LOG}

  Live request flow (steps 5-9) followed (proxy log is the record):

    $(sed -n '1,3p' "$PROXY_LOG" | tr '\n' '|')

  Do the same thing from the UI: Settings -> Upstream Proxies to create the
  profile, then pick it per service from the service editor's "Upstream Proxy"
  dropdown.
EOF

info "logs are in $LOG_DIR"
