#!/usr/bin/env bash
# LFCP-055: build the image and check it through Docker Compose.
#
#   server/deploy/check.sh
#
# Needs Docker with Compose v2, curl, a Rust toolchain, and the CI layout:
# server/, sdk-rs/ (at the commit in server/sdk-rs.lock) and spec/ (with
# the tag in server/spec.lock) side by side. Uses its own compose project
# and ports (18443/18080, server on 127.0.0.1:17820) and removes
# everything, volumes included, when it ends.
set -euo pipefail

deploy="$(cd "$(dirname "$0")" && pwd)"
server="$(dirname "$deploy")"
root="$(dirname "$server")"
fail() { echo "check: $*" >&2; exit 1; }

# The image is built from the sibling sdk-rs: it must be the locked commit,
# with no local changes to its sources.
lock="$(sed -n 's/.*"commit": *"\([0-9a-f]*\)".*/\1/p' "$server/sdk-rs.lock")"
[ "$(git -C "$root/sdk-rs" rev-parse HEAD)" = "$lock" ] ||
    fail "sdk-rs is not at $lock (server/sdk-rs.lock)"
git -C "$root/sdk-rs" diff --quiet HEAD -- Cargo.toml crates ||
    fail "sdk-rs has uncommitted changes"

export COMPOSE_PROJECT_NAME=lfcp-check
export LFCP_HTTPS_PORT=18443 LFCP_HTTP_PORT=18080 LFCP_CHECK_PORT=17820
compose=(docker compose -f "$deploy/compose.yaml" -f "$deploy/compose.check.yaml")
work="$(mktemp -d)"
cleanup() { "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT

phase() {
    echo "check: phase $1"
    (cd "$server" && LFCP_E2E_ADDR=127.0.0.1:17820 LFCP_E2E_PHASE="$1" LFCP_E2E_STATE="$work/state" \
        cargo test --quiet --test container -- --ignored --exact container_phase)
}

# The admin HTTP surface (LFCP-046) over https through the proxy, trusting
# Caddy's local CA (re-read after the proxy's volume is recreated).
trust() { "${compose[@]}" cp proxy:/data/caddy/pki/authorities/local/root.crt "$work/root.crt"; }
https() { curl --fail --silent --show-error --cacert "$work/root.crt" "$@"; }
field() { sed -n "s/.*\"$1\": *\"\{0,1\}\([^\",}]*\).*/\1/p"; }
# The body of an admin request: a proof by the vectors' bob for $1 ("pair"
# or "session") over the server ID and a fresh challenge.
admin_body() {
    local id challenge
    id="$(https https://localhost:18443/setup | field server_id)"
    challenge="$(https -X POST https://localhost:18443/admin/challenge | field challenge)"
    (cd "$server" && LFCP_E2E_PHASE=admin-proof LFCP_E2E_PURPOSE="$1" LFCP_E2E_SERVER_ID="$id" \
        LFCP_E2E_CHALLENGE="$challenge" LFCP_E2E_OUT="$2" LFCP_E2E_ADDR=127.0.0.1:1 LFCP_E2E_STATE=/dev/null \
        cargo test --quiet --test container -- --ignored --exact container_phase)
}
paired() { https https://localhost:18443/setup | field paired; }

echo "check: build and start"
"${compose[@]}" up -d --build --wait

echo "check: the image runs as non-root"
user="$(docker inspect --format '{{.Config.User}}' openlfcp/lfcp-server:dev)"
[ "$user" = "nonroot:nonroot" ] || fail "image user is '$user'"
uids="$("${compose[@]}" top lfcp-server | awk 'NR > 1 { print $1 }')"
[ -n "$uids" ] || fail "no server process"
if grep -qxE 'root|0' <<<"$uids"; then fail "server process runs as root"; fi

echo "check: health is green"
[ "$(docker inspect --format '{{.State.Health.Status}}' "$("${compose[@]}" ps -q lfcp-server)")" = healthy ] ||
    fail "container is not healthy"

# Security review M6: the pairing code is in a 0600 file in the state
# volume, and only its path is in the logs. The code itself is never
# echoed here.
echo "check: the pairing code is in its private file, not in the logs"
code="$("${compose[@]}" cp lfcp-server:/var/lib/lfcp/setup-code - | tar -xO)"
grep -qxE '[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}' <<<"$code" ||
    fail "no pairing code in /var/lib/lfcp/setup-code"
mode="$("${compose[@]}" cp lfcp-server:/var/lib/lfcp/setup-code - | tar -tvf - | awk '{ print $1 }')"
[ "$mode" = "-rw-------" ] || fail "setup-code has mode $mode, not 0600"
logs="$("${compose[@]}" logs lfcp-server 2>&1)"
grep -q 'pairing code written to /var/lib/lfcp/setup-code' <<<"$logs" ||
    fail "the logs do not say where the pairing code is"
if grep -qF "$code" <<<"$logs"; then fail "the pairing code is in docker logs"; fi

echo "check: wss through the proxy"
trust
curl --fail --silent --show-error --cacert "$work/root.crt" https://localhost:18443/health | grep -q '"ok"' ||
    fail "/health through the proxy"
# A WebSocket upgrade with lfcp-1: 101 and the subprotocol selected. curl
# then waits on the open socket, so it is cut off after two seconds.
curl --silent --http1.1 --cacert "$work/root.crt" --max-time 2 --dump-header "$work/upgrade" -o /dev/null \
    -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Protocol: lfcp-1' \
    https://localhost:18443/v1/ws || true
grep -q '^HTTP/1.1 101' "$work/upgrade" || fail "no 101 through the proxy: $(head -1 "$work/upgrade")"
grep -qi '^sec-websocket-protocol: lfcp-1' "$work/upgrade" || fail "lfcp-1 not selected"

# POST-003: the server believes the client address only from the proxy,
# and the proxy replaces a forged X-Forwarded-For with the real peer.
echo "check: the server sees the client address the proxy reports"
curl --silent --http1.1 --cacert "$work/root.crt" --max-time 2 -o /dev/null \
    -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Protocol: lfcp-1' \
    -H 'X-Forwarded-For: 203.0.113.77' https://localhost:18443/v1/ws || true
opened="$("${compose[@]}" logs lfcp-server 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep 'websocket open' | tail -1)"
grep -q 'peer=172\.30\.78\.10:' <<<"$opened" || fail "the WebSocket did not come from the proxy: $opened"
if grep -q 'client=172\.30\.78\.10' <<<"$opened"; then fail "the client is the proxy: $opened"; fi
if grep -q 'client=203\.0\.113\.77' <<<"$opened"; then fail "a forged X-Forwarded-For was believed: $opened"; fi
grep -q 'client=[0-9a-f.:]*' <<<"$opened" || fail "no client address: $opened"

# First-run pairing (LFCP-046) over https through the proxy, with the code
# read from its private file; the code is never echoed, and it is never
# in the logs.
echo "check: first-run pairing over https"
[ "$(paired)" = false ] || fail "a new server is already paired"
admin_body pair "$work/pair.json"
sed -i.bak "s/^{/{\"code\":\"$code\",/" "$work/pair.json"
https -X POST -H 'Content-Type: application/json' --data @"$work/pair.json" \
    https://localhost:18443/setup/pair >/dev/null || fail "pairing was refused"
rm -f "$work/pair.json" "$work/pair.json.bak"
[ "$(paired)" = true ] || fail "the server is not paired after /setup/pair"
if "${compose[@]}" cp lfcp-server:/var/lib/lfcp/setup-code - >/dev/null 2>&1; then
    fail "the pairing code file is still there after pairing"
fi
admin_body session "$work/session.json"
token="$(https -X POST -H 'Content-Type: application/json' --data @"$work/session.json" \
    https://localhost:18443/admin/session | field token)"
[ -n "$token" ] || fail "no admin session for the paired administrator"
https -H "Authorization: Bearer $token" https://localhost:18443/admin/status >/dev/null ||
    fail "/admin/status with the admin token"
if "${compose[@]}" logs lfcp-server 2>&1 | grep -qF "$code"; then fail "the pairing code is in docker logs"; fi

phase populate

echo "check: recreate the containers on the same volume"
"${compose[@]}" down
"${compose[@]}" up -d --wait
phase verify
[ "$(paired)" = true ] || fail "the pairing did not survive the restart"
if "${compose[@]}" cp lfcp-server:/var/lib/lfcp/setup-code - >/dev/null 2>&1; then
    fail "a paired server wrote a new pairing code"
fi

echo "check: destroy the volume"
"${compose[@]}" down -v
"${compose[@]}" up -d --wait
phase fresh
trust
[ "$(paired)" = false ] || fail "a destroyed volume is still paired"
fresh_code="$("${compose[@]}" cp lfcp-server:/var/lib/lfcp/setup-code - | tar -xO)"
[ -n "$fresh_code" ] && [ "$fresh_code" != "$code" ] || fail "a new server has no new pairing code"

echo "check: all passed"
