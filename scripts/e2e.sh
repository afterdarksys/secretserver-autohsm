#!/usr/bin/env bash
# End-to-end test: a real (non-dev) Vault with file storage and a Shamir seal,
# three simulated nodes each holding ONE share wrapped by its own SoftHSM2
# token, and an HTTPS alarm receiver. Everything runs in disposable local
# Docker containers on a private network and is destroyed on exit; nothing
# here talks to any real Vault or host.
#
# Usage: scripts/e2e.sh            (KEEP=1 leaves the containers up for poking)
set -euo pipefail

cd "$(dirname "$0")/.."

VAULT_IMAGE=${VAULT_IMAGE:-hashicorp/vault:1.20}
PFX=autohsm-e2e-$$
IMG=autohsm-e2e:local
NET=$PFX-net
VOL=$PFX-vol
NODES=(n1 n2 n3)

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "PASS  $*"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL  $*"; }

cleanup() {
  if [ "${KEEP:-0}" = 1 ]; then
    echo "KEEP=1: containers left running with prefix $PFX"
    return
  fi
  docker rm -f "$PFX-vault" "$PFX-alarms" "${NODES[@]/#/$PFX-}" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm "$VOL" >/dev/null 2>&1 || true
}
trap cleanup EXIT

on() { local n=$1; shift; docker exec "$PFX-$n" /src/scripts/e2e/node.sh "$@"; }
status() { on n1 seal-status; }
field() { status | jq -r ".$1"; }

wait_for() { # wait_for <seconds> <jq-expr on seal-status>
  local deadline=$((SECONDS + $1))
  while [ $SECONDS -lt $deadline ]; do
    if status 2>/dev/null | jq -e "$2" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

echo "== build node image"
docker build -q -f scripts/e2e/Dockerfile -t "$IMG" . >/dev/null

echo "== start disposable network, vault, alarm receiver, nodes"
docker network create "$NET" >/dev/null
docker volume create "$VOL" >/dev/null
for n in "${NODES[@]}" alarms; do
  docker run -d --name "$PFX-$n" --hostname "$n" --network "$NET" --network-alias "$n" \
    -v "$VOL:/e2e" "$IMG" sleep infinity >/dev/null
done
on n1 pki
for n in "${NODES[@]}" alarms; do on "$n" trust; done
docker exec -d "$PFX-alarms" /src/scripts/e2e/node.sh webhook
docker run -d --name "$PFX-vault" --network "$NET" --network-alias vault \
  --cap-add IPC_LOCK -v "$VOL:/e2e" "$VAULT_IMAGE" server -config=/e2e/vault.hcl >/dev/null
wait_for 90 '.initialized == false' || { echo "vault did not come up"; docker logs "$PFX-vault"; exit 1; }
echo "vault $(field version) up: type=$(field type) initialized=$(field initialized) sealed=$(field sealed)"

echo "== initialise vault (5 shares / threshold 3)"
[ "$(on n1 init-vault)" = 5 ] && pass "vault initialised with 5 Shamir shares" || fail "vault init"
wait_for 10 '.sealed == true and .t == 3' && pass "fresh vault is sealed, threshold 3" || fail "sealed after init"

echo "== provision: one SoftHSM token + non-extractable key + one wrapped share per node"
i=0
for n in "${NODES[@]}"; do
  i=$((i + 1))
  on "$n" provision "$n" "$i"
done
for n in "${NODES[@]}"; do
  if on "$n" selftest >/dev/null 2>&1; then pass "$n selftest (TLS pin, HSM key attributes, share unwraps, layout)"
  else fail "$n selftest"; on "$n" selftest || true; fi
done
# Wrapped files hold no plaintext.
for idx in 1 2 3; do
  key=$(docker exec "$PFX-n1" jq -r ".keys_base64[$((idx - 1))]" /e2e/secret/init.json)
  n=${NODES[$((idx - 1))]}
  if docker exec "$PFX-$n" grep -qF "$key" "/etc/autohsm/share-$idx.wrapped"; then
    fail "share-$idx.wrapped contains the plaintext share"
  else pass "share-$idx.wrapped does not contain the plaintext share"; fi
done

echo "== POSITIVE: daemons unseal the vault"
for n in "${NODES[@]}"; do on "$n" watch-bg; done
wait_for 30 '.sealed == false' && pass "3 nodes x 1 share unsealed vault" || fail "initial unseal"

echo "== POSITIVE: vault sealed again via API -> re-unsealed"
on n1 seal
wait_for 30 '.sealed == false' && pass "re-unsealed after operator seal" || fail "re-unseal after seal"

echo "== POSITIVE: vault process restarted -> re-unsealed"
docker restart "$PFX-vault" >/dev/null
wait_for 60 '.sealed == false' && pass "re-unsealed after vault container restart" || fail "re-unseal after restart"

if docker exec "$PFX-alarms" grep -q '"event":"vault_sealed"' /e2e/alarms.jsonl; then
  pass "vault_sealed alarm delivered over pinned HTTPS webhook"
else fail "no vault_sealed alarm received"; fi

for n in "${NODES[@]}"; do on "$n" watch-stop; done
sleep 2

echo "== POSITIVE: episode latch survives a peer contributing first after an unobserved reset"
# n1 contributes, its daemon stops, the unseal attempt is reset (as a Vault
# restart would), and a peer contributes first in the new episode. When n1's
# daemon comes back it must recognise its latch as stale and contribute again.
on n1 seal
on n1 watch-bg
latch_ok=0
if wait_for 20 '.progress == 1'; then
  on n1 watch-stop
  sleep 1
  # The precondition must hold or the check below proves nothing.
  if docker exec "$PFX-n1" grep -q '^nonce:..*' /run/autohsm/submitted-shares; then
    latch_ok=1
    pass "latch setup: n1 contributed and persisted a nonce-keyed latch"
  else fail "latch setup: n1 persisted no nonce-keyed latch"; fi
else
  fail "latch setup: n1 never contributed (progress $(field progress))"
  on n1 watch-stop
fi
if [ $latch_ok = 1 ]; then
  on n1 unseal-reset >/dev/null
  on n1 submit-raw 2 >/dev/null
  on n1 watch-bg
  on n3 watch-bg
  if wait_for 20 '.sealed == false'; then pass "stale per-episode latch cleared; vault unsealed"
  else fail "stale latch: n1 never re-contributed (progress $(field progress))"; fi
  for n in n1 n3; do on "$n" watch-stop; done
fi
sleep 2

echo "== NEGATIVE cases: each must refuse, submit nothing, and leave vault sealed"
negative() { # negative <label> <node> <config> <want-exit>
  local label=$1 node=$2 cfg=$3 want=$4 out
  on n1 seal >/dev/null 2>&1 || true
  on n1 unseal-reset >/dev/null
  wait_for 10 '.sealed == true and .progress == 0' || { fail "$label: could not reach sealed baseline"; return; }
  if on "$node" selftest "$cfg" >/dev/null 2>&1; then fail "$label: selftest accepted it"; else pass "$label: selftest refuses"; fi
  out=$(on "$node" watch-fg "$cfg")
  [ "$out" = "exit=$want" ] && pass "$label: watch daemon stops fail-closed ($out)" || fail "$label: watch $out, want exit=$want"
  if status | jq -e '.sealed == true and .progress == 0' >/dev/null; then
    pass "$label: vault still sealed, no share accepted"
  else fail "$label: vault state $(status)"; fi
}
negative "wrong node identity" n3 "$(on n3 mkbad wrong-node n3 3)" 78
negative "replayed under another index" n3 "$(on n3 mkbad replayed-index n3 3)" 78
negative "tampered wrapped blob" n3 "$(on n3 mkbad tampered n3 3)" 78
docker exec "$PFX-n3" cat /etc/autohsm/share-3.wrapped | docker exec -i "$PFX-n1" sh -c 'cat >/e2e/foreign-share.wrapped'
negative "share copied from another node's HSM" n1 "$(on n1 mkbad foreign-share n3 3 3)" 78
negative "wrong HSM PIN" n3 "$(on n3 mkbad wrong-pin n3 3)" 1
negative "vault cert from an untrusted CA" n3 "$(on n3 mkbad rogue-ca n3 3)" 124
negative "node holds >= threshold shares" n3 "$(on n3 mkbad unsafe-layout n3 3)" 78
cfg=$(on n3 mkbad missing-token n3 3)
docker exec "$PFX-n3" mv /var/lib/softhsm/tokens /var/lib/softhsm/tokens.gone
docker exec "$PFX-n3" install -d -m 0700 /var/lib/softhsm/tokens
negative "HSM token missing" n3 "$cfg" 1
docker exec "$PFX-n3" sh -c 'rm -rf /var/lib/softhsm/tokens && mv /var/lib/softhsm/tokens.gone /var/lib/softhsm/tokens'

echo "== NEGATIVE: two good nodes + one bad node cannot reach threshold"
on n1 seal >/dev/null 2>&1 || true
on n1 unseal-reset >/dev/null
on n1 watch-bg
on n2 watch-bg
out=$(on n3 watch-fg "$(on n3 mkbad tampered n3 3)")
if status | jq -e '.sealed == true and .progress == 2' >/dev/null; then
  pass "good n1+n2 contributed 2/3, tampered n3 refused ($out); vault stays sealed"
else fail "partial unseal state $(status)"; fi
for n in n1 n2; do on "$n" watch-stop; done

echo "== alarms for fail-closed daemon exits"
if docker exec "$PFX-alarms" grep -q '"event":"autohsm_failed"' /e2e/alarms.jsonl; then
  pass "autohsm_failed alarm delivered when a daemon stops"
else fail "no autohsm_failed alarm on daemon exit"; fi

echo "== leak check: no plaintext share or root token in any daemon log or alarm"
secrets=$(docker exec "$PFX-n1" jq -r '.keys_base64[], .keys[], .root_token' /e2e/secret/init.json)
leak=0
for n in "${NODES[@]}"; do
  logs=$(docker exec "$PFX-$n" sh -c 'cat /var/log/autohsm-*.log 2>/dev/null')
  while IFS= read -r s; do
    if grep -qF -- "$s" <<<"$logs"; then leak=1; echo "  leaked in $n log"; fi
  done <<<"$secrets"
done
alarms=$(docker exec "$PFX-alarms" cat /e2e/alarms.jsonl)
while IFS= read -r s; do grep -qF -- "$s" <<<"$alarms" && { leak=1; echo "  leaked in alarm"; }; done <<<"$secrets"
[ $leak = 0 ] && pass "no share/root-token material in $(wc -l <<<"$alarms" | tr -d ' ') alarms or daemon logs" || fail "secret material leaked"

if [ "$FAIL" != 0 ]; then
  for n in "${NODES[@]}"; do
    echo "--- $n daemon log (tail, sealed/unreachable noise filtered)"
    docker exec "$PFX-$n" sh -c 'grep -hv "is SEALED\|check failed" /var/log/autohsm-*.log | tail -25' || true
  done
fi

echo
echo "e2e: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
