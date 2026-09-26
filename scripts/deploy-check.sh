#!/usr/bin/env bash
# Deployment check: follow the README install/provision steps literally on a
# disposable Debian 12 container running systemd as PID 1, run the shipped
# deploy/autohsm.service against a disposable local Vault, and verify:
#   - systemd-analyze verify accepts the unit
#   - the README steps succeed as written, and selftest passes as the autohsm user
#   - the sandboxed service unseals Vault (with two peer shares supplied by hand)
#   - the service re-contributes after Vault restarts
#   - a terminal failure exits 78 and systemd does NOT restart it
#   - no share material reaches the journal
# Needs Docker able to run a privileged systemd container. Nothing here talks
# to any real host. Usage: scripts/deploy-check.sh   (KEEP=1 to leave it up)
set -euo pipefail

cd "$(dirname "$0")/.."

VAULT_IMAGE=${VAULT_IMAGE:-hashicorp/vault:1.20}
PFX=autohsm-deploy-$$
NET=$PFX-net
VOL=$PFX-vol
HOST=$PFX-host

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "PASS  $*"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL  $*"; }

cleanup() {
  if [ "${KEEP:-0}" = 1 ]; then echo "KEEP=1: left $PFX-* running"; return; fi
  docker rm -f "$PFX-vault" "$PFX-peer" "$HOST" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm "$VOL" >/dev/null 2>&1 || true
}
trap cleanup EXIT

peer() { docker exec "$PFX-peer" /src/scripts/e2e/node.sh "$@"; }
host() { docker exec "$HOST" "$@"; }
wait_for() {
  local deadline=$((SECONDS + $1))
  while [ $SECONDS -lt $deadline ]; do
    if peer seal-status 2>/dev/null | jq -e "$2" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

echo "== build images"
docker build -q -f scripts/e2e/Dockerfile -t autohsm-e2e:local . >/dev/null
docker build -q -f scripts/e2e/Dockerfile.systemd -t autohsm-systemd:local . >/dev/null

echo "== disposable vault + peer"
docker network create "$NET" >/dev/null
docker volume create "$VOL" >/dev/null
docker run -d --name "$PFX-peer" --network "$NET" -v "$VOL:/e2e" autohsm-e2e:local sleep infinity >/dev/null
peer pki
docker run -d --name "$PFX-vault" --network "$NET" --network-alias vault \
  --cap-add IPC_LOCK -v "$VOL:/e2e" "$VAULT_IMAGE" server -config=/e2e/vault.hcl >/dev/null
wait_for 90 '.initialized == false' || { echo "vault did not start"; exit 1; }
peer init-vault >/dev/null

echo "== systemd host"
docker run -d --name "$HOST" --hostname node1 --network "$NET" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw -v "$VOL:/e2e:ro" \
  -v "$PWD/scripts/e2e/readme-install.sh:/opt/readme-install.sh:ro" \
  --tmpfs /run --tmpfs /run/lock autohsm-systemd:local >/dev/null
for _ in $(seq 60); do
  state=$(host systemctl is-system-running 2>/dev/null || true)
  case "$state" in running | degraded) break ;; esac
  sleep 1
done
echo "systemd state: $state"

echo "== README install + provision, verbatim"
if host bash /opt/readme-install.sh >/tmp/readme-install.$$ 2>&1; then
  pass "README install/provision steps succeed as written (incl. selftest as autohsm)"
else
  fail "README install/provision steps"
  tail -25 /tmp/readme-install.$$
fi
rm -f /tmp/readme-install.$$

if host systemd-analyze verify /etc/systemd/system/autohsm.service; then
  pass "systemd-analyze verify deploy/autohsm.service (installed, binary present)"
else fail "systemd-analyze verify"; fi

echo "== README hardware-HSM guidance, run literally"
# The systemd-run selftest command, extracted verbatim from README.md.
sandbox_selftest=$(awk '/^sudo systemd-run /,/selftest --config/' README.md | sed 's/^sudo //')
if host bash -c "$sandbox_selftest" >/tmp/sandbox-selftest.$$ 2>&1 && grep -q 'selftest OK' /tmp/sandbox-selftest.$$; then
  pass "README systemd-run selftest passes under the unit's sandbox properties"
else fail "README systemd-run selftest"; tail -15 /tmp/sandbox-selftest.$$; fi
rm -f /tmp/sandbox-selftest.$$
# The example drop-in, extracted verbatim, must be a valid unit fragment.
awk '/^```ini/{f=1;next} /^```/{f=0} f' README.md >/tmp/dropin.$$
docker cp /tmp/dropin.$$ "$HOST:/root/hw.conf" >/dev/null && rm -f /tmp/dropin.$$
if host sh -c 'mkdir -p /etc/systemd/system/autohsm.service.d && cp /root/hw.conf /etc/systemd/system/autohsm.service.d/hw.conf &&
    systemd-analyze verify /etc/systemd/system/autohsm.service; rc=$?; rm -rf /etc/systemd/system/autohsm.service.d; exit $rc'; then
  pass "README hardware-HSM drop-in example passes systemd-analyze verify"
else fail "README hardware-HSM drop-in example"; fi

echo "== service unseals (node1 holds share 1; peers supply 2 and 3 by hand)"
peer submit-raw 2 >/dev/null
peer submit-raw 3 >/dev/null
if wait_for 60 '.sealed == false'; then pass "systemd service submitted its share; vault unsealed with two peer shares"
else fail "service did not unseal (progress $(peer seal-status | jq .progress))"; host journalctl -u autohsm --no-pager | tail -20; fi
[ "$(host systemctl is-active autohsm)" = active ] && pass "autohsm.service active under the shipped sandbox" || fail "service not active"

echo "== vault restart: service re-contributes"
docker restart "$PFX-vault" >/dev/null
wait_for 60 '.sealed == true and .progress >= 1' && pass "after vault restart the service re-submitted its share (progress>=1)" \
  || fail "service did not re-submit after restart ($(peer seal-status | jq -c '{sealed,progress}'))"
peer submit-raw 2 >/dev/null
peer submit-raw 3 >/dev/null
wait_for 30 '.sealed == false' && pass "vault unsealed again with peer shares" || fail "vault not unsealed after restart"

echo "== terminal failure exits 78 and is not restarted"
host sh -c "sed -i 's/interval: 30s/interval: 1s/' /etc/autohsm/autohsm.yaml"
host sh -c "cp /etc/autohsm/share-1.wrapped /root/share-1.good && \
  awk -F. 'BEGIN{OFS=\".\"} {c=substr(\$3,5,1); r=(c==\"A\")?\"B\":\"A\"; \$3=substr(\$3,1,4) r substr(\$3,6); print}' \
  /root/share-1.good > /etc/autohsm/share-1.wrapped"
host systemctl restart autohsm
peer seal
sleep 15
code=$(host systemctl show autohsm -p ExecMainStatus --value)
restarts=$(host systemctl show autohsm -p NRestarts --value)
active=$(host systemctl show autohsm -p ActiveState --value)
echo "service after tampered share: ExecMainStatus=$code NRestarts=$restarts ActiveState=$active"
[ "$code" = 78 ] && pass "tampered share -> exit 78" || fail "exit status $code, want 78"
[ "$restarts" = 0 ] && pass "RestartPreventExitStatus=78 honoured (NRestarts=0)" || fail "NRestarts=$restarts"
peer seal-status | jq -e '.sealed == true and .progress == 0' >/dev/null && pass "vault still sealed, nothing submitted" \
  || fail "vault state $(peer seal-status)"

echo "== wrong PIN exits 78 and is never retried (protects hardware PIN counters)"
host sh -c 'cp /root/share-1.good /etc/autohsm/share-1.wrapped && cp /etc/autohsm/pin /root/pin.good &&
  printf "000000\n" > /etc/autohsm/pin && chown root:autohsm /etc/autohsm/pin /etc/autohsm/share-1.wrapped &&
  chmod 0640 /etc/autohsm/pin /etc/autohsm/share-1.wrapped'
host systemctl reset-failed autohsm
host systemctl restart autohsm || true
sleep 20
code=$(host systemctl show autohsm -p ExecMainStatus --value)
restarts=$(host systemctl show autohsm -p NRestarts --value)
echo "service with wrong PIN: ExecMainStatus=$code NRestarts=$restarts"
[ "$code" = 78 ] && pass "wrong PIN -> exit 78" || fail "wrong PIN exit status $code, want 78"
[ "$restarts" = 0 ] && pass "wrong PIN not retried by systemd (NRestarts=0 after 20s)" || fail "wrong PIN NRestarts=$restarts"
logins=$(host journalctl -u autohsm --no-pager | grep -c 'HSM rejected the PIN' || true)
[ "$logins" -ge 1 ] && pass "journal reports the PIN rejection" || fail "no PIN rejection in journal"
host sh -c 'cp /root/pin.good /etc/autohsm/pin'

echo "== journal leak check"
journal=$(host journalctl -u autohsm --no-pager)
leak=0
while IFS= read -r s; do grep -qF -- "$s" <<<"$journal" && leak=1; done \
  < <(docker exec "$PFX-peer" jq -r '.keys_base64[], .keys[], .root_token' /e2e/secret/init.json)
[ $leak = 0 ] && pass "no share or root-token material in the service journal" || fail "secret in journal"

echo
echo "deploy-check: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
