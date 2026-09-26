#!/usr/bin/env bash
# In-container helper for scripts/e2e.sh. Runs inside a disposable node
# container; never used against real hosts. Every HSM/Vault secret here is
# generated for the test and destroyed with the containers.
set -euo pipefail

MODULE=/usr/lib/softhsm/libsofthsm2.so
VAULT=https://vault:8200
CA=/e2e/pki/ca.pem
SO_PIN=87654321

vcurl() { curl -sS --fail-with-body --cacert "$CA" "$@"; }

write_config() { # write_config <path> <node_id> <pin_file> <ca> <index:path>...
  local path=$1 node=$2 pin=$3 ca=$4; shift 4
  {
    echo "node_id: $node"
    echo "vault:"
    echo "  address: $VAULT"
    echo "  ca_cert_path: $ca"
    echo "  timeout: 5s"
    echo "keys:"
    echo "  source: pkcs11"
    echo "  pkcs11:"
    echo "    module_path: $MODULE"
    echo "    token_label: autohsm"
    echo "    key_label: autohsm-wrap"
    echo "    pin_file: $pin"
    echo "  shares:"
    for s in "$@"; do
      echo "    - index: ${s%%:*}"
      echo "      path: ${s#*:}"
    done
    echo "watch:"
    echo "  interval: 1s"
    echo "  max_unseal_attempts: 3"
    echo "alarm:"
    echo "  webhook_url: https://alarms:8443/hook"
  } >"$path"
  chmod 0600 "$path"
}

case "$1" in
pki)
  install -d -m 0755 /e2e/pki /e2e/secret
  chmod 0700 /e2e/secret
  cd /e2e/pki
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj "/CN=autohsm-e2e-ca" -keyout ca-key.pem -out ca.pem 2>/dev/null
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj "/CN=autohsm-e2e-rogue-ca" -keyout rogue-ca-key.pem -out rogue-ca.pem 2>/dev/null
  for host in vault alarms; do
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -subj "/CN=$host" -keyout "$host-key.pem" -out "$host.csr" 2>/dev/null
    printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$host" >"$host.ext"
    openssl x509 -req -in "$host.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
      -days 2 -extfile "$host.ext" -out "$host.pem" 2>/dev/null
  done
  # Disposable test keys; the vault container's non-root user must read them.
  chmod 0644 ./*.pem
  cat >/e2e/vault.hcl <<'HCL'
storage "file" {
  path = "/vault/file"
}
listener "tcp" {
  address         = "0.0.0.0:8200"
  tls_cert_file   = "/e2e/pki/vault.pem"
  tls_key_file    = "/e2e/pki/vault-key.pem"
  tls_min_version = "tls13"
}
api_addr     = "https://vault:8200"
disable_mlock = true
ui            = false
HCL
  ;;
trust)
  cp /e2e/pki/ca.pem /usr/local/share/ca-certificates/autohsm-e2e.crt
  update-ca-certificates >/dev/null 2>&1
  ;;
webhook)
  exec python3 /src/scripts/e2e/webhook.py /e2e/alarms.jsonl
  ;;
seal-status)
  vcurl "$VAULT/v1/sys/seal-status"
  ;;
init-vault)
  umask 077
  vcurl -X PUT -d '{"secret_shares":5,"secret_threshold":3}' "$VAULT/v1/sys/init" >/e2e/secret/init.json
  jq -r '.keys_base64 | length' /e2e/secret/init.json
  ;;
seal)
  vcurl -X PUT -H "X-Vault-Token: $(jq -r .root_token /e2e/secret/init.json)" "$VAULT/v1/sys/seal" >/dev/null
  ;;
unseal-reset)
  vcurl -X PUT -d '{"reset":true}' "$VAULT/v1/sys/unseal"
  ;;
submit-raw) # submit-raw <index>: act as a peer node contributing share <index> by hand
  jq -n --arg k "$(jq -r ".keys_base64[$(($2 - 1))]" /e2e/secret/init.json)" '{key:$k}' |
    vcurl -X PUT -d @- "$VAULT/v1/sys/unseal"
  ;;
provision) # provision <node_id> <index>: follow the README provisioning steps literally
  node=$2 idx=$3
  umask 077
  install -d -m 0750 /etc/autohsm /run/autohsm
  head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n' >/etc/autohsm/pin
  chmod 0600 /etc/autohsm/pin
  PIN=$(cat /etc/autohsm/pin)
  softhsm2-util --init-token --slot 0 --label autohsm --so-pin "$SO_PIN" --pin "$PIN" >/dev/null
  AUTOHSM_PIN=$PIN pkcs11-tool --module "$MODULE" \
    --login --pin env:AUTOHSM_PIN \
    --keygen --key-type aes:32 --label autohsm-wrap --private --sensitive \
    --usage-decrypt >/dev/null
  write_config /etc/autohsm/autohsm.yaml "$node" /etc/autohsm/pin "$CA" "$idx:/etc/autohsm/share-$idx.wrapped"
  jq -r ".keys_base64[$((idx - 1))]" /e2e/secret/init.json |
    autohsm wrap --config /etc/autohsm/autohsm.yaml --index "$idx" >/etc/autohsm/share-"$idx".wrapped
  chmod 0600 /etc/autohsm/share-"$idx".wrapped
  ;;
key-attrs)
  PIN=$(cat /etc/autohsm/pin)
  AUTOHSM_PIN=$PIN pkcs11-tool --module "$MODULE" --login --pin env:AUTOHSM_PIN --list-objects --type secrkey
  ;;
selftest) # selftest [config]
  autohsm selftest --config "${2:-/etc/autohsm/autohsm.yaml}"
  ;;
watch-bg)
  nohup autohsm watch --config /etc/autohsm/autohsm.yaml >>/var/log/autohsm-watch.log 2>&1 &
  echo $! >/run/autohsm-watch.pid
  ;;
watch-stop)
  if [ -f /run/autohsm-watch.pid ]; then
    kill "$(cat /run/autohsm-watch.pid)" 2>/dev/null || true
    rm -f /run/autohsm-watch.pid
  fi
  ;;
watch-fg) # watch-fg <config>: run the daemon until it exits on its own; print its exit code
  set +e
  timeout 15 autohsm watch --config "$2" >/tmp/last-negative.log 2>&1
  rc=$?
  cat /tmp/last-negative.log >>/var/log/autohsm-negative.log
  echo "exit=$rc"
  ;;
mkbad) # mkbad <case> <node_id> <index>: build a negative-case config under /etc/autohsm/bad
  case_=$2 node=$3 idx=$4
  d=/etc/autohsm/bad/$case_
  install -d -m 0700 "$d"
  share=/etc/autohsm/share-$idx.wrapped
  pin=/etc/autohsm/pin
  ca=$CA
  cfg_node=$node cfg_idx=$idx
  case "$case_" in
  wrong-node) cfg_node="$node-impostor" ;;
  replayed-index) cfg_idx=$((idx + 1)) ;;
  tampered)
    # Flip one character inside the ciphertext field (field 3).
    awk -F. 'BEGIN{OFS="."} {c=substr($3,5,1); r=(c=="A")?"B":"A"; $3=substr($3,1,4) r substr($3,6); print}' \
      "$share" >"$d/share.wrapped"
    share=$d/share.wrapped
    ;;
  foreign-share) share=/e2e/foreign-share.wrapped ; cfg_idx=$5 ;;
  wrong-pin) printf '000000' >"$d/pin"; chmod 0600 "$d/pin"; pin=$d/pin ;;
  rogue-ca) ca=/e2e/pki/rogue-ca.pem ;;
  missing-token) ;; # config unchanged; the token directory is removed by the caller
  unsafe-layout)
    for i in 1 2 3; do cp "$share" "$d/share-$i.wrapped"; done
    ;;
  esac
  [ -f "$share" ] && chmod 0600 "$share"
  if [ "$case_" = unsafe-layout ]; then
    write_config "$d/autohsm.yaml" "$cfg_node" "$pin" "$ca" \
      "1:$d/share-1.wrapped" "2:$d/share-2.wrapped" "3:$d/share-3.wrapped"
    chmod 0600 "$d"/share-*.wrapped
  else
    write_config "$d/autohsm.yaml" "$cfg_node" "$pin" "$ca" "$cfg_idx:$share"
  fi
  echo "$d/autohsm.yaml"
  ;;
*)
  echo "unknown command $1" >&2
  exit 2
  ;;
esac
