#!/usr/bin/env bash
# Runs INSIDE the disposable systemd container: the README "Install" and
# "Provision" steps, verbatim except for values an operator must supply
# (Vault address, CA, PIN, share). Test-only secrets, destroyed with the container.
set -euxo pipefail
cd /opt/autohsm

PIN=$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')
SO_PIN=87654321
umask 077
printf '%s\n' "$PIN" >/root/hsm-pin
jq -r '.keys_base64[0]' /e2e/secret/init.json >/root/share-1.txt

# --- README: Install
install -m 0755 bin/autohsm /usr/local/bin/autohsm
useradd --system --no-create-home --shell /usr/sbin/nologin autohsm
install -d -o root -g autohsm -m 0750 /etc/autohsm

install -o root -g autohsm -m 0640 examples/autohsm.yaml /etc/autohsm/autohsm.yaml
install -o root -g autohsm -m 0640 /e2e/pki/ca.pem /etc/autohsm/vault-ca.pem
install -o root -g autohsm -m 0640 /root/hsm-pin /etc/autohsm/pin

cp deploy/autohsm.service /etc/systemd/system/

# Operator edit: point the example config at this Vault.
sed -i 's#address: https://apps2.afterdarksys.com:8200#address: https://vault:8200#' /etc/autohsm/autohsm.yaml

# --- README: Provision the HSM key and shares
sudo usermod -aG softhsm autohsm
sudo -u autohsm softhsm2-util --init-token --slot 0 --label autohsm --so-pin "$SO_PIN" --pin "$PIN"
sudo -u autohsm AUTOHSM_PIN="$PIN" pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin env:AUTOHSM_PIN \
  --keygen --key-type aes:32 --label autohsm-wrap --private --sensitive \
  --usage-decrypt

sudo -u autohsm autohsm wrap --index 1 < /root/share-1.txt \
  | sudo tee /etc/autohsm/share-1.wrapped
sudo chown root:autohsm /etc/autohsm/share-1.wrapped
sudo chmod 0640 /etc/autohsm/share-1.wrapped

sudo -u autohsm autohsm selftest

systemctl daemon-reload
systemctl enable --now autohsm
