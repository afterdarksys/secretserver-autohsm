# secretserver-autohsm

Keeps a HashiCorp Vault **unsealed across restarts** using unseal key shares wrapped
by a unique, non-replicated HSM key on each node.

Built because Vault's native PKCS#11 auto-unseal is **Enterprise-only**, and a
community-edition Vault that reboots stays sealed until a human types three keys.

## Why this exists

A sealed Vault is silent. Ours sat sealed for three months and nothing noticed — the
symptom was a filtered port, the cause was a stale Docker network, and the effect was
that secret storage simply did not work. This daemon addresses both halves:

- **Availability** — Vault comes back unsealed after a reboot, without a human.
- **Visibility** — every sealed observation fires an alarm, even when the unseal
  then succeeds, so you learn that Vault restarted at all.

Of the two, the alarm matters more. Automation that fails silently is how you get
another three-month outage.

## Security model

Each share is stored as an AEAD envelope:

```
autohsm-v1.<base64(nonce)>.<base64(ciphertext||tag)>
```

encrypted with **AES-256-GCM** using a **non-extractable key inside the HSM**. The
additional authenticated data binds the share to its node and index:

```
autohsm-v1|node=<node_id>|idx=<n>
```

Consequences, all covered by tests:

| Property | Result |
|---|---|
| Share used with a different configured node label | **fails** — AAD mismatch |
| Share replayed under a different index | **fails** — AAD index mismatch |
| Ciphertext tampered with | **fails** — GCM tag |
| Disk, backup, or snapshot stolen | **inert** — key never leaves the HSM |
| Wrong CA presented by "Vault" | **fails** — pinned CA, no system-root fallback |
| Plaintext `http://` Vault address | **refused at config load** |

`node_id` is an operator-controlled context label, not hardware attestation. It
prevents accidental cross-node use; it does not prove which physical machine is
calling the HSM. Actual node separation comes from provisioning a unique,
non-replicated HSM key per node. A host with access to the same HSM key and the
original `node_id` can unwrap the envelope.

### What this does *not* protect against

Auto-unseal has an irreducible tension: something must unseal without a human. The
daemon authenticates to the HSM unattended, so the **PIN must be available at boot**
(environment variable or protected file). An attacker with code execution on this
host can ask the HSM to unwrap exactly as the daemon does.

The HSM upgrades your threat model from *"keys are readable on disk"* to *"keys are
unusable without the token"*. That is genuine defence in depth against disk and backup
theft. It is **not** equivalent to a human-held key, and you should not tell yourself
otherwise.

The real protection is **distribution**: give each node **fewer shares than the unseal
threshold**. If any single node can reach threshold alone, compromising that node is
equivalent to holding every key and this design buys you nothing.

With Vault at 5 shares / threshold 3, a sound layout is:

| Node | Shares held |
|---|---|
| apps2 | 1 |
| dr1 | 1 |
| .229 | 1 |

Any two nodes surviving a reboot is not enough; all three must be up. That is the
trade: availability against blast radius. Choose deliberately.

## Install

```bash
make build
sudo install -m 0755 bin/autohsm /usr/local/bin/autohsm
sudo useradd --system --no-create-home --shell /usr/sbin/nologin autohsm
sudo install -d -o root -g autohsm -m 0750 /etc/autohsm

sudo install -o root -g autohsm -m 0640 examples/autohsm.yaml /etc/autohsm/autohsm.yaml
sudo install -o root -g autohsm -m 0640 /path/to/vault-ca.pem /etc/autohsm/vault-ca.pem
sudo install -o root -g autohsm -m 0640 /secure/path/hsm-pin /etc/autohsm/pin

sudo cp deploy/autohsm.service /etc/systemd/system/
```

### Provision the HSM key and shares

Create one non-extractable AES-256 key on the token (SoftHSM shown):

```bash
softhsm2-util --init-token --slot 0 --label autohsm --so-pin <SO_PIN> --pin <PIN>
AUTOHSM_PIN=<PIN> pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin env:AUTOHSM_PIN \
  --keygen --key-type aes:32 --label autohsm-wrap --private --sensitive \
  --usage-decrypt
```

The daemon verifies at startup that the selected key is AES-256, sensitive,
always-sensitive, non-extractable, never-extractable, and enabled for AES-GCM
encryption and decryption. A mislabeled or weak key fails closed.

Then wrap this node's share (plaintext is read from stdin, never echoed, and wiped):

```bash
sudo -u autohsm autohsm wrap --index 1 < /path/to/share-1.txt \
  | sudo tee /etc/autohsm/share-1.wrapped
sudo chown root:autohsm /etc/autohsm/share-1.wrapped
sudo chmod 0640 /etc/autohsm/share-1.wrapped
```

Verify before you rely on it:

```bash
sudo -u autohsm autohsm selftest
```

`selftest` checks config, the pinned TLS connection to Vault, HSM login, and that
**every configured share actually unwraps for this node context**. It also refuses
a node holding enough shares to meet the threshold by itself. Wrong context, index,
key, and unsafe distribution errors are caught during provisioning rather than an outage.

Only after `selftest` succeeds, enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now autohsm
```

During a partial distributed unseal, each daemon records accepted share indexes in
`/run/autohsm`. This prevents resubmission after a daemon crash while allowing a host
reboot or a Vault status reporting zero progress to begin a fresh episode. Terminal
share rejection exits with status 78, which the supplied systemd unit deliberately
does not restart.

## Commands

| Command | Purpose |
|---|---|
| `autohsm watch` | The daemon. What systemd runs. |
| `autohsm status` | Print seal state; **exit 2 if sealed** (for external monitors). |
| `autohsm wrap --index N` | Wrap one share for this node, from stdin. |
| `autohsm selftest` | Verify config, TLS pin, HSM, and every share. |

`status` exiting 2 is the cheapest possible monitor and needs no webhook:

```
*/5 * * * * autohsm status >/dev/null 2>&1 || echo "vault sealed" | mail -s ALERT you@example.com
```

## Development

`keys.source: file` swaps the HSM for an AES-256-GCM key in `AUTOHSM_DEV_KEY`
(64 hex chars). It exercises the identical envelope and AAD logic, so the
authentication properties are testable without a token.

It offers **no hardware protection** and must be opted into explicitly with
`allow_insecure_file_source: true` — it can never be reached by omission.

```bash
make test
```

With SoftHSM installed, run the real PKCS#11 integration test against an isolated
temporary token:

```bash
make test-integration \
  AUTOHSM_TEST_MODULE=/usr/local/opt/softhsm/lib/softhsm/libsofthsm2.so
```

Use your platform's actual `libsofthsm2.so` path. The test creates its token under
the test temporary directory and never touches the system SoftHSM token store.

## Status

| Component | State |
|---|---|
| Envelope, AAD binding, software source | tested, incl. negative cases |
| Config validation and permission gates | tested, incl. negative cases |
| Vault client, TLS pinning, timeouts, body limits | tested, incl. negative cases |
| Watcher loop, failure budget, alarm hook | tested |
| PKCS#11 attribute/mechanism validation | unit tested |
| PKCS#11 source against SoftHSM 2.7 | integration tested |
| **PKCS#11 source against production hardware** | **not yet exercised** |

The PKCS#11 path is written against the v2.40 AES-GCM interface and is exercised
against SoftHSM in the opt-in integration test. Run `autohsm selftest` against the
actual production token before trusting a deployment; hardware and vendor modules
can differ from SoftHSM.
