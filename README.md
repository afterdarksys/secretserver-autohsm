# secretserver-autohsm

Keeps a HashiCorp Vault **unsealed across restarts** using unseal key shares wrapped
by a unique, non-replicated HSM key on each node.

Built because Vault's native PKCS#11 auto-unseal is **Enterprise-only**, and a
community-edition Vault that reboots stays sealed until a human types three keys.

## Why this exists

A sealed Vault is silent. It can stay sealed for months without anything noticing:
the symptom looks like a filtered port or a network fault, and the effect is that
secret storage simply does not work. This daemon addresses both halves:

- **Availability** — Vault comes back unsealed after a reboot, without a human.
- **Visibility** — every sealed observation fires an alarm, even when the unseal
  then succeeds, so you learn that Vault restarted at all.

Of the two, the alarm matters more. Automation that fails silently is how you get
a months-long outage.

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
| node-a | 1 |
| node-b | 1 |
| node-c | 1 |

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
# Debian/Ubuntu SoftHSM: config and token store are group "softhsm", and token
# files are created owner-only, so the token must be created BY the service user.
sudo usermod -aG softhsm autohsm
sudo -u autohsm softhsm2-util --init-token --slot 0 --label autohsm --so-pin <SO_PIN> --pin <PIN>
sudo -u autohsm AUTOHSM_PIN=<PIN> pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin env:AUTOHSM_PIN \
  --keygen --key-type aes:32 --label autohsm-wrap --private --sensitive \
  --usage-decrypt
```

A token created as root is unreadable to the `autohsm` user and every later step
fails with `pkcs11 initialize: CKR_GENERAL_ERROR`. For a hardware HSM, grant the
`autohsm` user access to the vendor module's device and config instead.

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

### Hardware HSMs

The shipped unit is tuned for SoftHSM. Vendor PKCS#11 modules usually need more,
and every relaxation below is a deliberate hole in the sandbox, so add only what
your module demonstrably needs, in a drop-in (`systemctl edit autohsm`) rather than
by editing the shipped unit:

```ini
[Service]
# Client state, logs, or session caches the vendor library writes
# (examples: Luna /usr/safenet/lunaclient, nShield /opt/nfast/kmdata,
# YubiHSM connector config). ProtectSystem=strict makes everything else read-only.
ReadWritePaths=/opt/vendor/client-state /var/log/vendor-hsm

# FIPS-mode libraries that read /proc/sys/crypto/fips_enabled or other
# non-process /proc files. The shipped unit uses ProcSubset=pid.
ProcSubset=all

# Network HSM clients (Luna Network HSM, nShield Connect, CloudHSM client)
# that enumerate interfaces or routes via netlink.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

# USB/PCIe tokens: PrivateDevices=no is already set; grant the device node's
# group (from your udev rule) rather than running as root.
SupplementaryGroups=hsm
```

For USB/PCIe tokens, install a udev rule that gives the device a dedicated group
(for example `SUBSYSTEM=="usb", ATTRS{idVendor}=="1050", GROUP="hsm", MODE="0660"`
for a YubiHSM 2) and add `autohsm` to that group; never loosen the device to 0666.

Run `selftest` **under the same sandbox** as the service before enabling it, so a
path, device, or syscall the sandbox blocks fails now rather than at the next
reboot:

```bash
sudo systemd-run --pipe --wait --collect -p User=autohsm -p Group=autohsm \
  -p NoNewPrivileges=yes -p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes \
  -p CapabilityBoundingSet= -p SystemCallArchitectures=native \
  -p SystemCallFilter=@system-service -p SystemCallFilter=~@privileged \
  -p ProtectProc=invisible -p ProcSubset=pid \
  -p "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX" -p ReadOnlyPaths=/etc/autohsm \
  /usr/local/bin/autohsm selftest --config /etc/autohsm/autohsm.yaml
```

Add the same `-p` properties you put in the drop-in. A wrong PIN exits 78 and is
never retried, so a mistyped PIN cannot count a hardware token down to lockout.
If the token is absent when the daemon starts, or it or its session goes away
while the daemon runs, the daemon keeps running: it raises `hsm_unavailable` once,
reconnects with backoff (up to 5 minutes between attempts), submits nothing
meanwhile, and raises `hsm_recovered` when the session is back. Failures that
retrying cannot fix exit 78 and are not restarted: a rejected PIN, an unloadable
module, a token without AES-GCM, a missing, ambiguous or unsafe key, and any
configuration error.

During a partial distributed unseal, each daemon records accepted share indexes in
`/run/autohsm`, keyed to the unseal nonce Vault returned when the share was accepted.
This prevents resubmission after a daemon crash within the same unseal attempt, while a
host reboot, a Vault status reporting zero progress, or a different Vault nonce (a new
attempt, e.g. after a Vault restart) begins a fresh episode. A share that completes the
unseal is never latched. Terminal
share rejection exits with status 78, which the supplied systemd unit deliberately
does not restart.

## Commands

| Command | Purpose |
|---|---|
| `autohsm watch` | The daemon. What systemd runs. |
| `autohsm status` | Print seal state; **exit 2 if sealed** (for external monitors). |
| `autohsm wrap --index N` | Wrap one share for this node, from stdin. |
| `autohsm selftest` | Verify config, TLS pin, HSM, and every share. |
| `autohsm wrap --index N --install` | Wrap from stdin and atomically replace that configured share file (used by `vaultkeeper rekey`). |
| `autohsm contribute generate-root\|rekey` | Submit this node's share to a pinned vaultkeeper ceremony. See below. |

With `alarm.webhook_url` set, the daemon posts:

| Event | When |
|---|---|
| `vault_sealed` | every poll that finds Vault sealed |
| `vault_unreachable` | every poll that cannot reach Vault |
| `hsm_unavailable` / `hsm_recovered` | once when the HSM session is lost and cannot be re-opened / when it is back |
| `shares_stale` | Vault rejected the key material itself (for example shares from before a re-init); the daemon stops submitting until restarted and repeats this alarm with backoff (up to hourly) instead of `vault_sealed` |
| `autohsm_failed` | just before the daemon exits on an error (PIN rejected, unusable HSM module or key, configuration error, retry budget exhausted, unsafe layout) |

`status` never opens the HSM. Exiting 2 is the cheapest possible monitor and needs no webhook:

```
*/5 * * * * autohsm status >/dev/null 2>&1 || echo "vault sealed" | mail -s ALERT you@example.com
```

## vaultkeeper: no standing root token

`vaultkeeper` (in `cmd/vaultkeeper`) removes the standing root token from a
community-edition Vault. Root exists only for minutes, for one allowlisted task,
opens only with the operator's PGP key, and is revoked on every exit path. The
unseal-key quorum it needs comes from the autohsm nodes: each one unwraps its own
share inside its HSM and submits it **directly to Vault**; the share never leaves
the node.

```
operator workstation: vaultkeeper (holds no share and no standing token)
  | starts the attempt, locked to the operator PGP key
  | has the approval-gated fleet runner run `autohsm contribute <op>` per node
  v
node-a .. node-d: autohsm contribute <op>
  | checks the attempt against its pins, unwraps its share, submits it with the
  | attempt nonce, wipes it
  v
Vault: result PGP-encrypted to the operator key -> gpg decrypts it on the workstation
  -> one allowlisted task -> revoke-self -> lookup-self must return 403
```

| Job | Runs where | Needs root? |
|---|---|---|
| `vaultkeeper root-task <task> --approval-contract FILE` | operator workstation | minutes, single use |
| `vaultkeeper rekey --approval-contract FILE` | operator workstation | no (unseal-key quorum) |
| `vaultkeeper rotate-keyring` | vault host, `deploy/vaultkeeper-rotate.timer` | no: AppRole with `update,sudo` on `sys/rotate`, `read` on `sys/key-status` |
| `vaultkeeper status` | anywhere | no |

**Task allowlist (v1, hardcoded):** `revoke-token <accessor>` (then confirms the
accessor no longer resolves), `rekey-cancel`, and `policy-write <name> <sha256>`
(writes `policy_dir/<name>.hcl` only if its SHA-256 matches; the bytes hashed are the
bytes written). There is no free-form command and no shell.

**root-task guarantees.** Refuses to start while any generate-root attempt exists and
never cancels one it did not start. A result line is trusted only once Vault shows the
attempt consumed (a result that arrives while the attempt is still collecting shares is
rejected as forged, and our attempt is cancelled). After decrypting, vaultkeeper requires
the token to be a fresh generate-root token from this ceremony: policies exactly
`[root]`, no TTL, no expiry, created by `auth/token/root`, and created no earlier than
the attempt start minus 5 s. A substituted token (for example a pre-minted root token
encrypted to the operator key) is rejected before any task, revoked, and raises
`vaultkeeper_root_undecrypted` saying the real ceremony token may be live.

Once a token is decrypted, a deferred revoke runs on success, on error, and on
SIGTERM/SIGINT/SIGHUP (signals are caught for the whole run). Exit 0 requires a verified
revoke: `lookup-self` with the token must return 403. An unverified revoke exits
non-zero, raises `vaultkeeper_root_revoke_unverified`, and prints the token accessor
(never the token). If the result cannot be decrypted or read, the encrypted result
line (or the raw node output) is saved to `output_dir` (0600, never overwritten) and
`vaultkeeper_root_undecrypted` fires: the token is live, but only the operator key opens
it, so it can be recovered and revoked by hand.

**rekey.** Vault rekeys with `require_verification`: it keeps the old shares until
enough new shares have been proven back to it. Vault's verification only covers 3
shares, so vaultkeeper proves the rest itself, and it never deletes or shreds anything
on the strength of a node's own report. The flow is:

1. Start a 5/3 rekey with `pgp_keys = [operator x4, offline]`, backup off, verification
   on, and collect node contributions. The result is trusted only once Vault reports
   share collection finished (a pending `verification_nonce` for our attempt).
2. Save all five encrypted shares to `output_dir/vault-share<i>.<stamp>.gpg` (0600,
   never overwritten) before anything else happens, and record each file's SHA-256 in
   `vault-rekey.<stamp>.json`. The ceremony never deletes them, and every later step
   (`verify-share5`, `rekey-cleanup`) refuses a file whose hash no longer matches
   (constant-time compare).
3. Decrypt shares 1-4 once and, **before Vault switches**, prove share 4 lies on the
   same polynomial as shares 1-3 (`internal/shamir`, Vault's share format and GF(2^8)
   field; every 3-subset containing share 1 must combine to the same secret, compared in
   constant time). Vault's verification never sees share 4, and a completing node could
   have replaced it. On a mismatch vaultkeeper cancels the rekey (Vault keeps the old
   shares), raises `vaultkeeper_rekey_inconsistent` ("before verify; rekey cancelled")
   and keeps the files.
4. Submit shares 1-3 to `sys/rekey/verify`. Only now does Vault switch, to shares that
   open with the operator key and that share 4 agrees with. A forged result that is
   still consistent (for example replayed old shares) fails here; the rekey is
   cancelled and Vault keeps the old shares. The proof (1-3 verified, 4 consistent) is
   recorded in the state file.
5. Deliver each node share over the runner's stdin to `autohsm wrap --index N
   --install` (the previous envelope is kept as `<path>.prev`) and run `autohsm
   selftest`. A selftest is the node's own claim: it gates nothing.
6. The rekey ends with `vaultkeeper_rekey_unconfirmed`: share 5 is UNVERIFIED and is not
   counted as a backup, and the old init file is not shredded.

Then, separately:

- **Unseal drill.** Prove the new node shares unseal Vault. Sealing Vault through the
  API needs root, which vaultkeeper deliberately does not keep, so the practical drill
  is restarting the Vault process: **this is an outage**, and the autohsm nodes must
  unseal it with their new shares. This is what proves the nodes really installed them.
  vaultkeeper cannot observe the drill; the confirmation `rekey-cleanup` asks for is
  only the operator's acknowledgement.
- **`vaultkeeper verify-share5 <output_dir>/vault-share5.<stamp>.gpg`**, run where the
  offline key is temporarily available (it also needs the operator key). It decrypts
  share 5 and shares 1-3 and proves share 5 is consistent with them; on success it
  writes `vault-share5.<stamp>.verified` (the SHA-256 of the share 5 file).
- **`vaultkeeper rekey-cleanup <stamp> [--shred-init-file PATH]`** removes the
  operator-encrypted node shares 1-4 only after a fresh check that Vault is unsealed and
  a terminal confirmation of the unseal drill. `--shred-init-file` is honoured only when
  shares 1-3 were verified by Vault, share 4 was proven consistent, and share 5 was
  verified (and its file is unchanged since); otherwise it refuses and says why. Share 5
  is always kept. `rekey --shred-init-file` applies the same gate, so during the
  ceremony itself it always refuses (share 5 cannot be verified yet).

Delivery (step 5) can be interrupted safely: every share is already on disk. Re-wrap an
undelivered node with `gpg -d FILE | <runner> node-x autohsm wrap --index N --install`.
`install` refuses a share path that is not a regular file (no symlinks); a leftover
`.<name>.new` from an interrupted install makes it fail closed: inspect and remove it,
then re-run.

**generate-root completion vs cancellation.** Vault clears a generate-root attempt both
when it completes and when someone cancels it, so the two cannot be told apart: when
the attempt disappears without a usable result, vaultkeeper reports it as "completed or
cancelled" and assumes a root token may be live. When a decrypted token fails the
freshness check, it is revoked and reported as "rejected token revoked/invalid", never
with the normal success line.

### Node side: `autohsm contribute generate-root|rekey`

Takes no arguments (beyond `--config`), so a runbook can allowlist the exact command.
It reads the current attempt and **refuses, before opening the HSM and without any
write to Vault**, when:

- no attempt is in progress;
- generate-root: the attempt uses an OTP (empty `pgp_fingerprint`) or a key other than
  the pinned `vaultkeeper.pgp_fingerprint`, or the config has no pin;
- rekey: the 5 `pgp_fingerprints` are not exactly `[operator x4, offline]` in that order
  (from `vaultkeeper.pgp_fingerprint` and `vaultkeeper.offline_fingerprint`), `n` is
  not 5, `t` is not 3, `backup` is true, verification is NOT required, the attempt has
  already collected its shares, or either pin is missing.

Pins are full 40-hex v4 fingerprints, validated at config load:

```yaml
vaultkeeper:
  pgp_fingerprint: <operator key fingerprint>
  offline_fingerprint: <offline key fingerprint>
```

On success it prints `contribute op=<op> nonce=<first 8> progress=<n>/<t>` and posts a
`contribute` alarm; a refusal posts `contribute_refused`. Neither ever carries a share,
an OTP or a token. The node whose share completes the attempt is the only place Vault
returns the result, so that node also prints one `vaultkeeper-result {...}` line holding
the **PGP-encrypted** token or shares (re-checked against the pins first); the runner
hands it back to vaultkeeper. With the manual runner, paste that line when asked.

### Runners

vaultkeeper never contacts a node itself. With `runner.exec` unset it prints the exact
per-node command for the operator's approval-gated runner and polls Vault's progress
(up to `runner.timeout`); when the attempt completes it asks for the result line (read
through a bounded reader). With `runner.exec` set it runs that runner binary directly (no
shell), substituting `{node}` and `{approval}`, appends the node command, and kills it
after `runner.timeout`. `rekey` requires `runner.exec`, because new shares are delivered
over stdin and are never printed. The result line is parsed strictly (no prefixes, no
trailing data); output that should hold a result but does not parse is saved raw to
`output_dir`, never dropped.

**Alarms.** `alarm.webhook_url` must be https, and alarm clients (vaultkeeper and the
autohsm nodes) require TLS 1.3; `alarm.ca_cert_path` optionally pins the receiver's CA
instead of the system roots. A failure before the notifier exists (bad config, bad
alarm setup) cannot alarm: it is logged at error level to stderr (the journal under
systemd) and the command exits non-zero. For the `vaultkeeper-rotate` timer, monitor
the unit's failed state (`systemctl is-failed vaultkeeper-rotate.service`, or an
`OnFailure=` unit). Events: `contribute`, `contribute_refused`
(nodes); `vaultkeeper_foreign_attempt`, `vaultkeeper_root_undecrypted`,
`vaultkeeper_root_revoke_unverified`, `vaultkeeper_rekey_inconsistent`,
`vaultkeeper_rekey_unconfirmed`, `vaultkeeper_keyring_rotated`,
`vaultkeeper_rotate_failed`.

**gpg.** `gpg_path` must be absolute. gpg runs with vaultkeeper's environment, so
`GNUPGHOME` (default `~/.gnupg`) selects the keyring. vaultkeeper passes
`--no-auto-key-retrieve --no-auto-key-locate` and `--try-secret-key <operator
fingerprint>`.

**AppRole for rotate-keyring.** `deploy/vaultkeeper-rotate-policy.hcl` is the whole
policy (`update,sudo` on `sys/rotate`, `read` on `sys/key-status`), and
`deploy/vaultkeeper-rotate-role.json` the role settings: 5-minute tokens, at most 6
uses (rotate-keyring needs 4, status 2), and `token_bound_cidrs` /
`secret_id_bound_cidrs` set to a placeholder you replace with the vault host's address:

```
vault policy write vaultkeeper-rotate deploy/vaultkeeper-rotate-policy.hcl
vault write auth/approle/role/vaultkeeper-rotate @deploy/vaultkeeper-rotate-role.json
```

### Vault version note

The integration suite passes against Vault 1.15.6 and 2.0.3.

Vault 1.x serves `sys/generate-root/*` and `sys/rekey/*` without authentication. Vault
2.x authenticates them by default; the node-side contribute calls then need
`enable_unauthenticated_access = ["generate-root", "rekey"]` in the server config (the
integration tests set it on 2.x). **Enabling it re-opens the 1.x attempt surface: anyone
who can reach Vault can start, and cancel, a generate-root or rekey attempt, and the
node-side PGP pin is then the only boundary between such an attempt and the node
shares.** Leaving the endpoints authenticated on 2.x is stricter, but then nodes need a
token to contribute, which this design does not provide.

For the same reason, "the rotate AppRole gets 403 on `sys/generate-root`" (acceptance
criterion 6) should read: the AppRole gets 403 on every path outside `sys/rotate` and
`sys/key-status` (tested: `secret/`, policy writes, `token/create`, `sys/seal`), and on
`sys/generate-root/attempt` it gets exactly what an anonymous caller gets: 200 where the
endpoint is unauthenticated (1.15.6, and 2.0.3 with the setting above), 403 where it is
authenticated (2.x default). The AppRole adds nothing to that surface.

### Threats

**Protects against:** a standing root token existing at all; a stolen root token
outliving its single task; an attacker starting their own generate-root or rekey and
harvesting node shares (pinned PGP fingerprints and rekey layout, OTP attempts refused,
shares bound to the validated attempt by nonce); a forged or substituted ceremony result
(results trusted only after Vault shows the attempt consumed; generated tokens must be
fresh `auth/token/root` tokens; rekeys switch only after Vault verifies shares 1-3, share 4
must be locally proven consistent with them before anything is delivered, and share 5
counts as a backup only after `verify-share5`); losing the new shares after Vault switched (all encrypted shares
are saved before verification, raw output is saved on parse failure, and the previous
node envelope is kept as `.prev`); a share transiting or resting outside a node's HSM,
except during rekey (workstation memory, a pipe, and operator-key-encrypted files until
`rekey-cleanup` after an unseal drill); share 5 resting in plaintext; one compromised node reaching
quorum (one share each, threshold 3).

**Does NOT protect against:** root on 3 nodes at once; code execution on the operator
workstation that captures the gpg passphrase (until the hardware-key upgrade; after it,
only during a touch); a malicious Vault binary on the vault host; an attacker who can
make the operator approve a ceremony and touch the key; an attacker who only wants to
cancel attempts (denial of service: `status` alarms on any attempt vaultkeeper did not
start). `vaultkeeper status` does not yet list root tokens (that needs root, so it is a
later root-task) or node share staleness (autohsm's `shares_stale` alarm covers it).

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

With `vault` and `gpg` on PATH, `go test ./...` also runs the vaultkeeper
integration tests against a real Vault in a temp dir (they skip, saying so, when
either binary is missing); `make test-vaultkeeper` runs only those, verbosely.

With Docker, two disposable harnesses exercise the whole system locally (they
never contact a real Vault or host):

```bash
make e2e           # real non-dev Vault + 3 SoftHSM nodes: unseal, reseal, restart, 8 negative cases
make deploy-check  # README steps + deploy/autohsm.service under systemd on Debian 12
```

See `VALIDATION.md` for what was verified and what was not.

## Status

| Component | State |
|---|---|
| Envelope, AAD binding, software source | tested, incl. negative cases |
| Config validation and permission gates | tested, incl. negative cases |
| Vault client, TLS pinning, timeouts, body limits | tested, incl. negative cases |
| Watcher loop, failure budget, alarm hook | tested |
| PKCS#11 attribute/mechanism validation | unit tested |
| PKCS#11 source against SoftHSM 2.6/2.7 | integration + e2e tested |
| Unseal against real Vault 1.20 (Shamir, 3 nodes) | e2e tested, incl. negative cases |
| systemd unit + README install on Debian 12 | deploy-check tested |
| vaultkeeper root-task, SIGTERM revoke, rekey (verified), forged/substituted results, rotate-keyring, attacker attempts | integration tested against real Vault 1.15.6 and 2.0.3 (software key source on 4 nodes), incl. a secret-leak grep |
| **PKCS#11 source against production hardware** | **not yet exercised** |

The PKCS#11 path is written against the v2.40 AES-GCM interface and is exercised
against SoftHSM in the opt-in integration test. Run `autohsm selftest` against the
actual production token before trusting a deployment; hardware and vendor modules
can differ from SoftHSM.
