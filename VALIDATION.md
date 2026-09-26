# Validation — 2026-09-26

What was verified on branch `prod-readiness-2026-09-26`, how, and what was not.
Every result below came from a command run on that date; rerun the commands to
reproduce. Nothing touched a real Vault or any afterdarksys host: all Vault,
HSM, and systemd testing used disposable local Docker containers.

## Environment

| Item | Version |
|---|---|
| Go (host) | go1.27.1 darwin/amd64; e2e images build with golang:1.24-bookworm |
| Vault | hashicorp/vault:1.20 (v1.20.4), **non-dev**: file storage, Shamir seal 5/3, TLS 1.3 listener with a throwaway CA |
| HSM | SoftHSM 2.6 (Debian 12 package) in containers; SoftHSM 2.7 (Homebrew) for the host integration test |
| PKCS#11 tooling | OpenSC `pkcs11-tool` (Debian 12) |
| systemd | 252 (Debian 12), PID 1 in a privileged disposable container |

## Results

| Check | Command | Result |
|---|---|---|
| Static analysis | `go vet ./...` | clean |
| Unit tests (race) | `go test -race -count=1 ./...` | 106 passed, 0 failed, 0 skipped |
| Makefile | `make all` (vet, test, build) | pass |
| PKCS#11 integration | `make test-integration AUTOHSM_TEST_MODULE=.../libsofthsm2.so` | pass |
| End-to-end | `make e2e` (`scripts/e2e.sh`) | 40/40 checks; 10 consecutive full runs green after the fixes below |
| Deployment | `make deploy-check` (`scripts/deploy-check.sh`) | 10/10 checks |

### End-to-end (`scripts/e2e.sh`)

Three node containers, each with its **own** SoftHSM token and non-extractable
AES-256 key, each holding **one** share of a 5-share/threshold-3 Vault, plus an
HTTPS alarm receiver that trusts the throwaway CA.

Positive:
- Tokens and keys created with the README's `softhsm2-util` / `pkcs11-tool`
  commands pass the daemon's key-attribute gate (sensitive, never-extractable,
  AES-256, GCM encrypt+decrypt); `selftest` passes on all three nodes.
- Wrapped share files do not contain the plaintext share.
- The three daemons unseal a freshly initialised Vault.
- They unseal it again after an operator `sys/seal`, and after the Vault
  container is restarted.
- A node whose latch predates an unseal reset re-contributes when a peer
  contributes first to the new attempt (regression for the latch defects below).
- `vault_sealed` alarms arrive over the https webhook.

Negative — each case must fail `selftest`, stop the daemon fail-closed, and leave
Vault sealed with **progress 0** (nothing submitted):

| Case | selftest | daemon | Vault |
|---|---|---|---|
| Wrong node identity (`node_id` changed) | refuses | exit 78 | sealed, 0 |
| Share replayed under another index | refuses | exit 78 | sealed, 0 |
| Tampered wrapped blob (1 ciphertext char flipped) | refuses | exit 78 | sealed, 0 |
| Share copied from another node (other HSM key) | refuses | exit 78 | sealed, 0 |
| Wrong HSM PIN | refuses | exit 1 at startup | sealed, 0 |
| HSM token missing | refuses | exit 1 at startup | sealed, 0 |
| Impostor Vault (untrusted CA) | refuses | keeps polling, never submits (killed at 15 s) | sealed, 0 |
| Node holds >= threshold shares | refuses | exit 78 | sealed, 0 |

Also: two good nodes plus one tampered node reach progress 2/3 and Vault stays
sealed; an `autohsm_failed` alarm is delivered when a daemon stops; none of the
five unseal keys (base64 or hex) nor the root token appears in any daemon log or
in any of the ~400 alarm payloads.

### Deployment (`scripts/deploy-check.sh`)

On a disposable Debian 12 container with systemd as PID 1, the README Install
and Provision steps run verbatim (only operator-supplied values substituted: Vault
address, CA, PIN, share), then:
- `sudo -u autohsm autohsm selftest` passes with config, CA, PIN and share all
  `root:autohsm 0640` — the paths and ownership the code expects.
- `systemd-analyze verify` accepts the installed unit.
- `autohsm.service` runs under the shipped sandbox (ProtectSystem=strict with
  the SoftHSM token store read-only, syscall filter, empty capability set),
  contributes its share, and Vault unseals once two peer shares are supplied.
- After a Vault restart the service re-submits its share.
- With a tampered share the service exits 78, `NRestarts=0` (RestartPreventExitStatus
  honoured), and Vault stays sealed with nothing submitted.
- No share or root-token material appears in the service journal.
- `systemd-analyze security autohsm`: 1.6 OK (was 6.4 MEDIUM before hardening).

## Defects found and fixed

| Severity | Location | Defect | Fix commit |
|---|---|---|---|
| Medium (availability) | `internal/watch/watcher.go` submitShares | Latch recorded the seal-status nonce from *before* submitting, which real Vault reports as empty at progress 0. After an unobserved reset, a peer contributing first left the node believing it had already contributed; unseal stalled below threshold. | fix(watch): key the submission latch to the nonce Vault returns |
| Medium (availability) | `internal/watch/watcher.go` submitShares | A share that completed the unseal was still latched (with an empty nonce). A Vault restart before the next poll then stalled the next unseal one share short. Reproduced by the e2e restart test. | fix(watch): never latch a share that completed the unseal |
| Medium (silent failure) | `cmd/autohsm/main.go` runWatch | When the daemon stopped for good (HSM missing, wrong PIN, retry budget exhausted, unsafe layout) it sent no alarm; exit 78 is not restarted, so alerts simply ceased. Now posts `autohsm_failed`. | fix(alarm): raise autohsm_failed |
| Low (least privilege) | `cmd/autohsm/main.go` runStatus | `status` (the documented cron monitor) logged in to the HSM with the PIN on every run. It now uses only config + pinned Vault client. | fix(status) |
| Low (DoS) | `internal/config/config.go` OpenSecretFile | A FIFO at a secret path blocked `open` forever before the regular-file check. Now opened `O_NONBLOCK`. | fix(config) |
| Medium (deploy) | `README.md` provisioning | README steps created the SoftHSM token as root; the `autohsm` user could not read it (`CKR_GENERAL_ERROR`). | docs(readme) |
| Low (hardening) | `deploy/autohsm.service` | No capability/syscall restrictions. | deploy: tighten the systemd sandbox |
| Low (build) | `Makefile` | `.PHONY` named nonexistent targets, omitted `build-linux`. | build: ... |

Each code fix has a regression test that fails on the pre-fix code.

## Security review notes (no change needed)

- Envelope: AES-256-GCM, 12-byte nonce from the token/`crypto/rand`, AAD
  `autohsm-v1|node=<id>|idx=<n>`; unwrap errors are opaque (no key-vs-AAD oracle).
- Secret files are checked with `fstat` on the already-open descriptor (no
  check/use race). Symlinks are followed, but the ownership/mode gate applies to
  the file actually opened, so a link cannot lead to anything the gate would reject.
- TLS to Vault: pinned CA pool only, no `InsecureSkipVerify` path, TLS 1.3 default,
  redirects refused, bodies bounded.
- Duplicate submission of the same share within one attempt is ignored by Vault,
  so the latch protects the failure budget and logs rather than Vault's state.
- Shares wrapped for a Vault that has since been re-initialised are accepted by
  Vault until the threshold is reached, then rejected; the daemons keep retrying
  and alarming `vault_sealed` every poll. Loud and fail-closed, not self-healing.

## Limits — not verified

- **No physical HSM or TPM.** Only SoftHSM. Vendor PKCS#11 modules may differ
  (GCM IV handling, attribute defaults, session loss). Run `autohsm selftest`
  on the real token before trusting a deployment.
- **HSM session loss is not recovered.** The PKCS#11 session is opened once. If a
  network HSM drops it, unwraps fail, the retry budget runs out, and the daemon
  exits 78 with an `autohsm_failed` alarm; an operator must restart it.
- **Memory hygiene is best-effort.** Go buffers are wiped, but the PIN copy made
  by `miekg/pkcs11` `Login`, the C buffer behind `Decrypt`, and TLS write buffers
  are freed without zeroing. `LimitCORE=0` prevents core dumps.
- **`node_id` is a label, not attestation** (as the README states).
- Only Vault 1.20.4 was tested; nonce semantics were confirmed empirically on it.
- The deployment check ran on Debian 12 under Docker Desktop, not on a real
  apps2/dr1 host. Hardware-HSM device access (`PrivateDevices=no`, udev rules,
  vendor config paths under `ProtectSystem=strict`) is untested.
- One e2e run before the second latch fix failed intermittently. It is
  consistent with that defect (a restart racing the completing node's poll), and
  10 consecutive runs after the fix passed, but that is not proof of a root cause.
- The `wrap` subcommand prints a truncated SHA-256 fingerprint of the plaintext
  share. It is safe only because Vault shares are high-entropy random values.
