# Validation — 2026-09-26

This file records what was verified on branch `prod-readiness-2026-09-26`, how it
was verified, and what was not. Every result below came from a command run on that
date; rerun the commands to reproduce them. Nothing touched a real Vault or any
production host. All Vault, HSM and systemd testing used disposable local Docker
containers.

There were three rounds. The second round fixed issues raised by an independent
review, plus limits the first round had documented. The third round made the
daemon survive an HSM that is absent at startup.

## Environment

| Item | Version |
|---|---|
| Go (host) | go1.27.1 darwin/amd64; e2e images build with golang:1.24-bookworm |
| Vault | hashicorp/vault:1.20 (v1.20.4), **non-dev**: file storage, Shamir seal 5/3, TLS 1.3 listener with a throwaway CA |
| HSM | SoftHSM 2.6 (Debian 12 package) in containers; SoftHSM 2.7 (Homebrew) for the host integration test |
| PKCS#11 tooling | OpenSC `pkcs11-tool` (Debian 12) |
| systemd | 252 (Debian 12), PID 1 in a privileged disposable container |

## Results (final run)

| Check | Command | Result |
|---|---|---|
| Static analysis | `go vet ./...`, `gofmt -l .` | clean |
| Unit tests (race) | `go test -race -count=1 ./...` | 126 passed, 0 failed, 0 skipped |
| Makefile | `make all` (vet, test, build) | pass |
| PKCS#11 integration | `make test-integration AUTOHSM_TEST_MODULE=.../libsofthsm2.so` | pass: `TestSoftHSMPKCS11` (session-loss recovery, wrong PIN) and `TestSoftHSMStartupWithoutToken` (round 3) |
| End-to-end | `make e2e` (`scripts/e2e.sh`) | 53/53 checks at round 2; **not rerun in round 3** (see below) |
| Deployment | `make deploy-check` (`scripts/deploy-check.sh`) | 15/15 checks at round 2; **not rerun in round 3** |

Round 3 note: the Docker VM had 3.3 GB free (`docker run --rm alpine df -h /`),
below the agreed 4 GB threshold, with other agents' containers running. So the
Docker harnesses were not rerun. The round-3 change was verified with unit tests
and the SoftHSM integration test only. The e2e "HSM token missing" case was
updated to the new behaviour (daemon keeps running, exit 124 at the 15 s timeout,
reason "HSM unavailable", `hsm_unavailable` alarm) but **has not been run**.
deploy-check does not exercise this path.

### End-to-end (`scripts/e2e.sh`)

The setup is three node containers and an HTTPS alarm receiver that trusts the
throwaway CA. Each node has its **own** SoftHSM token and non-extractable AES-256
key, and holds **one** share of a Vault with 5 shares and a threshold of 3.

Positive:
- The README's `softhsm2-util` / `pkcs11-tool` commands produce keys that pass the
  daemon's key-attribute check. `selftest` passes on all three nodes.
- The wrapped share files do not contain the plaintext share.
- The daemons unseal a freshly initialised Vault. They unseal it again after an
  operator `sys/seal`, and again after the Vault container is restarted.
- Latch recovery: a node whose submission latch predates an unseal reset
  contributes again when a peer contributes first. The check fails unless its
  setup really produced a persisted, nonce-keyed latch.
- `vault_sealed` alarms arrive over the https webhook.

Negative cases. Each one must meet all of these:
- `selftest` fails.
- The daemon stops fail-closed.
- The daemon's log contains the **intended reason**.
- Vault stays sealed with **progress 0**, meaning nothing was submitted.

| Case | Daemon | Asserted reason |
|---|---|---|
| Wrong node identity (`node_id` changed) | exit 78 | not authentic for this node and index |
| Share replayed under another index | exit 78 | not authentic for this node and index |
| Tampered wrapped blob (1 ciphertext char flipped) | exit 78 | not authentic for this node and index |
| Share copied from another node (other HSM key) | exit 78 | not authentic for this node and index |
| Wrong HSM PIN | exit 78, never retried | HSM rejected the PIN |
| Vault certificate from an untrusted CA | keeps polling, never submits (killed at 15 s) | certificate signed by unknown authority |
| Node holds >= threshold shares | exit 78 | meeting Vault's threshold |
| HSM token missing | exit 1 at startup (round 2); round 3 changes this to "keeps running, never submits" — updated in the script, not yet run | no token with label → HSM unavailable |

Additional scenarios:
- **Two good nodes plus one tampered node:** progress reaches 2/3 and Vault stays
  sealed.
- **Vault re-initialised (stale shares):** Vault's storage is destroyed and
  initialised again.
  - The node whose submission reaches the threshold receives Vault's rejection:
    HTTP 400 "invalid key: failed to decrypt keys from storage ... message
    authentication failed".
  - That node raises `shares_stale` and submits nothing afterwards. It sent 5 alarms
    in 25 s of 1 s polls, where one alarm per poll would have been about 25.
  - Vault stays sealed.
- `autohsm_failed` alarms are delivered when a daemon stops.
- None of the unseal keys (base64 or hex) or root tokens from either
  initialisation appears in any daemon log or alarm.

### Deployment (`scripts/deploy-check.sh`)

The check uses a disposable Debian 12 container with systemd as PID 1. It runs the
README Install and Provision steps verbatim; only operator-supplied values are
substituted (Vault address, CA, PIN, share). It then verifies:
- `sudo -u autohsm autohsm selftest` passes with the config, CA, PIN and share all
  `root:autohsm 0640`.
- `systemd-analyze verify` accepts the installed unit.
- The README's `systemd-run` command runs selftest under the unit's sandbox
  properties and passes. The command is extracted verbatim from README.md.
- The README's hardware-HSM drop-in example, also extracted verbatim, passes
  `systemd-analyze verify`.
- The sandboxed service submits its share, and Vault unseals once two peer shares
  are supplied.
- After a Vault restart, the service submits its share again.
- With a tampered share the service exits 78, `NRestarts=0`, and Vault stays
  sealed with nothing submitted.
- With a wrong PIN the service exits 78, and `NRestarts=0` after 20 s: no C_Login
  retry loop.
- No share or root-token material appears in the service journal.
- `systemd-analyze security autohsm` scores 1.6 OK.

## Defects fixed

Each code fix has a regression test that fails on the pre-fix code.

### Round 1

| Severity | Location | Defect |
|---|---|---|
| Medium | `internal/watch/watcher.go` submitShares | The latch recorded the pre-submission nonce, which Vault reports as empty at progress 0. After an unobserved reset the unseal stalled below threshold. |
| Medium | `internal/watch/watcher.go` submitShares | A share that completed the unseal was latched with an empty nonce. A Vault restart before the next poll stalled the next unseal. |
| Medium | `cmd/autohsm/main.go` runWatch | When the daemon exited it sent no alarm, so alerts simply stopped. It now sends `autohsm_failed`. |
| Low | `cmd/autohsm/main.go` runStatus | `status` logged in to the HSM on every cron run. |
| Low | `internal/config/config.go` OpenSecretFile | A FIFO at a secret path hung the daemon. |
| Medium | `README.md` | SoftHSM token provisioning as root was unusable by the service user. |
| Low | `deploy/autohsm.service`, `Makefile` | The sandbox was too permissive (exposure 6.4 → 1.6), and `.PHONY` listed targets that do not exist. |

### Round 2

| Severity | Location | Defect / change |
|---|---|---|
| Medium | `internal/watch/watcher.go` submitShares | A node holding ≥2 shares could keep indexes from an earlier attempt when the nonce changed between its own submissions. For example, the latch ended up as {1,2}@N2 when N2 only received share 2, and the unseal stalled at 2/3. The latch is now cleared when the response nonce changes. Reviewer's reproduction, using a Vault-faithful fake. |
| Low | `scripts/e2e.sh` | `wait_for ... \|\| true` let the latch-recovery check pass without exercising the latch. |
| Low (hardware lockout) | `internal/keysource/pkcs11.go`, `cmd/autohsm/main.go` | A wrong PIN exited 1, so systemd restarted the service and retried C_Login, counting a hardware token down toward lockout. PIN errors (INCORRECT/LOCKED/EXPIRED/INVALID/LEN_RANGE) are now `ErrPINRejected`: sticky, never retried, exit 78. |
| Test harness | `scripts/e2e/node.sh` | **Round 1's "wrong PIN" pass was invalid.** The harness wrote the PIN file with mode 0644, so the daemon refused the file mode and never tried the PIN. Round 2 found this by asserting the refusal reason. |
| Limit → fixed | `internal/keysource/pkcs11.go`, `internal/watch` | HSM session recovery. On session or device loss the source re-initialises, logs in again and re-locates the key. The watcher probes the session every poll, raises `hsm_unavailable` once per outage and `hsm_recovered` when it returns, backs off from one interval up to 5 min, and does not spend the unseal budget while the HSM is down. |
| Limit → fixed | `internal/vaultclient`, `internal/watch` | Stale shares. Vault's key-rejection reply is classified (`IsKeyRejected`). The watcher then raises `shares_stale`, stops submitting until it is restarted, suppresses the per-poll `vault_sealed` alarm, and repeats `shares_stale` with backoff up to hourly. |
| Limit → fixed | `internal/config` ReadBounded, `cmd/autohsm` readShare | PIN, config and plaintext-share reads used `io.ReadAll`, whose growth reallocations left partial copies in freed memory that was never zeroed. They now read into a single buffer that gets wiped. The PIN is re-read for each login and wiped right after C_Login instead of being held. |
| Nits | watcher log, deploy-check, e2e labels | Log wording is neutral when a peer completed the unseal. The deploy-check message is corrected. The untrusted-CA case is relabelled. The latch comment is corrected: Vault ignores duplicate parts. |
| Docs | `README.md`, `deploy/autohsm.service` | Hardware-HSM section: drop-in with ReadWritePaths / ProcSubset=all / AF_NETLINK / SupplementaryGroups, a udev rule, and selftest under the sandbox via `systemd-run`. |

### Round 3

| Severity | Location | Defect / change |
|---|---|---|
| Medium (availability) | `internal/keysource/pkcs11.go`, `cmd/autohsm/main.go`, `internal/watch` | An HSM absent at startup made `watch` exit 1. systemd retried 5 times in 5 minutes and then gave up, so a token attached a few minutes after boot left Vault sealed. Startup failures are now classified. **Retryable** (`ErrHSMUnavailable`): C_Initialize, slot list, token absent, open session, and non-PIN login failures. The daemon opens with `DeferUnavailable`, so for these it starts disconnected and follows the mid-run outage path: `hsm_unavailable` once, backoff up to 5 min, nothing submitted, budget untouched, `hsm_recovered` on reconnect. **Terminal, exit 78**: `ErrPINRejected`; `ErrHSMMisconfigured` (module cannot load, no AES-GCM, key missing, ambiguous or unsafe, PIN source unusable); and any config or CA error in `watch`. Wrong-node and tampered shares remain terminal through the unwrap budget. Short-lived commands (`selftest`, `wrap`) still fail immediately. |

`TestSoftHSMStartupWithoutToken` (in `internal/watch`, tag `integration`) runs
against real SoftHSM 2.7:
- It provisions a token and wraps a share through it.
- Wrong PIN and a missing key label are rejected at open even with
  `DeferUnavailable`.
- It renames the token store away. `OpenPKCS11` without deferral returns
  `ErrHSMUnavailable`; with deferral it returns a source.
- Six watcher polls against a Vault-faithful fake produce exactly one
  `hsm_unavailable`, no submission, no budget use, and a backoff above one
  interval.
- It restores the token store and has two peers contribute. The next poll after
  the backoff produces one `hsm_recovered` and one submission unwrapped by the real
  token, and Vault is unsealed.

Unit tests cover the watcher treating `ErrHSMMisconfigured` as terminal, from both
the probe and the unwrap path, and `exitCode` mapping it to 78.

## Security review notes

- **Envelope:** AES-256-GCM with a 12-byte nonce from the token or `crypto/rand`.
  The AAD is `autohsm-v1|node=<id>|idx=<n>`. Unwrap errors are opaque, so there is
  no oracle distinguishing a wrong key from a wrong AAD. A bad GCM tag is never
  classified as a lost session: a unit test covers the error codes, and the e2e
  tampered-blob case asserts the refusal reason.
- **Secret files:** they are checked with `fstat` on the already-open descriptor
  and opened `O_NONBLOCK`. Symlinks are followed, but the ownership/mode check
  applies to the file actually opened.
- **TLS to Vault:** only the pinned CA pool is trusted, and there is no
  `InsecureSkipVerify` path. TLS 1.3 is the default, redirects are refused, and
  response bodies are bounded.
- **Vault error messages:** these are now carried into logs and alarms, capped at 4
  messages of 300 bytes each with control characters removed. Vault's unseal errors
  describe the failure, never the key: a unit test asserts the submitted share is
  not echoed, and the e2e leak check covers the real replies.
- **Duplicates:** Vault ignores a duplicate part within an attempt, as confirmed on
  1.20.4. The latch exists to avoid needless HSM unwraps and re-sending key
  material, not to protect Vault.

## Memory zeroing — what is and is not wiped

Wiped by this code after use:
- The PIN buffer, once per login.
- Every plaintext share returned by the key source, after submission, selftest or
  wrap.
- The JSON unseal request body.
- The stdin buffer for `wrap`.
- The config buffer.
- The dev-only software key.

All of these are single allocations: there are no growth copies and no string
conversions.

Cannot be wiped by this code:
- **`miekg/pkcs11` `Login`:** it copies the PIN into a C string (`C.CString`) and
  frees it without zeroing.
- **`miekg/pkcs11` `Decrypt`:** it returns plaintext via a C buffer that is copied
  into Go (`C.GoBytes`) and then freed without zeroing. The same applies to the
  plaintext passed to `Encrypt` during `wrap`.
- **The PKCS#11 module's own internal buffers** (SoftHSM or vendor).
- **`net/http` and `crypto/tls`:** the transport's buffered writer holds a copy of
  the unseal request body until it is reused or collected. TLS record buffers hold
  only ciphertext.
- **`pin_env` (short-lived subcommands only; refused for `watch`):** the value comes
  from `os.Getenv` as an immutable Go string, and the process's exec-time
  environment block stays readable in `/proc/<pid>/environ`.
- **`AUTOHSM_DEV_KEY`** (dev-only software source): same as `pin_env`.
- **The Go runtime:** it may have copied a buffer (stack growth, GC) before `Wipe`.

`LimitCORE=0` in the unit prevents core dumps. Swap exposure depends on the host.

## Limits — not verified

- **No physical HSM or TPM, only SoftHSM.** Vendor modules may differ in GCM IV
  handling, attribute defaults and the error codes they return on session loss.
  The recovery path handles the standard codes. Run `autohsm selftest` under the
  sandbox (README) on the real token.
- **Session loss was tested only inside the integration test.** It was simulated
  with `C_CloseAllSessions` and by removing and restoring the token directory; the
  e2e does not simulate an HSM outage under a running daemon. SoftHSM keeps working
  from its cache when files disappear, so a mid-run outage could not be produced
  that way.
- **Only the node that submits the threshold share sees the stale-share
  rejection.** Vault's rejection does not say which share is stale, so that node
  alone raises `shares_stale` and stops. Peers resubmit once, then wait at progress
  < threshold with `vault_sealed` alarms. That is fail-closed but noisier.
- **One wrong manual key trips the stale latch.** A single rejected combine, for
  example an operator typing a wrong key, latches the node until it is restarted.
  This is deliberately fail-closed.
- **Only Vault 1.20.4 was tested.** The nonce semantics and the key-rejection
  message were confirmed empirically on it; other versions may word the error
  differently.
- **The deployment check ran on Debian 12 under Docker Desktop, not on a real
  host.** For the hardware-HSM drop-in, only its syntax was verified; no vendor
  client was run.
- **The `wrap` subcommand prints a truncated SHA-256 fingerprint of the plaintext
  share.** This is safe only because Vault shares are high-entropy random values.
