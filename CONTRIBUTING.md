# Contributing to sshsign

This file documents the parts of the codebase that aren't obvious from
reading the source — the security posture, the key-derivation chain,
and the gotchas around rotation and backup. If you're touching crypto,
storage, or the audit log, read this first.

For the user-facing command surface, see [README.md](README.md).

## Development

```bash
# build
go build ./...

# tests (every package; under 15s on commodity hardware)
go test ./... -race -count=1

# fuzzers (run for a fixed budget; CI runs short, you can run longer)
go test ./internal/server/... -run='^$' -fuzz=FuzzParseJSONArg -fuzztime=30s

# benchmarks (e.g., catching a KEK derivation regression before it ships)
go test -bench=BenchmarkKEKRingNew -benchtime=5x ./internal/crypto/...
```

Conventions:
- ES-module-style imports are irrelevant here; this is Go. Follow the
  project's existing style — short package names, exported functions
  with full doc comments, in-package tests use `_test` suffix and
  share a fixture helper where applicable.
- Conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`).
- Every PR that touches storage or crypto must include a test that
  exercises the modified code path. If you can't write one, explain
  why in the PR body.

## Security posture

### Key derivation chain

```
SSHSIGN_KEK_SECRET (env, 32+ chars, never persisted)
        │
        ├──► SHA-256 ─────► legacy KEK (decrypts pre-migration DEKs)
        │
        ├──► Argon2id ───► current KEK (encrypts new DEKs)
        │      ▲
        │      │  salt: server_config.kek_salt (random, persisted in DB)
        │      │  params: time=3, memory=64MiB, threads=4
        │
        ├──► HKDF-Expand("sshsign-audit-chain-v1") ──► audit chain MAC key
        │      (input: current KEK)
        │
        └──► HKDF-Expand("sshsign-pending-mac-v1") ──► cosign binding MAC key
               (input: current KEK)
```

Three things to understand:

**1. The salt lives in the DB, not in env.** `internal/storage/server_config.go::GetOrCreateKEKSalt` generates the salt on first server start and persists it in the `server_config` table. Backing up the DB also backs up the salt. Losing the salt means losing the Argon2id KEK — which means every signing key written under the current scheme is unrecoverable.

**2. Both KEKs are kept alive.** `KEKRing` carries the legacy SHA-256 KEK alongside the current Argon2id KEK so existing wrapped DEKs (created before the Argon2id migration) still decrypt. The `signing_keys.kek_algo` column tags each row with which KEK wrapped it.

**3. The MAC keys derive from the current KEK.** The audit-chain MAC key and the cosign pending-row MAC key are both HKDF-derived from the current (Argon2id) KEK with stable `info` strings. This means:

  - A KEK change (new `SSHSIGN_KEK_SECRET` or new salt) invalidates the audit chain head pointer and every open pending row's MAC.
  - To rotate the KEK, you need a migration that re-MACs every open pending row and re-chains the audit log from a known-good checkpoint.
  - The `info` strings are versioned (`v1`). Bumping the version is the canonical "force re-derivation" signal.

### Pending-row MAC (cosign tamper protection)

When a signing request enters the cosign queue, `pending_signatures.pending_mac` carries an HMAC over the canonical encoding of the fields a human would review before approving:

```
SigningKeyID, AuthTokenID, RequesterID, DocType, PayloadHash, Metadata
```

Both the SSH `approve` handler and the HTTP `POST /approve` handler verify the MAC before any irreversible work. The encoding is length-prefixed (4-byte big-endian length per field) so `{"foo", "barbaz"}` can't alias `{"foobar", "baz"}`. See `internal/crypto/encrypt.go::PendingBinding`.

Pre-migration rows have NULL MAC. **They are rejected on approve**, not silently downgraded — see `crypto.VerifyApprovalToken` for the explicit empty-mac check. This matters: an attacker who could zero the `pending_mac` column would otherwise skip the integrity check entirely.

### Audit chain (MemoryLogger only)

`MemoryLogger.VerifyChain` walks every entry in `TxID` order and checks that each entry's `EntryHash` matches `HMAC(chainKey, canonical(entry))` and that each entry's `PrevHash` equals the previous entry's `EntryHash`. Modifying any entry breaks every chain pointer that follows it.

The `ImmuDBLogger` gets equivalent tamper evidence from immudb's signed Merkle root (every `Get` and `Set` goes through `VerifiedGet`/`VerifiedSet`), so its `VerifyChain` is a no-op health check.

### Session codes and view tokens

- Session codes (`INV-XXXXXX`) are 6 chars from a 29-char alphabet via rejection sampling — ~29 bits of entropy with no modulo bias. They're constant-time-compared at the lookup boundary, and the per-user `get-session` rate limiter caps brute-force attempts.
- View tokens (`/audit/<session_id>?token=...`) are 22-char URL-safe base64 (~128 bits) and are constant-time-compared in `internal/sessions/repo.go::GetByViewToken`.

### Approval tokens

The single-use web approval URLs are 64-hex-char random tokens. The DB stores `$sha256$<hex(SHA256(token))>`, not the raw token. The raw token is returned once in the sign response and never recoverable from the DB. Compare path uses `subtle.ConstantTimeCompare`. Pre-migration rows (raw stored tokens) still work via a length-and-prefix sniff in `VerifyApprovalToken`.

## SSH argv mangling and the -b64 escape hatch

SSH strips inner double quotes from argv and splits on spaces. JSON like:

```
{"company":"Blue Fund"}
```

arrives at the handler as the multi-token mess `{company:Blue Fund}` (no quotes around `company`, no quotes around `Blue Fund`, split on the space).

`parseJSONArg` repairs the bare-key case with a regex (`bareKeyRe`) and rejoins space-split tokens up to the next `--flag`. This is fragile by design — it works on most inputs but can't recover bare string values that contained spaces. The `-b64` escape hatch is the canonical fix.

Every JSON-accepting flag has a `<name>-b64` variant that takes the same JSON, base64-encoded. The encoding is whitespace-free so SSH transports it opaquely. See `decodeB64JSON` in `internal/server/commands.go`.

```bash
# These two are equivalent on the wire — but the second one always
# survives argv mangling, where the first one only works if no string
# value contains a space.
ssh sshsign.dev sign --metadata     '{"v":1}'
ssh sshsign.dev sign --metadata-b64 "$(echo -n '{"v":1}' | base64)"
```

Clients integrating with sshsign should default to the `-b64` form for any flag whose value can contain spaces, quotes, or other shell-active characters.

## Database migrations

Schema lives in `internal/storage/db.go`. The `migrations` slice is the
ordered history; each entry has a `version` integer and an `up` SQL
block. New changes append; existing entries must never be edited
post-release.

`Migrate` is safe to call on:
- **Fresh databases** — applies every migration from v1.
- **Legacy databases** (created by the pre-versioning loop) — detected by `users` table existence with empty `schema_migrations`; gets baselined into every known version without re-running any body.
- **Already-versioned databases** — applies only unapplied migrations.

To add a column or table, append a new entry to `migrations`. To re-run an old migration body (e.g., to fix a botched up-step), bump the version and write a corrective new entry. **Never modify a released migration.**

## Rotation gotchas

- **Rotating `SSHSIGN_KEK_SECRET`**: requires a script that unwraps every DEK with the old KEK and re-wraps with the new one. Until that script exists, treat the secret as install-once.
- **Rotating the audit chain key**: requires a checkpoint mechanism that isn't yet built. The current chain tolerates restarts under the same secret+salt, but a KEK rotation breaks the chain.
- **Rotating per-pending MACs**: easier — `pending_signatures` rows expire in 24h, so the rotation window is bounded. Best practice is to gate the rotation on "no open pending rows under the old key."
- **Salt rotation**: equivalent to KEK rotation since the salt feeds into Argon2id. Don't do it casually.

## Testing approach

- **Unit tests** live next to the code they test (`*_test.go`).
- **Integration tests** in `internal/server/` exercise the SSH command surface end-to-end via `sshClientWithStdin`.
- **TUI tests** drive sub-models via synthetic `tea.KeyMsg` and assert on state transitions + storage side effects. No mocks; the storage layer is the real (in-memory) SQLite.
- **Fuzz targets** in `internal/server/commands_fuzz_test.go`. Run for at least 5 minutes when touching `parseJSONArg`, `fixBareJSONKeys`, or `decodeB64JSON`.
- **Benchmarks** in `internal/crypto/encrypt_test.go`. Document any KEK-param change with the new benchmark output in the PR.

## Code layout

```
cmd/
  sshsign/             CLI tool (used as git's gpg.ssh.program)
  sshsign-server/      Server entrypoint

internal/
  audit/               Audit log: interface, memory chain, immudb backend
  auth/                Authorization engine (constraints, rules)
  config/              Env loading, validation
  crypto/              KEK ring, DEK wrap, pending MAC, approval token hash
  evidence/            Sealed evidence envelopes
  ratelimit/           Token bucket + sliding window
  server/              SSH server, per-command handlers, session context
  sessions/            Multi-party signing session repo
  signing/             SSHSIG-format signing
  storage/             SQLite repository layer, migrations
  tui/                 Bubble Tea TUI sub-models
  web/                 HTTP server for cosign approval URLs
```

## Code review checklist (for new contributions)

- [ ] `go test ./...` and `go test ./... -race` both green
- [ ] Touched a handler? Did `mustUnmarshal` make it into your test setup?
- [ ] Touched storage? Tested with both a fresh DB and a legacy-baseline DB?
- [ ] Touched crypto? Did you exercise the new code with a sibling `KEKRing` (proves keys round-trip correctly)?
- [ ] Touched a parser? Ran the relevant fuzzer for at least 30 seconds?
- [ ] Added a new env var or config field? Updated `internal/config/config_test.go`?
- [ ] Changing argv-visible behavior? Updated the README's "Programmatic interface" section?
