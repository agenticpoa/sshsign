# sshsign

SSH-based signing service for AI agents. No accounts, no passwords, no OAuth. SSH key = identity, scoped token = authorization, immutable receipt = proof.

```
ssh sshsign.dev
```

## What it does

- Agents and developers SSH in, identity detected from their public key
- Create Ed25519 signing keys with scoped authorizations
- Sign git commits (and arbitrary payloads) through the service
- Every sign, deny, and revoke action is logged to an immutable audit trail
- Signatures are PEM-armored SSH format, compatible with `git commit -S`

## Quick start

### Try the TUI

```bash
ssh sshsign.dev
```

### Set up git commit signing (~5 minutes)

1. Install the CLI:

```bash
# Go install
go install github.com/agenticpoa/sshsign/cmd/sshsign@latest

# Or Homebrew
brew install agenticpoa/tap/sshsign
```

2. Pin the host key:

```bash
echo "sshsign.dev ssh-ed25519 AAAAC3..." >> ~/.ssh/known_hosts
```

3. SSH in and create a signing key:

```bash
ssh sshsign.dev
# Follow the TUI to create a key and set up authorization
# Note your key ID (e.g. ak_7xm3...)
```

4. Configure git:

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program "sshsign"
git config --global user.signingkey "ak_7xm3..."
```

5. Sign commits:

```bash
git commit -S -m "signed commit"
```

## Programmatic interface

Agents interact via SSH command arguments:

```bash
# Sign a payload
ssh sshsign.dev sign \
  --type git-commit \
  --key-id ak_7xm3... \
  --repo github.com/user/repo \
  < commit-data

# Returns JSON: {"signature":"-----BEGIN SSH SIGNATURE-----\n...","key_id":"ak_7xm3...","audit_tx_id":42}

# List keys
ssh sshsign.dev keys

# Revoke a key
ssh sshsign.dev revoke --key-id ak_7xm3...
```

## Running the server locally

```bash
# Required
export SSHSIGN_KEK_SECRET="your-secret-here"

# Optional
export SSHSIGN_LISTEN_ADDR=":2222"        # default :2222
export SSHSIGN_DB_PATH="./sshsign.db"     # default ./sshsign.db
export SSHSIGN_HOST_KEY_PATH="./host_key" # default ./host_key

# Optional: immudb for production audit trail
export SSHSIGN_IMMUDB_ADDRESS="127.0.0.1"
export SSHSIGN_IMMUDB_PORT="3322"

go run ./cmd/sshsign-server/
```

Then connect:

```bash
ssh -p 2222 localhost
```

## Architecture

```
Developer/Agent --SSH--> wish server
                            |
                   +--------+--------+
                   |                 |
              Bubble Tea TUI   Programmatic CLI
                   |                 |
                   +--------+--------+
                            |
                   Authorization Engine
                   (scopes, constraints,
                    hard/soft rules)
                            |
                     Signing Engine
                    (Ed25519, SSHSIG)
                            |
                  +---------+---------+
                  |                   |
               SQLite             immudb
           (users, keys,      (immutable
            tokens)            audit trail)
```

## Tech stack

| Component | Technology |
|-----------|-----------|
| Language | Go |
| SSH server | charmbracelet/wish |
| Terminal UI | charmbracelet/bubbletea |
| Signing | crypto/ed25519, SSHSIG format |
| Authorization | Scoped tokens with constraints and rules |
| Audit trail | codenotary/immudb |
| Metadata | SQLite (modernc.org/sqlite, CGO-free) |

## License

MIT
