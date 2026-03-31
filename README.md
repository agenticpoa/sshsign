![sshsign logo](web/logo.png)

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
echo "sshsign.dev ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEHD3y2HaBA+KveRWiMN5vigPzDs7s0meo0b/DZcAHne" >> ~/.ssh/known_hosts
```

Fingerprint: `SHA256:07UTOOLZj6oOs+bAZQJ98/40368zyR73DeOevE+8uMw`

3. SSH in and create a signing key:

```bash
ssh sshsign.dev
# Follow the TUI to create a key and set up authorization
# Note your key ID (e.g. ak_7xm3...)
```

4. Configure git:

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program "sshsign"  # must be on $PATH, or use full path e.g. ~/go/bin/sshsign
git config --global user.signingkey "ak_7xm3..."
```

5. Sign commits:

```bash
git commit -S -m "signed commit"
```

### Verifying signatures

To verify signed commits, you need an `allowed_signers` file that maps email addresses to trusted public keys.

1. Create the file:

```bash
mkdir -p ~/.config/git

# Add one line per signer: <email> <public-key>
echo "alice@example.com ssh-ed25519 AAAAC3Nza..." >> ~/.config/git/allowed_signers
```

2. Tell git where to find it:

```bash
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

3. Verify:

```bash
git log --show-signature
# or for a single commit
git verify-commit HEAD
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
# Required: key encryption key for protecting signing keys at rest
# Generate with: openssl rand -hex 32
export SSHSIGN_KEK_SECRET="your-secret-here"

# Optional
export SSHSIGN_LISTEN_ADDR=":2222"        # default :2222
export SSHSIGN_DB_PATH="./sshsign.db"     # default ./sshsign.db
export SSHSIGN_HOST_KEY_PATH="./host_key" # default ./host_key

# Optional: immudb for tamper-proof audit trail
# Without immudb, audit events are stored in SQLite only.
# This works fine for development but offers weaker tamper-evidence
# guarantees since SQLite rows can be modified after the fact.
# For production use, immudb provides cryptographic proof that
# audit records have not been altered.
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

## Troubleshooting

**"Permission denied (publickey)"** - The server doesn't recognize your SSH key. Make sure you have an SSH key (`ssh-add -l`) and that you've connected at least once to register it.

**"Host key verification failed"** - You haven't pinned the host key yet. See step 2 in the quick start, or connect with `ssh -o StrictHostKeyChecking=accept-new sshsign.dev` to trust on first use.

**Connection refused on port 2222** - When running locally, make sure the server is running and your firewall allows connections on the configured port.

**"unknown key id"** - The signing key ID in your git config doesn't match any key on the server. Run `ssh sshsign.dev keys` to list your keys and update `user.signingkey` accordingly.

**immudb connection errors** - If `SSHSIGN_IMMUDB_ADDRESS` is set but immudb isn't running, the server will fail to start. Either start immudb or unset the variable to fall back to SQLite-only audit.

## A note on the CLI name

The `sshsign` binary acts as a drop-in `gpg.ssh.program` for git. This is unrelated to OpenSSH's built-in `ssh-keygen -Y sign` functionality. The CLI proxies signing requests to the sshsign server over SSH rather than signing locally.

## License

MIT
