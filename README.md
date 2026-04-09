![sshsign logo](web/social-preview.png)

# sshsign

SSH-based signing service for AI agents. No accounts, no passwords, no OAuth. SSH key = identity, scoped authorization = boundaries, immutable receipt = proof.

```
ssh sshsign.dev
```

## What it does

- Agents and developers SSH in, identity detected from their public key
- Create Ed25519 signing keys with scoped authorizations and metadata constraints
- Sign git commits, legal agreements (SAFEs, NDAs), or arbitrary payloads
- Co-sign approval flow: agents act, humans approve with optional handwritten signature
- Negotiation logging with turn enforcement and immutable chain linking
- Every sign, deny, and revoke is logged to an immutable audit trail (immudb)

## Quick start

### Try the TUI

```bash
ssh sshsign.dev
```

### Set up git commit signing (~5 minutes)

1. Install the CLI:

```bash
# Homebrew
brew install agenticpoa/tap/sshsign

# Or Go install
go install github.com/agenticpoa/sshsign/cmd/sshsign@latest
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
git config --global gpg.ssh.program "sshsign"
git config --global user.signingkey "ak_7xm3..."
```

5. Sign commits:

```bash
git commit -S -m "signed commit"
```

## Programmatic interface

All commands are SSH-based:

```bash
# Create a signing key with constraints
ssh sshsign.dev create-key \
  --scope safe-agreement \
  --tier cosign \
  --require-signature \
  --constraints '{"valuation_cap": {"min": 5000000, "max": 15000000}, "discount_rate": {"min": 0.15}}'

# Sign a payload (cosign returns a pending ID + approval URL)
echo '{"valuation_cap": 8000000}' | ssh sshsign.dev sign \
  --type safe-agreement \
  --key-id ak_xxx \
  --metadata '{"valuation_cap": 8000000, "discount_rate": 0.20}'

# Retrieve the evidence envelope after web approval
ssh sshsign.dev get-envelope --id pnd_xxx

# Log negotiation offers with turn enforcement
ssh sshsign.dev log-offer \
  --negotiation-id neg_xxx \
  --round 0 --from founder --type offer \
  --metadata '{"valuation_cap": 12000000}'

# View negotiation history
ssh sshsign.dev history --negotiation-id neg_xxx

# List keys, revoke, approve, deny
ssh sshsign.dev keys
ssh sshsign.dev revoke --key-id ak_xxx
ssh sshsign.dev approve --id pnd_xxx
ssh sshsign.dev deny --id pnd_xxx
```

## Authorization model

Each signing key has scoped authorizations with typed constraints:

| Constraint type | Example |
|----------------|---------|
| `range` | Valuation cap between $5M and $15M |
| `minimum` | Discount rate at least 15% |
| `maximum` | Penalty no more than $500K |
| `enum` | NDA type: mutual or one-way |
| `required_bool` | Pro-rata rights required |

**Confirmation tiers:**
- **Autonomous** - agent signs immediately
- **Co-sign** - requires human approval before signing
- **Co-sign + handwritten signature** - human approves via web with a drawn signature, sealed into a tamper-evident evidence envelope

## Web approval flow

When an authorization has `require_signature` enabled, the sign response includes an approval URL:

```
https://sshsign.dev/approve/pnd_xxx?token=...
```

The approver opens this in a browser, reviews the agreed terms, draws their handwritten signature, and clicks "Sign & Approve". The signature image is sealed into an evidence envelope alongside the document hash, signer identity, IP, and timestamp. The image exists only inside the sealed envelope.

## Running the server

```bash
export SSHSIGN_KEK_SECRET="$(openssl rand -hex 32)"

# Optional
export SSHSIGN_LISTEN_ADDR=":2222"
export SSHSIGN_DB_PATH="./sshsign.db"
export SSHSIGN_HOST_KEY_PATH="./host_key"
export SSHSIGN_HTTP_ADDR=":8443"
export SSHSIGN_HTTP_DOMAIN="sshsign.dev"

# Optional: immudb for tamper-proof audit trail
export SSHSIGN_IMMUDB_ADDRESS="127.0.0.1"

go run ./cmd/sshsign-server/
```

## Architecture

```
Agent/Developer --SSH--> wish server --HTTP--> web approval
                            |                    (signature
                   +--------+--------+            capture)
                   |                 |
              Bubble Tea TUI   Programmatic CLI
                   |                 |
                   +--------+--------+
                            |
                   Authorization Engine
                   (scopes, typed constraints,
                    hard/soft rules, cosign)
                            |
                  +---------+---------+
                  |         |         |
               Signing   Evidence   Negotiation
               Engine    Envelopes  Offers
               (Ed25519) (sealed)   (turn-enforced)
                  |         |         |
                  +---------+---------+
                            |
                  +---------+---------+
                  |                   |
               SQLite             immudb
           (users, keys,      (immutable
            tokens, offers)    audit trail)
```

## Tech stack

| Component | Technology |
|-----------|-----------|
| Language | Go |
| SSH server | charmbracelet/wish |
| Terminal UI | charmbracelet/bubbletea |
| Web approval | net/http, HTML5 Canvas |
| Signing | crypto/ed25519, SSHSIG format |
| Authorization | Scoped tokens with typed constraints and rules |
| Evidence | Sealed JSON envelopes with SHA-256 binding |
| Audit trail | codenotary/immudb |
| Storage | SQLite (modernc.org/sqlite, CGO-free) |

## Related projects

- [APOA](https://github.com/agenticpoa/apoa) - Agentic Power of Attorney specification
- [negotiate](https://github.com/agenticpoa/negotiate) - AI agent negotiation protocol and SAFE demo

## Troubleshooting

**"Permission denied (publickey)"** - Make sure you have an SSH key (`ssh-add -l`) and that you've connected at least once to register it.

**"Host key verification failed"** - Pin the host key (see quick start step 2), or connect with `ssh -o StrictHostKeyChecking=accept-new sshsign.dev`.

**"unknown key id"** - Run `ssh sshsign.dev keys` to list your keys and check the ID.

**"not your turn"** - Negotiation offers must alternate between parties.

**"this approval requires a handwritten signature"** - The authorization has `require_signature` enabled. Open the approval URL in a browser to draw your signature.

## License

MIT
