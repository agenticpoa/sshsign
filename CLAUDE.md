# sshsign

SSH-based signing service. SSH in, signatures out. Agents sign on behalf of humans
under scoped authorization tokens.

## When to use sshsign

- **Sign a document** (SAFE, NDA, arbitrary payload) as an individual or agent
- **Coordinate a multi-party signing ceremony** — two or more parties jointly sign
  after agreeing on terms. Use signing sessions (below)
- **Log a negotiation offer** with cryptographic turn-enforcement
- **Retrieve a sealed evidence envelope** with signature + audit metadata

## Interface

All commands run through SSH. Your SSH public key is your identity.

```bash
ssh sshsign.dev <command> [flags]
```

## Common commands

### Single signature

```bash
# Create a signing key with a scoped authorization
ssh sshsign.dev create-key \
  --scope safe-agreement \
  --tier cosign \
  --require-signature \
  --constraints '{"valuation_cap":{"min":8000000,"max":12000000}}'

# Sign a payload (cosign returns a pending_id + approval URL)
echo '{"valuation_cap":10000000}' | ssh sshsign.dev sign \
  --type safe-agreement \
  --key-id ak_xxx \
  --metadata '{"valuation_cap":10000000}'

# Approve (or deny) a pending signature from the CLI
ssh sshsign.dev approve --id pnd_xxx
ssh sshsign.dev deny --id pnd_xxx

# Fetch the sealed evidence envelope after approval
ssh sshsign.dev get-envelope --id pnd_xxx
```

### Multi-party signing sessions

Use when 2+ parties need to jointly sign. General-purpose — not tied to any
specific document type.

```bash
# 1. Creator starts the session and gets a shareable code
ssh sshsign.dev create-session \
  --session-id neg_abc \
  --role founder \
  --apoa-pubkey "$(cat apoa.pub)" \
  --metadata-public '{"use_case":"safe"}' \
  --metadata-member '{"company_name":"Acme"}'
# → returns session_code: INV-7K3X9

# 2. Other party joins using the code
ssh sshsign.dev join-session \
  --session-code INV-7K3X9 \
  --role investor \
  --apoa-pubkey "$(cat apoa.pub)"

# 3. Each party signs via regular `sign` commands.
#    Include the session_id in --session-id on sign so pendings correlate.

# 4. Creator completes once all parties have signed.
#    Returns a view_token for a shareable public audit URL.
ssh sshsign.dev complete-session \
  --session-id neg_abc \
  --executed-artifact sshsign://artifact/final.pdf

# 5. Cancel (any member) or rescind-after-sign
ssh sshsign.dev cancel-session --session-id neg_abc
ssh sshsign.dev cancel-session --session-id neg_abc --rescind

# 6. Read the append-only transition log (members only)
ssh sshsign.dev audit-session --session-id neg_abc

# 7. Inspect state. Non-members only see metadata_public + status.
ssh sshsign.dev get-session --session-code INV-7K3X9
```

### Negotiation offer log

```bash
ssh sshsign.dev log-offer \
  --negotiation-id neg_abc \
  --round 1 --from founder --type offer \
  --metadata '{"valuation_cap":10000000}'

ssh sshsign.dev history --negotiation-id neg_abc
```

## Key concepts

- **Signing key + authorization**: a per-use-case key gated by typed constraints. Agents can only sign within the authorized range.
- **Co-sign flow**: high-stakes signatures require a human approval step (browser, handwritten signature) before the signing key emits a signature.
- **Signing session**: shared record that groups a multi-party signing ceremony. Has a short shareable code, a member list (each with their APOA pubkey), a lifecycle (`open` → `joined` → `completed`), and a publicly-shareable audit URL on completion that preserves privacy.

## Public audit URLs

Completed signing sessions have a view URL:

```
https://sshsign.dev/audit/<session_id>?token=<view_token>
```

Shareable with lawyers, cap-table software, or any auditor. Shows: timeline,
party roles, DIDs, APOA pubkey fingerprints (not keys), executed artifact URI,
public metadata.

Never exposes: authorized ranges, raw pubkeys, offer-level history.

## Related

- [APOA](https://github.com/agenticpoa/apoa) — Agentic Power of Attorney spec
- [negotiate](https://github.com/agenticpoa/negotiate) — AI agent negotiation protocol, uses signing sessions to coordinate two-party SAFE flows
