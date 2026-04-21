#!/usr/bin/env bash
#
# counter-sign-nda.sh — a minimal, runnable demo of multi-party signing
# sessions in sshsign. Two parties create a session, join it, each sign
# an NDA payload, and the creator marks the session complete.
#
# This script is deliberately plain. No APOA token minting, no real
# NDA PDF generation — the point is to show the sshsign primitives
# in isolation so you can see the shape of a multi-party flow.
#
# Requirements:
#   - `ssh sshsign.dev` works (SSH key registered)
#   - `jq` installed (for JSON extraction)
#   - Two SSH identities set up: alice's key and bob's key
#     (e.g., IdentityFile blocks in ~/.ssh/config for aliases
#      sshsign-alice and sshsign-bob pointing at sshsign.dev)
#
# Usage:
#   ./counter-sign-nda.sh

set -euo pipefail

ALICE_HOST="${ALICE_HOST:-sshsign-alice}"
BOB_HOST="${BOB_HOST:-sshsign-bob}"

SESSION_ID="nda_$(date +%Y%m%d)_$(openssl rand -hex 4)"
ALICE_PUB="-----BEGIN APOA-----\nALICEPUBKEYDEMO\n-----END APOA-----"
BOB_PUB="-----BEGIN APOA-----\nBOBPUBKEYDEMO\n-----END APOA-----"

echo "== 1. Alice creates the signing session =="
RESPONSE=$(ssh "$ALICE_HOST" create-session \
  --session-id "$SESSION_ID" \
  --role party_a \
  --apoa-pubkey "$ALICE_PUB" \
  --metadata-public '{"use_case":"nda","version":1}' \
  --metadata-member '{"doc":"Mutual NDA — Acme and Bay Capital"}')

CODE=$(echo "$RESPONSE" | jq -r .session_code)
echo "   → session_code: $CODE"
echo "   → session_id:   $SESSION_ID"
echo

echo "== 2. Bob joins using the code =="
ssh "$BOB_HOST" join-session \
  --session-code "$CODE" \
  --role party_b \
  --apoa-pubkey "$BOB_PUB" \
  | jq '{status, members: .members | map({role, user_id})}'
echo

echo "== 3. Check current state (Alice's view — includes metadata_member) =="
ssh "$ALICE_HOST" get-session --session-code "$CODE" \
  | jq '{status, metadata_member, members: .members | map(.role)}'
echo

echo "== 4. Check non-member view — metadata_member is hidden =="
echo "   (skipped in this script; run from a third SSH identity to see the difference)"
echo

echo "== 5. Both parties would run sign commands here =="
echo "   (omitted — use the existing sign/approve flow; set --session-id=$SESSION_ID"
echo "    on each pending_signatures so they correlate back to this session)"
echo

echo "== 6. Alice completes the session (creator-only) =="
ssh "$ALICE_HOST" complete-session \
  --session-id "$SESSION_ID" \
  --executed-artifact "sshsign://artifact/${SESSION_ID}.pdf" \
  | jq '{status, view_token, executed_artifact}'
echo

echo "== 7. Fetch the append-only audit timeline =="
ssh "$ALICE_HOST" audit-session --session-id "$SESSION_ID" \
  | jq 'map({event_type, actor_id, created_at})'
echo

echo "Done. The public audit URL is:"
VIEW_TOKEN=$(ssh "$ALICE_HOST" get-session --session-id "$SESSION_ID" | jq -r .view_token)
echo "  https://sshsign.dev/audit/$SESSION_ID?token=$VIEW_TOKEN"
echo
echo "Anyone with that URL can see the timeline, parties, and executed artifact —"
echo "but neither party's authorized ranges or private metadata."
