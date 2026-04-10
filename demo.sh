#!/bin/bash
# APOA + sshsign Demo Script
# Records with asciinema. Run: ./demo.sh
#
# Prerequisites:
#   - asciinema installed (brew install asciinema)
#   - sshsign.dev accessible via SSH
#   - negotiate repo at ../negotiate/ with working setup
#   - pv installed (brew install pv) for simulated typing

set -e

BLUE='\033[1;34m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# Simulated typing effect
type_cmd() {
  echo ""
  printf "${GREEN}\$ ${RESET}"
  echo -n "$1" | pv -qL 30
  echo ""
  sleep 0.5
}

# Commentary text (not a command)
narrate() {
  echo ""
  echo -e "${BLUE}# $1${RESET}"
  sleep 1.5
}

# Section header
scene() {
  echo ""
  echo ""
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${BOLD}  $1${RESET}"
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  sleep 2
}

pause() {
  sleep "${1:-2}"
}

# Run a command with typing effect
run() {
  type_cmd "$1"
  eval "$1"
  pause
}

# ============================================================
# DEMO START
# ============================================================

clear
echo ""
echo -e "${BOLD}  APOA: Agentic Power of Attorney${RESET}"
echo -e "${DIM}  AI agents negotiate. Humans approve. Cryptography proves everything.${RESET}"
echo ""
echo -e "${DIM}  github.com/agenticpoa/apoa${RESET}"
echo -e "${DIM}  github.com/agenticpoa/sshsign${RESET}"
echo -e "${DIM}  github.com/agenticpoa/negotiate${RESET}"
sleep 3

# ============================================================
# SCENE 1: Set boundaries
# ============================================================

scene "Scene 1: Delegate Authority"

narrate "A founder grants their AI agent authority to negotiate SAFEs."
narrate "The constraints ARE the power of attorney - the agent can only agree to terms within these bounds."

run "ssh sshsign.dev create-key --scope safe-agreement --tier cosign --require-signature --constraints '{\"valuation_cap\": {\"min\": 6000000, \"max\": 15000000}, \"discount_rate\": {\"min\": 0.15}, \"pro_rata\": {\"required\": true}}'"

narrate "The agent can negotiate valuation caps between \$6M-\$15M, discount rates above 15%,"
narrate "and pro-rata rights are required. Cosign with handwritten signature means nothing is final"
narrate "without the founder's explicit approval."

pause 3

# ============================================================
# SCENE 2: Agent Negotiation
# ============================================================

scene "Scene 2: AI Agents Negotiate"

narrate "Two Claude agents negotiate a YC SAFE using the Rubinstein alternating offers protocol."
narrate "Every offer is validated against APOA constraints and logged to an immutable audit trail."

pause 1

# Extract the key ID from the previous command's output
# In the actual recording, replace KEY_ID with the real key ID
echo ""
echo -e "${GREEN}\$ ${RESET}cd ../negotiate && python negotiate.py \\"
echo -e "    --founder-token tokens/founder.jwt \\"
echo -e "    --investor-token tokens/investor.jwt \\"
echo -e "    --founder-pubkey keys/founder_public.pem \\"
echo -e "    --investor-pubkey keys/investor_public.pem \\"
echo -e "    --sshsign-host sshsign.dev \\"
echo -e "    --signing-key-id \$KEY_ID \\"
echo -e "    --founder-name \"Juan Figuera\" --founder-title \"CEO\" \\"
echo -e "    --poll"
echo ""
echo -e "${DIM}  [The negotiation runs here - agents go back and forth for ~30 seconds]${RESET}"
echo -e "${DIM}  [Press Enter when ready to continue to the next scene]${RESET}"
read -r

# ============================================================
# SCENE 3: Human Approves with Handwritten Signature
# ============================================================

scene "Scene 3: Human Reviews and Signs"

narrate "The founder's agent reached a deal. Now the founder reviews and approves."
narrate "A unique approval URL was generated - the founder draws their signature in the browser."

echo ""
echo -e "${YELLOW}  The negotiate script outputs an approval URL like:${RESET}"
echo -e "${YELLOW}  https://sshsign.dev/approve/pnd_xxx?token=...${RESET}"
echo ""
echo -e "${DIM}  The founder opens this URL and sees:${RESET}"
echo -e "${DIM}  - The agreed terms (valuation cap, discount rate, pro-rata)${RESET}"
echo -e "${DIM}  - Their authorized range (what they delegated to the agent)${RESET}"
echo -e "${DIM}  - A consent checkbox${RESET}"
echo -e "${DIM}  - A signature canvas${RESET}"
echo ""
echo -e "${DIM}  Drawing the signature IS the approval.${RESET}"
echo -e "${DIM}  The handwritten image is sealed into a tamper-evident evidence envelope,${RESET}"
echo -e "${DIM}  cryptographically signed, and the deal is done.${RESET}"

pause 4

# ============================================================
# SCENE 4: Verify the proof
# ============================================================

scene "Scene 4: Cryptographic Proof"

narrate "Every step is provable. The negotiation history, the approval, the signature -"
narrate "all cryptographically linked in an immutable audit trail."

echo ""
echo -e "${GREEN}\$ ${RESET}ssh sshsign.dev history --negotiation-id \$NEG_ID"
echo ""
echo -e "${DIM}  [Shows the full negotiation chain with immudb transaction IDs]${RESET}"
echo -e "${DIM}  [Each offer references the previous one - tamper-proof chain]${RESET}"
echo ""
pause 2

echo -e "${GREEN}\$ ${RESET}ssh sshsign.dev get-envelope --id \$PENDING_ID"
echo ""
echo -e "${DIM}  [Returns the sealed evidence envelope containing:]${RESET}"
echo -e "${DIM}  - The handwritten signature image (base64 PNG)${RESET}"
echo -e "${DIM}  - Signer identity, IP, timestamp${RESET}"
echo -e "${DIM}  - Document hash and agreed terms${RESET}"
echo -e "${DIM}  - SHA-256 envelope hash bound to the cryptographic signature${RESET}"
echo ""

pause 3

# ============================================================
# SCENE 5: Guardrails
# ============================================================

scene "Scene 5: Guardrails Work"

narrate "What happens when an agent tries to exceed its authority?"

run "echo '{\"valuation_cap\": 3000000}' | ssh sshsign.dev sign --type safe-agreement --metadata '{\"valuation_cap\": 3000000, \"discount_rate\": 0.10, \"pro_rata\": false}'"

narrate "Denied. The agent tried to agree to a \$3M cap (below the \$6M minimum)"
narrate "and 10% discount (below the 15% minimum). The protocol caught it."
narrate "This is logged to the audit trail as a denial."

pause 3

# ============================================================
# CLOSING
# ============================================================

echo ""
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "${BOLD}  APOA: Agentic Power of Attorney${RESET}"
echo ""
echo -e "  AI agents that can negotiate contracts, within boundaries"
echo -e "  you define, with cryptographic proof of everything."
echo ""
echo -e "  ${DIM}Spec:      ${RESET}github.com/agenticpoa/apoa"
echo -e "  ${DIM}Signing:   ${RESET}github.com/agenticpoa/sshsign"
echo -e "  ${DIM}Negotiate: ${RESET}github.com/agenticpoa/negotiate"
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

pause 3
