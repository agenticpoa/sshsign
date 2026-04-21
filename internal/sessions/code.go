// Package sessions implements multi-party signing session coordination —
// a general-purpose primitive for flows where two or more parties need
// to jointly sign a document after agreeing on terms.
//
// The package is deliberately decoupled from the rest of sshsign: no
// references to pending_signatures, negotiation_offers, or other
// existing tables. Sessions are their own thing, correlated with other
// records only through soft ID references (e.g., pending_signatures's
// signing_session_id column points here informally).
//
// This isolation makes future extraction to a standalone rooms service
// a clean package move if signing_sessions ever grow consumers beyond
// sshsign-gated signatures.
package sessions

import (
	"crypto/rand"
	"fmt"
)

// Alphabet excludes visually-ambiguous characters (0/O, 1/I/L, U/V) to
// keep session_codes robust when read aloud or transcribed by hand.
// 23 characters ≈ 4.5 bits of entropy each; 5 characters gives ~22 bits
// (~4M combinations). With 50 open sessions per DID cap the odds of
// collision on a fresh generate are negligible; we retry on collision
// anyway.
const codeAlphabet = "23456789ABCDEFGHJKMNPQRSTWXYZ"
const codeLength = 5
const codePrefix = "INV-"

// GenerateCode returns a fresh, prefixed, dash-separated alphanumeric
// session code like "INV-7K3X9". Uniqueness is enforced at the repo
// layer via the session_code UNIQUE index and retry-on-conflict.
func GenerateCode() (string, error) {
	buf := make([]byte, codeLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random read: %w", err)
	}
	out := make([]byte, codeLength)
	for i, b := range buf {
		out[i] = codeAlphabet[int(b)%len(codeAlphabet)]
	}
	return codePrefix + string(out), nil
}
