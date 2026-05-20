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
// 29 characters ≈ 4.86 bits per char; 6 characters yields ~29 bits
// (~590M combinations) — comfortably out of brute-force range under
// the per-user rate limit on get-session, and still readable aloud.
const codeAlphabet = "23456789ABCDEFGHJKMNPQRSTWXYZ"
const codeLength = 6
const codePrefix = "INV-"

// codeRejectThreshold is the largest multiple of len(codeAlphabet) that
// fits in a byte. Random bytes ≥ this value are rejected so the modulo
// mapping is uniform — without rejection sampling, byte values in
// [0, 256 % 29) would map to a slightly higher probability bucket than
// the rest, biasing toward the start of the alphabet by ~8%.
const codeRejectThreshold = 256 - (256 % len(codeAlphabet))

// GenerateCode returns a fresh, prefixed, dash-separated alphanumeric
// session code like "INV-7K3X9F". Uniqueness is enforced at the repo
// layer via the session_code UNIQUE index and retry-on-conflict.
func GenerateCode() (string, error) {
	out := make([]byte, codeLength)
	var b [1]byte
	for i := 0; i < codeLength; i++ {
		for {
			if _, err := rand.Read(b[:]); err != nil {
				return "", fmt.Errorf("random read: %w", err)
			}
			if int(b[0]) < codeRejectThreshold {
				out[i] = codeAlphabet[int(b[0])%len(codeAlphabet)]
				break
			}
			// b[0] fell in the bias zone; reject and re-roll. The
			// expected rejection rate is (256 mod 29) / 256 ≈ 3%.
		}
	}
	return codePrefix + string(out), nil
}
