package server

import (
	"github.com/charmbracelet/ssh"
	gossh "golang.org/x/crypto/ssh"
)

type contextKey string

const (
	ctxFingerprint contextKey = "fingerprint"
	ctxPublicKey   contextKey = "publickey"
)

// PublicKeyHandler returns a wish public key auth handler that accepts all keys
// and stores identity info in the session context for later use.
// We accept all keys because user creation happens on first connect,
// not at auth time. Rejecting unknown keys would prevent new users from joining.
func PublicKeyHandler() ssh.PublicKeyHandler {
	return func(ctx ssh.Context, key ssh.PublicKey) bool {
		// charmbracelet/ssh.PublicKey wraps x/crypto/ssh.PublicKey
		// We need the x/crypto/ssh functions for fingerprint and marshal
		cryptoKey, err := gossh.ParsePublicKey(key.Marshal())
		if err != nil {
			return false
		}
		fingerprint := gossh.FingerprintSHA256(cryptoKey)
		authorizedKey := gossh.MarshalAuthorizedKey(cryptoKey)
		pubKeyStr := string(authorizedKey[:len(authorizedKey)-1])

		ctx.SetValue(ctxFingerprint, fingerprint)
		ctx.SetValue(ctxPublicKey, pubKeyStr)

		return true
	}
}

func FingerprintFromContext(ctx ssh.Context) string {
	v, _ := ctx.Value(ctxFingerprint).(string)
	return v
}

func PublicKeyFromContext(ctx ssh.Context) string {
	v, _ := ctx.Value(ctxPublicKey).(string)
	return v
}
