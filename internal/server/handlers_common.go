package server

import (
	"crypto/ed25519"
	"log"

	"github.com/charmbracelet/ssh"

	"github.com/agenticpoa/sshsign/internal/audit"
	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/storage"
)

// decryptSigningKey unwraps the DEK and decrypts the wrapped ed25519
// private key. Same reject contract as requireSigningKey. Callers must
// crypto.ZeroBytes the returned key once they're done with it; the DEK
// is zeroed internally so it never outlives this function.
func decryptSigningKey(sess ssh.Session, sc *SessionContext, sk *storage.SigningKey) (ed25519.PrivateKey, bool) {
	dek, err := sc.KEK.UnwrapDEK(sk.DEKEncrypted, sk.KEKAlgo)
	if err != nil {
		writeJSON(sess, errorResponse{Error: "internal error: key decryption failed"})
		log.Printf("error unwrapping DEK for key %s: %v", sk.KeyID, err)
		return nil, false
	}
	defer apoacrypto.ZeroBytes(dek)

	privKey, err := apoacrypto.DecryptPrivateKey(sk.PrivateKeyEncrypted, dek)
	if err != nil {
		writeJSON(sess, errorResponse{Error: "internal error: key decryption failed"})
		log.Printf("error decrypting private key %s: %v", sk.KeyID, err)
		return nil, false
	}
	return privKey, true
}

// auditDenial emits a DENIED audit entry. Lifted so every handler that
// rejects mid-flow uses the same field set and reason language stays
// consistent across the codebase. Callers still write their own SSH
// response and return after this. The audit write failure is logged
// but not surfaced: a denial that fails to record is strictly less
// dangerous than a missing SIGNED entry.
func auditDenial(sc *SessionContext, userID, signingKeyID, actionType, authTokenID, payloadHash, reason string) {
	_, _ = logAudit(sc.Audit, audit.Entry{
		UserID:             userID,
		SigningKeyID:       signingKeyID,
		ActionType:         actionType,
		AuthorizationToken: authTokenID,
		PayloadHash:        payloadHash,
		Result:             "DENIED",
		DenialReason:       reason,
	})
}
