package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/charmbracelet/ssh"

	"github.com/agenticpoa/sshsign/internal/audit"
	"github.com/agenticpoa/sshsign/internal/auth"
	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/signing"
	"github.com/agenticpoa/sshsign/internal/storage"
)

// JSON response types for the programmatic interface.

type signResponse struct {
	Signature string `json:"signature"`
	KeyID     string `json:"key_id"`
	TokenID   string `json:"token_id,omitempty"`
	AuditTxID uint64 `json:"audit_tx_id,omitempty"`
}

type verifyResponse struct {
	Valid     bool   `json:"valid"`
	KeyID     string `json:"key_id,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	Error     string `json:"error,omitempty"`
}

type keyResponse struct {
	KeyID     string  `json:"key_id"`
	PublicKey string  `json:"public_key"`
	CreatedAt string  `json:"created_at"`
	RevokedAt *string `json:"revoked_at,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(sess ssh.Session, v any) {
	enc := json.NewEncoder(sess)
	enc.Encode(v)
}

// handleSign processes: ssh sign.agenticpoa.com sign --type git-commit [--key-id ak_xxx]
// Reads payload from stdin, signs it, returns JSON with signature.
func handleSign(sess ssh.Session, sc *SessionContext, args []string) {
	var actionType, keyID, repo, branch string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--type":
			if i+1 < len(args) {
				actionType = args[i+1]
				i++
			}
		case "--key-id":
			if i+1 < len(args) {
				keyID = args[i+1]
				i++
			}
		case "--repo":
			if i+1 < len(args) {
				repo = args[i+1]
				i++
			}
		case "--branch":
			if i+1 < len(args) {
				branch = args[i+1]
				i++
			}
		}
	}

	if actionType == "" {
		actionType = "git-commit"
	}

	// Check server-level rate limit
	if sc.RateLimits != nil && !sc.RateLimits.SigningRequests.Allow(sc.User.UserID) {
		writeJSON(sess, errorResponse{Error: "rate limit exceeded: too many signing requests"})
		return
	}

	// Read payload from stdin
	payload, err := io.ReadAll(sess)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("reading payload: %v", err)})
		return
	}
	if len(payload) == 0 {
		writeJSON(sess, errorResponse{Error: "empty payload"})
		return
	}

	// Find a signing key
	var sk *storage.SigningKey
	if keyID != "" {
		sk, err = storage.GetSigningKey(sc.DB, keyID)
		if err != nil || sk == nil {
			writeJSON(sess, errorResponse{Error: fmt.Sprintf("signing key %s not found", keyID)})
			return
		}
		if sk.OwnerID != sc.User.UserID {
			writeJSON(sess, errorResponse{Error: "signing key does not belong to you"})
			return
		}
	} else {
		// Use first active signing key
		keys, err := storage.ListSigningKeys(sc.DB, sc.User.UserID)
		if err != nil {
			writeJSON(sess, errorResponse{Error: fmt.Sprintf("listing signing keys: %v", err)})
			return
		}
		for _, k := range keys {
			if k.RevokedAt == nil {
				skCopy := k
				sk = &skCopy
				break
			}
		}
		if sk == nil {
			writeJSON(sess, errorResponse{Error: "no active signing keys found"})
			return
		}
	}

	if sk.RevokedAt != nil {
		writeJSON(sess, errorResponse{Error: "signing key is revoked"})
		return
	}

	// Check authorization
	auths, err := storage.FindAuthorizationsForKey(sc.DB, sk.KeyID)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("checking authorization: %v", err)})
		return
	}

	metadata := map[string]string{}
	if repo != "" {
		metadata["repo"] = repo
	}
	if branch != "" {
		metadata["branch"] = branch
	}

	decision := auth.Authorize(auths, auth.SignRequest{
		ActionType: actionType,
		Metadata:   metadata,
	}, time.Now())

	payloadHash := sha256Hash(payload)

	if !decision.Allowed {
		log.Printf("DENIED sign %s for %s key %s: %s", actionType, sc.User.UserID, sk.KeyID, decision.DenialReason)

		// Audit log the denial
		logAudit(sc.Audit, audit.Entry{
			UserID:             sc.User.UserID,
			SigningKeyID:       sk.KeyID,
			ActionType:         actionType,
			PayloadHash:        payloadHash,
			AuthorizationToken: decision.TokenID,
			ScopesChecked:      decision.ScopesChecked,
			RulesEvaluated:     decision.RulesChecked,
			Result:             "DENIED",
			DenialReason:       decision.DenialReason,
		})

		writeJSON(sess, errorResponse{Error: fmt.Sprintf("denied: %s", decision.DenialReason)})
		return
	}

	for _, w := range decision.SoftWarnings {
		log.Printf("SOFT WARNING sign %s for %s key %s: %s", actionType, sc.User.UserID, sk.KeyID, w)
	}

	// Audit logging is synchronous: if unavailable, signing fails
	if sc.Audit != nil && !sc.Audit.Healthy() {
		writeJSON(sess, errorResponse{Error: "audit log unavailable: signing denied for safety"})
		return
	}

	// Decrypt the private key
	dek, err := apoacrypto.UnwrapDEK(sk.DEKEncrypted, sc.KEK)
	if err != nil {
		writeJSON(sess, errorResponse{Error: "internal error: key decryption failed"})
		log.Printf("error unwrapping DEK for key %s: %v", sk.KeyID, err)
		return
	}
	defer apoacrypto.ZeroBytes(dek)

	privKey, err := apoacrypto.DecryptPrivateKey(sk.PrivateKeyEncrypted, dek)
	if err != nil {
		writeJSON(sess, errorResponse{Error: "internal error: key decryption failed"})
		log.Printf("error decrypting private key %s: %v", sk.KeyID, err)
		return
	}
	defer apoacrypto.ZeroBytes(privKey)

	// Sign
	sig, err := signing.Sign(privKey, payload, "git")
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("signing failed: %v", err)})
		return
	}

	// Audit log the successful signing
	auditTxID := logAudit(sc.Audit, audit.Entry{
		UserID:             sc.User.UserID,
		SigningKeyID:       sk.KeyID,
		ActionType:         actionType,
		PayloadHash:        payloadHash,
		AuthorizationToken: decision.TokenID,
		ScopesChecked:      decision.ScopesChecked,
		RulesEvaluated:     decision.RulesChecked,
		Result:             "SIGNED",
		Signature:          string(sig),
	})

	log.Printf("SIGNED %s for %s key %s token %s audit_tx=%d", actionType, sc.User.UserID, sk.KeyID, decision.TokenID, auditTxID)

	writeJSON(sess, signResponse{
		Signature: string(sig),
		KeyID:     sk.KeyID,
		TokenID:   decision.TokenID,
		AuditTxID: auditTxID,
	})
}

// handleVerify processes: ssh sign.agenticpoa.com verify --key-id ak_xxx --signature <base64>
// Reads payload from stdin, verifies against the signing key's public key.
func handleVerify(sess ssh.Session, sc *SessionContext, args []string) {
	var keyID, sigStr string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--key-id":
			if i+1 < len(args) {
				keyID = args[i+1]
				i++
			}
		case "--signature":
			if i+1 < len(args) {
				sigStr = args[i+1]
				i++
			}
		}
	}

	if keyID == "" {
		writeJSON(sess, errorResponse{Error: "missing --key-id"})
		return
	}
	if sigStr == "" {
		writeJSON(sess, errorResponse{Error: "missing --signature"})
		return
	}

	payload, err := io.ReadAll(sess)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("reading payload: %v", err)})
		return
	}

	sk, err := storage.GetSigningKey(sc.DB, keyID)
	if err != nil || sk == nil {
		writeJSON(sess, verifyResponse{Valid: false, Error: fmt.Sprintf("signing key %s not found", keyID)})
		return
	}

	err = signing.Verify([]byte(sigStr), payload, sk.PublicKey, "git")
	if err != nil {
		writeJSON(sess, verifyResponse{Valid: false, KeyID: keyID, Error: err.Error()})
		return
	}

	writeJSON(sess, verifyResponse{Valid: true, KeyID: keyID, PublicKey: sk.PublicKey})
}

// handleKeys processes: ssh sign.agenticpoa.com keys
// Lists all signing keys for the authenticated user.
func handleKeys(sess ssh.Session, sc *SessionContext) {
	keys, err := storage.ListSigningKeys(sc.DB, sc.User.UserID)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("listing keys: %v", err)})
		return
	}

	var resp []keyResponse
	for _, k := range keys {
		kr := keyResponse{
			KeyID:     k.KeyID,
			PublicKey: k.PublicKey,
			CreatedAt: k.CreatedAt.Format(time.RFC3339),
		}
		if k.RevokedAt != nil {
			s := k.RevokedAt.Format(time.RFC3339)
			kr.RevokedAt = &s
		}
		resp = append(resp, kr)
	}

	writeJSON(sess, resp)
}

// handleRevoke processes: ssh sign.agenticpoa.com revoke --key-id ak_xxx
func handleRevoke(sess ssh.Session, sc *SessionContext, args []string) {
	var keyID string

	for i := 0; i < len(args); i++ {
		if args[i] == "--key-id" && i+1 < len(args) {
			keyID = args[i+1]
			i++
		}
	}

	if keyID == "" {
		writeJSON(sess, errorResponse{Error: "missing --key-id"})
		return
	}

	// Verify ownership
	sk, err := storage.GetSigningKey(sc.DB, keyID)
	if err != nil || sk == nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("signing key %s not found", keyID)})
		return
	}
	if sk.OwnerID != sc.User.UserID {
		writeJSON(sess, errorResponse{Error: "signing key does not belong to you"})
		return
	}

	if err := storage.RevokeSigningKey(sc.DB, keyID); err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("revoking key: %v", err)})
		return
	}

	logAudit(sc.Audit, audit.Entry{
		UserID:       sc.User.UserID,
		SigningKeyID: keyID,
		ActionType:   "revoke",
		Result:       "REVOKED",
	})

	log.Printf("REVOKED key %s by user %s", keyID, sc.User.UserID)
	writeJSON(sess, map[string]string{"status": "revoked", "key_id": keyID})
}

// logAudit writes an audit entry. Returns the tx ID, or 0 if logging fails/is nil.
func logAudit(logger audit.Logger, entry audit.Entry) uint64 {
	if logger == nil {
		return 0
	}
	txID, err := logger.Log(entry)
	if err != nil {
		log.Printf("audit log error: %v", err)
		return 0
	}
	return txID
}

func sha256Hash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
