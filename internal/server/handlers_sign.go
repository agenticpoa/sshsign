package server

import (
	"crypto/rand"
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

// handleSign processes: ssh sign.agenticpoa.com sign --type git-commit [--key-id ak_xxx]
// Reads payload from stdin, signs it, returns JSON with signature.
func handleSign(sess ssh.Session, sc *SessionContext, args []string) {
	var actionType, keyID, repo, branch, metadataJSON, sessionID string

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
		case "--session-id":
			if i+1 < len(args) {
				sessionID = args[i+1]
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
		case "--metadata":
			if i+1 < len(args) {
				i++
				metadataJSON = parseJSONArg(args, &i)
			}
		case "--metadata-b64":
			if i+1 < len(args) {
				i++
				decoded, err := decodeB64JSON(args[i])
				if err != nil {
					writeJSON(sess, errorResponse{Error: fmt.Sprintf("--metadata-b64: %v", err)})
					return
				}
				metadataJSON = decoded
			}
		}
	}

	if actionType == "" {
		actionType = "git-commit"
	}

	// Check server-level rate limit
	if sc.RateLimits != nil && sc.RateLimits.SigningRequests.Allow(sc.User.UserID) != nil {
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
		sk, err = storage.GetSigningKey(sess.Context(), sc.DB, keyID)
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
		keys, err := storage.ListSigningKeys(sess.Context(), sc.DB, sc.User.UserID)
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
	auths, err := storage.FindAuthorizationsForKey(sess.Context(), sc.DB, sk.KeyID)
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

	var requestMetadata json.RawMessage
	if metadataJSON != "" {
		requestMetadata = json.RawMessage(metadataJSON)
	}

	decision := auth.Authorize(auths, auth.SignRequest{
		ActionType:      actionType,
		Metadata:        metadata,
		RequestMetadata: requestMetadata,
	}, time.Now())

	payloadHash := sha256Hash(payload)

	if !decision.Allowed {
		log.Printf("DENIED sign %s for %s key %s: %s", actionType, sc.User.UserID, sk.KeyID, decision.DenialReason)

		// Audit log the denial. Same posture as auditDenial: log
		// failures locally but don't override the denial response.
		_, _ = logAudit(sc.Audit, audit.Entry{
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

	// Co-sign flow: if confirmation tier is "cosign", hold the request
	if decision.ConfirmationTier == "cosign" {
		var approvalToken string
		if decision.RequireSignature {
			tokenBytes := make([]byte, 32)
			if _, err := rand.Read(tokenBytes); err != nil {
				writeJSON(sess, errorResponse{Error: "generating approval token"})
				return
			}
			approvalToken = hex.EncodeToString(tokenBytes)
		}

		// Persist only the verifier hash; the raw token is returned once,
		// below, in the approval URL, then never recoverable from the DB.
		// pendingMAC binds the row's signing-intent fields so a DB
		// tamper between sign-request and approval is detected at the
		// approval handler.
		pendingMAC := sc.KEK.ComputePendingMAC(apoacrypto.PendingBinding{
			SigningKeyID: sk.KeyID,
			AuthTokenID:  decision.TokenID,
			RequesterID:  sc.User.UserID,
			DocType:      actionType,
			PayloadHash:  payloadHash,
			Metadata:     metadataJSON,
		})
		ps, err := storage.CreatePendingSignature(
			sess.Context(),
			sc.DB, sk.KeyID, decision.TokenID, sc.User.UserID,
			actionType, payloadHash, metadataJSON,
			apoacrypto.HashApprovalToken(approvalToken), sessionID,
			pendingMAC,
		)
		if err != nil {
			writeJSON(sess, errorResponse{Error: fmt.Sprintf("creating pending signature: %v", err)})
			return
		}

		log.Printf("PENDING_COSIGN %s for %s key %s pending_id=%s require_sig=%v", actionType, sc.User.UserID, sk.KeyID, ps.ID, decision.RequireSignature)

		resp := pendingSignResponse{
			Status:           "pending_cosign",
			PendingID:        ps.ID,
			SigningSessionID: sessionID,
		}
		if decision.RequireSignature {
			resp.RequiresSignature = true
			resp.ApprovalURL = fmt.Sprintf("https://%s/approve/%s?token=%s", approvalDomain(sc), ps.ID, approvalToken)
		}
		writeJSON(sess, resp)
		return
	}

	// Audit logging is synchronous: if unavailable, signing fails
	if sc.Audit != nil && !sc.Audit.Healthy() {
		writeJSON(sess, errorResponse{Error: "audit log unavailable: signing denied for safety"})
		return
	}

	privKey, ok := decryptSigningKey(sess, sc, sk)
	if !ok {
		return
	}
	defer apoacrypto.ZeroBytes(privKey)

	// Sign
	sig, err := signing.Sign(privKey, payload, "git")
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("signing failed: %v", err)})
		return
	}

	// Audit log the successful signing. We already gated on
	// sc.Audit.Healthy() above, so a write failure here is transient
	// — log and proceed rather than fail the user's signature.
	auditTxID, _ := logAudit(sc.Audit, audit.Entry{
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
	storage.RecordKeyUsage(sess.Context(), sc.DB, sk.KeyID)

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

	sk, err := storage.GetSigningKey(sess.Context(), sc.DB, keyID)
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
