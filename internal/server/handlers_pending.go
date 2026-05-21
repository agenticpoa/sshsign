package server

import (
	"fmt"
	"log"
	"time"

	"github.com/charmbracelet/ssh"

	"github.com/agenticpoa/sshsign/internal/audit"
	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/signing"
	"github.com/agenticpoa/sshsign/internal/storage"
)

func handlePending(sess ssh.Session, sc *SessionContext) {
	pending, err := storage.ListPendingSignatures(sc.DB, sc.User.UserID)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("listing pending signatures: %v", err)})
		return
	}

	type pendingResponse struct {
		ID           string `json:"id"`
		SigningKeyID string `json:"signing_key_id"`
		DocType      string `json:"doc_type"`
		PayloadHash  string `json:"payload_hash"`
		Metadata     string `json:"metadata,omitempty"`
		CreatedAt    string `json:"created_at"`
	}

	var resp []pendingResponse
	for _, ps := range pending {
		resp = append(resp, pendingResponse{
			ID:           ps.ID,
			SigningKeyID: ps.SigningKeyID,
			DocType:      ps.DocType,
			PayloadHash:  ps.PayloadHash,
			Metadata:     ps.Metadata,
			CreatedAt:    ps.CreatedAt.Format(time.RFC3339),
		})
	}

	writeJSON(sess, resp)
}

// handleApprove approves a pending signature, re-validates authorization, and signs.
func handleApprove(sess ssh.Session, sc *SessionContext, args []string) {
	var pendingID string
	var confirmed bool
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--id":
			if i+1 < len(args) {
				pendingID = args[i+1]
				i++
			}
		case "--confirm":
			confirmed = true
		}
	}

	if pendingID == "" {
		writeJSON(sess, errorResponse{Error: "missing --id"})
		return
	}

	ps, err := storage.GetPendingSignature(sc.DB, pendingID)
	if err != nil || ps == nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("pending signature %s not found", pendingID)})
		return
	}

	if ps.Status != "pending" {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("pending signature %s already resolved: %s", pendingID, ps.Status)})
		return
	}

	// Tamper detection: refuse to sign if the row's bound fields no
	// longer match the MAC computed at sign-request time. Catches DB
	// tamper that swapped the payload hash or metadata between request
	// and approval.
	if !sc.KEK.VerifyPendingMAC(pendingBindingFor(ps), ps.PendingMAC) {
		log.Printf("PENDING_MAC_MISMATCH pending_id=%s requester=%s", ps.ID, ps.RequesterID)
		auditDenial(sc, sc.User.UserID, ps.SigningKeyID, ps.DocType, ps.AuthTokenID, ps.PayloadHash, "pending row tamper detected (MAC mismatch)")
		writeJSON(sess, errorResponse{Error: "pending signature integrity check failed; refusing to sign"})
		return
	}

	// Only the principal (authorization granter) can approve
	authToken, err := storage.GetAuthorization(sc.DB, ps.AuthTokenID)
	if err != nil || authToken == nil {
		writeJSON(sess, errorResponse{Error: "authorization not found"})
		return
	}
	if authToken.GrantedBy != sc.User.UserID {
		writeJSON(sess, errorResponse{Error: "only the authorization principal can approve"})
		return
	}

	// Re-validate authorization: check it hasn't been revoked or expired (race condition defense)
	if authToken.RevokedAt != nil {
		writeJSON(sess, errorResponse{Error: "authorization has been revoked since the request was submitted"})
		return
	}
	if authToken.ExpiresAt != nil && time.Now().After(*authToken.ExpiresAt) {
		writeJSON(sess, errorResponse{Error: "authorization has expired since the request was submitted"})
		return
	}

	// Check signing key hasn't been revoked
	sk, err := storage.GetSigningKey(sc.DB, ps.SigningKeyID)
	if err != nil || sk == nil {
		writeJSON(sess, errorResponse{Error: "signing key not found"})
		return
	}
	if sk.RevokedAt != nil {
		writeJSON(sess, errorResponse{Error: "signing key has been revoked since the request was submitted"})
		return
	}

	// If require_signature is set, check for evidence envelope (web approval)
	if authToken.RequireSignature {
		env, _ := storage.GetEvidenceEnvelope(sc.DB, pendingID)
		if env == nil {
			writeJSON(sess, errorResponse{Error: "this approval requires a handwritten signature: open the approval URL returned at sign time"})
			return
		}
	}

	// Require explicit consent for CLI approvals
	if !confirmed {
		writeJSON(sess, map[string]any{
			"consent_required": true,
			"pending_id":       ps.ID,
			"doc_type":         ps.DocType,
			"metadata":         ps.Metadata,
			"disclosure": "By approving, you confirm: (1) you have reviewed the terms, " +
				"(2) your approval is legally binding as an electronic signature under the ESIGN Act " +
				"(15 U.S.C. 7001), and (3) a tamper-evident record will be created. " +
				"Re-run with --confirm to approve.",
		})
		return
	}

	// Audit logging is synchronous: if unavailable, signing fails
	if sc.Audit != nil && !sc.Audit.Healthy() {
		writeJSON(sess, errorResponse{Error: "audit log unavailable: signing denied for safety"})
		return
	}

	// Decrypt and sign
	privKey, ok := decryptSigningKey(sess, sc, sk)
	if !ok {
		return
	}
	defer apoacrypto.ZeroBytes(privKey)

	// Sign using the payload hash as the payload (the original payload isn't stored)
	sig, err := signing.Sign(privKey, []byte(ps.PayloadHash), ps.DocType)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("signing failed: %v", err)})
		return
	}

	// Mark as approved and persist signature
	if err := storage.ResolvePendingSignature(sc.DB, pendingID, "approved", sc.User.UserID, string(sig)); err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("resolving pending signature: %v", err)})
		return
	}

	// Audit log the approval
	auditTxID := logAudit(sc.Audit, audit.Entry{
		UserID:             sc.User.UserID,
		SigningKeyID:       sk.KeyID,
		ActionType:         ps.DocType,
		PayloadHash:        ps.PayloadHash,
		AuthorizationToken: ps.AuthTokenID,
		Result:             "SIGNED",
		Signature:          string(sig),
	})
	storage.RecordKeyUsage(sc.DB, sk.KeyID)

	log.Printf("APPROVED pending %s by %s, signed with key %s audit_tx=%d", pendingID, sc.User.UserID, sk.KeyID, auditTxID)

	writeJSON(sess, signResponse{
		Signature: string(sig),
		KeyID:     sk.KeyID,
		TokenID:   ps.AuthTokenID,
		AuditTxID: auditTxID,
	})
}

// handleDeny denies a pending signature and logs the denial.
// handleGetEnvelope processes: ssh host get-envelope --id pnd_xxx
// Returns the sealed evidence envelope with the handwritten signature image.
