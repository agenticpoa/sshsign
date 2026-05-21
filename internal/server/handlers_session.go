package server

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/charmbracelet/ssh"

	"github.com/agenticpoa/sshsign/internal/sessions"
	"github.com/agenticpoa/sshsign/internal/storage"
)

func handleGetEnvelope(sess ssh.Session, sc *SessionContext, args []string) {
	var pendingID string
	for i := 0; i < len(args); i++ {
		if args[i] == "--id" && i+1 < len(args) {
			pendingID = args[i+1]
			i++
		}
	}

	if pendingID == "" {
		writeJSON(sess, errorResponse{Error: "missing --id"})
		return
	}

	ps, err := storage.GetPendingSignature(sess.Context(), sc.DB, pendingID)
	if err != nil || ps == nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("pending signature %s not found", pendingID)})
		return
	}

	// Verify the caller owns the pending (is the principal or the requester),
	// OR is a member of the signing session this pending is linked to. The
	// session-member path exists so that during a multi-party signing
	// ceremony, either party can fetch the other's envelope to reconstruct
	// the fully-signed artifact locally. Without this, a two-party SAFE
	// signature only produces an executed PDF for the creator side.
	authToken, _ := storage.GetAuthorization(sess.Context(), sc.DB, ps.AuthTokenID)
	ownsDirectly := authToken != nil &&
		(authToken.GrantedBy == sc.User.UserID || ps.RequesterID == sc.User.UserID)
	if !ownsDirectly {
		ownsViaSession := false
		if ps.SigningSessionID != "" {
			repo := sessions.NewRepo(sc.DB)
			if m, err := repo.IsMember(ps.SigningSessionID, sc.User.UserID); err == nil && m {
				ownsViaSession = true
			}
		}
		if !ownsViaSession {
			writeJSON(sess, errorResponse{Error: "not authorized to access this pending signature"})
			return
		}
	}

	// Build response with status info
	resp := map[string]any{
		"pending_id": ps.ID,
		"status":     ps.Status,
		"key_id":     ps.SigningKeyID,
		"doc_type":   ps.DocType,
	}

	if ps.Signature != "" {
		resp["signature"] = ps.Signature
	}

	// Get the evidence envelope if it exists
	env, _ := storage.GetEvidenceEnvelope(sess.Context(), sc.DB, pendingID)
	if env != nil {
		var envelopeJSON any
		json.Unmarshal(env.Data, &envelopeJSON)
		resp["envelope"] = envelopeJSON
		resp["envelope_hash"] = env.Hash
	}

	writeJSON(sess, resp)
}

// handleSession processes: ssh host session --id session_xxx
// Returns the status of all pending signatures in a signing session.
func handleSession(sess ssh.Session, sc *SessionContext, args []string) {
	var sessionID string
	for i := 0; i < len(args); i++ {
		if args[i] == "--id" && i+1 < len(args) {
			sessionID = args[i+1]
			i++
		}
	}

	if sessionID == "" {
		writeJSON(sess, errorResponse{Error: "missing --id"})
		return
	}

	pendings, err := storage.ListSessionPendings(sess.Context(), sc.DB, sessionID)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("querying session: %v", err)})
		return
	}

	if len(pendings) == 0 {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("session %s not found", sessionID)})
		return
	}

	type signerInfo struct {
		PendingID string `json:"pending_id"`
		Status    string `json:"status"`
		KeyID     string `json:"key_id"`
		Signature string `json:"signature,omitempty"`
	}

	var signers []signerInfo
	allApproved := true
	anyDenied := false

	for _, ps := range pendings {
		si := signerInfo{
			PendingID: ps.ID,
			Status:    ps.Status,
			KeyID:     ps.SigningKeyID,
			Signature: ps.Signature,
		}
		signers = append(signers, si)
		if ps.Status != "approved" {
			allApproved = false
		}
		if ps.Status == "denied" {
			anyDenied = true
		}
	}

	sessionStatus := "pending"
	if allApproved {
		sessionStatus = "complete"
	} else if anyDenied {
		sessionStatus = "failed"
	}

	writeJSON(sess, map[string]any{
		"session_id": sessionID,
		"status":     sessionStatus,
		"signers":    signers,
	})
}

func handleDeny(sess ssh.Session, sc *SessionContext, args []string) {
	var pendingID string
	for i := 0; i < len(args); i++ {
		if args[i] == "--id" && i+1 < len(args) {
			pendingID = args[i+1]
			i++
		}
	}

	if pendingID == "" {
		writeJSON(sess, errorResponse{Error: "missing --id"})
		return
	}

	ps, err := storage.GetPendingSignature(sess.Context(), sc.DB, pendingID)
	if err != nil || ps == nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("pending signature %s not found", pendingID)})
		return
	}

	if ps.Status != "pending" {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("pending signature %s already resolved: %s", pendingID, ps.Status)})
		return
	}

	// Only the principal can deny
	authToken, err := storage.GetAuthorization(sess.Context(), sc.DB, ps.AuthTokenID)
	if err != nil || authToken == nil {
		writeJSON(sess, errorResponse{Error: "authorization not found"})
		return
	}
	if authToken.GrantedBy != sc.User.UserID {
		writeJSON(sess, errorResponse{Error: "only the authorization principal can deny"})
		return
	}

	if err := storage.ResolvePendingSignature(sess.Context(), sc.DB, pendingID, "denied", sc.User.UserID, ""); err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("resolving pending signature: %v", err)})
		return
	}

	auditDenial(sc, sc.User.UserID, ps.SigningKeyID, ps.DocType, ps.AuthTokenID, ps.PayloadHash, "co-sign denied by principal")
	log.Printf("DENIED pending %s by %s", pendingID, sc.User.UserID)
	writeJSON(sess, map[string]string{"status": "denied", "pending_id": pendingID})
}

// handleLogOffer logs a structured negotiation offer to the audit trail.
