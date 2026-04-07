package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"regexp"
	"time"

	"github.com/charmbracelet/ssh"

	"github.com/agenticpoa/sshsign/internal/audit"
	"github.com/agenticpoa/sshsign/internal/auth"
	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/signing"
	"github.com/agenticpoa/sshsign/internal/storage"
)

// bareKeyRe matches unquoted JSON keys like {foo: or ,bar:
var bareKeyRe = regexp.MustCompile(`([{,])\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:`)

// parseJSONArg extracts a JSON value from args starting at args[*idx].
// SSH strips inner double quotes, so {foo:1} arrives instead of {"foo":1}.
// This function tries fixing bare keys first. If the JSON contains spaces,
// it rejoins subsequent args, but only if they don't look like flags.
func parseJSONArg(args []string, idx *int) string {
	raw := args[*idx]

	// Try as-is first
	if json.Valid([]byte(raw)) {
		return raw
	}

	// Try fixing bare keys (SSH stripped double quotes)
	fixed := fixBareJSONKeys(raw)
	if json.Valid([]byte(fixed)) {
		return fixed
	}

	// Rejoin subsequent args that aren't flags, in case JSON had spaces
	for *idx+1 < len(args) && !isFlag(args[*idx+1]) {
		*idx++
		raw += " " + args[*idx]
	}

	if json.Valid([]byte(raw)) {
		return raw
	}

	return fixBareJSONKeys(raw)
}

func isFlag(s string) bool {
	return len(s) >= 2 && s[0] == '-' && s[1] == '-'
}

// fixBareJSONKeys adds double quotes around unquoted JSON object keys.
// SSH command parsing strips inner double quotes, so {"key":1} arrives as {key:1}.
func fixBareJSONKeys(s string) string {
	return bareKeyRe.ReplaceAllString(s, `$1"$2":`)
}

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

type createKeyResponse struct {
	KeyID       string                       `json:"key_id"`
	PublicKey   string                       `json:"public_key"`
	TokenID     string                       `json:"token_id"`
	Scope       string                       `json:"scope"`
	Tier        string                       `json:"tier"`
	Constraints []storage.MetadataConstraint `json:"constraints,omitempty"`
	ExpiresAt   string                       `json:"expires_at"`
}

type pendingSignResponse struct {
	Status            string `json:"status"`
	PendingID         string `json:"pending_id"`
	RequiresSignature bool   `json:"requires_signature,omitempty"`
	ApprovalURL       string `json:"approval_url,omitempty"`
	SigningSessionID  string `json:"signing_session_id,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func approvalDomain(sc *SessionContext) string {
	if sc.HTTPDomain != "" {
		return sc.HTTPDomain
	}
	return "sshsign.dev"
}

func writeJSON(sess ssh.Session, v any) {
	enc := json.NewEncoder(sess)
	enc.Encode(v)
}

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

		ps, err := storage.CreatePendingSignature(
			sc.DB, sk.KeyID, decision.TokenID, sc.User.UserID,
			actionType, payloadHash, metadataJSON, approvalToken, sessionID,
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
	storage.RecordKeyUsage(sc.DB, sk.KeyID)

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

// handleCreateKey processes: ssh host create-key --scope <scope> [--tier autonomous|cosign] [--expiry 30] [--constraints '{...}']
// Generates a new signing key and authorization in one step.
func handleCreateKey(sess ssh.Session, sc *SessionContext, args []string) {
	var scope, tier, constraintsJSON string
	var requireSignature bool
	expiryDays := 30

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--scope":
			if i+1 < len(args) {
				i++
				scope = args[i]
			}
		case "--tier":
			if i+1 < len(args) {
				i++
				tier = args[i]
			}
		case "--require-signature":
			requireSignature = true
		case "--expiry":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &expiryDays)
			}
		case "--constraints":
			if i+1 < len(args) {
				i++
				constraintsJSON = parseJSONArg(args, &i)
			}
		}
	}

	if scope == "" {
		writeJSON(sess, errorResponse{Error: "missing required --scope flag"})
		return
	}
	if tier == "" {
		tier = "autonomous"
	}
	if tier != "autonomous" && tier != "cosign" {
		writeJSON(sess, errorResponse{Error: "tier must be 'autonomous' or 'cosign'"})
		return
	}

	// Parse constraints JSON into metadata constraints.
	// Format: {"field_name": {"min": N, "max": N, "allowed": [...], "required": bool}}
	var metaConstraints []storage.MetadataConstraint
	if constraintsJSON != "" {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(constraintsJSON), &raw); err != nil {
			writeJSON(sess, errorResponse{Error: fmt.Sprintf("invalid constraints JSON: %v", err)})
			return
		}
		for field, data := range raw {
			var parsed struct {
				Min      *float64 `json:"min"`
				Max      *float64 `json:"max"`
				Allowed  []string `json:"allowed"`
				Required *bool    `json:"required"`
			}
			if err := json.Unmarshal(data, &parsed); err != nil {
				writeJSON(sess, errorResponse{Error: fmt.Sprintf("invalid constraint for field '%s': %v", field, err)})
				return
			}
			mc := storage.MetadataConstraint{Field: field}
			switch {
			case parsed.Min != nil && parsed.Max != nil:
				mc.Type = "range"
				mc.Min = parsed.Min
				mc.Max = parsed.Max
			case parsed.Min != nil:
				mc.Type = "minimum"
				mc.Min = parsed.Min
			case parsed.Max != nil:
				mc.Type = "maximum"
				mc.Max = parsed.Max
			case len(parsed.Allowed) > 0:
				mc.Type = "enum"
				mc.Allowed = parsed.Allowed
			case parsed.Required != nil:
				mc.Type = "required_bool"
				mc.Required = parsed.Required
			default:
				writeJSON(sess, errorResponse{Error: fmt.Sprintf("constraint for '%s' must have min, max, allowed, or required", field)})
				return
			}
			metaConstraints = append(metaConstraints, mc)
		}
	}

	// Generate signing key
	pub, priv, err := apoacrypto.GenerateEd25519Keypair()
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("generating keypair: %v", err)})
		return
	}

	pubSSH, err := apoacrypto.MarshalPublicKeySSH(pub)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("marshaling public key: %v", err)})
		return
	}

	dek, err := apoacrypto.GenerateDEK()
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("generating DEK: %v", err)})
		return
	}
	defer apoacrypto.ZeroBytes(dek)

	encPrivKey, err := apoacrypto.EncryptPrivateKey(priv, dek)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("encrypting key: %v", err)})
		return
	}
	apoacrypto.ZeroBytes(priv)

	wrappedDEK, err := apoacrypto.WrapDEK(dek, sc.KEK)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("wrapping DEK: %v", err)})
		return
	}

	// Persist key
	sk, err := storage.CreateSigningKey(sc.DB, sc.User.UserID, pubSSH, encPrivKey, wrappedDEK)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("storing key: %v", err)})
		return
	}

	// Create authorization
	expires := time.Now().AddDate(0, 0, expiryDays)
	authorization, err := storage.CreateAuthorizationFull(
		sc.DB, sk.KeyID, sc.User.UserID,
		[]string{scope}, nil, metaConstraints, tier, requireSignature,
		nil, nil, &expires,
	)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("creating authorization: %v", err)})
		return
	}

	writeJSON(sess, createKeyResponse{
		KeyID:       sk.KeyID,
		PublicKey:   sk.PublicKey,
		TokenID:     authorization.TokenID,
		Scope:       scope,
		Tier:        tier,
		Constraints: metaConstraints,
		ExpiresAt:   expires.Format(time.RFC3339),
	})
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

// handlePending lists pending signatures for the current user (as principal).
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

	ps, err := storage.GetPendingSignature(sc.DB, pendingID)
	if err != nil || ps == nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("pending signature %s not found", pendingID)})
		return
	}

	if ps.Status != "pending" {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("pending signature %s already resolved: %s", pendingID, ps.Status)})
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
			url := fmt.Sprintf("https://%s/approve/%s?token=%s", approvalDomain(sc), ps.ID, ps.ApprovalToken)
			writeJSON(sess, errorResponse{Error: fmt.Sprintf("this approval requires a handwritten signature: %s", url)})
			return
		}
	}

	// Audit logging is synchronous: if unavailable, signing fails
	if sc.Audit != nil && !sc.Audit.Healthy() {
		writeJSON(sess, errorResponse{Error: "audit log unavailable: signing denied for safety"})
		return
	}

	// Decrypt and sign
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

	ps, err := storage.GetPendingSignature(sc.DB, pendingID)
	if err != nil || ps == nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("pending signature %s not found", pendingID)})
		return
	}

	// Verify the caller owns the pending (is the principal or the requester)
	authToken, _ := storage.GetAuthorization(sc.DB, ps.AuthTokenID)
	if authToken == nil || (authToken.GrantedBy != sc.User.UserID && ps.RequesterID != sc.User.UserID) {
		writeJSON(sess, errorResponse{Error: "not authorized to access this pending signature"})
		return
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
	env, _ := storage.GetEvidenceEnvelope(sc.DB, pendingID)
	if env != nil {
		var envelopeJSON any
		json.Unmarshal(env.Data, &envelopeJSON)
		resp["envelope"] = envelopeJSON
		resp["envelope_hash"] = env.Hash
	}

	writeJSON(sess, resp)
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

	ps, err := storage.GetPendingSignature(sc.DB, pendingID)
	if err != nil || ps == nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("pending signature %s not found", pendingID)})
		return
	}

	if ps.Status != "pending" {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("pending signature %s already resolved: %s", pendingID, ps.Status)})
		return
	}

	// Only the principal can deny
	authToken, err := storage.GetAuthorization(sc.DB, ps.AuthTokenID)
	if err != nil || authToken == nil {
		writeJSON(sess, errorResponse{Error: "authorization not found"})
		return
	}
	if authToken.GrantedBy != sc.User.UserID {
		writeJSON(sess, errorResponse{Error: "only the authorization principal can deny"})
		return
	}

	if err := storage.ResolvePendingSignature(sc.DB, pendingID, "denied", sc.User.UserID, ""); err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("resolving pending signature: %v", err)})
		return
	}

	logAudit(sc.Audit, audit.Entry{
		UserID:             sc.User.UserID,
		SigningKeyID:       ps.SigningKeyID,
		ActionType:         ps.DocType,
		PayloadHash:        ps.PayloadHash,
		AuthorizationToken: ps.AuthTokenID,
		Result:             "DENIED",
		DenialReason:       "co-sign denied by principal",
	})

	log.Printf("DENIED pending %s by %s", pendingID, sc.User.UserID)
	writeJSON(sess, map[string]string{"status": "denied", "pending_id": pendingID})
}

// handleLogOffer logs a structured negotiation offer to the audit trail.
func handleLogOffer(sess ssh.Session, sc *SessionContext, args []string) {
	var negotiationID, fromParty, offerType, metadata string
	var round int
	var previousTx uint64

	for i := 0; i < len(args); i++ {
		if i+1 >= len(args) {
			break
		}
		switch args[i] {
		case "--negotiation-id":
			negotiationID = args[i+1]
			i++
		case "--round":
			fmt.Sscanf(args[i+1], "%d", &round)
			i++
		case "--from":
			fromParty = args[i+1]
			i++
		case "--type":
			offerType = args[i+1]
			i++
		case "--metadata":
			i++
			metadata = parseJSONArg(args, &i)
		case "--previous-tx":
			fmt.Sscanf(args[i+1], "%d", &previousTx)
			i++
		}
	}

	if negotiationID == "" {
		writeJSON(sess, errorResponse{Error: "missing --negotiation-id"})
		return
	}
	if fromParty == "" {
		writeJSON(sess, errorResponse{Error: "missing --from"})
		return
	}
	if offerType == "" {
		writeJSON(sess, errorResponse{Error: "missing --type"})
		return
	}

	// Turn validation: parties must alternate
	lastOffer, err := storage.GetLastOffer(sc.DB, negotiationID)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("checking turn order: %v", err)})
		return
	}
	if lastOffer != nil && lastOffer.FromParty == fromParty {
		writeJSON(sess, errorResponse{Error: "not your turn"})
		return
	}

	// If previous_tx > 0, verify it exists
	if previousTx > 0 {
		prev, err := storage.FindOfferByAuditTx(sc.DB, previousTx)
		if err != nil {
			writeJSON(sess, errorResponse{Error: fmt.Sprintf("checking previous tx: %v", err)})
			return
		}
		if prev == nil {
			writeJSON(sess, errorResponse{Error: fmt.Sprintf("previous_tx %d not found", previousTx)})
			return
		}
	}

	// Log to audit trail
	auditTxID := logAudit(sc.Audit, audit.Entry{
		UserID:     sc.User.UserID,
		ActionType: "negotiation-offer",
		Result:     "LOGGED",
	})

	// Store the offer
	offer, err := storage.CreateNegotiationOffer(
		sc.DB, negotiationID, round, fromParty, offerType,
		metadata, previousTx, auditTxID, sc.User.UserID,
	)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("creating offer: %v", err)})
		return
	}

	log.Printf("OFFER %s round=%d from=%s type=%s audit_tx=%d", negotiationID, round, fromParty, offerType, auditTxID)

	writeJSON(sess, map[string]any{
		"immudb_tx":      auditTxID,
		"negotiation_id": offer.NegotiationID,
		"round":          offer.Round,
		"offer_id":       offer.ID,
	})
}

// handleHistory returns all offers in a negotiation chain.
func handleHistory(sess ssh.Session, sc *SessionContext, args []string) {
	var negotiationID string
	for i := 0; i < len(args); i++ {
		if args[i] == "--negotiation-id" && i+1 < len(args) {
			negotiationID = args[i+1]
			i++
		}
	}

	if negotiationID == "" {
		writeJSON(sess, errorResponse{Error: "missing --negotiation-id"})
		return
	}

	offers, err := storage.ListNegotiationOffers(sc.DB, negotiationID)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("listing offers: %v", err)})
		return
	}

	type offerResponse struct {
		Round      int    `json:"round"`
		From       string `json:"from"`
		Type       string `json:"type"`
		Metadata   string `json:"metadata,omitempty"`
		PreviousTx uint64 `json:"previous_tx"`
		AuditTxID  uint64 `json:"audit_tx_id"`
		CreatedAt  string `json:"created_at"`
	}

	var resp []offerResponse
	for _, o := range offers {
		resp = append(resp, offerResponse{
			Round:      o.Round,
			From:       o.FromParty,
			Type:       o.OfferType,
			Metadata:   o.Metadata,
			PreviousTx: o.PreviousTx,
			AuditTxID:  o.AuditTxID,
			CreatedAt:  o.CreatedAt.Format(time.RFC3339),
		})
	}

	writeJSON(sess, resp)
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
