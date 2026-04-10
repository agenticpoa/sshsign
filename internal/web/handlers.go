package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/evidence"
	"github.com/agenticpoa/sshsign/internal/signing"
	"github.com/agenticpoa/sshsign/internal/storage"
)

var pendingIDPattern = regexp.MustCompile(`^pnd_[0-9a-f]{12}$`)

const (
	maxImageSize       = 500 * 1024      // 500KB
	approvalTokenTTL   = 15 * time.Minute // approval URLs expire after 15 minutes
)

// handleGetApproval renders the signature capture page.
func (s *Server) handleGetApproval(w http.ResponseWriter, r *http.Request) {
	pendingID := r.PathValue("pendingID")
	token := r.URL.Query().Get("token")

	if !pendingIDPattern.MatchString(pendingID) {
		http.Error(w, "invalid pending ID", http.StatusBadRequest)
		return
	}

	ps, err := storage.GetPendingSignature(s.db, pendingID)
	if err != nil || ps == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if ps.ApprovalToken == "" || ps.ApprovalToken != token {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if time.Since(ps.CreatedAt) > approvalTokenTTL {
		http.Error(w, "this approval link has expired", http.StatusGone)
		return
	}

	if ps.Status != "pending" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, approvalAlreadyDonePage(ps.Status))
		return
	}

	// Check authorization is still valid
	auth, _ := storage.GetAuthorization(s.db, ps.AuthTokenID)
	if auth == nil || auth.RevokedAt != nil || (auth.ExpiresAt != nil && time.Now().After(*auth.ExpiresAt)) {
		http.Error(w, "authorization expired or revoked", http.StatusGone)
		return
	}

	// Check key is still valid
	sk, _ := storage.GetSigningKey(s.db, ps.SigningKeyID)
	if sk == nil || sk.RevokedAt != nil {
		http.Error(w, "signing key revoked", http.StatusGone)
		return
	}

	// Build the page with document details
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, approvalPage(ps, auth))
}

// handlePostApproval processes the drawn signature and completes the approval.
func (s *Server) handlePostApproval(w http.ResponseWriter, r *http.Request) {
	pendingID := r.PathValue("pendingID")
	token := r.URL.Query().Get("token")

	if !pendingIDPattern.MatchString(pendingID) {
		http.Error(w, `{"error":"invalid pending ID"}`, http.StatusBadRequest)
		return
	}

	ps, err := storage.GetPendingSignature(s.db, pendingID)
	if err != nil || ps == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	if ps.ApprovalToken == "" || ps.ApprovalToken != token {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}

	if time.Since(ps.CreatedAt) > approvalTokenTTL {
		http.Error(w, `{"error":"approval link expired"}`, http.StatusGone)
		return
	}

	if ps.Status != "pending" {
		http.Error(w, `{"error":"already resolved"}`, http.StatusConflict)
		return
	}

	// Re-validate authorization and key
	auth, _ := storage.GetAuthorization(s.db, ps.AuthTokenID)
	if auth == nil || auth.RevokedAt != nil || (auth.ExpiresAt != nil && time.Now().After(*auth.ExpiresAt)) {
		http.Error(w, `{"error":"authorization expired or revoked"}`, http.StatusGone)
		return
	}

	sk, _ := storage.GetSigningKey(s.db, ps.SigningKeyID)
	if sk == nil || sk.RevokedAt != nil {
		http.Error(w, `{"error":"signing key revoked"}`, http.StatusGone)
		return
	}

	// Parse request body
	var req struct {
		SignatureImage string `json:"signature_image"` // base64 PNG data URL
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxImageSize+4096)).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Strip data URL prefix if present
	imageB64 := req.SignatureImage
	if idx := strings.Index(imageB64, ","); idx != -1 {
		imageB64 = imageB64[idx+1:]
	}

	imageBytes, err := base64.StdEncoding.DecodeString(imageB64)
	if err != nil {
		http.Error(w, `{"error":"invalid base64 image"}`, http.StatusBadRequest)
		return
	}

	if len(imageBytes) == 0 {
		http.Error(w, `{"error":"empty signature image"}`, http.StatusBadRequest)
		return
	}

	if len(imageBytes) > maxImageSize {
		http.Error(w, `{"error":"signature image too large"}`, http.StatusRequestEntityTooLarge)
		return
	}

	// Validate PNG header
	if len(imageBytes) < 8 || string(imageBytes[1:4]) != "PNG" {
		http.Error(w, `{"error":"invalid PNG image"}`, http.StatusBadRequest)
		return
	}

	// Build evidence envelope
	now := time.Now().UTC()
	env := &evidence.Envelope{
		Version:        1,
		PendingID:      ps.ID,
		PayloadHash:    ps.PayloadHash,
		Scope:          ps.DocType,
		Metadata:       ps.Metadata,
		SignerID:       auth.GrantedBy,
		SignerIP:       clientIP(r),
		SignatureImage: imageB64,
		ImageHash:      evidence.HashImage(imageBytes),
		CapturedAt:     now,
	}

	sealed, err := evidence.Seal(env)
	if err != nil {
		log.Printf("error sealing envelope for %s: %v", pendingID, err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Store the sealed envelope
	if err := storage.SaveEvidenceEnvelope(s.db, ps.ID, sealed.Data, sealed.Hash); err != nil {
		log.Printf("error saving envelope for %s: %v", pendingID, err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Cryptographic sign: composite payload covers both document and envelope
	composite := evidence.CompositePayload(ps.PayloadHash, sealed.Hash)

	dek, err := apoacrypto.UnwrapDEK(sk.DEKEncrypted, s.kek)
	if err != nil {
		log.Printf("error unwrapping DEK for %s: %v", sk.KeyID, err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	defer apoacrypto.ZeroBytes(dek)

	privKey, err := apoacrypto.DecryptPrivateKey(sk.PrivateKeyEncrypted, dek)
	if err != nil {
		log.Printf("error decrypting key %s: %v", sk.KeyID, err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	defer apoacrypto.ZeroBytes(privKey)

	sig, err := signing.Sign(privKey, []byte(composite), ps.DocType)
	if err != nil {
		log.Printf("error signing for %s: %v", pendingID, err)
		http.Error(w, `{"error":"signing failed"}`, http.StatusInternalServerError)
		return
	}

	// Mark as approved and persist signature
	if err := storage.ResolvePendingSignature(s.db, ps.ID, "approved", auth.GrantedBy, string(sig)); err != nil {
		log.Printf("error resolving %s: %v", pendingID, err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	storage.RecordKeyUsage(s.db, sk.KeyID)

	log.Printf("WEB_APPROVED pending %s by %s, key %s, envelope %s", pendingID, auth.GrantedBy, sk.KeyID, sealed.Hash[:16])

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":        "approved",
		"pending_id":    ps.ID,
		"key_id":        sk.KeyID,
		"signature":     string(sig),
		"envelope_hash": sealed.Hash,
	})
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if parts := strings.SplitN(xff, ",", 2); len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if host, _, ok := strings.Cut(r.RemoteAddr, ":"); ok {
		return host
	}
	return r.RemoteAddr
}
