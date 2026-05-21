package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/charmbracelet/ssh"

	"github.com/agenticpoa/sshsign/internal/audit"
	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/sessions"
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

func hostedSessionID(negotiationID string) string {
	if strings.HasPrefix(negotiationID, "session_") {
		return negotiationID
	}
	return "session_" + negotiationID
}

func requireNegotiationMember(sc *SessionContext, negotiationID string) error {
	repo := sessions.NewRepo(sc.DB)
	ok, err := repo.IsMember(hostedSessionID(negotiationID), sc.User.UserID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("not a member of this negotiation session")
	}
	return nil
}

func requireNegotiationRoleMember(sc *SessionContext, negotiationID, role string) error {
	repo := sessions.NewRepo(sc.DB)
	members, err := repo.Members(hostedSessionID(negotiationID))
	if err != nil {
		return err
	}
	for _, m := range members {
		if m.UserID == sc.User.UserID && m.Role == role {
			return nil
		}
	}
	return fmt.Errorf("not authorized to log offers as %s", role)
}

func pendingBindingFor(ps *storage.PendingSignature) apoacrypto.PendingBinding {
	return apoacrypto.PendingBinding{
		SigningKeyID: ps.SigningKeyID,
		AuthTokenID:  ps.AuthTokenID,
		RequesterID:  ps.RequesterID,
		DocType:      ps.DocType,
		PayloadHash:  ps.PayloadHash,
		Metadata:     ps.Metadata,
	}
}

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
