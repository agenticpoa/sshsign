package server

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/charmbracelet/ssh"

	"github.com/agenticpoa/sshsign/internal/audit"
	apoacrypto "github.com/agenticpoa/sshsign/internal/crypto"
	"github.com/agenticpoa/sshsign/internal/storage"
)

func handleKeys(sess ssh.Session, sc *SessionContext) {
	keys, err := storage.ListSigningKeys(sess.Context(), sc.DB, sc.User.UserID)
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
	if sc.RateLimits != nil && sc.RateLimits.KeyCreation != nil && sc.RateLimits.KeyCreation.Allow(sc.User.UserID) != nil {
		writeJSON(sess, errorResponse{Error: "rate limit exceeded: too many key creation requests"})
		return
	}

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
		case "--constraints-b64":
			if i+1 < len(args) {
				i++
				decoded, err := decodeB64JSON(args[i])
				if err != nil {
					writeJSON(sess, errorResponse{Error: fmt.Sprintf("--constraints-b64: %v", err)})
					return
				}
				constraintsJSON = decoded
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
	if expiryDays < 1 {
		writeJSON(sess, errorResponse{Error: "expiry must be at least 1 day"})
		return
	}
	if scope == "safe-agreement" && expiryDays > 1 {
		expiryDays = 1
	} else if expiryDays > 30 {
		expiryDays = 30
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

	wrappedDEK, kekAlgo, err := sc.KEK.WrapDEK(dek)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("wrapping DEK: %v", err)})
		return
	}

	// Persist key
	sk, err := storage.CreateSigningKey(sess.Context(), sc.DB, sc.User.UserID, pubSSH, encPrivKey, wrappedDEK, kekAlgo)
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("storing key: %v", err)})
		return
	}

	// Create authorization
	expires := time.Now().AddDate(0, 0, expiryDays)
	authorization, err := storage.CreateAuthorizationFull(
		sess.Context(),
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
	sk, err := storage.GetSigningKey(sess.Context(), sc.DB, keyID)
	if err != nil || sk == nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("signing key %s not found", keyID)})
		return
	}
	if sk.OwnerID != sc.User.UserID {
		writeJSON(sess, errorResponse{Error: "signing key does not belong to you"})
		return
	}

	if err := storage.RevokeSigningKey(sess.Context(), sc.DB, keyID); err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("revoking key: %v", err)})
		return
	}

	_, _ = logAudit(sc.Audit, audit.Entry{
		UserID:       sc.User.UserID,
		SigningKeyID: keyID,
		ActionType:   "revoke",
		Result:       "REVOKED",
	})

	log.Printf("REVOKED key %s by user %s", keyID, sc.User.UserID)
	writeJSON(sess, map[string]string{"status": "revoked", "key_id": keyID})
}

// handlePending lists pending signatures for the current user (as principal).
