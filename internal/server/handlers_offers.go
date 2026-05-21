package server

import (
	"fmt"
	"log"
	"time"

	"github.com/charmbracelet/ssh"

	"github.com/agenticpoa/sshsign/internal/audit"
	"github.com/agenticpoa/sshsign/internal/storage"
)

func handleLogOffer(sess ssh.Session, sc *SessionContext, args []string) {
	if sc.RateLimits != nil && sc.RateLimits.OfferMutation != nil && sc.RateLimits.OfferMutation.Allow(sc.User.UserID) != nil {
		writeJSON(sess, errorResponse{Error: "rate limit exceeded: too many offer operations"})
		return
	}

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
		case "--metadata-b64":
			i++
			decoded, err := decodeB64JSON(args[i])
			if err != nil {
				writeJSON(sess, errorResponse{Error: fmt.Sprintf("--metadata-b64: %v", err)})
				return
			}
			metadata = decoded
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
	if err := requireNegotiationRoleMember(sc, negotiationID, fromParty); err != nil {
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}

	// Turn validation: parties must alternate
	lastOffer, err := storage.GetLastOffer(sess.Context(), sc.DB, negotiationID)
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
		prev, err := storage.FindOfferByAuditTx(sess.Context(), sc.DB, previousTx)
		if err != nil {
			writeJSON(sess, errorResponse{Error: fmt.Sprintf("checking previous tx: %v", err)})
			return
		}
		if prev == nil {
			writeJSON(sess, errorResponse{Error: fmt.Sprintf("previous_tx %d not found", previousTx)})
			return
		}
	}

	// Log to audit trail. The audit txID is stored as the offer's
	// previous_tx pointer for the next offer — without it the offer
	// chain breaks, so a failure must surface to the caller rather
	// than silently produce a chain with 0 links.
	auditTxID, err := logAudit(sc.Audit, audit.Entry{
		UserID:     sc.User.UserID,
		ActionType: "negotiation-offer",
		Result:     "LOGGED",
	})
	if err != nil {
		writeJSON(sess, errorResponse{Error: fmt.Sprintf("audit log unavailable: %v", err)})
		return
	}

	// Store the offer
	offer, err := storage.CreateNegotiationOffer(
		sess.Context(),
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
	if err := requireNegotiationMember(sc, negotiationID); err != nil {
		writeJSON(sess, errorResponse{Error: err.Error()})
		return
	}

	offers, err := storage.ListNegotiationOffers(sess.Context(), sc.DB, negotiationID)
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
// pendingBindingFor extracts the MAC binding fields from a stored
// pending row. Centralized so the sign-time and approve-time encodings
// stay in lockstep — a divergence would silently break every cosign.
