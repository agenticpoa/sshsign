package storage

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func NewUserID() string {
	return "u_" + randomHex(12)
}

func NewKeyID() string {
	return "ak_" + randomHex(12)
}

func NewTokenID() string {
	return "tok_" + randomHex(12)
}

func NewPendingID() string {
	return "pnd_" + randomHex(12)
}

func NewOfferID() string {
	return "ofr_" + randomHex(12)
}

func randomHex(n int) string {
	b := make([]byte, n/2)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("reading random bytes: %v", err))
	}
	return hex.EncodeToString(b)
}
