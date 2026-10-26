package anonymizer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type Anonymizer struct {
	key []byte
}

func New(key string) *Anonymizer {
	return &Anonymizer{
		key: []byte(key),
	}
}

// hashIdentifier creates a deterministic keyed hash.
// The same input with the same key always produces the same alias.
func (a *Anonymizer) hashIdentifier(value string) string {
	mac := hmac.New(sha256.New, a.key)
	mac.Write([]byte(value))

	sum := mac.Sum(nil)

	// A short identifier is sufficient for readable output.
	return hex.EncodeToString(sum[:6])
}

// IP returns a deterministic alias for an IP address.
func (a *Anonymizer) IP(ip string) string {
	if ip == "" {
		return ""
	}

	return fmt.Sprintf("IP-%s", a.hashIdentifier(ip))
}

// MAC returns a deterministic alias for a MAC address.
func (a *Anonymizer) MAC(address string) string {
	if address == "" {
		return ""
	}

	return fmt.Sprintf("MAC-%s", a.hashIdentifier(address))
}
