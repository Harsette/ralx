package secretbox

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// LookupHash is a domain-separated keyed index. It does not permit offline
// guessing of a website's origin from a copy of SQLite alone.
func (b *Box) LookupHash(domain, value string) string {
	h := hmac.New(sha256.New, b.lookupKey[:])
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}
func deriveLookupKey(master []byte) [32]byte {
	h := hmac.New(sha256.New, master)
	h.Write([]byte("ralx/lookup-key/v1"))
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}
