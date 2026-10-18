package daemon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// softAuthn is a minimal software passkey (ES256, "none" attestation) used to
// drive real WebAuthn ceremonies against the daemon in tests.
type softAuthn struct {
	key    *ecdsa.PrivateKey
	credID []byte
	origin string
	rpID   string
	count  uint32
	uv     bool
}

func newSoftAuthn(t *testing.T, origin string) *softAuthn {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &softAuthn{key: k, credID: id, origin: origin, rpID: "localhost", uv: true}
}

var b64 = base64.RawURLEncoding

func (a *softAuthn) clientData(typ string, challenge string) []byte {
	cd, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return cd
}

func (a *softAuthn) flags(attested bool) byte {
	f := byte(0x01) // UP
	if a.uv {
		f |= 0x04
	}
	if attested {
		f |= 0x40
	}
	return f
}

// challengeOf pulls publicKey.challenge out of creation/assertion options.
func challengeOf(t *testing.T, opts []byte) string {
	var m struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(opts, &m); err != nil || m.PublicKey.Challenge == "" {
		t.Fatalf("no challenge in options: %s", opts)
	}
	return m.PublicKey.Challenge
}

func (a *softAuthn) register(t *testing.T, opts []byte) json.RawMessage {
	chal := challengeOf(t, opts)
	rpHash := sha256.Sum256([]byte(a.rpID))
	x := a.key.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.key.PublicKey.Y.FillBytes(make([]byte, 32))
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		t.Fatal(err)
	}
	var ad []byte
	ad = append(ad, rpHash[:]...)
	ad = append(ad, a.flags(true))
	ad = binary.BigEndian.AppendUint32(ad, a.count)
	ad = append(ad, make([]byte, 16)...) // AAGUID
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(a.credID)))
	ad = append(ad, a.credID...)
	ad = append(ad, cose...)
	att, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{"attestationObject": b64.EncodeToString(att), "clientDataJSON": b64.EncodeToString(a.clientData("webauthn.create", chal))},
	})
	return resp
}

func (a *softAuthn) assert(t *testing.T, opts []byte) json.RawMessage {
	chal := challengeOf(t, opts)
	a.count++
	rpHash := sha256.Sum256([]byte(a.rpID))
	var ad []byte
	ad = append(ad, rpHash[:]...)
	ad = append(ad, a.flags(false))
	ad = binary.BigEndian.AppendUint32(ad, a.count)
	cd := a.clientData("webauthn.get", chal)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{"authenticatorData": b64.EncodeToString(ad), "clientDataJSON": b64.EncodeToString(cd), "signature": b64.EncodeToString(sig)},
	})
	return resp
}
