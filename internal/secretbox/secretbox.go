// Package secretbox encrypts vault values with AES-256-GCM under a master key.
// The master key itself is protected by the OS (DPAPI on Windows, an
// owner-only file elsewhere) and only ever lives in the daemon's memory.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const keyLen = 32

// Box seals and opens values. Additional data binds a ciphertext to its row so
// a sealed value cannot be swapped onto another credential.
type Box struct {
	aead      cipher.AEAD
	lookupKey [32]byte
}

func New(key []byte) (*Box, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("secretbox: key must be %d bytes", keyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead, lookupKey: deriveLookupKey(key)}, nil
}

func (b *Box) Seal(plaintext, ad []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, b.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, b.aead.Seal(nil, nonce, plaintext, ad), nil
}

func (b *Box) Open(nonce, ciphertext, ad []byte) ([]byte, error) {
	if len(nonce) != b.aead.NonceSize() {
		return nil, errors.New("secretbox: bad nonce")
	}
	return b.aead.Open(nil, nonce, ciphertext, ad)
}

// LoadOrCreateKey returns the master key stored (OS-protected) at path,
// creating a fresh random key on first run.
func LoadOrCreateKey(path string) ([]byte, error) {
	blob, err := os.ReadFile(path)
	if err == nil {
		key, err := unprotect(blob)
		if err != nil {
			return nil, fmt.Errorf("secretbox: unprotect master key: %w", err)
		}
		if len(key) != keyLen {
			return nil, errors.New("secretbox: master key has wrong length")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	blob, err = protect(key)
	if err != nil {
		return nil, fmt.Errorf("secretbox: protect master key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return key, nil
}
