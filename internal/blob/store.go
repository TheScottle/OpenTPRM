package blob

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const segmentSize = 1 << 20 // 1 MiB

// Store is an encrypted object store under dataDir/blobs.
type Store struct {
	Root string
	KEK  []byte
}

func (s *Store) pathFor(id string) string {
	if len(id) < 4 {
		id = id + "0000"
	}
	return filepath.Join(s.Root, "blobs", id[0:2], id[2:4], id)
}

// Put writes an immutable encrypted object (chunked AEAD).
func (s *Store) Put(id string, r io.Reader) (sha string, err error) {
	path := s.pathFor(id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("blob %s already exists (immutable)", id)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	// Wrap object key with KEK (simple AES-GCM)
	wrapped, err := seal(s.KEK, key)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(wrapped); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	buf := make([]byte, segmentSize)
	var nseg int
	for {
		n, readErr := io.ReadFull(r, buf)
		if n > 0 {
			nonce := make([]byte, gcm.NonceSize())
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				return "", err
			}
			ct := gcm.Seal(nonce, nonce, buf[:n], []byte(fmt.Sprintf("%d", nseg)))
			if _, err := f.Write(ct); err != nil {
				return "", err
			}
			nseg++
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return "", readErr
		}
	}
	return hex.EncodeToString(key[:8]), nil
}

func seal(kek, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}
