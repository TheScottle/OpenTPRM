package blob

import (
	"bytes"
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

// Get decrypts an immutable object written by Put and writes plaintext to w.
func (s *Store) Get(id string, w io.Writer) error {
	path := s.pathFor(id)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Wrapped object key: nonce||ciphertext (AES-GCM over 32-byte key).
	kekBlock, err := aes.NewCipher(s.KEK)
	if err != nil {
		return err
	}
	kekGCM, err := cipher.NewGCM(kekBlock)
	if err != nil {
		return err
	}
	wrappedLen := kekGCM.NonceSize() + 32 + kekGCM.Overhead()
	wrapped := make([]byte, wrappedLen)
	if _, err := io.ReadFull(f, wrapped); err != nil {
		return fmt.Errorf("read wrapped key: %w", err)
	}
	key, err := open(s.KEK, wrapped)
	if err != nil {
		return fmt.Errorf("unwrap object key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	seg := 0
	nonceSize := gcm.NonceSize()
	fullCT := nonceSize + segmentSize + gcm.Overhead()
	buf := make([]byte, fullCT)
	for {
		n, err := io.ReadFull(f, buf)
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			if n == 0 {
				break
			}
			// Final short segment.
		} else if err != nil {
			return err
		} else {
			n = fullCT
		}
		if n < nonceSize+gcm.Overhead() {
			return fmt.Errorf("truncated segment %d", seg)
		}
		nonce, ct := buf[:nonceSize], buf[nonceSize:n]
		pt, err := gcm.Open(nil, nonce, ct, []byte(fmt.Sprintf("%d", seg)))
		if err != nil {
			return fmt.Errorf("segment %d: %w", seg, err)
		}
		if _, err := w.Write(pt); err != nil {
			return err
		}
		seg++
		if n < fullCT {
			break
		}
	}
	return nil
}

// PutBytes is a convenience wrapper around Put.
func (s *Store) PutBytes(id string, data []byte) (string, error) {
	return s.Put(id, bytes.NewReader(data))
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

func open(kek, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
