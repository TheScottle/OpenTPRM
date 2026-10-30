package blob_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/blob"
)

func TestBlobRoundTrip(t *testing.T) {
	kek := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, kek)
	s := &blob.Store{Root: t.TempDir(), KEK: kek}
	payload := []byte("evidence bytes for EVD blob round-trip")
	if _, err := s.PutBytes("aabbccdd-1111-2222-3333-444455556666", payload); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := s.Get("aabbccdd-1111-2222-3333-444455556666", &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("got %q want %q", out.Bytes(), payload)
	}
	// Immutable: second put fails
	if _, err := s.PutBytes("aabbccdd-1111-2222-3333-444455556666", payload); err == nil {
		t.Fatal("expected immutable refusal")
	}
}

func TestBlobMultiSegmentRoundTrip(t *testing.T) {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
	}
	s := &blob.Store{Root: t.TempDir(), KEK: kek}
	payload := bytes.Repeat([]byte("abcdefgh"), (1<<20)/8+100) // > 1 MiB
	id := "deadbeefdeadbeefdeadbeefdeadbeef"
	if _, err := s.PutBytes(id, payload); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := s.Get(id, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("len got=%d want=%d", out.Len(), len(payload))
	}
}
