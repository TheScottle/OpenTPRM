package store_test

import (
	"bytes"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/blob"
	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/google/uuid"
)

func TestEVD_ChunkedUploadCompleteQuarantine(t *testing.T) {
	st, ctx := testStore(t)
	vid := uuid.Must(uuid.NewV7()).String()
	if err := st.CreateVendor(ctx, store.Vendor{
		ID: vid, LegalName: "Upload Co", Status: "active", CreatedBy: "analyst1", UpdatedBy: "analyst1",
	}); err != nil {
		t.Fatal(err)
	}
	eid := uuid.Must(uuid.NewV7()).String()
	if err := st.CreateEngagement(ctx, store.Engagement{
		ID: eid, ThirdPartyID: vid, ServiceDescription: "docs",
		RelationshipOwner: "ro", CreatedBy: "analyst1", UpdatedBy: "analyst1",
	}); err != nil {
		t.Fatal(err)
	}

	u, err := st.CreateUploadSession(ctx, store.UploadSession{
		EngagementID: eid, Uploader: "analyst1", DeclaredName: "note.txt",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("hello evidence quarantine")
	if _, err := st.AppendUploadChunk(ctx, u.ID, bytes.NewReader(payload[:5]), 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AppendUploadChunk(ctx, u.ID, bytes.NewReader(payload[5:]), 1<<20); err != nil {
		t.Fatal(err)
	}

	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 3)
	}
	blobs := &blob.Store{Root: t.TempDir(), KEK: kek}
	ev, err := st.CompleteUpload(ctx, u.ID, blobs, "analyst1")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != "quarantined" || ev.BlobID == "" || ev.SHA256 == "" {
		t.Fatalf("%+v", ev)
	}
	var out bytes.Buffer
	if err := blobs.Get(ev.BlobID, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("blob mismatch %q", out.Bytes())
	}
	items, err := st.ListEvidence(ctx)
	if err != nil || len(items) != 1 {
		t.Fatalf("evidence list=%d err=%v", len(items), err)
	}
}

func TestEVD_UploadRejectsArchiveBomb(t *testing.T) {
	st, ctx := testStore(t)
	vid := uuid.Must(uuid.NewV7()).String()
	_ = st.CreateVendor(ctx, store.Vendor{ID: vid, LegalName: "B", Status: "active", CreatedBy: "a", UpdatedBy: "a"})
	eid := uuid.Must(uuid.NewV7()).String()
	_ = st.CreateEngagement(ctx, store.Engagement{
		ID: eid, ThirdPartyID: vid, ServiceDescription: "x", RelationshipOwner: "ro",
		CreatedBy: "a", UpdatedBy: "a",
	})
	u, err := st.CreateUploadSession(ctx, store.UploadSession{EngagementID: eid, Uploader: "a"})
	if err != nil {
		t.Fatal(err)
	}
	// Declare oversized uncompressed zip (AT-08 / QST-011 style).
	bomb := craftBomb()
	if _, err := st.AppendUploadChunk(ctx, u.ID, bytes.NewReader(bomb), 1<<20); err != nil {
		t.Fatal(err)
	}
	_, err = st.CompleteUpload(ctx, u.ID, nil, "a")
	if err == nil {
		t.Fatal("expected rejection")
	}
}

func craftBomb() []byte {
	name := []byte("bomb.bin")
	payload := []byte("x")
	var local bytes.Buffer
	local.Write([]byte("PK\x03\x04"))
	for _, v := range []uint16{20, 0, 0, 0, 0} {
		local.WriteByte(byte(v))
		local.WriteByte(byte(v >> 8))
	}
	write32 := func(b *bytes.Buffer, v uint32) {
		b.WriteByte(byte(v))
		b.WriteByte(byte(v >> 8))
		b.WriteByte(byte(v >> 16))
		b.WriteByte(byte(v >> 24))
	}
	write32(&local, 0)
	write32(&local, uint32(len(payload)))
	write32(&local, 200<<20+1)
	local.WriteByte(byte(len(name)))
	local.WriteByte(0)
	local.WriteByte(0)
	local.WriteByte(0)
	local.Write(name)
	local.Write(payload)
	lb := local.Bytes()
	var central bytes.Buffer
	central.Write([]byte("PK\x01\x02"))
	for _, v := range []uint16{20, 20, 0, 0, 0, 0} {
		central.WriteByte(byte(v))
		central.WriteByte(byte(v >> 8))
	}
	write32(&central, 0)
	write32(&central, uint32(len(payload)))
	write32(&central, 200<<20+1)
	central.WriteByte(byte(len(name)))
	central.WriteByte(0)
	for i := 0; i < 10; i++ {
		central.WriteByte(0)
	}
	write32(&central, 0)
	central.Write(name)
	cb := central.Bytes()
	var end bytes.Buffer
	end.Write([]byte("PK\x05\x06"))
	for i := 0; i < 4; i++ {
		end.WriteByte(0)
	}
	end.WriteByte(1)
	end.WriteByte(0)
	end.WriteByte(1)
	end.WriteByte(0)
	write32(&end, uint32(len(cb)))
	write32(&end, uint32(len(lb)))
	end.WriteByte(0)
	end.WriteByte(0)
	out := append(lb, cb...)
	return append(out, end.Bytes()...)
}
