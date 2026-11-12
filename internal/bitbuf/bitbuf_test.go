package bitbuf

import (
	"encoding/hex"
	"reflect"
	"testing"
)

// Quick Match search captured from the retail game (lobby service 5, task 5).
const capturedFind = "c7c110180503e0040000001c190000800300000070000000000e000000c0a9020000380000000007000000e028" +
	"0000001c000000801300000070000000004e000000c0010000003800000000c7010000e0000000001c00000080" +
	"0300000078feffffff0000000000000000"

func TestUntypedLayout(t *testing.T) {
	b := NewWriter(false).U32(0x12345678).U8(0xab).Raw([]byte{1, 2, 3}).Bytes()
	if b[0] != (0x78<<1)&0xff {
		t.Fatalf("first byte %#x: flag bit then value shifted by one", b[0])
	}
	r, _ := NewReader(b)
	v, _ := r.U32()
	u, _ := r.U8()
	raw, _ := r.Raw(3)
	if r.Typed || v != 0x12345678 || u != 0xab || hex.EncodeToString(raw) != "010203" {
		t.Fatalf("got %v %#x %#x %x", r.Typed, v, u, raw)
	}
}

func TestTypedFieldsRoundTrip(t *testing.T) {
	fields := []Field{Bytes(Blob, make([]byte, 25)), Int(I32, 4), Bytes(String, []byte("Host")),
		Int(I64, 0x1122334455667788), Int(U8, 9), Bytes(Blob, []byte{1, 2})}
	r, _ := NewReader(NewWriter(true).Fields(fields).Bytes())
	got, err := r.Fields()
	if err != nil || !reflect.DeepEqual(got, fields) {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestTypedMarkerMismatch(t *testing.T) {
	r, _ := NewReader(NewWriter(true).U8(5).Bytes())
	if _, err := r.U32(); err == nil {
		t.Fatal("expected a type mismatch")
	}
}

func TestCapturedFindQuery(t *testing.T) {
	b, _ := hex.DecodeString(capturedFind)
	r, _ := NewReader(b)
	slot, _ := r.U8()
	seq, _ := r.U8()
	task, _ := r.U8()
	fields, err := r.Fields()
	if err != nil || task != 5 || len(fields) != 21 || !reflect.DeepEqual(fields[0], Int(U8, 0)) {
		t.Fatalf("slot %d seq %d task %d, %d fields, %v", slot, seq, task, len(fields), err)
	}
	for _, f := range fields[1:] {
		if f.Type != I32 {
			t.Fatalf("query field %v is not i32", f)
		}
	}
}
