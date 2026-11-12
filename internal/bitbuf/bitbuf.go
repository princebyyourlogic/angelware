// Package bitbuf implements DemonWare's bdBitBuffer: bits packed least-significant first.
//
// The first bit of every buffer says whether fields carry 5-bit data-type markers.
// Auth messages are untyped; lobby-service tasks are typed.
package bitbuf

import (
	"errors"
	"fmt"
)

// Data types seen in SvR 2007 (bdBitBufferDataType).
const (
	Bool   = 1
	I8     = 2
	U8     = 3
	I16    = 5
	U16    = 6
	I32    = 7
	U32    = 8
	I64    = 9
	U64    = 10
	F32    = 13
	F64    = 14
	String = 16 // NUL-terminated bytes
	Blob   = 19 // typed u32 byte count, then the bytes
)

var widths = map[uint8]int{Bool: 1, I8: 8, U8: 8, I16: 16, U16: 16, I32: 32, U32: 32,
	I64: 64, U64: 64, F32: 32, F64: 64}

// ErrShort is returned when a read runs past the end of the buffer.
var ErrShort = errors.New("bitbuf: read past end")

// Field is one typed value: Int for numbers, Bytes for strings and blobs.
type Field struct {
	Type  uint8
	Int   uint64
	Bytes []byte
}

func Int(t uint8, v uint64) Field   { return Field{Type: t, Int: v} }
func Bytes(t uint8, b []byte) Field { return Field{Type: t, Bytes: b} }
func (f Field) String() string {
	if f.Type == String || f.Type == Blob {
		return fmt.Sprintf("%d:%x", f.Type, f.Bytes)
	}
	return fmt.Sprintf("%d:%#x", f.Type, f.Int)
}

// Writer builds a buffer.
type Writer struct {
	buf   []byte
	n     int
	typed bool
}

// NewWriter starts a buffer; typed buffers carry data-type markers.
func NewWriter(typed bool) *Writer {
	w := &Writer{typed: typed}
	if typed {
		w.bits(1, 1)
	} else {
		w.bits(0, 1)
	}
	return w
}

func (w *Writer) bits(v uint64, n int) {
	for i := 0; i < n; i++ {
		if w.n%8 == 0 {
			w.buf = append(w.buf, 0)
		}
		w.buf[w.n/8] |= byte(v>>i&1) << (w.n % 8)
		w.n++
	}
}

func (w *Writer) marker(t uint8) {
	if w.typed {
		w.bits(uint64(t), 5)
	}
}

func (w *Writer) U8(v uint8) *Writer   { w.marker(U8); w.bits(uint64(v), 8); return w }
func (w *Writer) U32(v uint32) *Writer { w.marker(U32); w.bits(uint64(v), 32); return w }

// Raw writes untyped bytes, like bdBitBuffer::writeBits(ptr, len*8).
func (w *Writer) Raw(b []byte) *Writer {
	for _, c := range b {
		w.bits(uint64(c), 8)
	}
	return w
}

// Field writes one typed field.
func (w *Writer) Field(f Field) *Writer {
	w.bits(uint64(f.Type), 5)
	switch f.Type {
	case String:
		w.Raw(f.Bytes)
		w.bits(0, 8)
	case Blob:
		w.bits(U32, 5)
		w.bits(uint64(len(f.Bytes)), 32)
		w.Raw(f.Bytes)
	default:
		w.bits(f.Int, widths[f.Type])
	}
	return w
}

func (w *Writer) Fields(fs []Field) *Writer {
	for _, f := range fs {
		w.Field(f)
	}
	return w
}

func (w *Writer) Bytes() []byte { return w.buf }

// Reader parses a buffer.
type Reader struct {
	buf   []byte
	pos   int
	Typed bool
}

func NewReader(b []byte) (*Reader, error) {
	r := &Reader{buf: b}
	t, err := r.bits(1)
	r.Typed = t == 1
	return r, err
}

func (r *Reader) Remaining() int { return len(r.buf)*8 - r.pos }

func (r *Reader) bits(n int) (uint64, error) {
	if n > r.Remaining() {
		return 0, ErrShort
	}
	var v uint64
	for i := 0; i < n; i++ {
		v |= uint64(r.buf[r.pos/8]>>(r.pos%8)&1) << i
		r.pos++
	}
	return v, nil
}

func (r *Reader) marker(t uint8) error {
	if !r.Typed {
		return nil
	}
	got, err := r.bits(5)
	if err == nil && uint8(got) != t {
		err = fmt.Errorf("bitbuf: expected type %d, got %d at bit %d", t, got, r.pos-5)
	}
	return err
}

func (r *Reader) U8() (uint8, error) {
	if err := r.marker(U8); err != nil {
		return 0, err
	}
	v, err := r.bits(8)
	return uint8(v), err
}

func (r *Reader) U32() (uint32, error) {
	if err := r.marker(U32); err != nil {
		return 0, err
	}
	v, err := r.bits(32)
	return uint32(v), err
}

// Raw reads n untyped bytes.
func (r *Reader) Raw(n int) ([]byte, error) {
	if n*8 > r.Remaining() {
		return nil, ErrShort
	}
	out := make([]byte, n)
	for i := range out {
		v, _ := r.bits(8)
		out[i] = byte(v)
	}
	return out, nil
}

// Field reads one typed field.
func (r *Reader) Field() (Field, error) {
	t, err := r.bits(5)
	if err != nil {
		return Field{}, err
	}
	f := Field{Type: uint8(t)}
	switch f.Type {
	case String:
		for {
			c, err := r.bits(8)
			if err != nil {
				return f, err
			}
			if c == 0 {
				return f, nil
			}
			f.Bytes = append(f.Bytes, byte(c))
		}
	case Blob:
		if lt, err := r.bits(5); err != nil || lt != U32 {
			return f, fmt.Errorf("bitbuf: blob without length at bit %d", r.pos)
		}
		n, err := r.bits(32)
		if err != nil {
			return f, err
		}
		f.Bytes, err = r.Raw(int(n))
		return f, err
	default:
		width, ok := widths[f.Type]
		if !ok {
			return f, fmt.Errorf("bitbuf: unsupported data type %d at bit %d", f.Type, r.pos-5)
		}
		f.Int, err = r.bits(width)
		return f, err
	}
}

// Fields reads typed fields until the buffer ends or a zero marker (padding) appears.
func (r *Reader) Fields() ([]Field, error) {
	var fs []Field
	for r.Remaining() >= 5 {
		save := r.pos
		if t, _ := r.bits(5); t == 0 {
			break
		}
		r.pos = save
		f, err := r.Field()
		if err != nil {
			return fs, err
		}
		fs = append(fs, f)
	}
	return fs, nil
}
