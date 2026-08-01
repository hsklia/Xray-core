package naive

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"testing"
)

// TestVariant1WireFormat pins the exact framing: the first eight writes carry a
// 3-byte header and trailing zeros, the ninth is raw.
func TestVariant1WireFormat(t *testing.T) {
	var wire bytes.Buffer
	w := newPaddingWriter(&wire)

	payloads := [][]byte{
		[]byte("one"), []byte("two"), []byte("three"), []byte("four"),
		[]byte("five"), []byte("six"), []byte("seven"), []byte("eight"),
		[]byte("nine"), []byte("ten"),
	}
	for _, p := range payloads {
		n, err := w.Write(p)
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		if n != len(p) {
			t.Fatalf("write returned %d payload bytes, want %d", n, len(p))
		}
	}

	b := wire.Bytes()
	for i := 0; i < firstPaddings; i++ {
		if len(b) < 3 {
			t.Fatalf("frame %d: truncated", i)
		}
		size := int(binary.BigEndian.Uint16(b[0:2]))
		pad := int(b[2])
		if size != len(payloads[i]) {
			t.Fatalf("frame %d: payload_size %d, want %d", i, size, len(payloads[i]))
		}
		if len(b) < 3+size+pad {
			t.Fatalf("frame %d: truncated body", i)
		}
		if !bytes.Equal(b[3:3+size], payloads[i]) {
			t.Fatalf("frame %d: payload %q, want %q", i, b[3:3+size], payloads[i])
		}
		for _, c := range b[3+size : 3+size+pad] {
			if c != 0 {
				t.Fatalf("frame %d: padding is not zero-filled", i)
			}
		}
		b = b[3+size+pad:]
	}
	if !bytes.Equal(b, []byte("nineten")) {
		t.Fatalf("after %d frames the stream must be raw, got %q", firstPaddings, b)
	}
}

// TestVariant1RoundTrip drives the reader from the writer's output, including a
// payload larger than one frame can express.
func TestVariant1RoundTrip(t *testing.T) {
	var wire bytes.Buffer
	w := newPaddingWriter(&wire)

	big := bytes.Repeat([]byte("x"), maxPayloadSize+1234)
	writes := [][]byte{
		[]byte("hello"), {}, []byte("world"), big,
		[]byte("a"), []byte("b"), []byte("c"), []byte("d"),
		[]byte("e"), []byte("raw tail"),
	}
	var want []byte
	for _, p := range writes {
		if _, err := w.Write(p); err != nil {
			t.Fatalf("write: %v", err)
		}
		want = append(want, p...)
	}

	got, err := io.ReadAll(newPaddingReader(bytes.NewReader(wire.Bytes())))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round trip mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

// TestPaddingReaderHonoursSmallBuffers checks the reader's state machine when a
// frame spans several Read calls.
func TestPaddingReaderHonoursSmallBuffers(t *testing.T) {
	var wire bytes.Buffer
	w := newPaddingWriter(&wire)
	payload := bytes.Repeat([]byte("abcdefgh"), 1000)
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("tail")); err != nil {
		t.Fatal(err)
	}

	r := newPaddingReader(bytes.NewReader(wire.Bytes()))
	var got []byte
	buf := make([]byte, 7)
	for {
		n, err := r.Read(buf)
		got = append(got, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if want := append(append([]byte{}, payload...), []byte("tail")...); !bytes.Equal(got, want) {
		t.Fatalf("mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

func TestNegotiateServerPadding(t *testing.T) {
	cases := []struct {
		name   string
		header http.Header
		want   int
	}{
		{"variant1 preferred", http.Header{"Padding-Type-Request": {"1, 0"}, "Padding": {"abc"}}, PaddingTypeVariant1},
		{"none preferred", http.Header{"Padding-Type-Request": {"0, 1"}}, PaddingTypeNone},
		{"unknown types fall back to none", http.Header{"Padding-Type-Request": {"7, 9"}}, PaddingTypeNone},
		{"legacy client infers variant1", http.Header{"Padding": {"abc"}}, PaddingTypeVariant1},
		{"nothing means nothing", http.Header{}, PaddingTypeNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NegotiateServerPadding(c.header); got != c.want {
				t.Fatalf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestNegotiateClientPadding(t *testing.T) {
	if got, err := NegotiateClientPadding(http.Header{"Padding-Type-Reply": {"1"}}); err != nil || got != PaddingTypeVariant1 {
		t.Fatalf("reply wins: got %d, %v", got, err)
	}
	if got, err := NegotiateClientPadding(http.Header{"Padding-Type-Reply": {"0"}, "Padding": {"abc"}}); err != nil || got != PaddingTypeNone {
		t.Fatalf("an explicit 0 reply wins over a padding header: got %d, %v", got, err)
	}
	if got, err := NegotiateClientPadding(http.Header{"Padding": {"abc"}}); err != nil || got != PaddingTypeVariant1 {
		t.Fatalf("legacy inference: got %d, %v", got, err)
	}
	if got, err := NegotiateClientPadding(http.Header{}); err != nil || got != PaddingTypeNone {
		t.Fatalf("no padding: got %d, %v", got, err)
	}
	if _, err := NegotiateClientPadding(http.Header{"Padding-Type-Reply": {"banana"}}); err == nil {
		t.Fatal("an unparseable reply must be an error")
	}
	if _, err := NegotiateClientPadding(http.Header{"Padding-Type-Reply": {"9"}}); err == nil {
		t.Fatal("an unknown variant must be an error")
	}
}

func TestPaddingHeaderShape(t *testing.T) {
	for i := 0; i < 200; i++ {
		v := RequestPaddingHeader()
		if len(v) < 16 || len(v) > 32 {
			t.Fatalf("request padding length %d out of [16,32]", len(v))
		}
		checkAlphabet(t, v)
		v = ReplyPaddingHeader()
		if len(v) < 30 || len(v) > 62 {
			t.Fatalf("reply padding length %d out of [30,62]", len(v))
		}
		checkAlphabet(t, v)
	}
}

func checkAlphabet(t *testing.T, v string) {
	t.Helper()
	for i := 0; i < len(v); i++ {
		if i < len(paddingHeaderChars) {
			if !bytes.ContainsRune([]byte(paddingHeaderChars), rune(v[i])) {
				t.Fatalf("byte %d of %q is not from the padding alphabet", i, v)
			}
		} else if v[i] != '~' {
			t.Fatalf("byte %d of %q must be '~'", i, v)
		}
	}
}
