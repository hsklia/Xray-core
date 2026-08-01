package naive

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

// NaiveProxy's padding layer. There is exactly one wire variant upstream:
//
//	kNone = 0, kVariant1 = 1
//
// Variant1 frames the first eight writes of each direction (counted
// independently) as
//
//	uint16 payload_size (big endian) | uint8 padding_size | payload | zeros
//
// and then falls through to raw bytes. Payloads are chunked at 65535 because
// that is what payload_size can express.
const (
	PaddingTypeNone     = 0
	PaddingTypeVariant1 = 1

	firstPaddings  = 8
	maxPaddingSize = 255
	maxPayloadSize = 65535
)

const (
	headerPadding            = "padding"
	headerPaddingTypeRequest = "padding-type-request"
	headerPaddingTypeReply   = "padding-type-reply"
	// headerConnectAuthority is a Cronet quirk: naiveproxy's client puts the
	// real CONNECT target here as well, and some clients (sing-box's naive
	// outbound among them) only put it here. Read it first.
	headerConnectAuthority = "-connect-authority"

	headerProxyAuthorization = "Proxy-Authorization"
	headerProxyAuthenticate  = "Proxy-Authenticate"
)

// paddingHeaderChars is the alphabet naiveproxy fills the leading bytes of a
// padding header with; the remainder is '~'.
const paddingHeaderChars = "!#$()+<>?@[]^`{}"

var errInvalidResponse = errors.New("naive: invalid response")

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// randomInt returns a value in [min, max].
func randomInt(min, max int) int {
	if max <= min {
		return min
	}
	b := randomBytes(2)
	return min + int(binary.BigEndian.Uint16(b))%(max-min+1)
}

// PaddingHeaderValue builds a padding header of a random length in [min, max].
func PaddingHeaderValue(min, max int) string {
	n := randomInt(min, max)
	b := make([]byte, n)
	pick := randomBytes(n)
	for i := 0; i < n; i++ {
		if i < len(paddingHeaderChars) {
			b[i] = paddingHeaderChars[int(pick[i])%len(paddingHeaderChars)]
		} else {
			b[i] = '~'
		}
	}
	return string(b)
}

// RequestPaddingHeader is what a client sends (16-32 bytes).
func RequestPaddingHeader() string { return PaddingHeaderValue(16, 32) }

// ReplyPaddingHeader is what a server answers with (30-62 bytes).
func ReplyPaddingHeader() string { return PaddingHeaderValue(30, 62) }

func parsePaddingTypeList(v string) []int {
	var out []int
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	return out
}

// NegotiateServerPadding picks the padding variant for an inbound request.
// A client that only sends "padding:" (and no padding-type-request) is a legacy
// client and means Variant1.
func NegotiateServerPadding(h http.Header) int {
	if v := h.Get(headerPaddingTypeRequest); v != "" {
		for _, t := range parsePaddingTypeList(v) {
			switch t {
			case PaddingTypeVariant1, PaddingTypeNone:
				return t
			}
		}
		return PaddingTypeNone
	}
	if h.Get(headerPadding) != "" {
		return PaddingTypeVariant1
	}
	return PaddingTypeNone
}

// NegotiateClientPadding resolves the variant from a server's 200 response.
// A reply header wins; otherwise a bare "padding:" implies Variant1; a response
// carrying neither means no padding. Anything unparseable is a protocol error,
// which is what naiveproxy reports as ERR_INVALID_RESPONSE.
func NegotiateClientPadding(h http.Header) (int, error) {
	if v := h.Get(headerPaddingTypeReply); v != "" {
		t, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, errInvalidResponse
		}
		switch t {
		case PaddingTypeNone, PaddingTypeVariant1:
			return t, nil
		}
		return 0, errInvalidResponse
	}
	if h.Get(headerPadding) != "" {
		return PaddingTypeVariant1, nil
	}
	return PaddingTypeNone, nil
}

// paddingReader unwraps Variant1 framing.
type paddingReader struct {
	reader io.Reader
	frames int

	payloadRemain int
	padRemain     int
	header        [3]byte
}

func newPaddingReader(r io.Reader) io.Reader { return &paddingReader{reader: r} }

func (r *paddingReader) Read(p []byte) (int, error) {
	for {
		if r.payloadRemain > 0 {
			n := len(p)
			if n > r.payloadRemain {
				n = r.payloadRemain
			}
			n, err := r.reader.Read(p[:n])
			r.payloadRemain -= n
			return n, err
		}
		if r.padRemain > 0 {
			if _, err := io.CopyN(io.Discard, r.reader, int64(r.padRemain)); err != nil {
				return 0, err
			}
			r.padRemain = 0
		}
		if r.frames >= firstPaddings {
			return r.reader.Read(p)
		}
		if _, err := io.ReadFull(r.reader, r.header[:]); err != nil {
			return 0, err
		}
		r.frames++
		r.payloadRemain = int(binary.BigEndian.Uint16(r.header[:2]))
		r.padRemain = int(r.header[2])
	}
}

// paddingWriter applies Variant1 framing. It reports the number of *payload*
// bytes consumed, not the number of wire bytes, so it composes with
// io.WriteAll-style callers such as buf.WriteAllBytes.
type paddingWriter struct {
	writer io.Writer
	frames int
	buf    []byte
}

func newPaddingWriter(w io.Writer) io.Writer { return &paddingWriter{writer: w} }

func (w *paddingWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		if w.frames >= firstPaddings {
			n, err := w.writer.Write(p)
			return total + n, err
		}
		chunk := p
		if len(chunk) > maxPayloadSize {
			chunk = chunk[:maxPayloadSize]
		}
		padSize := int(randomBytes(1)[0]) % (maxPaddingSize + 1)
		size := 3 + len(chunk) + padSize
		if cap(w.buf) < size {
			w.buf = make([]byte, size)
		}
		b := w.buf[:size]
		binary.BigEndian.PutUint16(b[0:2], uint16(len(chunk)))
		b[2] = byte(padSize)
		copy(b[3:], chunk)
		for i := 3 + len(chunk); i < size; i++ {
			b[i] = 0
		}
		if _, err := w.writer.Write(b); err != nil {
			return total, err
		}
		w.frames++
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// flushWriter pushes every write out of the HTTP/2 or HTTP/3 response buffer.
// Without it a tunnel stalls behind net/http's 4 KiB body buffer.
type flushWriter struct {
	writer  io.Writer
	flusher http.Flusher
}

func newFlushWriter(w http.ResponseWriter) io.Writer {
	f, _ := w.(http.Flusher)
	return &flushWriter{writer: w, flusher: f}
}

func (w *flushWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if w.flusher != nil {
		w.flusher.Flush()
	}
	return n, err
}
