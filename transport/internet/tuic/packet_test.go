package tuic

import (
	"bytes"
	"context"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

func fragment(packetID uint16, fragmentID, fragmentTotal uint8, data []byte) *udpMessage {
	m := &udpMessage{
		sessionID:     1,
		packetID:      packetID,
		fragmentID:    fragmentID,
		fragmentTotal: fragmentTotal,
		data:          data,
	}
	if fragmentID == 0 {
		m.destination = xnet.UDPDestination(xnet.LocalHostIP, 53)
	}
	return m
}

// A fragment set that never completes must not pin its buffers forever. Feeding
// fragment 1 of 2 and never fragment 0 is the cheapest way for a peer to force
// it, and ordinary loss in native UDP mode produces the same shape.
func TestDefraggerExpiresIncompleteFragments(t *testing.T) {
	d := newUDPDefragger()
	start := time.Now()

	held := make([]*udpMessage, 0, 8)
	for i := 0; i < 8; i++ {
		m := fragment(uint16(i), 1, 2, bytes.Repeat([]byte{byte(i)}, 1024))
		held = append(held, m)
		if out := d.feedAt(start, m); out != nil {
			t.Fatalf("incomplete fragment set %d reassembled", i)
		}
	}
	if got := d.size(); got != 8 {
		t.Fatalf("buffered fragment sets = %d, want 8", got)
	}

	// Nothing has expired yet.
	d.feedAt(start.Add(defragTTL-time.Second), fragment(100, 1, 2, []byte("x")))
	if got := d.size(); got != 9 {
		t.Fatalf("buffered fragment sets before TTL = %d, want 9", got)
	}

	// Past the TTL every set older than the TTL is swept on the next insert.
	// The two survivors are packet 100 (fed one second before the TTL elapsed)
	// and packet 200 (just fed).
	d.feedAt(start.Add(defragTTL+time.Second), fragment(200, 1, 2, []byte("y")))
	if got := d.size(); got != 2 {
		t.Fatalf("buffered fragment sets after TTL = %d, want 2 (the two still inside their TTL)", got)
	}

	// The payloads must actually be dropped, not merely unmapped: anything still
	// holding the *udpMessage would otherwise keep 1 KiB alive per fragment.
	for i, m := range held {
		if m.data != nil {
			t.Fatalf("fragment %d still holds %d bytes after expiry", i, len(m.data))
		}
	}
}

// The TTL alone still allows a flood of fresh packet IDs within one TTL window,
// so the map is also hard-capped.
func TestDefraggerCapsInflightFragmentSets(t *testing.T) {
	d := newUDPDefragger()
	now := time.Now()
	for i := 0; i < defragMaxItems*4; i++ {
		// uint16 wraps at 65536; defragMaxItems*4 stays well under that.
		d.feedAt(now, fragment(uint16(i), 1, 2, bytes.Repeat([]byte{1}, 512)))
	}
	if got := d.size(); got > defragMaxItems {
		t.Fatalf("buffered fragment sets = %d, want <= %d", got, defragMaxItems)
	}
}

func TestDefraggerReassembles(t *testing.T) {
	d := newUDPDefragger()
	now := time.Now()

	if out := d.feedAt(now, fragment(7, 1, 3, []byte("world"))); out != nil {
		t.Fatal("reassembled before all fragments arrived")
	}
	if out := d.feedAt(now, fragment(7, 2, 3, []byte("!"))); out != nil {
		t.Fatal("reassembled before all fragments arrived")
	}
	out := d.feedAt(now, fragment(7, 0, 3, []byte("hello ")))
	if out == nil {
		t.Fatal("did not reassemble a complete fragment set")
	}
	if string(out.data) != "hello world!" {
		t.Fatalf("reassembled payload = %q, want %q", out.data, "hello world!")
	}
	if !out.destination.IsValid() {
		t.Fatal("reassembled message lost its destination")
	}
	if got := d.size(); got != 0 {
		t.Fatalf("buffered fragment sets after reassembly = %d, want 0", got)
	}
}

func TestDefraggerRejectsOutOfRangeFragment(t *testing.T) {
	d := newUDPDefragger()
	if out := d.feedAt(time.Now(), fragment(1, 5, 3, []byte("x"))); out != nil {
		t.Fatal("accepted a fragment ID beyond the fragment total")
	}
	if got := d.size(); got != 0 {
		t.Fatalf("buffered fragment sets = %d, want 0", got)
	}
}

// A fragment set whose total changes mid-flight is restarted, and the buffers
// from the abandoned set are released.
func TestDefraggerRestartsOnFragmentTotalChange(t *testing.T) {
	d := newUDPDefragger()
	now := time.Now()

	first := fragment(3, 1, 2, bytes.Repeat([]byte{9}, 256))
	d.feedAt(now, first)
	d.feedAt(now, fragment(3, 1, 4, bytes.Repeat([]byte{8}, 256)))

	if first.data != nil {
		t.Fatal("abandoned fragment set still holds its payload")
	}
	if got := d.size(); got != 1 {
		t.Fatalf("buffered fragment sets = %d, want 1", got)
	}
}

// udpTimeout was parsed, stored, and never read: idle UDP associations were
// never reaped, so a client could pin one dispatched link per session ID.
func TestUDPPacketConnReapsIdleAssociation(t *testing.T) {
	destroyed := make(chan struct{})
	c := newUDPPacketConn(context.Background(), nil, false, true, nil, func() {
		close(destroyed)
	})
	go c.watchIdle(50 * time.Millisecond)

	select {
	case <-destroyed:
	case <-time.After(3 * time.Second):
		t.Fatal("idle association was never reaped")
	}
	if !c.done() {
		t.Fatal("association reported as reaped but its context is still live")
	}
	if _, _, err := c.ReadPacket(); err == nil {
		t.Fatal("reading from a reaped association should fail")
	}
}

// Traffic must keep the association alive.
func TestUDPPacketConnIdleTimerResetsOnTraffic(t *testing.T) {
	destroyed := make(chan struct{})
	c := newUDPPacketConn(context.Background(), nil, false, true, nil, func() {
		close(destroyed)
	})
	go c.watchIdle(200 * time.Millisecond)

	deadline := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(deadline) {
		c.inputPacket(&udpMessage{fragmentTotal: 1, data: []byte("keepalive")})
		time.Sleep(50 * time.Millisecond)
		select {
		case <-destroyed:
			t.Fatal("association reaped while still carrying traffic")
		default:
		}
	}

	select {
	case <-destroyed:
	case <-time.After(3 * time.Second):
		t.Fatal("association was never reaped after traffic stopped")
	}
}
