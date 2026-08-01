package reno

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

const testMSS = congestion.ByteCount(1280)

type fakeRTTStats struct {
	latest   time.Duration
	minimum  time.Duration
	smoothed time.Duration
}

func (r *fakeRTTStats) MinRTT() time.Duration          { return r.minimum }
func (r *fakeRTTStats) LatestRTT() time.Duration       { return r.latest }
func (r *fakeRTTStats) SmoothedRTT() time.Duration     { return r.smoothed }
func (r *fakeRTTStats) MeanDeviation() time.Duration   { return 0 }
func (r *fakeRTTStats) MaxAckDelay() time.Duration     { return 0 }
func (r *fakeRTTStats) PTO(bool) time.Duration         { return r.smoothed }
func (r *fakeRTTStats) UpdateRTT(_, _ time.Duration)   {}
func (r *fakeRTTStats) SetMaxAckDelay(_ time.Duration) {}
func (r *fakeRTTStats) SetInitialRTT(t time.Duration)  { r.smoothed = t }

func newTestSender() *Sender {
	s := NewSender(testMSS)
	s.SetRTTStatsProvider(&fakeRTTStats{
		latest:   50 * time.Millisecond,
		minimum:  50 * time.Millisecond,
		smoothed: 50 * time.Millisecond,
	})
	return s
}

// ack drives one packet through send + ack with the sender kept cwnd-limited,
// which is the only state in which either algorithm grows the window.
func ack(s *Sender, packetNumber congestion.PacketNumber) {
	now := monotime.Now()
	s.OnPacketSent(now, s.GetCongestionWindow(), packetNumber, testMSS, true)
	s.OnPacketAcked(packetNumber, testMSS, s.GetCongestionWindow(), now)
}

func TestInitialWindow(t *testing.T) {
	s := newTestSender()
	if got, want := s.GetCongestionWindow(), initialCongestionWindow*testMSS; got != want {
		t.Fatalf("initial cwnd = %d, want %d", got, want)
	}
	if !s.InSlowStart() {
		t.Fatal("sender did not start in slow start")
	}
	if !s.CanSend(0) {
		t.Fatal("sender cannot send with nothing in flight")
	}
}

// Slow start is exponential: one extra MSS per ACK.
func TestSlowStartGrowsOnePacketPerAck(t *testing.T) {
	s := newTestSender()
	before := s.GetCongestionWindow()
	for i := 1; i <= 10; i++ {
		ack(s, congestion.PacketNumber(i))
	}
	if got, want := s.GetCongestionWindow(), before+10*testMSS; got != want {
		t.Fatalf("cwnd after 10 slow-start acks = %d, want %d", got, want)
	}
}

// The Reno backoff: cwnd *= 0.7 on loss, and slow start ends there.
func TestLossAppliesRenoBeta(t *testing.T) {
	s := newTestSender()
	for i := 1; i <= 5; i++ {
		ack(s, congestion.PacketNumber(i))
	}
	before := s.GetCongestionWindow()

	s.OnPacketSent(monotime.Now(), before, 6, testMSS, true)
	s.OnCongestionEvent(6, testMSS, before)

	want := congestion.ByteCount(float64(before) * renoBeta)
	if got := s.GetCongestionWindow(); got != want {
		t.Fatalf("cwnd after loss = %d, want %d (%.2f x %d)", got, want, renoBeta, before)
	}
	if s.InSlowStart() {
		t.Fatal("still in slow start after a loss event")
	}
	if !s.InRecovery() {
		t.Fatal("not in recovery right after a loss event")
	}
}

// This is the test that distinguishes New Reno from the CUBIC the server used to
// silently fall back to. In congestion avoidance Reno adds exactly one MSS per
// cwnd-worth of ACKs (one MSS per RTT), independent of elapsed time. CUBIC grows
// as a cubic function of the time since the last loss epoch and would overshoot
// this by a wide margin.
func TestCongestionAvoidanceGrowsOneMSSPerWindow(t *testing.T) {
	s := newTestSender()

	// Force congestion avoidance via a loss event.
	var packetNumber congestion.PacketNumber
	for i := 1; i <= 5; i++ {
		packetNumber = congestion.PacketNumber(i)
		ack(s, packetNumber)
	}
	packetNumber++
	s.OnPacketSent(monotime.Now(), s.GetCongestionWindow(), packetNumber, testMSS, true)
	s.OnCongestionEvent(packetNumber, testMSS, s.GetCongestionWindow())

	// Leave recovery: recovery ends once a packet sent after the cutback is acked.
	packetNumber++
	ack(s, packetNumber)
	if s.InRecovery() {
		t.Fatal("still in recovery after acking a packet sent past the cutback")
	}
	if s.InSlowStart() {
		t.Fatal("back in slow start, expected congestion avoidance")
	}

	before := s.GetCongestionWindow()
	packetsPerWindow := int(before / testMSS)

	// One window of ACKs must add exactly one MSS.
	for i := 0; i < packetsPerWindow; i++ {
		packetNumber++
		ack(s, packetNumber)
	}
	if got, want := s.GetCongestionWindow(), before+testMSS; got != want {
		t.Fatalf("cwnd after one window of acks = %d, want %d (grew %d MSS, want 1)",
			got, want, (got-before)/testMSS)
	}

	// And a second window adds exactly one more.
	before = s.GetCongestionWindow()
	packetsPerWindow = int(before / testMSS)
	for i := 0; i < packetsPerWindow; i++ {
		packetNumber++
		ack(s, packetNumber)
	}
	if got, want := s.GetCongestionWindow(), before+testMSS; got != want {
		t.Fatalf("cwnd after a second window of acks = %d, want %d", got, want)
	}
}

// An application-limited sender must not inflate its window.
func TestNoGrowthWhenNotCwndLimited(t *testing.T) {
	s := newTestSender()
	before := s.GetCongestionWindow()
	now := monotime.Now()
	for i := 1; i <= 10; i++ {
		s.OnPacketSent(now, 0, congestion.PacketNumber(i), testMSS, true)
		s.OnPacketAcked(congestion.PacketNumber(i), testMSS, 0, now)
	}
	if got := s.GetCongestionWindow(); got != before {
		t.Fatalf("cwnd grew to %d while application limited, want %d", got, before)
	}
}

func TestLossCannotDriveWindowBelowMinimum(t *testing.T) {
	s := newTestSender()
	var packetNumber congestion.PacketNumber
	for i := 0; i < 50; i++ {
		packetNumber++
		s.OnPacketSent(monotime.Now(), s.GetCongestionWindow(), packetNumber, testMSS, true)
		s.OnCongestionEvent(packetNumber, testMSS, s.GetCongestionWindow())
	}
	if got, want := s.GetCongestionWindow(), minCongestionWindowPackets*testMSS; got != want {
		t.Fatalf("cwnd after repeated losses = %d, want the %d floor", got, want)
	}
}

func TestRetransmissionTimeoutHalvesThreshold(t *testing.T) {
	s := newTestSender()
	for i := 1; i <= 10; i++ {
		ack(s, congestion.PacketNumber(i))
	}
	before := s.GetCongestionWindow()

	s.OnRetransmissionTimeout(true)

	if got, want := s.GetCongestionWindow(), minCongestionWindowPackets*testMSS; got != want {
		t.Fatalf("cwnd after RTO = %d, want %d", got, want)
	}
	if got, want := s.slowStartThreshold, before/2; got != want {
		t.Fatalf("ssthresh after RTO = %d, want %d", got, want)
	}
}

// The pacer must never see a zero bandwidth: quic-go's send loop spins when
// HasPacingBudget is false while TimeUntilSend is already in the past.
func TestPacerBandwidthNeverZero(t *testing.T) {
	s := NewSender(testMSS) // no RTT stats provider installed yet
	if got := s.bandwidthForPacer(); got <= 0 {
		t.Fatalf("pacer bandwidth without RTT stats = %d, want > 0", got)
	}
	s.SetRTTStatsProvider(&fakeRTTStats{})
	if got := s.bandwidthForPacer(); got <= 0 {
		t.Fatalf("pacer bandwidth with a zero RTT = %d, want > 0", got)
	}
}

func TestSetMaxDatagramSizeDoesNotPanicOnShrink(t *testing.T) {
	s := newTestSender()
	s.SetMaxDatagramSize(testMSS * 2)
	if got := s.maxDatagramSize; got != testMSS*2 {
		t.Fatalf("maxDatagramSize = %d, want %d", got, testMSS*2)
	}
	s.SetMaxDatagramSize(testMSS / 2) // quic-go's own sender panics here
	if got := s.maxDatagramSize; got != testMSS*2 {
		t.Fatalf("maxDatagramSize = %d after a shrink, want it clamped at %d", got, testMSS*2)
	}
}

func TestImplementsCongestionControl(t *testing.T) {
	var _ congestion.CongestionControl = NewSender(testMSS)
}
