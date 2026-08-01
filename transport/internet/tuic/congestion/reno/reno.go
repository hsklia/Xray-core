// Package reno implements TCP New Reno (RFC 6582) congestion control against
// the public github.com/apernet/quic-go congestion.CongestionControl interface.
//
// quic-go already contains this algorithm: internal/congestion/cubic_sender.go
// carries a `reno bool` that switches its increase/decrease rules from CUBIC to
// New Reno. That package is under internal/ and cannot be imported, and the
// public quic-go API exposes no way to ask for it, so `SetCongestionControl` is
// the only lever available and it needs a sender of our own. This file is a
// port of that sender with `reno` fixed to true: the CUBIC bookkeeping and the
// qlog/connection-stats plumbing are dropped, everything else (hybrid slow
// start, the pacer, the cwnd rules, the recovery rules) matches upstream.
package reno

import (
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"

	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/common"
)

const (
	maxBurstPackets            = 3
	renoBeta                   = 0.7 // Reno backoff factor.
	minCongestionWindowPackets = 2
	initialCongestionWindow    = 32

	invalidPacketNumber congestion.PacketNumber = -1
	maxByteCount                                = congestion.ByteCount(1<<62 - 1)

	// timerGranularity mirrors protocol.TimerGranularity.
	timerGranularity = time.Millisecond
	// minPacerBandwidth keeps the pacer's bandwidth estimate off zero. At zero
	// the pacer reports HasPacingBudget=false while TimeUntilSend is already in
	// the past, and quic-go's send loop spins. Same guard bbr uses.
	minPacerBandwidth = congestion.ByteCount(16 * 1024)
)

// Sender is a New Reno congestion controller.
type Sender struct {
	hybridSlowStart hybridSlowStart
	rttStats        congestion.RTTStatsProvider
	pacer           *common.Pacer

	// Track the largest packet that has been sent.
	largestSentPacketNumber congestion.PacketNumber

	// Track the largest packet that has been acked.
	largestAckedPacketNumber congestion.PacketNumber

	// Track the largest packet number outstanding when a CWND cutback occurs.
	largestSentAtLastCutback congestion.PacketNumber

	// Whether the last loss event caused us to exit slow start.
	lastCutbackExitedSlowstart bool

	// Congestion window in bytes.
	congestionWindow congestion.ByteCount

	// Slow start congestion window in bytes, aka ssthresh.
	slowStartThreshold congestion.ByteCount

	// ACK counter for the Reno implementation.
	numAckedPackets uint64

	initialCongestionWindow    congestion.ByteCount
	initialMaxCongestionWindow congestion.ByteCount

	maxDatagramSize congestion.ByteCount
}

var _ congestion.CongestionControl = (*Sender)(nil)

// NewSender makes a new New Reno sender.
func NewSender(initialMaxDatagramSize congestion.ByteCount) *Sender {
	return newSender(
		initialMaxDatagramSize,
		initialCongestionWindow*initialMaxDatagramSize,
		congestion.MaxCongestionWindowPackets*initialMaxDatagramSize,
	)
}

func newSender(initialMaxDatagramSize, initialCongestionWindow, initialMaxCongestionWindow congestion.ByteCount) *Sender {
	s := &Sender{
		largestSentPacketNumber:    invalidPacketNumber,
		largestAckedPacketNumber:   invalidPacketNumber,
		largestSentAtLastCutback:   invalidPacketNumber,
		initialCongestionWindow:    initialCongestionWindow,
		initialMaxCongestionWindow: initialMaxCongestionWindow,
		congestionWindow:           initialCongestionWindow,
		slowStartThreshold:         maxByteCount,
		maxDatagramSize:            initialMaxDatagramSize,
	}
	s.pacer = common.NewPacer(s.bandwidthForPacer)
	s.pacer.SetMaxDatagramSize(initialMaxDatagramSize)
	return s
}

// SetRTTStatsProvider is called by quic-go right after the sender is installed.
func (s *Sender) SetRTTStatsProvider(provider congestion.RTTStatsProvider) {
	s.rttStats = provider
}

// TimeUntilSend returns when the next packet should be sent.
func (s *Sender) TimeUntilSend(_ congestion.ByteCount) monotime.Time {
	return s.pacer.TimeUntilSend()
}

func (s *Sender) HasPacingBudget(now monotime.Time) bool {
	return s.pacer.Budget(now) >= s.maxDatagramSize
}

func (s *Sender) maxCongestionWindow() congestion.ByteCount {
	return s.maxDatagramSize * congestion.MaxCongestionWindowPackets
}

func (s *Sender) minCongestionWindow() congestion.ByteCount {
	return s.maxDatagramSize * minCongestionWindowPackets
}

func (s *Sender) OnPacketSent(
	sentTime monotime.Time,
	_ congestion.ByteCount,
	packetNumber congestion.PacketNumber,
	bytes congestion.ByteCount,
	isRetransmittable bool,
) {
	s.pacer.SentPacket(sentTime, bytes)
	if !isRetransmittable {
		return
	}
	s.largestSentPacketNumber = packetNumber
	s.hybridSlowStart.OnPacketSent(packetNumber)
}

func (s *Sender) CanSend(bytesInFlight congestion.ByteCount) bool {
	return bytesInFlight < s.GetCongestionWindow()
}

func (s *Sender) InRecovery() bool {
	return s.largestAckedPacketNumber != invalidPacketNumber && s.largestAckedPacketNumber <= s.largestSentAtLastCutback
}

func (s *Sender) InSlowStart() bool {
	return s.GetCongestionWindow() < s.slowStartThreshold
}

func (s *Sender) GetCongestionWindow() congestion.ByteCount {
	return s.congestionWindow
}

func (s *Sender) MaybeExitSlowStart() {
	if s.rttStats == nil {
		return
	}
	if s.InSlowStart() &&
		s.hybridSlowStart.ShouldExitSlowStart(s.rttStats.LatestRTT(), s.rttStats.MinRTT(), s.GetCongestionWindow()/s.maxDatagramSize) {
		// exit slow start
		s.slowStartThreshold = s.congestionWindow
	}
}

func (s *Sender) OnPacketAcked(
	ackedPacketNumber congestion.PacketNumber,
	ackedBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount,
	eventTime monotime.Time,
) {
	s.largestAckedPacketNumber = max(ackedPacketNumber, s.largestAckedPacketNumber)
	if s.InRecovery() {
		return
	}
	s.maybeIncreaseCwnd(ackedPacketNumber, ackedBytes, priorInFlight, eventTime)
	if s.InSlowStart() {
		s.hybridSlowStart.OnPacketAcked(ackedPacketNumber)
	}
}

func (s *Sender) OnCongestionEvent(packetNumber congestion.PacketNumber, lostBytes, priorInFlight congestion.ByteCount) {
	// TCP NewReno (RFC6582) says that once a loss occurs, any losses in packets
	// already sent should be treated as a single loss event, since it's expected.
	if packetNumber <= s.largestSentAtLastCutback {
		return
	}
	s.lastCutbackExitedSlowstart = s.InSlowStart()

	s.congestionWindow = congestion.ByteCount(float64(s.congestionWindow) * renoBeta)
	if minCwnd := s.minCongestionWindow(); s.congestionWindow < minCwnd {
		s.congestionWindow = minCwnd
	}
	s.slowStartThreshold = s.congestionWindow
	s.largestSentAtLastCutback = s.largestSentPacketNumber
	// Reset the packet count from congestion avoidance mode. We start counting
	// again when we're out of recovery.
	s.numAckedPackets = 0
}

// maybeIncreaseCwnd is called when we receive an ack. Normal TCP tracks how many
// packets one ack represents, but QUIC has a separate ack for each packet.
func (s *Sender) maybeIncreaseCwnd(
	_ congestion.PacketNumber,
	_ congestion.ByteCount,
	priorInFlight congestion.ByteCount,
	_ monotime.Time,
) {
	// Do not increase the congestion window unless the sender is close to using
	// the current window.
	if !s.isCwndLimited(priorInFlight) {
		return
	}
	if s.congestionWindow >= s.maxCongestionWindow() {
		return
	}
	if s.InSlowStart() {
		// TCP slow start, exponential growth, increase by one for each ACK.
		s.congestionWindow += s.maxDatagramSize
		return
	}
	// Classic Reno congestion avoidance: one extra datagram per cwnd worth of ACKs.
	s.numAckedPackets++
	if s.numAckedPackets >= uint64(s.congestionWindow/s.maxDatagramSize) {
		s.congestionWindow += s.maxDatagramSize
		s.numAckedPackets = 0
	}
}

func (s *Sender) isCwndLimited(bytesInFlight congestion.ByteCount) bool {
	congestionWindow := s.GetCongestionWindow()
	if bytesInFlight >= congestionWindow {
		return true
	}
	availableBytes := congestionWindow - bytesInFlight
	slowStartLimited := s.InSlowStart() && bytesInFlight > congestionWindow/2
	return slowStartLimited || availableBytes <= maxBurstPackets*s.maxDatagramSize
}

// bandwidthForPacer returns the current bandwidth estimate in bytes per second.
func (s *Sender) bandwidthForPacer() congestion.ByteCount {
	srtt := timerGranularity
	if s.rttStats != nil {
		if rtt := s.rttStats.SmoothedRTT(); rtt > 0 {
			srtt = rtt
		}
	}
	bps := congestion.ByteCount(int64(s.GetCongestionWindow()) * int64(time.Second) / int64(srtt))
	if bps < minPacerBandwidth {
		return minPacerBandwidth
	}
	return bps
}

// OnRetransmissionTimeout is called on a retransmission timeout.
func (s *Sender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	s.largestSentAtLastCutback = invalidPacketNumber
	if !packetsRetransmitted {
		return
	}
	s.hybridSlowStart.Restart()
	s.slowStartThreshold = s.congestionWindow / 2
	s.congestionWindow = s.minCongestionWindow()
}

// OnConnectionMigration resets the controller after a path change.
func (s *Sender) OnConnectionMigration() {
	s.hybridSlowStart.Restart()
	s.largestSentPacketNumber = invalidPacketNumber
	s.largestAckedPacketNumber = invalidPacketNumber
	s.largestSentAtLastCutback = invalidPacketNumber
	s.lastCutbackExitedSlowstart = false
	s.numAckedPackets = 0
	s.congestionWindow = s.initialCongestionWindow
	s.slowStartThreshold = s.initialMaxCongestionWindow
}

func (s *Sender) SetMaxDatagramSize(size congestion.ByteCount) {
	if size < s.maxDatagramSize {
		// quic-go's own sender panics here. A live proxy must not die because a
		// peer shrank its datagram size, so clamp instead.
		return
	}
	cwndIsMinCwnd := s.congestionWindow == s.minCongestionWindow()
	s.maxDatagramSize = size
	if cwndIsMinCwnd {
		s.congestionWindow = s.minCongestionWindow()
	}
	s.pacer.SetMaxDatagramSize(size)
}
