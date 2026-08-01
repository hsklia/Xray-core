package reno

import (
	"time"

	"github.com/apernet/quic-go/congestion"
)

// Ported verbatim from github.com/apernet/quic-go internal/congestion/hybrid_slow_start.go,
// which is unimportable (internal/). The magic clamping numbers come from the
// original code in tcp_cubic.c.

const hybridStartLowWindow = congestion.ByteCount(16)

// Number of delay samples for detecting the increase of delay.
const hybridStartMinSamples = uint32(8)

// Exit slow start if the min rtt has increased by more than 1/8th.
const hybridStartDelayFactorExp = 3 // 2^3 = 8

// The original paper specifies 2 and 8ms, but those have changed over time.
const (
	hybridStartDelayMinThresholdUs = int64(4000)
	hybridStartDelayMaxThresholdUs = int64(16000)
)

// hybridSlowStart implements the TCP hybrid slow start algorithm.
type hybridSlowStart struct {
	endPacketNumber      congestion.PacketNumber
	lastSentPacketNumber congestion.PacketNumber
	started              bool
	currentMinRTT        time.Duration
	rttSampleCount       uint32
	hystartFound         bool
}

// StartReceiveRound is called for the start of each receive round (burst) in the slow start phase.
func (s *hybridSlowStart) StartReceiveRound(lastSent congestion.PacketNumber) {
	s.endPacketNumber = lastSent
	s.currentMinRTT = 0
	s.rttSampleCount = 0
	s.started = true
}

// IsEndOfRound returns true if this ack is the last packet number of our current slow start round.
func (s *hybridSlowStart) IsEndOfRound(ack congestion.PacketNumber) bool {
	return s.endPacketNumber < ack
}

// ShouldExitSlowStart should be called on every new ack frame, since a new
// RTT measurement can be made then.
// latestRTT: the RTT for this ack packet.
// minRTT: the lowest delay (RTT) we have seen during the session.
// congestionWindow: the congestion window in packets.
func (s *hybridSlowStart) ShouldExitSlowStart(latestRTT, minRTT time.Duration, congestionWindow congestion.ByteCount) bool {
	if !s.started {
		// Time to start the hybrid slow start.
		s.StartReceiveRound(s.lastSentPacketNumber)
	}
	if s.hystartFound {
		return true
	}
	// Second detection parameter - delay increase detection.
	// Compare the minimum delay (s.currentMinRTT) of the current
	// burst of packets relative to the minimum delay during the session.
	// Note: we only look at the first few(8) packets in each burst, since we
	// only want to compare the lowest RTT of the burst relative to previous bursts.
	s.rttSampleCount++
	if s.rttSampleCount <= hybridStartMinSamples {
		if s.currentMinRTT == 0 || s.currentMinRTT > latestRTT {
			s.currentMinRTT = latestRTT
		}
	}
	// We only need to check this once per round.
	if s.rttSampleCount == hybridStartMinSamples {
		// Divide minRTT by 8 to get a rtt increase threshold for exiting.
		minRTTincreaseThresholdUs := int64(minRTT / time.Microsecond >> hybridStartDelayFactorExp)
		// Ensure the rtt threshold is never less than 4ms or more than 16ms.
		minRTTincreaseThresholdUs = min(minRTTincreaseThresholdUs, hybridStartDelayMaxThresholdUs)
		minRTTincreaseThreshold := time.Duration(max(minRTTincreaseThresholdUs, hybridStartDelayMinThresholdUs)) * time.Microsecond

		if s.currentMinRTT > (minRTT + minRTTincreaseThreshold) {
			s.hystartFound = true
		}
	}
	// Exit from slow start if the cwnd is greater than 16 and increasing delay is found.
	return congestionWindow >= hybridStartLowWindow && s.hystartFound
}

// OnPacketSent is called when a packet was sent.
func (s *hybridSlowStart) OnPacketSent(packetNumber congestion.PacketNumber) {
	s.lastSentPacketNumber = packetNumber
}

// OnPacketAcked gets invoked after ShouldExitSlowStart, so it's best to end
// the round when the final packet of the burst is received and start it on
// the next incoming ack.
func (s *hybridSlowStart) OnPacketAcked(ackedPacketNumber congestion.PacketNumber) {
	if s.IsEndOfRound(ackedPacketNumber) {
		s.started = false
	}
}

// Started returns true if started.
func (s *hybridSlowStart) Started() bool {
	return s.started
}

// Restart the slow start phase.
func (s *hybridSlowStart) Restart() {
	s.started = false
	s.hystartFound = false
}
