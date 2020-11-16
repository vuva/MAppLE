package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockCongestion struct {
	argsOnPacketSent        []interface{}
	maybeExitSlowStart      bool
	onRetransmissionTimeout bool
	getCongestionWindow     bool
	packetsAcked            [][]interface{}
	packetsLost             [][]interface{}
}

func (m *mockCongestion) TimeUntilSend(now time.Time, bytesInFlight protocol.ByteCount) time.Duration {
	panic("not implemented")
}

func (m *mockCongestion) OnPacketSent(sentTime time.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) bool {
	m.argsOnPacketSent = []interface{}{sentTime, bytesInFlight, packetNumber, bytes, isRetransmittable}
	return false
}

func (m *mockCongestion) GetCongestionWindow() protocol.ByteCount {
	m.getCongestionWindow = true
	return protocol.DefaultTCPMSS
}

func (m *mockCongestion) MaybeExitSlowStart() {
	m.maybeExitSlowStart = true
}

func (m *mockCongestion) OnRetransmissionTimeout(packetsRetransmitted bool) {
	m.onRetransmissionTimeout = true
}

func (m *mockCongestion) RetransmissionDelay() time.Duration {
	return defaultRTOTimeout
}

func (m *mockCongestion) SetNumEmulatedConnections(n int)         { panic("not implemented") }
func (m *mockCongestion) OnConnectionMigration()                  { panic("not implemented") }
func (m *mockCongestion) SetSlowStartLargeReduction(enabled bool) { panic("not implemented") }
func (m *mockCongestion) SmoothedRTT() time.Duration              { return defaultRTOTimeout / 10 }

func (m *mockCongestion) OnPacketAcked(n protocol.PacketNumber, l protocol.ByteCount, bif protocol.ByteCount) {
	m.packetsAcked = append(m.packetsAcked, []interface{}{n, l, bif})
}

func (m *mockCongestion) OnPacketLost(n protocol.PacketNumber, l protocol.ByteCount, bif protocol.ByteCount) {
	m.packetsLost = append(m.packetsLost, []interface{}{n, l, bif})
}

func retransmittablePacket(num protocol.PacketNumber) *Packet {
	return &Packet{
		PacketNumber:    num,
		Length:          1,
		Frames:          []wire.Frame{&wire.PingFrame{}},
		EncryptionLevel: protocol.EncryptionForwardSecure,
	}
}

func nonRetransmittablePacket(num protocol.PacketNumber) *Packet {
	return &Packet{PacketNumber: num, Length: 1, Frames: []wire.Frame{&wire.AckFrame{}}}
}

func handshakePacket(num protocol.PacketNumber) *Packet {
	return &Packet{
		PacketNumber:    num,
		Length:          1,
		Frames:          []wire.Frame{&wire.PingFrame{}},
		EncryptionLevel: protocol.EncryptionUnencrypted,
	}
}

var _ = Describe("SentPacketHandler", func() {
	var (
		handler     *sentPacketHandler
		streamFrame wire.StreamFrame
	)

	BeforeEach(func() {
		rttStats := &congestion.RTTStats{}
		handler = NewSentPacketHandler(rttStats, nil, nil, func(_ protocol.PacketNumber) {}, func(_ protocol.PacketNumber) {}, false).(*sentPacketHandler)
		handler.SetHandshakeComplete()
		streamFrame = wire.StreamFrame{
			StreamID: 5,
			Data:     []byte{0x13, 0x37},
		}
	})

	getPacketElement := func(p protocol.PacketNumber) *PacketElement {
		for el := handler.packetHistory.Front(); el != nil; el = el.Next() {
			if el.Value.PacketNumber == p {
				return el
			}
		}
		return nil
	}

	It("gets the LeastUnacked packet number", func() {
		handler.LargestAcked = 0x1337
		Expect(handler.GetLeastUnacked()).To(Equal(protocol.PacketNumber(0x1337 + 1)))
	})

	Context("registering sent packets", func() {
		It("accepts two consecutive packets", func() {
			packet1 := Packet{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1}
			packet2 := Packet{PacketNumber: 2, Frames: []wire.Frame{&streamFrame}, Length: 2}
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.packetHistory.Back().Value.PacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(3)))
			Expect(handler.skippedPackets).To(BeEmpty())
		})

		It("rejects packets with the same packet number", func() {
			packet1 := Packet{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1}
			packet2 := Packet{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 2}
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).To(MatchError(errPacketNumberNotIncreasing))
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(1)))
			Expect(handler.skippedPackets).To(BeEmpty())
		})

		It("rejects packets with decreasing packet number", func() {
			packet1 := Packet{PacketNumber: 2, Frames: []wire.Frame{&streamFrame}, Length: 1}
			packet2 := Packet{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 2}
			err := handler.SentPacket(&packet1)
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(&packet2)
			Expect(err).To(MatchError(errPacketNumberNotIncreasing))
			Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(1)))
		})

		It("stores the sent time", func() {
			packet := Packet{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1}
			err := handler.SentPacket(&packet)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.packetHistory.Front().Value.SendTime.Unix()).To(BeNumerically("~", time.Now().Unix(), 1))
		})

		It("does not store non-retransmittable packets", func() {
			err := handler.SentPacket(&Packet{PacketNumber: 1, Length: 1})
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.packetHistory.Len()).To(BeZero())
		})

		Context("skipped packet numbers", func() {
			It("works with non-consecutive packet numbers", func() {
				packet1 := Packet{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1}
				packet2 := Packet{PacketNumber: 3, Frames: []wire.Frame{&streamFrame}, Length: 2}
				err := handler.SentPacket(&packet1)
				Expect(err).ToNot(HaveOccurred())
				err = handler.SentPacket(&packet2)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.lastSentPacketNumber).To(Equal(protocol.PacketNumber(3)))
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(1)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(3)))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(3)))
				Expect(handler.skippedPackets).To(HaveLen(1))
				Expect(handler.skippedPackets[0]).To(Equal(protocol.PacketNumber(2)))
			})

			It("recognizes multiple skipped packets", func() {
				packet1 := Packet{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1}
				packet2 := Packet{PacketNumber: 3, Frames: []wire.Frame{&streamFrame}, Length: 2}
				packet3 := Packet{PacketNumber: 5, Frames: []wire.Frame{&streamFrame}, Length: 2}
				err := handler.SentPacket(&packet1)
				Expect(err).ToNot(HaveOccurred())
				err = handler.SentPacket(&packet2)
				Expect(err).ToNot(HaveOccurred())
				err = handler.SentPacket(&packet3)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.skippedPackets).To(HaveLen(2))
				Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{2, 4}))
			})

			It("recognizes multiple consecutive skipped packets", func() {
				packet1 := Packet{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1}
				packet2 := Packet{PacketNumber: 4, Frames: []wire.Frame{&streamFrame}, Length: 2}
				err := handler.SentPacket(&packet1)
				Expect(err).ToNot(HaveOccurred())
				err = handler.SentPacket(&packet2)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.skippedPackets).To(HaveLen(2))
				Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{2, 3}))
			})

			It("limits the lengths of the skipped packet slice", func() {
				for i := 0; i < protocol.MaxTrackedSkippedPackets+5; i++ {
					packet := Packet{PacketNumber: protocol.PacketNumber(2*i + 1), Frames: []wire.Frame{&streamFrame}, Length: 1}
					err := handler.SentPacket(&packet)
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(handler.skippedPackets).To(HaveLen(protocol.MaxUndecryptablePackets))
				Expect(handler.skippedPackets[0]).To(Equal(protocol.PacketNumber(10)))
				Expect(handler.skippedPackets[protocol.MaxTrackedSkippedPackets-1]).To(Equal(protocol.PacketNumber(10 + 2*(protocol.MaxTrackedSkippedPackets-1))))
			})

			Context("garbage collection", func() {
				It("keeps all packet numbers above the LargestAcked", func() {
					handler.skippedPackets = []protocol.PacketNumber{2, 5, 8, 10}
					handler.LargestAcked = 1
					handler.garbageCollectSkippedPackets()
					Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{2, 5, 8, 10}))
				})

				It("doesn't keep packet numbers below the LargestAcked", func() {
					handler.skippedPackets = []protocol.PacketNumber{1, 5, 8, 10}
					handler.LargestAcked = 5
					handler.garbageCollectSkippedPackets()
					Expect(handler.skippedPackets).To(Equal([]protocol.PacketNumber{8, 10}))
				})

				It("deletes all packet numbers if LargestAcked is sufficiently high", func() {
					handler.skippedPackets = []protocol.PacketNumber{1, 5, 10}
					handler.LargestAcked = 15
					handler.garbageCollectSkippedPackets()
					Expect(handler.skippedPackets).To(BeEmpty())
				})
			})
		})
	})

	Context("forcing retransmittable packets", func() {
		It("says that every 20th packet should be retransmittable", func() {
			// send 19 non-retransmittable packets
			for i := 1; i <= protocol.MaxNonRetransmittablePackets; i++ {
				Expect(handler.ShouldSendRetransmittablePacket()).To(BeFalse())
				err := handler.SentPacket(nonRetransmittablePacket(protocol.PacketNumber(i)))
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.ShouldSendRetransmittablePacket()).To(BeTrue())
		})

		It("resets the counter when a retransmittable packet is sent", func() {
			// send 19 non-retransmittable packets
			for i := 1; i <= protocol.MaxNonRetransmittablePackets; i++ {
				Expect(handler.ShouldSendRetransmittablePacket()).To(BeFalse())
				err := handler.SentPacket(nonRetransmittablePacket(protocol.PacketNumber(i)))
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.SentPacket(retransmittablePacket(20))
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.ShouldSendRetransmittablePacket()).To(BeFalse())
		})
	})

	Context("DoS mitigation", func() {
		It("checks the size of the packet history, for unacked packets", func() {
			i := protocol.PacketNumber(1)
			for ; i <= protocol.MaxTrackedSentPackets; i++ {
				err := handler.SentPacket(retransmittablePacket(i))
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.SentPacket(retransmittablePacket(i))
			Expect(err).To(MatchError(ErrTooManyTrackedSentPackets))
		})

		// TODO: add a test that the length of the retransmission queue is considered, even if packets have already been ACKed. Relevant once we drop support for QUIC 33 and earlier
	})

	Context("ACK processing", func() {
		var packets []*Packet

		BeforeEach(func() {
			packets = []*Packet{
				{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 2, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 3, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 4, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 5, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 6, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 7, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 8, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 9, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 10, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 12, Frames: []wire.Frame{&streamFrame}, Length: 1},
			}
			for _, packet := range packets {
				err := handler.SentPacket(packet)
				Expect(err).NotTo(HaveOccurred())
			}
			// Increase RTT, because the tests would be flaky otherwise
			handler.rttStats.UpdateRTT(time.Hour, 0, time.Now())
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets))))
		})

		Context("ACK validation", func() {
			It("rejects duplicate ACKs", func() {
				largestAcked := 3
				ack := wire.AckFrame{
					LargestAcked: protocol.PacketNumber(largestAcked),
					LowestAcked:  1,
				}
				err := handler.ReceivedAck(&ack, 1337, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 3)))
				err = handler.ReceivedAck(&ack, 1337, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).To(MatchError(ErrDuplicateOrOutOfOrderAck))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 3)))
			})

			It("rejects out of order ACKs", func() {
				ack := wire.AckFrame{
					LargestAcked: 3,
				}
				err := handler.ReceivedAck(&ack, 1337, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 3)))
				err = handler.ReceivedAck(&ack, 1337-1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).To(MatchError(ErrDuplicateOrOutOfOrderAck))
				Expect(handler.LargestAcked).To(Equal(protocol.PacketNumber(3)))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 3)))
			})

			It("rejects ACKs with a too high LargestAcked packet number", func() {
				ack := wire.AckFrame{
					LargestAcked: packets[len(packets)-1].PacketNumber + 1337,
				}
				err := handler.ReceivedAck(&ack, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).To(MatchError(errAckForUnsentPacket))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets))))
			})

			It("ignores repeated ACKs", func() {
				ack := wire.AckFrame{
					LargestAcked: 3,
					LowestAcked:  1,
				}
				err := handler.ReceivedAck(&ack, 1337, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 3)))
				err = handler.ReceivedAck(&ack, 1337+1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.LargestAcked).To(Equal(protocol.PacketNumber(3)))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 3)))
			})

			It("rejects ACKs for skipped packets", func() {
				ack := wire.AckFrame{
					LargestAcked: 12,
					LowestAcked:  5,
				}
				err := handler.ReceivedAck(&ack, 1337, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).To(MatchError(ErrAckForSkippedPacket))
			})

			It("accepts an ACK that correctly nacks a skipped packet", func() {
				ack := wire.AckFrame{
					LargestAcked: 12,
					LowestAcked:  5,
					AckRanges: []wire.AckRange{
						{First: 12, Last: 12},
						{First: 5, Last: 10},
					},
				}
				err := handler.ReceivedAck(&ack, 1337, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.LargestAcked).ToNot(BeZero())
			})
		})

		Context("acks and nacks the right packets", func() {
			It("adjusts the LargestAcked", func() {
				ack := wire.AckFrame{
					LargestAcked: 5,
					LowestAcked:  1,
				}
				err := handler.ReceivedAck(&ack, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.LargestAcked).To(Equal(protocol.PacketNumber(5)))
				el := handler.packetHistory.Front()
				for i := 6; i <= 10; i++ {
					Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(i)))
					el = el.Next()
				}
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(12)))
			})

			It("rejects an ACK that acks packets with a higher encryption level", func() {
				err := handler.SentPacket(&Packet{
					PacketNumber:    13,
					EncryptionLevel: protocol.EncryptionForwardSecure,
					Frames:          []wire.Frame{&streamFrame},
					Length:          1,
				})
				ack := wire.AckFrame{
					LargestAcked: 13,
					LowestAcked:  13,
				}
				Expect(err).ToNot(HaveOccurred())
				err = handler.ReceivedAck(&ack, 1, protocol.EncryptionSecure, time.Now())
				Expect(err).To(MatchError("Received ACK with encryption level encrypted (not forward-secure) that acks a packet 13 (encryption level forward-secure)"))
			})

			It("ACKs all packets for an ACK frame with no missing packets", func() {
				ack := wire.AckFrame{
					LargestAcked: 8,
					LowestAcked:  2,
				}
				err := handler.ReceivedAck(&ack, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(1)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(9)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(10)))
				Expect(el.Next().Value.PacketNumber).To(Equal(protocol.PacketNumber(12)))
			})

			It("handles an ACK frame with one missing packet range", func() {
				ack := wire.AckFrame{
					LargestAcked: 9,
					LowestAcked:  2,
					AckRanges: []wire.AckRange{ // packets 4 and 5 were lost
						{First: 6, Last: 9},
						{First: 2, Last: 3},
					},
				}
				err := handler.ReceivedAck(&ack, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(1)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(4)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(5)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(10)))
				Expect(el.Next().Value.PacketNumber).To(Equal(protocol.PacketNumber(12)))
			})

			It("does not ack packets below the LowestAcked", func() {
				ack := wire.AckFrame{
					LargestAcked: 8,
					LowestAcked:  3,
				}
				err := handler.ReceivedAck(&ack, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(1)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(2)))
				Expect(el.Next().Value.PacketNumber).To(Equal(protocol.PacketNumber(9)))
			})

			It("handles an ACK with multiple missing packet ranges", func() {
				ack := wire.AckFrame{
					LargestAcked: 9,
					LowestAcked:  1,
					AckRanges: []wire.AckRange{ // packets 2, 4 and 5, and 8 were lost
						{First: 9, Last: 9},
						{First: 6, Last: 7},
						{First: 3, Last: 3},
						{First: 1, Last: 1},
					},
				}
				err := handler.ReceivedAck(&ack, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(2)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(4)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(5)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(8)))
				el = el.Next()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(10)))
			})

			It("processes an ACK frame that would be sent after a late arrival of a packet", func() {
				largestObserved := 6
				ack1 := wire.AckFrame{
					LargestAcked: protocol.PacketNumber(largestObserved),
					LowestAcked:  1,
					AckRanges: []wire.AckRange{
						{First: 4, Last: protocol.PacketNumber(largestObserved)},
						{First: 1, Last: 2},
					},
				}
				err := handler.ReceivedAck(&ack1, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 5)))
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(3)))
				ack2 := wire.AckFrame{
					LargestAcked: protocol.PacketNumber(largestObserved),
					LowestAcked:  1,
				}
				err = handler.ReceivedAck(&ack2, 2, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 6)))
				Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(7)))
			})

			It("processes an ACK frame that would be sent after a late arrival of a packet and another packet", func() {
				ack1 := wire.AckFrame{
					LargestAcked: 6,
					LowestAcked:  1,
					AckRanges: []wire.AckRange{
						{First: 4, Last: 6},
						{First: 1, Last: 2},
					},
				}
				err := handler.ReceivedAck(&ack1, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 5)))
				el := handler.packetHistory.Front()
				Expect(el.Value.PacketNumber).To(Equal(protocol.PacketNumber(3)))
				ack2 := wire.AckFrame{
					LargestAcked: 7,
					LowestAcked:  1,
				}
				err = handler.ReceivedAck(&ack2, 2, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 7)))
				Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(8)))
			})

			It("processes an ACK that contains old ACK ranges", func() {
				ack1 := wire.AckFrame{
					LargestAcked: 6,
					LowestAcked:  1,
				}
				err := handler.ReceivedAck(&ack1, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(7)))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 6)))
				ack2 := wire.AckFrame{
					LargestAcked: 10,
					LowestAcked:  1,
					AckRanges: []wire.AckRange{
						{First: 8, Last: 10},
						{First: 3, Last: 3},
						{First: 1, Last: 1},
					},
				}
				err = handler.ReceivedAck(&ack2, 2, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(len(packets) - 6 - 3)))
				Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(7)))
				Expect(handler.packetHistory.Back().Value.PacketNumber).To(Equal(protocol.PacketNumber(12)))
			})
		})

		Context("calculating RTT", func() {
			It("computes the RTT", func() {
				now := time.Now()
				// First, fake the sent times of the first, second and last packet
				getPacketElement(1).Value.SendTime = now.Add(-10 * time.Minute)
				getPacketElement(2).Value.SendTime = now.Add(-5 * time.Minute)
				getPacketElement(6).Value.SendTime = now.Add(-1 * time.Minute)
				// Now, check that the proper times are used when calculating the deltas
				err := handler.ReceivedAck(&wire.AckFrame{LargestAcked: 1}, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 10*time.Minute, 1*time.Second))
				err = handler.ReceivedAck(&wire.AckFrame{LargestAcked: 2}, 2, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 5*time.Minute, 1*time.Second))
				err = handler.ReceivedAck(&wire.AckFrame{LargestAcked: 6}, 3, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 1*time.Minute, 1*time.Second))
			})

			It("uses the DelayTime in the ack frame", func() {
				now := time.Now()
				getPacketElement(1).Value.SendTime = now.Add(-10 * time.Minute)
				err := handler.ReceivedAck(&wire.AckFrame{LargestAcked: 1, DelayTime: 5 * time.Minute}, 1, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).NotTo(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 5*time.Minute, 1*time.Second))
			})
		})
	})

	Context("Retransmission handling", func() {
		var packets []*Packet

		BeforeEach(func() {
			packets = []*Packet{
				{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 2, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 3, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 4, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 5, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 6, Frames: []wire.Frame{&streamFrame}, Length: 1},
				{PacketNumber: 7, Frames: []wire.Frame{&streamFrame}, Length: 1},
			}
			for _, packet := range packets {
				handler.SentPacket(packet)
			}
			// Increase RTT, because the tests would be flaky otherwise
			handler.rttStats.UpdateRTT(time.Minute, 0, time.Now())
			// Ack a single packet so that we have non-RTO timings
			handler.ReceivedAck(&wire.AckFrame{LargestAcked: 2, LowestAcked: 2}, 1, protocol.EncryptionUnencrypted, time.Now())
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(6)))
		})

		It("does not dequeue a packet if no ack has been received", func() {
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		It("dequeues a packet for retransmission", func() {
			getPacketElement(1).Value.SendTime = time.Now().Add(-time.Hour)
			handler.OnAlarm()
			Expect(getPacketElement(1)).To(BeNil())
			Expect(handler.retransmissionQueue).To(HaveLen(1))
			Expect(handler.retransmissionQueue[0].PacketNumber).To(Equal(protocol.PacketNumber(1)))
			packet := handler.DequeuePacketForRetransmission()
			Expect(packet).ToNot(BeNil())
			Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})

		Context("StopWaitings", func() {
			It("gets a StopWaitingFrame", func() {
				ack := wire.AckFrame{LargestAcked: 5, LowestAcked: 5}
				err := handler.ReceivedAck(&ack, 2, protocol.EncryptionUnencrypted, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetStopWaitingFrame(false)).To(Equal(&wire.StopWaitingFrame{LeastUnacked: 6}))
			})

			It("gets a StopWaitingFrame after queueing a retransmission", func() {
				handler.queuePacketForRetransmission(getPacketElement(5))
				Expect(handler.GetStopWaitingFrame(false)).To(Equal(&wire.StopWaitingFrame{LeastUnacked: 6}))
			})
		})
	})

	It("calculates bytes in flight", func() {
		packet1 := Packet{PacketNumber: 1, Frames: []wire.Frame{&streamFrame}, Length: 1}
		packet2 := Packet{PacketNumber: 2, Frames: []wire.Frame{&streamFrame}, Length: 2}
		packet3 := Packet{PacketNumber: 3, Frames: []wire.Frame{&streamFrame}, Length: 3}
		err := handler.SentPacket(&packet1)
		Expect(err).NotTo(HaveOccurred())
		Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(1)))
		err = handler.SentPacket(&packet2)
		Expect(err).NotTo(HaveOccurred())
		Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(1 + 2)))
		err = handler.SentPacket(&packet3)
		Expect(err).NotTo(HaveOccurred())
		Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(1 + 2 + 3)))

		// Increase RTT, because the tests would be flaky otherwise
		handler.rttStats.UpdateRTT(time.Minute, 0, time.Now())

		// ACK 1 and 3, NACK 2
		ack := wire.AckFrame{
			LargestAcked: 3,
			LowestAcked:  1,
			AckRanges: []wire.AckRange{
				{First: 3, Last: 3},
				{First: 1, Last: 1},
			},
		}
		err = handler.ReceivedAck(&ack, 1, protocol.EncryptionUnencrypted, time.Now())
		Expect(err).NotTo(HaveOccurred())
		Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(2)))

		handler.packetHistory.Front().Value.SendTime = time.Now().Add(-time.Hour)
		handler.OnAlarm()

		Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(0)))
	})

	Context("congestion", func() {
		var (
			cong *mockCongestion
		)

		BeforeEach(func() {
			cong = &mockCongestion{}
			handler.congestion = cong
		})

		It("should call OnSent", func() {
			p := &Packet{
				PacketNumber: 1,
				Length:       42,
				Frames:       []wire.Frame{&wire.PingFrame{}},
			}
			err := handler.SentPacket(p)
			Expect(err).NotTo(HaveOccurred())
			Expect(cong.argsOnPacketSent[1]).To(Equal(protocol.ByteCount(42)))
			Expect(cong.argsOnPacketSent[2]).To(Equal(protocol.PacketNumber(1)))
			Expect(cong.argsOnPacketSent[3]).To(Equal(protocol.ByteCount(42)))
			Expect(cong.argsOnPacketSent[4]).To(BeTrue())
		})

		It("should call MaybeExitSlowStart and OnPacketAcked", func() {
			handler.SentPacket(retransmittablePacket(1))
			handler.SentPacket(retransmittablePacket(2))
			err := handler.ReceivedAck(&wire.AckFrame{LargestAcked: 1, LowestAcked: 1}, 1, protocol.EncryptionForwardSecure, time.Now())
			Expect(err).NotTo(HaveOccurred())
			Expect(cong.maybeExitSlowStart).To(BeTrue())
			Expect(cong.packetsAcked).To(BeEquivalentTo([][]interface{}{
				{protocol.PacketNumber(1), protocol.ByteCount(1), protocol.ByteCount(1)},
			}))
			Expect(cong.packetsLost).To(BeEmpty())
		})

		It("should call MaybeExitSlowStart and OnPacketLost", func() {
			handler.SentPacket(retransmittablePacket(1))
			handler.SentPacket(retransmittablePacket(2))
			handler.SentPacket(retransmittablePacket(3))
			handler.tlpCount = maxTailLossProbes
			handler.OnAlarm() // RTO, meaning 2 lost packets
			Expect(cong.maybeExitSlowStart).To(BeFalse())
			Expect(cong.onRetransmissionTimeout).To(BeTrue())
			Expect(cong.packetsAcked).To(BeEmpty())
			Expect(cong.packetsLost).To(BeEquivalentTo([][]interface{}{
				{protocol.PacketNumber(1), protocol.ByteCount(1), protocol.ByteCount(2)},
				{protocol.PacketNumber(2), protocol.ByteCount(1), protocol.ByteCount(1)},
			}))
		})

		It("allows or denies sending based on congestion", func() {
			Expect(handler.SendingAllowed()).To(BeTrue())
			err := handler.SentPacket(&Packet{
				PacketNumber: 1,
				Frames:       []wire.Frame{&wire.PingFrame{}},
				Length:       protocol.DefaultTCPMSS + 1,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.SendingAllowed()).To(BeFalse())
		})

		It("allows or denies sending based on the number of tracked packets", func() {
			Expect(handler.SendingAllowed()).To(BeTrue())
			handler.retransmissionQueue = make([]*Packet, protocol.MaxTrackedSentPackets)
			Expect(handler.SendingAllowed()).To(BeFalse())
		})

		It("allows sending if there are retransmisisons outstanding", func() {
			err := handler.SentPacket(&Packet{
				PacketNumber: 1,
				Frames:       []wire.Frame{&wire.PingFrame{}},
				Length:       protocol.DefaultTCPMSS + 1,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.SendingAllowed()).To(BeFalse())
			handler.retransmissionQueue = []*Packet{nil}
			Expect(handler.SendingAllowed()).To(BeTrue())
		})
	})

	Context("calculating RTO", func() {
		It("uses default RTO", func() {
			Expect(handler.ComputeRTOTimeout()).To(Equal(defaultRTOTimeout))
		})

		It("uses RTO from rttStats", func() {
			rtt := time.Second
			expected := rtt + rtt/2*4
			handler.rttStats.UpdateRTT(rtt, 0, time.Now())
			Expect(handler.ComputeRTOTimeout()).To(Equal(expected))
		})

		It("limits RTO min", func() {
			rtt := time.Millisecond
			handler.rttStats.UpdateRTT(rtt, 0, time.Now())
			Expect(handler.ComputeRTOTimeout()).To(Equal(minRTOTimeout))
		})

		It("limits RTO max", func() {
			rtt := time.Hour
			handler.rttStats.UpdateRTT(rtt, 0, time.Now())
			Expect(handler.ComputeRTOTimeout()).To(Equal(maxRTOTimeout))
		})

		It("implements exponential backoff", func() {
			handler.rtoCount = 0
			Expect(handler.ComputeRTOTimeout()).To(Equal(defaultRTOTimeout))
			handler.rtoCount = 1
			Expect(handler.ComputeRTOTimeout()).To(Equal(2 * defaultRTOTimeout))
			handler.rtoCount = 2
			Expect(handler.ComputeRTOTimeout()).To(Equal(4 * defaultRTOTimeout))
		})
	})

	Context("Delay-based loss detection", func() {
		It("detects a packet as lost", func() {
			err := handler.SentPacket(retransmittablePacket(1))
			Expect(err).NotTo(HaveOccurred())
			err = handler.SentPacket(retransmittablePacket(2))
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.lossTime.IsZero()).To(BeTrue())

			err = handler.ReceivedAck(&wire.AckFrame{LargestAcked: 2, LowestAcked: 2}, 1, protocol.EncryptionForwardSecure, time.Now().Add(time.Hour))
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.lossTime.IsZero()).To(BeFalse())

			// RTT is around 1h now.
			// The formula is (1+1/8) * RTT, so this should be around that number
			Expect(handler.lossTime.Sub(time.Now())).To(BeNumerically("~", time.Hour*9/8, time.Minute))
			Expect(handler.GetAlarmTimeout().Sub(time.Now())).To(BeNumerically("~", time.Hour*9/8, time.Minute))

			handler.packetHistory.Front().Value.SendTime = time.Now().Add(-2 * time.Hour)
			handler.OnAlarm()
			Expect(handler.DequeuePacketForRetransmission()).NotTo(BeNil())
		})

		It("does not detect packets as lost without ACKs", func() {
			err := handler.SentPacket(&Packet{PacketNumber: 1, Length: 1})
			Expect(err).NotTo(HaveOccurred())
			err = handler.SentPacket(retransmittablePacket(2))
			Expect(err).NotTo(HaveOccurred())
			err = handler.SentPacket(retransmittablePacket(3))
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.lossTime.IsZero()).To(BeTrue())

			err = handler.ReceivedAck(&wire.AckFrame{LargestAcked: 1, LowestAcked: 1}, 1, protocol.EncryptionUnencrypted, time.Now().Add(time.Hour))
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.lossTime.IsZero()).To(BeTrue())
			Expect(handler.GetAlarmTimeout().Sub(time.Now())).To(BeNumerically("~", handler.ComputeRTOTimeout(), time.Minute))

			// This means RTO, so both packets should be lost
			handler.tlpCount = maxTailLossProbes
			handler.OnAlarm()
			Expect(handler.DequeuePacketForRetransmission()).ToNot(BeNil())
			Expect(handler.DequeuePacketForRetransmission()).ToNot(BeNil())
			Expect(handler.DequeuePacketForRetransmission()).To(BeNil())
		})
	})

	Context("retransmission for handshake packets", func() {
		BeforeEach(func() {
			handler.handshakeComplete = false
		})

		It("detects the handshake timeout", func() {
			// send handshake packets: 1, 2, 4
			// send a forward-secure packet: 3
			err := handler.SentPacket(handshakePacket(1))
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(handshakePacket(2))
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(retransmittablePacket(3))
			Expect(err).ToNot(HaveOccurred())
			err = handler.SentPacket(handshakePacket(4))
			Expect(err).ToNot(HaveOccurred())

			err = handler.ReceivedAck(&wire.AckFrame{LargestAcked: 1, LowestAcked: 1}, 1, protocol.EncryptionSecure, time.Now().Add(time.Hour))
			Expect(err).NotTo(HaveOccurred())
			Expect(handler.lossTime.IsZero()).To(BeTrue())
			handshakeTimeout := handler.computeHandshakeTimeout()
			Expect(handler.GetAlarmTimeout().Sub(time.Now())).To(BeNumerically("~", handshakeTimeout, time.Minute))

			handler.OnAlarm()
			p := handler.DequeuePacketForRetransmission()
			Expect(p).ToNot(BeNil())
			Expect(p.PacketNumber).To(Equal(protocol.PacketNumber(2)))
			p = handler.DequeuePacketForRetransmission()
			Expect(p).ToNot(BeNil())
			Expect(p.PacketNumber).To(Equal(protocol.PacketNumber(4)))
			Expect(handler.packetHistory.Len()).To(Equal(1))
			Expect(handler.packetHistory.Front().Value.PacketNumber).To(Equal(protocol.PacketNumber(3)))
			Expect(handler.handshakeCount).To(BeEquivalentTo(1))
			// make sure the exponential backoff is used
			Expect(handler.computeHandshakeTimeout()).To(BeNumerically("~", 2*handshakeTimeout, time.Minute))
		})
	})

	Context("RTO retransmission", func() {
		It("queues two packets if RTO expires", func() {
			err := handler.SentPacket(retransmittablePacket(1))
			Expect(err).NotTo(HaveOccurred())
			err = handler.SentPacket(retransmittablePacket(2))
			Expect(err).NotTo(HaveOccurred())

			handler.rttStats.UpdateRTT(time.Hour, 0, time.Now())
			Expect(handler.lossTime.IsZero()).To(BeTrue())
			Expect(handler.GetAlarmTimeout().Sub(time.Now())).To(BeNumerically("~", handler.ComputeRTOTimeout(), time.Minute))

			// Disable TLP
			handler.tlpCount = maxTailLossProbes
			handler.OnAlarm()
			p := handler.DequeuePacketForRetransmission()
			Expect(p).ToNot(BeNil())
			Expect(p.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			p = handler.DequeuePacketForRetransmission()
			Expect(p).ToNot(BeNil())
			Expect(p.PacketNumber).To(Equal(protocol.PacketNumber(2)))

			Expect(handler.rtoCount).To(BeEquivalentTo(1))
		})
	})
})
