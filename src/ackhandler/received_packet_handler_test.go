package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("receivedPacketHandler", func() {
	var (
		handler *receivedPacketHandler
	)

	BeforeEach(func() {
		handler = NewReceivedPacketHandler(protocol.VersionWhatever, false).(*receivedPacketHandler)
	})

	Context("accepting packets", func() {
		It("handles a packet that arrives late", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(1), true, false)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(protocol.PacketNumber(3), true, false)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(protocol.PacketNumber(2), true, false)
			Expect(err).ToNot(HaveOccurred())
		})

		It("rejects packets with packet number 0", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(0), true, false)
			Expect(err).To(MatchError(errInvalidPacketNumber))
		})

		It("saves the time when each packet arrived", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(3), true, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.largestObservedReceivedTime).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
		})

		It("updates the largestObserved and the largestObservedReceivedTime", func() {
			handler.largestObserved = 3
			handler.largestObservedReceivedTime = time.Now().Add(-1 * time.Second)
			err := handler.ReceivedPacket(5, true, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(5)))
			Expect(handler.largestObservedReceivedTime).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
		})

		It("doesn't update the largestObserved and the largestObservedReceivedTime for a belated packet", func() {
			timestamp := time.Now().Add(-1 * time.Second)
			handler.largestObserved = 5
			handler.largestObservedReceivedTime = timestamp
			err := handler.ReceivedPacket(4, true, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(5)))
			Expect(handler.largestObservedReceivedTime).To(Equal(timestamp))
		})

		It("passes on errors from receivedPacketHistory", func() {
			var err error
			for i := protocol.PacketNumber(0); i < 5*protocol.MaxTrackedReceivedAckRanges; i++ {
				err = handler.ReceivedPacket(2*i+1, true, false)
				// this will eventually return an error
				// details about when exactly the receivedPacketHistory errors are tested there
				if err != nil {
					break
				}
			}
			Expect(err).To(MatchError(errTooManyOutstandingReceivedAckRanges))
		})
	})

	Context("ACKs", func() {
		Context("queueing ACKs", func() {
			receiveAndAck10Packets := func() {
				for i := 1; i <= 10; i++ {
					err := handler.ReceivedPacket(protocol.PacketNumber(i), true, false)
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(handler.GetAckFrame()).ToNot(BeNil())
				Expect(handler.ackQueued).To(BeFalse())
			}

			It("always queues an ACK for the first packet", func() {
				err := handler.ReceivedPacket(1, false, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.ackQueued).To(BeTrue())
				Expect(handler.GetAlarmTimeout()).To(BeZero())
			})

			It("only queues one ACK for many non-retransmittable packets", func() {
				receiveAndAck10Packets()
				for i := 11; i < 10+protocol.MaxPacketsReceivedBeforeAckSend; i++ {
					err := handler.ReceivedPacket(protocol.PacketNumber(i), false, false)
					Expect(err).ToNot(HaveOccurred())
					Expect(handler.ackQueued).To(BeFalse())
				}
				err := handler.ReceivedPacket(10+protocol.MaxPacketsReceivedBeforeAckSend, false, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.ackQueued).To(BeTrue())
				Expect(handler.GetAlarmTimeout()).To(BeZero())
			})

			It("doesn't queue an ACK for non-retransmittable packets, for QUIC >= 39", func() {
				receiveAndAck10Packets()
				handler.version = protocol.Version39
				for i := 11; i < 10+10*protocol.MaxPacketsReceivedBeforeAckSend; i++ {
					err := handler.ReceivedPacket(protocol.PacketNumber(i), false, false)
					Expect(err).ToNot(HaveOccurred())
					Expect(handler.ackQueued).To(BeFalse())
				}
			})

			It("queues an ACK for every second retransmittable packet, if they are arriving fast", func() {
				receiveAndAck10Packets()
				err := handler.ReceivedPacket(11, true, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.ackQueued).To(BeFalse())
				Expect(handler.GetAlarmTimeout()).NotTo(BeZero())
				err = handler.ReceivedPacket(12, true, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.ackQueued).To(BeTrue())
				Expect(handler.GetAlarmTimeout()).To(BeZero())
			})

			It("only sets the timer when receiving a retransmittable packets", func() {
				receiveAndAck10Packets()
				err := handler.ReceivedPacket(11, false, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.ackQueued).To(BeFalse())
				Expect(handler.ackAlarm).To(BeZero())
				err = handler.ReceivedPacket(12, true, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.ackQueued).To(BeFalse())
				Expect(handler.ackAlarm).ToNot(BeZero())
				Expect(handler.GetAlarmTimeout()).NotTo(BeZero())
			})

			It("queues an ACK if it was reported missing before", func() {
				receiveAndAck10Packets()
				err := handler.ReceivedPacket(11, true, false)
				Expect(err).ToNot(HaveOccurred())
				err = handler.ReceivedPacket(13, true, false)
				Expect(err).ToNot(HaveOccurred())
				ack := handler.GetAckFrame() // ACK: 1 and 3, missing: 2
				Expect(ack).ToNot(BeNil())
				Expect(ack.HasMissingRanges()).To(BeTrue())
				Expect(handler.ackQueued).To(BeFalse())
				err = handler.ReceivedPacket(12, false, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.ackQueued).To(BeTrue())
			})

			It("queues an ACK if it creates a new missing range", func() {
				receiveAndAck10Packets()
				for i := 11; i < 16; i++ {
					err := handler.ReceivedPacket(protocol.PacketNumber(i), true, false)
					Expect(err).ToNot(HaveOccurred())
				}
				err := handler.ReceivedPacket(20, true, false) // we now know that packets 16 to 19 are missing
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.ackQueued).To(BeTrue())
				ack := handler.GetAckFrame()
				Expect(ack.HasMissingRanges()).To(BeTrue())
				Expect(ack).ToNot(BeNil())
			})
		})

		Context("ACK generation", func() {
			BeforeEach(func() {
				handler.ackQueued = true
			})

			It("generates a simple ACK frame", func() {
				err := handler.ReceivedPacket(1, true, false)
				Expect(err).ToNot(HaveOccurred())
				err = handler.ReceivedPacket(2, true, false)
				Expect(err).ToNot(HaveOccurred())
				ack := handler.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(2)))
				Expect(ack.LowestAcked).To(Equal(protocol.PacketNumber(1)))
				Expect(ack.AckRanges).To(BeEmpty())
			})

			It("saves the last sent ACK", func() {
				err := handler.ReceivedPacket(1, true, false)
				Expect(err).ToNot(HaveOccurred())
				ack := handler.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(handler.lastAck).To(Equal(ack))
				err = handler.ReceivedPacket(2, true, false)
				Expect(err).ToNot(HaveOccurred())
				handler.ackQueued = true
				ack = handler.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(handler.lastAck).To(Equal(ack))
			})

			It("generates an ACK frame with missing packets", func() {
				err := handler.ReceivedPacket(1, true, false)
				Expect(err).ToNot(HaveOccurred())
				err = handler.ReceivedPacket(4, true, false)
				Expect(err).ToNot(HaveOccurred())
				ack := handler.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(4)))
				Expect(ack.LowestAcked).To(Equal(protocol.PacketNumber(1)))
				Expect(ack.AckRanges).To(HaveLen(2))
				Expect(ack.AckRanges[0]).To(Equal(wire.AckRange{First: 4, Last: 4}))
				Expect(ack.AckRanges[1]).To(Equal(wire.AckRange{First: 1, Last: 1}))
			})

			It("accepts packets below the lower limit", func() {
				handler.SetLowerLimit(5)
				err := handler.ReceivedPacket(2, true, false)
				Expect(err).ToNot(HaveOccurred())
			})

			It("doesn't add delayed packets to the packetHistory", func() {
				handler.SetLowerLimit(6)
				err := handler.ReceivedPacket(4, true, false)
				Expect(err).ToNot(HaveOccurred())
				err = handler.ReceivedPacket(10, true, false)
				Expect(err).ToNot(HaveOccurred())
				ack := handler.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(10)))
				Expect(ack.LowestAcked).To(Equal(protocol.PacketNumber(10)))
			})

			It("deletes packets from the packetHistory when a lower limit is set", func() {
				for i := 1; i <= 12; i++ {
					err := handler.ReceivedPacket(protocol.PacketNumber(i), true, false)
					Expect(err).ToNot(HaveOccurred())
				}
				handler.SetLowerLimit(6)
				// check that the packets were deleted from the receivedPacketHistory by checking the values in an ACK frame
				ack := handler.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(12)))
				Expect(ack.LowestAcked).To(Equal(protocol.PacketNumber(7)))
				Expect(ack.HasMissingRanges()).To(BeFalse())
			})

			// TODO: remove this test when dropping support for STOP_WAITINGs
			It("handles a lower limit of 0", func() {
				handler.SetLowerLimit(0)
				err := handler.ReceivedPacket(1337, true, false)
				Expect(err).ToNot(HaveOccurred())
				ack := handler.GetAckFrame()
				Expect(ack).ToNot(BeNil())
				Expect(ack.LargestAcked).To(Equal(protocol.PacketNumber(1337)))
			})

			It("resets all counters needed for the ACK queueing decision when sending an ACK", func() {
				err := handler.ReceivedPacket(1, true, false)
				Expect(err).ToNot(HaveOccurred())
				handler.ackAlarm = time.Now().Add(-time.Minute)
				Expect(handler.GetAckFrame()).ToNot(BeNil())
				Expect(handler.packetsReceivedSinceLastAck).To(BeZero())
				Expect(handler.ackAlarm).To(BeZero())
				Expect(handler.retransmittablePacketsReceivedSinceLastAck).To(BeZero())
				Expect(handler.ackQueued).To(BeFalse())
			})

			It("doesn't generate an ACK when none is queued and the timer is not set", func() {
				err := handler.ReceivedPacket(1, true, false)
				Expect(err).ToNot(HaveOccurred())
				handler.ackQueued = false
				handler.ackAlarm = time.Time{}
				Expect(handler.GetAckFrame()).To(BeNil())
			})

			It("doesn't generate an ACK when none is queued and the timer has not yet expired", func() {
				err := handler.ReceivedPacket(1, true, false)
				Expect(err).ToNot(HaveOccurred())
				handler.ackQueued = false
				handler.ackAlarm = time.Now().Add(time.Minute)
				Expect(handler.GetAckFrame()).To(BeNil())
			})

			It("generates an ACK when the timer has expired", func() {
				err := handler.ReceivedPacket(1, true, false)
				Expect(err).ToNot(HaveOccurred())
				handler.ackQueued = false
				handler.ackAlarm = time.Now().Add(-time.Minute)
				Expect(handler.GetAckFrame()).ToNot(BeNil())
			})
		})
	})
})
