package flowcontrol

import (
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream Flow controller", func() {
	var controller *streamFlowController

	BeforeEach(func() {
		rttStats := &congestion.RTTStats{}
		controller = &streamFlowController{
			streamID:   10,
			connection: NewConnectionFlowController(1000, 1000, rttStats, make(map[protocol.PathID]time.Duration)).(*connectionFlowController),
		}
		controller.maxReceiveWindowIncrement = 10000
		controller.rttStats = rttStats
	})

	Context("Constructor", func() {
		rttStats := &congestion.RTTStats{}

		It("sets the send and receive windows", func() {
			receiveWindow := protocol.ByteCount(2000)
			maxReceiveWindow := protocol.ByteCount(3000)
			sendWindow := protocol.ByteCount(4000)

			cc := NewConnectionFlowController(0, 0, nil, make(map[protocol.PathID]time.Duration))
			fc := NewStreamFlowController(5, true, cc, receiveWindow, maxReceiveWindow, sendWindow, rttStats, make(map[protocol.PathID]time.Duration)).(*streamFlowController)
			Expect(fc.streamID).To(Equal(protocol.StreamID(5)))
			Expect(fc.receiveWindow).To(Equal(receiveWindow))
			Expect(fc.maxReceiveWindowIncrement).To(Equal(maxReceiveWindow))
			Expect(fc.sendWindow).To(Equal(sendWindow))
			Expect(fc.contributesToConnection).To(BeTrue())
		})
	})

	Context("receiving data", func() {
		Context("registering received offsets", func() {
			var receiveWindow protocol.ByteCount = 10000
			var receiveWindowIncrement protocol.ByteCount = 600

			BeforeEach(func() {
				controller.receiveWindow = receiveWindow
				controller.receiveWindowIncrement = receiveWindowIncrement
			})

			It("updates the highestReceived", func() {
				controller.highestReceived = 1337
				err := controller.UpdateHighestReceived(1338, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1338)))
			})

			It("informs the connection flow controller about received data", func() {
				controller.highestReceived = 10
				controller.contributesToConnection = true
				controller.connection.(*connectionFlowController).highestReceived = 100
				err := controller.UpdateHighestReceived(20, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(controller.connection.(*connectionFlowController).highestReceived).To(Equal(protocol.ByteCount(100 + 10)))
			})

			It("doesn't informs the connection flow controller about received data if it doesn't contribute", func() {
				controller.highestReceived = 10
				controller.connection.(*connectionFlowController).highestReceived = 100
				err := controller.UpdateHighestReceived(20, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(controller.connection.(*connectionFlowController).highestReceived).To(Equal(protocol.ByteCount(100)))
			})

			It("does not decrease the highestReceived", func() {
				controller.highestReceived = 1337
				err := controller.UpdateHighestReceived(1000, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1337)))
			})

			It("does nothing when setting the same byte offset", func() {
				controller.highestReceived = 1337
				err := controller.UpdateHighestReceived(1337, false)
				Expect(err).ToNot(HaveOccurred())
			})

			It("does not give a flow control violation when using the window completely", func() {
				err := controller.UpdateHighestReceived(receiveWindow, false)
				Expect(err).ToNot(HaveOccurred())
			})

			It("detects a flow control violation", func() {
				err := controller.UpdateHighestReceived(receiveWindow+1, false)
				Expect(err).To(MatchError("FlowControlReceivedTooMuchData: Received 10001 bytes on stream 10, allowed 10000 bytes"))
			})

			It("accepts a final offset higher than the highest received", func() {
				controller.highestReceived = 100
				err := controller.UpdateHighestReceived(101, true)
				Expect(err).ToNot(HaveOccurred())
				Expect(controller.highestReceived).To(Equal(protocol.ByteCount(101)))
			})

			It("errors when receiving a final offset smaller than the highest offset received so far", func() {
				controller.highestReceived = 100
				err := controller.UpdateHighestReceived(99, true)
				Expect(err).To(MatchError(qerr.StreamDataAfterTermination))
			})

			It("accepts delayed data after receiving a final offset", func() {
				err := controller.UpdateHighestReceived(300, true)
				Expect(err).ToNot(HaveOccurred())
				err = controller.UpdateHighestReceived(250, false)
				Expect(err).ToNot(HaveOccurred())
			})

			It("errors when receiving a higher offset after receiving a final offset", func() {
				err := controller.UpdateHighestReceived(200, true)
				Expect(err).ToNot(HaveOccurred())
				err = controller.UpdateHighestReceived(250, false)
				Expect(err).To(MatchError(qerr.StreamDataAfterTermination))
			})

			It("accepts duplicate final offsets", func() {
				err := controller.UpdateHighestReceived(200, true)
				Expect(err).ToNot(HaveOccurred())
				err = controller.UpdateHighestReceived(200, true)
				Expect(err).ToNot(HaveOccurred())
				Expect(controller.highestReceived).To(Equal(protocol.ByteCount(200)))
			})

			It("errors when receiving inconsistent final offsets", func() {
				err := controller.UpdateHighestReceived(200, true)
				Expect(err).ToNot(HaveOccurred())
				err = controller.UpdateHighestReceived(201, true)
				Expect(err).To(MatchError("StreamDataAfterTermination: Received inconsistent final offset for stream 10 (old: 200, new: 201 bytes)"))
			})
		})

		Context("registering data read", func() {
			It("saves when data is read, on a stream not contributing to the connection", func() {
				controller.AddBytesRead(100)
				Expect(controller.bytesRead).To(Equal(protocol.ByteCount(100)))
				Expect(controller.connection.(*connectionFlowController).bytesRead).To(BeZero())
			})

			It("saves when data is read, on a stream not contributing to the connection", func() {
				controller.contributesToConnection = true
				controller.AddBytesRead(200)
				Expect(controller.bytesRead).To(Equal(protocol.ByteCount(200)))
				Expect(controller.connection.(*connectionFlowController).bytesRead).To(Equal(protocol.ByteCount(200)))
			})
		})

		Context("generating window updates", func() {
			var oldIncrement protocol.ByteCount

			// update the congestion such that it returns a given value for the smoothed RTT
			setRtt := func(t time.Duration) {
				controller.rttStats.UpdateRTT(t, 0, time.Now())
				Expect(controller.rttStats.SmoothedRTT()).To(Equal(t)) // make sure it worked
			}

			BeforeEach(func() {
				controller.receiveWindow = 100
				controller.receiveWindowIncrement = 60
				controller.connection.(*connectionFlowController).receiveWindowIncrement = 120
				oldIncrement = controller.receiveWindowIncrement
			})

			It("tells the connection flow controller when the window was autotuned", func() {
				controller.contributesToConnection = true
				controller.AddBytesRead(75)
				setRtt(20 * time.Millisecond)
				controller.lastWindowUpdateTime = time.Now().Add(-35 * time.Millisecond)
				offset := controller.GetWindowUpdate(false)
				Expect(offset).To(Equal(protocol.ByteCount(75 + 2*60)))
				Expect(controller.receiveWindowIncrement).To(Equal(2 * oldIncrement))
				Expect(controller.connection.(*connectionFlowController).receiveWindowIncrement).To(Equal(protocol.ByteCount(float64(controller.receiveWindowIncrement) * protocol.ConnectionFlowControlMultiplier)))
			})

			It("doesn't tell the connection flow controller if it doesn't contribute", func() {
				controller.contributesToConnection = false
				controller.AddBytesRead(75)
				setRtt(20 * time.Millisecond)
				controller.lastWindowUpdateTime = time.Now().Add(-35 * time.Millisecond)
				offset := controller.GetWindowUpdate(false)
				Expect(offset).ToNot(BeZero())
				Expect(controller.receiveWindowIncrement).To(Equal(2 * oldIncrement))
				Expect(controller.connection.(*connectionFlowController).receiveWindowIncrement).To(Equal(protocol.ByteCount(120))) // unchanged
			})
		})
	})

	Context("sending data", func() {
		It("gets the size of the send window", func() {
			controller.UpdateSendWindow(15)
			controller.AddBytesSent(5)
			Expect(controller.SendWindowSize()).To(Equal(protocol.ByteCount(10)))
		})

		It("gets the number of bytes retrans at connection-level, if contributes", func() {
			controller.contributesToConnection = true
			controller.AddBytesRetrans(15)
			Expect(controller.connection.GetBytesRetrans()).To(Equal(protocol.ByteCount(15)))
		})

		It("doesn't get the number of bytes retrans at connection-level, if not contributing to connection", func() {
			controller.contributesToConnection = false
			controller.AddBytesRetrans(15)
			Expect(controller.connection.GetBytesRetrans()).To(Equal(protocol.ByteCount(0)))
		})

		It("doesn't care about the connection-level window, if it doesn't contribute", func() {
			controller.UpdateSendWindow(15)
			controller.connection.UpdateSendWindow(1)
			controller.AddBytesSent(5)
			Expect(controller.SendWindowSize()).To(Equal(protocol.ByteCount(10)))
		})

		It("makes sure that it doesn't overflow the connection-level window", func() {
			controller.contributesToConnection = true
			controller.connection.UpdateSendWindow(12)
			controller.UpdateSendWindow(20)
			controller.AddBytesSent(10)
			Expect(controller.SendWindowSize()).To(Equal(protocol.ByteCount(2)))
		})

		It("doesn't say that it's blocked, if only the connection is blocked", func() {
			controller.contributesToConnection = true
			controller.connection.UpdateSendWindow(50)
			controller.UpdateSendWindow(100)
			controller.AddBytesSent(50)
			Expect(controller.connection.IsBlocked()).To(BeTrue())
			Expect(controller.IsBlocked()).To(BeFalse())
		})
	})
})
