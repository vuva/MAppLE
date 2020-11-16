package flowcontrol

import (
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

type streamFlowController struct {
	baseFlowController

	streamID protocol.StreamID

	connection              connectionFlowControllerI
	contributesToConnection bool // does the stream contribute to connection level flow control

	receivedFinalOffset bool
}

var _ StreamFlowController = &streamFlowController{}

// NewStreamFlowController gets a new flow controller for a stream
func NewStreamFlowController(
	streamID protocol.StreamID,
	contributesToConnection bool,
	cfc ConnectionFlowController,
	receiveWindow protocol.ByteCount,
	maxReceiveWindow protocol.ByteCount,
	initialSendWindow protocol.ByteCount,
	rttStats *congestion.RTTStats,
	remoteRTTs map[protocol.PathID]time.Duration,
) StreamFlowController {
	return &streamFlowController{
		streamID:                streamID,
		contributesToConnection: contributesToConnection,
		connection:              cfc.(connectionFlowControllerI),
		baseFlowController: baseFlowController{
			rttStats:                  rttStats,
			receiveWindow:             receiveWindow,
			receiveWindowIncrement:    receiveWindow,
			maxReceiveWindowIncrement: maxReceiveWindow,
			remoteRTTs:                remoteRTTs,
			sendWindow:                initialSendWindow,
		},
	}
}

// UpdateHighestReceived updates the highestReceived value, if the byteOffset is higher
// it returns an ErrReceivedSmallerByteOffset if the received byteOffset is smaller than any byteOffset received before
func (c *streamFlowController) UpdateHighestReceived(byteOffset protocol.ByteCount, final bool) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// when receiving a final offset, check that this final offset is consistent with a final offset we might have received earlier
	if final && c.receivedFinalOffset && byteOffset != c.highestReceived {
		return qerr.Error(qerr.StreamDataAfterTermination, fmt.Sprintf("Received inconsistent final offset for stream %d (old: %d, new: %d bytes)", c.streamID, c.highestReceived, byteOffset))
	}
	// if we already received a final offset, check that the offset in the STREAM frames is below the final offset
	if c.receivedFinalOffset && byteOffset > c.highestReceived {
		return qerr.StreamDataAfterTermination
	}
	if final {
		c.receivedFinalOffset = true
	}
	if byteOffset == c.highestReceived {
		return nil
	}
	if byteOffset <= c.highestReceived {
		// a STREAM_FRAME with a higher offset was received before.
		if final {
			// If the current byteOffset is smaller than the offset in that STREAM_FRAME, this STREAM_FRAME contained data after the end of the stream
			return qerr.StreamDataAfterTermination
		}
		// this is a reordered STREAM_FRAME
		return nil
	}

	increment := byteOffset - c.highestReceived
	c.highestReceived = byteOffset
	if c.checkFlowControlViolation() {
		return qerr.Error(qerr.FlowControlReceivedTooMuchData, fmt.Sprintf("Received %d bytes on stream %d, allowed %d bytes", byteOffset, c.streamID, c.receiveWindow))
	}
	if c.contributesToConnection {
		return c.connection.IncrementHighestReceived(increment)
	}
	return nil
}

func (c *streamFlowController) GetHighestReceived() protocol.ByteCount {
	return c.highestReceived
}

func (c *streamFlowController) AddBytesRead(n protocol.ByteCount) {
	c.baseFlowController.AddBytesRead(n)
	if c.contributesToConnection {
		c.connection.AddBytesRead(n)
	}
}

func (c *streamFlowController) AddBytesSent(n protocol.ByteCount) {
	c.baseFlowController.AddBytesSent(n)
	if c.contributesToConnection {
		c.connection.AddBytesSent(n)
	}
}

func (c *streamFlowController) AddBytesRetrans(n protocol.ByteCount) {
	c.baseFlowController.AddBytesRetrans(n)
	if c.contributesToConnection {
		c.connection.AddBytesRetrans(n)
	}
}

func (c *streamFlowController) SendWindowSize() protocol.ByteCount {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	window := c.baseFlowController.sendWindowSize()
	if c.contributesToConnection {
		window = utils.MinByteCount(window, c.connection.SendWindowSize())
	}
	return window
}

func (c *streamFlowController) GetWindowUpdate(force bool) protocol.ByteCount {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	oldWindowIncrement := c.receiveWindowIncrement
	offset := c.baseFlowController.getWindowUpdate(force)
	if c.receiveWindowIncrement > oldWindowIncrement { // auto-tuning enlarged the window increment
		utils.Debugf("Increasing receive flow control window for the connection to %d kB", c.receiveWindowIncrement/(1<<10))
		if c.contributesToConnection {
			c.connection.EnsureMinimumWindowIncrement(protocol.ByteCount(float64(c.receiveWindowIncrement) * protocol.ConnectionFlowControlMultiplier))
		}
	}
	return offset
}
