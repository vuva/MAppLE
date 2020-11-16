package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A MaxStreamDataFrame carries flow control information for a stream
type MaxStreamDataFrame struct {
	StreamID   protocol.StreamID
	ByteOffset protocol.ByteCount
}

// ParseMaxStreamDataFrame parses a MAX_STREAM_DATA frame
func ParseMaxStreamDataFrame(r *bytes.Reader, version protocol.VersionNumber) (*MaxStreamDataFrame, error) {
	frame := &MaxStreamDataFrame{}

	// read the TypeByte
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}

	sid, err := utils.GetByteOrder(version).ReadUint32(r)
	if err != nil {
		return nil, err
	}
	frame.StreamID = protocol.StreamID(sid)

	byteOffset, err := utils.GetByteOrder(version).ReadUint64(r)
	if err != nil {
		return nil, err
	}
	frame.ByteOffset = protocol.ByteCount(byteOffset)
	return frame, nil
}

// Write writes a MAX_STREAM_DATA frame
func (f *MaxStreamDataFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	if !version.UsesMaxDataFrame() {
		return (&windowUpdateFrame{
			StreamID:   f.StreamID,
			ByteOffset: f.ByteOffset,
		}).Write(b, version)
	}
	b.WriteByte(0x5)
	utils.GetByteOrder(version).WriteUint32(b, uint32(f.StreamID))
	utils.GetByteOrder(version).WriteUint64(b, uint64(f.ByteOffset))
	return nil
}

// MinLength of a written frame
func (f *MaxStreamDataFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	return 1 + 4 + 8, nil
}
