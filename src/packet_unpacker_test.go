package quic

import (
	"bytes"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockAEAD struct {
	encLevelOpen protocol.EncryptionLevel
}

func (m *mockAEAD) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error) {
	nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveClient, 0x1337, protocol.VersionWhatever)
	Expect(err).ToNot(HaveOccurred())
	res, err := nullAEAD.Open(dst, src, packetNumber, associatedData)
	return res, m.encLevelOpen, err
}
func (m *mockAEAD) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel) {
	nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveServer, 0x1337, protocol.VersionWhatever)
	Expect(err).ToNot(HaveOccurred())
	return nullAEAD.Seal(dst, src, packetNumber, associatedData), protocol.EncryptionUnspecified
}

var _ quicAEAD = &mockAEAD{}

var _ = Describe("Packet unpacker", func() {
	var (
		unpacker *packetUnpacker
		hdr      *wire.Header
		hdrBin   []byte
		data     []byte
		buf      *bytes.Buffer
		sess     *session
	)

	BeforeEach(func() {
		sess = &session{version: protocol.VersionWhatever, perspective: protocol.PerspectiveClient, recoveredPackets: make(chan *receivedPacket, 10)}
		hdr = &wire.Header{
			PacketNumber:    10,
			PacketNumberLen: 1,
		}
		hdrBin = []byte{0x04, 0x4c, 0x01}
		unpacker = &packetUnpacker{aead: &mockAEAD{}, sess: sess}
		data = nil
		buf = &bytes.Buffer{}
	})

	setData := func(p []byte) {
		data, _ = unpacker.aead.(*mockAEAD).Seal(nil, p, 0, hdrBin)
	}

	It("does not read read a private flag for QUIC Version >= 34", func() {
		f := &wire.ConnectionCloseFrame{ReasonPhrase: "foo"}
		err := f.Write(buf, 0)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{f}))
	})

	It("saves the encryption level", func() {
		f := &wire.ConnectionCloseFrame{ReasonPhrase: "foo"}
		err := f.Write(buf, 0)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		unpacker.aead.(*mockAEAD).encLevelOpen = protocol.EncryptionSecure
		packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.encryptionLevel).To(Equal(protocol.EncryptionSecure))
	})

	It("unpacks ACK frames", func() {
		unpacker.version = protocol.VersionWhatever
		f := &wire.AckFrame{
			LargestAcked: 0x13,
			LowestAcked:  1,
		}
		err := f.Write(buf, protocol.VersionWhatever)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(HaveLen(1))
		readFrame := packet.frames[0].(*wire.AckFrame)
		Expect(readFrame).ToNot(BeNil())
		Expect(readFrame.LargestAcked).To(Equal(protocol.PacketNumber(0x13)))
	})

	It("handles PADDING frames", func() {
		setData([]byte{0, 0, 0}) // 3 bytes PADDING
		packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(BeEmpty())
	})

	It("handles PADDING between two other frames", func() {
		f := &wire.PingFrame{}
		err := f.Write(buf, protocol.VersionWhatever)
		Expect(err).ToNot(HaveOccurred())
		_, err = buf.Write(bytes.Repeat([]byte{0}, 10)) // 10 bytes PADDING
		Expect(err).ToNot(HaveOccurred())
		err = f.Write(buf, protocol.VersionWhatever)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(HaveLen(2))
	})

	It("unpacks RST_STREAM frames", func() {
		f := &wire.RstStreamFrame{
			StreamID:   0xdeadbeef,
			ByteOffset: 0xdecafbad11223344,
			ErrorCode:  0x13371234,
		}
		err := f.Write(buf, protocol.VersionWhatever)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{f}))
	})

	It("unpacks CONNECTION_CLOSE frames", func() {
		f := &wire.ConnectionCloseFrame{ReasonPhrase: "foo"}
		err := f.Write(buf, protocol.VersionWhatever)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{f}))
	})

	It("unpacks GOAWAY frames", func() {
		f := &wire.GoawayFrame{
			ErrorCode:      1,
			LastGoodStream: 2,
			ReasonPhrase:   "foo",
		}
		err := f.Write(buf, 0)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{f}))
	})

	Context("flow control frames, when the crypto stream is stream 0", func() {
		BeforeEach(func() {
			unpacker.version = versionCryptoStream0
		})

		It("unpacks MAX_DATA frames", func() {
			f := &wire.MaxDataFrame{
				ByteOffset: 0xcafe000000001337,
			}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionCryptoStream0)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks MAX_STREAM_DATA frames", func() {
			f := &wire.MaxStreamDataFrame{
				StreamID:   0xdeadbeef,
				ByteOffset: 0xcafe000000001337,
			}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionCryptoStream0)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks connection-level BLOCKED frames", func() {
			f := &wire.BlockedFrame{}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionCryptoStream0)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks stream-level BLOCKED frames", func() {
			f := &wire.StreamBlockedFrame{StreamID: 0xdeadbeef}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionCryptoStream0)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("errors on invalid frames", func() {
			for b, e := range map[byte]qerr.ErrorCode{
				0x04: qerr.InvalidWindowUpdateData,
				0x05: qerr.InvalidWindowUpdateData,
				0x09: qerr.InvalidBlockedData,
			} {
				setData([]byte{b})
				_, err := unpacker.Unpack(hdrBin, hdr, data, false)
				Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(e))
			}
		})
	})

	Context("flow control frames, when the crypto stream is stream 1", func() {
		BeforeEach(func() {
			unpacker.version = versionCryptoStream1
		})

		It("unpacks a stream-level WINDOW_UPDATE frame", func() {
			f := &wire.MaxStreamDataFrame{
				StreamID:   0xdeadbeef,
				ByteOffset: 0xcafe000000001337,
			}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionCryptoStream1)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks a connection-level WINDOW_UPDATE frame", func() {
			f := &wire.MaxDataFrame{
				ByteOffset: 0xcafe000000001337,
			}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionCryptoStream1)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks connection-level BLOCKED frames", func() {
			f := &wire.BlockedFrame{}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionCryptoStream1)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks stream-level BLOCKED frames", func() {
			f := &wire.StreamBlockedFrame{StreamID: 0xdeadbeef}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionCryptoStream1)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("errors on invalid frames", func() {
			for b, e := range map[byte]qerr.ErrorCode{
				0x04: qerr.InvalidWindowUpdateData,
				0x05: qerr.InvalidBlockedData,
			} {
				setData([]byte{b})
				_, err := unpacker.Unpack(hdrBin, hdr, data, false)
				Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(e))
			}
		})
	})

	It("unpacks STOP_WAITING frames", func() {
		setData([]byte{0x06, 0x03})
		packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{
			&wire.StopWaitingFrame{LeastUnacked: 7},
		}))
	})

	It("unpacks PING frames", func() {
		setData([]byte{0x07})
		packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{
			&wire.PingFrame{},
		}))
	})

	It("unpacks ADD_ADDRESS frames", func() {
		f := &wire.AddAddressFrame{
			AddrID: 5,
			Addr:   net.UDPAddr{IP: net.IPv4(78, 85, 27, 6), Port: 1337},
		}
		buf := &bytes.Buffer{}
		err := f.Write(buf, versionCryptoStream1)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{
			&wire.AddAddressFrame{
				AddrID: 5,
				Addr:   net.UDPAddr{IP: net.IPv4(78, 85, 27, 6), Port: 1337},
			},
		}))
	})

	It("unpacks REMOVE_ADDRESS frames", func() {
		f := &wire.RemoveAddressFrame{
			AddrID: 5,
		}
		buf := &bytes.Buffer{}
		err := f.Write(buf, versionCryptoStream1)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{
			&wire.RemoveAddressFrame{
				AddrID: 5,
			},
		}))
	})

	It("unpacks PATHS frames", func() {
		pinfos := make(map[protocol.PathID]wire.PathInfoSection)
		pinfos[0] = wire.PathInfoSection{
			AddrID: protocol.AddressID(0),
			RTT:    7 * time.Millisecond,
		}
		pinfos[1] = wire.PathInfoSection{
			AddrID: protocol.AddressID(0),
			RTT:    14 * time.Millisecond, // Don"t have a too high value...
		}
		f := &wire.PathsFrame{
			ActivePaths: protocol.PathID(1),
			PathInfos:   pinfos,
		}
		buf := &bytes.Buffer{}
		err := f.Write(buf, versionCryptoStream1)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{
			f,
		}))
	})

	It("errors on invalid type", func() {
		setData([]byte{0xf})
		_, err := unpacker.Unpack(hdrBin, hdr, data, false)
		Expect(err).To(MatchError("InvalidFrameData: unknown type byte 0xf"))
	})

	It("errors on invalid frames", func() {
		for b, e := range map[byte]qerr.ErrorCode{
			0x80: qerr.InvalidStreamData,
			0x40: qerr.InvalidAckData,
			0x01: qerr.InvalidRstStreamData,
			0x02: qerr.InvalidConnectionCloseData,
			0x03: qerr.InvalidGoawayData,
			0x06: qerr.InvalidStopWaitingData,
		} {
			setData([]byte{b})
			_, err := unpacker.Unpack(hdrBin, hdr, data, false)
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(e))
		}
	})

	Context("unpacking STREAM frames", func() {
		It("unpacks unencrypted STREAM frames on the crypto stream", func() {
			unpacker.aead.(*mockAEAD).encLevelOpen = protocol.EncryptionUnencrypted
			f := &wire.StreamFrame{
				StreamID: unpacker.version.CryptoStreamID(),
				Data:     []byte("foobar"),
			}
			err := f.Write(buf, 0)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks encrypted STREAM frames on the crypto stream", func() {
			unpacker.aead.(*mockAEAD).encLevelOpen = protocol.EncryptionSecure
			f := &wire.StreamFrame{
				StreamID: unpacker.version.CryptoStreamID(),
				Data:     []byte("foobar"),
			}
			err := f.Write(buf, 0)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("does not unpack unencrypted STREAM frames on higher streams", func() {
			unpacker.aead.(*mockAEAD).encLevelOpen = protocol.EncryptionUnencrypted
			f := &wire.StreamFrame{
				StreamID: 3,
				Data:     []byte("foobar"),
			}
			err := f.Write(buf, 0)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			_, err = unpacker.Unpack(hdrBin, hdr, data, false)
			Expect(err).To(MatchError(qerr.Error(qerr.UnencryptedStreamData, "received unencrypted stream data on stream 3")))
		})
	})
})
