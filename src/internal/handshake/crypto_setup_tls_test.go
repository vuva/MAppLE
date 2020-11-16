package handshake

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/mocks/crypto"
	"github.com/lucas-clemente/quic-go/internal/mocks/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func mockKeyDerivation(crypto.TLSExporter, protocol.Perspective) (crypto.AEAD, error) {
	return mockcrypto.NewMockAEAD(mockCtrl), nil
}

var _ = Describe("TLS Crypto Setup", func() {
	var (
		cs          *cryptoSetupTLS
		paramsChan  chan TransportParameters
		aeadChanged chan protocol.EncryptionLevel
	)

	BeforeEach(func() {
		paramsChan = make(chan TransportParameters)
		aeadChanged = make(chan protocol.EncryptionLevel, 2)
		csInt, err := NewCryptoSetupTLSServer(
			nil,
			1,
			testdata.GetTLSConfig(),
			nil,
			&TransportParameters{},
			paramsChan,
			aeadChanged,
			nil,
			nil,
			protocol.VersionTLS,
		)
		Expect(err).ToNot(HaveOccurred())
		cs = csInt.(*cryptoSetupTLS)
		cs.nullAEAD = mockcrypto.NewMockAEAD(mockCtrl)
	})

	It("errors when the handshake fails", func() {
		alert := mint.AlertBadRecordMAC
		cs.tls = mockhandshake.NewMockmintTLS(mockCtrl)
		cs.tls.(*mockhandshake.MockmintTLS).EXPECT().Handshake().Return(alert)
		err := cs.HandleCryptoStream()
		Expect(err).To(MatchError(fmt.Errorf("TLS handshake error: %s (Alert %d)", alert.String(), alert)))
	})

	It("continues shaking hands when mint says that it would block", func() {
		cs.conn.stream = &bytes.Buffer{}
		cs.tls = mockhandshake.NewMockmintTLS(mockCtrl)
		cs.tls.(*mockhandshake.MockmintTLS).EXPECT().Handshake().Return(mint.AlertWouldBlock)
		cs.tls.(*mockhandshake.MockmintTLS).EXPECT().State().Return(mint.ConnectionState{})
		cs.tls.(*mockhandshake.MockmintTLS).EXPECT().Handshake().Return(mint.AlertNoAlert)
		cs.keyDerivation = mockKeyDerivation
		err := cs.HandleCryptoStream()
		Expect(err).ToNot(HaveOccurred())
	})

	It("derives keys", func() {
		cs.tls = mockhandshake.NewMockmintTLS(mockCtrl)
		cs.tls.(*mockhandshake.MockmintTLS).EXPECT().Handshake().Return(mint.AlertNoAlert)
		cs.keyDerivation = mockKeyDerivation
		err := cs.HandleCryptoStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(aeadChanged).To(Receive(Equal(protocol.EncryptionForwardSecure)))
		Expect(aeadChanged).To(BeClosed())
	})

	Context("determining the packet type", func() {
		Context("for the client", func() {
			var csClient *cryptoSetupTLS

			BeforeEach(func() {
				csInt, err := NewCryptoSetupTLSClient(
					nil,
					1,
					"quic.clemente.io",
					testdata.GetTLSConfig(),
					&TransportParameters{},
					paramsChan,
					aeadChanged,
					protocol.VersionTLS,
					[]protocol.VersionNumber{protocol.VersionTLS},
					protocol.VersionTLS,
				)
				Expect(err).ToNot(HaveOccurred())
				csClient = csInt.(*cryptoSetupTLS)
				csClient.tls = mockhandshake.NewMockmintTLS(mockCtrl)
			})

			It("sends a Client Initial first", func() {
				Expect(csClient.GetNextPacketType()).To(Equal(protocol.PacketTypeInitial))
			})

			It("sends a Handshake packet after the server sent a Server Hello", func() {
				csClient.tls.(*mockhandshake.MockmintTLS).EXPECT().State().Return(mint.ConnectionState{HandshakeState: mint.StateClientWaitEE})
				err := csClient.determineNextPacketType()
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("for the server", func() {
			BeforeEach(func() {
				cs.tls = mockhandshake.NewMockmintTLS(mockCtrl)
			})

			It("sends a Stateless Retry packet", func() {
				cs.tls.(*mockhandshake.MockmintTLS).EXPECT().State().Return(mint.ConnectionState{HandshakeState: mint.StateServerStart})
				err := cs.determineNextPacketType()
				Expect(err).ToNot(HaveOccurred())
				Expect(cs.GetNextPacketType()).To(Equal(protocol.PacketTypeRetry))
			})

			It("sends Handshake packet", func() {
				cs.tls.(*mockhandshake.MockmintTLS).EXPECT().State().Return(mint.ConnectionState{HandshakeState: mint.StateServerWaitFinished})
				err := cs.determineNextPacketType()
				Expect(err).ToNot(HaveOccurred())
				Expect(cs.GetNextPacketType()).To(Equal(protocol.PacketTypeHandshake))
			})
		})
	})

	Context("escalating crypto", func() {
		doHandshake := func() {
			cs.tls = mockhandshake.NewMockmintTLS(mockCtrl)
			cs.tls.(*mockhandshake.MockmintTLS).EXPECT().Handshake().Return(mint.AlertNoAlert)
			cs.keyDerivation = mockKeyDerivation
			err := cs.HandleCryptoStream()
			Expect(err).ToNot(HaveOccurred())
		}

		Context("null encryption", func() {
			It("is used initially", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(5), []byte{}).Return([]byte("foobar signed"))
				enc, sealer := cs.GetSealer()
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
				d := sealer.Seal(nil, []byte("foobar"), 5, []byte{})
				Expect(d).To(Equal([]byte("foobar signed")))
			})

			It("is accepted initially", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("foobar enc"), protocol.PacketNumber(10), []byte{}).Return([]byte("foobar"), nil)
				d, enc, err := cs.Open(nil, []byte("foobar enc"), 10, []byte{})
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("foobar")))
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
			})

			It("is used for crypto stream", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(20), []byte{}).Return([]byte("foobar signed"))
				enc, sealer := cs.GetSealerForCryptoStream()
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
				d := sealer.Seal(nil, []byte("foobar"), 20, []byte{})
				Expect(d).To(Equal([]byte("foobar signed")))
			})

			It("errors if the has the wrong hash", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("foobar enc"), protocol.PacketNumber(10), []byte{}).Return(nil, errors.New("authentication failed"))
				_, enc, err := cs.Open(nil, []byte("foobar enc"), 10, []byte{})
				Expect(err).To(MatchError("authentication failed"))
				Expect(enc).To(Equal(protocol.EncryptionUnspecified))
			})

			It("is not accepted after the handshake completes", func() {
				doHandshake()
				cs.aead.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("foobar encrypted"), protocol.PacketNumber(1), []byte{}).Return(nil, errors.New("authentication failed"))
				_, enc, err := cs.Open(nil, []byte("foobar encrypted"), 1, []byte{})
				Expect(err).To(MatchError("authentication failed"))
				Expect(enc).To(Equal(protocol.EncryptionUnspecified))
			})
		})

		Context("forward-secure encryption", func() {
			It("is used for sealing after the handshake completes", func() {
				doHandshake()
				cs.aead.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(5), []byte{}).Return([]byte("foobar forward sec"))
				enc, sealer := cs.GetSealer()
				Expect(enc).To(Equal(protocol.EncryptionForwardSecure))
				d := sealer.Seal(nil, []byte("foobar"), 5, []byte{})
				Expect(d).To(Equal([]byte("foobar forward sec")))
			})

			It("is used for opening after the handshake completes", func() {
				doHandshake()
				cs.aead.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("encrypted"), protocol.PacketNumber(6), []byte{}).Return([]byte("decrypted"), nil)
				d, enc, err := cs.Open(nil, []byte("encrypted"), 6, []byte{})
				Expect(err).ToNot(HaveOccurred())
				Expect(enc).To(Equal(protocol.EncryptionForwardSecure))
				Expect(d).To(Equal([]byte("decrypted")))
			})
		})

		Context("forcing encryption levels", func() {
			It("forces null encryption", func() {
				doHandshake()
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(5), []byte{}).Return([]byte("foobar signed"))
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionUnencrypted)
				Expect(err).ToNot(HaveOccurred())
				d := sealer.Seal(nil, []byte("foobar"), 5, []byte{})
				Expect(d).To(Equal([]byte("foobar signed")))
			})

			It("forces forward-secure encryption", func() {
				doHandshake()
				cs.aead.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(5), []byte{}).Return([]byte("foobar forward sec"))
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionForwardSecure)
				Expect(err).ToNot(HaveOccurred())
				d := sealer.Seal(nil, []byte("foobar"), 5, []byte{})
				Expect(d).To(Equal([]byte("foobar forward sec")))
			})

			It("errors if the forward-secure AEAD is not available", func() {
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionForwardSecure)
				Expect(err).To(MatchError("CryptoSetup: no sealer with encryption level forward-secure"))
				Expect(sealer).To(BeNil())
			})

			It("never returns a secure AEAD (they don't exist with TLS)", func() {
				doHandshake()
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionSecure)
				Expect(err).To(MatchError("CryptoSetup: no sealer with encryption level encrypted (not forward-secure)"))
				Expect(sealer).To(BeNil())
			})

			It("errors if no encryption level is specified", func() {
				seal, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionUnspecified)
				Expect(err).To(MatchError("CryptoSetup: no sealer with encryption level unknown"))
				Expect(seal).To(BeNil())
			})
		})
	})
})
