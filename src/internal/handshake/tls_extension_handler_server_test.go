package handshake

import (
	"fmt"

	"github.com/bifurcation/mint"
	"github.com/bifurcation/mint/syntax"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func parameterMapToList(paramMap map[transportParameterID][]byte) []transportParameter {
	var params []transportParameter
	for id, val := range paramMap {
		params = append(params, transportParameter{id, val})
	}
	return params
}

var _ = Describe("TLS Extension Handler, for the server", func() {
	var (
		handler    *extensionHandlerServer
		el         mint.ExtensionList
		paramsChan chan TransportParameters
	)

	BeforeEach(func() {
		// use a buffered channel here, so that we don't have to receive concurrently when parsing a message
		paramsChan = make(chan TransportParameters, 1)
		handler = newExtensionHandlerServer(&TransportParameters{}, paramsChan, nil, protocol.VersionWhatever)
		el = make(mint.ExtensionList, 0)
	})

	Context("sending", func() {
		It("only adds TransportParameters for the ClientHello", func() {
			// test 2 other handshake types
			err := handler.Send(mint.HandshakeTypeCertificateRequest, &el)
			Expect(err).ToNot(HaveOccurred())
			Expect(el).To(BeEmpty())
			err = handler.Send(mint.HandshakeTypeEndOfEarlyData, &el)
			Expect(err).ToNot(HaveOccurred())
			Expect(el).To(BeEmpty())
		})

		It("adds TransportParameters to the EncryptedExtensions message", func() {
			handler.supportedVersions = []protocol.VersionNumber{13, 37, 42}
			err := handler.Send(mint.HandshakeTypeEncryptedExtensions, &el)
			Expect(err).ToNot(HaveOccurred())
			Expect(el).To(HaveLen(1))
			ext := &tlsExtensionBody{}
			found, err := el.Find(ext)
			Expect(err).ToNot(HaveOccurred())
			Expect(found).To(BeTrue())
			eetp := &encryptedExtensionsTransportParameters{}
			_, err = syntax.Unmarshal(ext.data, eetp)
			Expect(err).ToNot(HaveOccurred())
			Expect(eetp.SupportedVersions).To(Equal([]uint32{13, 37, 42}))
		})
	})

	Context("receiving", func() {
		var fakeBody *tlsExtensionBody
		var parameters map[transportParameterID][]byte

		addClientHelloWithParameters := func(paramMap map[transportParameterID][]byte) {
			body, err := syntax.Marshal(clientHelloTransportParameters{Parameters: parameterMapToList(paramMap)})
			Expect(err).ToNot(HaveOccurred())
			err = el.Add(&tlsExtensionBody{data: body})
			Expect(err).ToNot(HaveOccurred())
		}

		BeforeEach(func() {
			fakeBody = &tlsExtensionBody{data: []byte("foobar foobar")}
			parameters = map[transportParameterID][]byte{
				initialMaxStreamDataParameterID: []byte{0x11, 0x22, 0x33, 0x44},
				initialMaxDataParameterID:       []byte{0x22, 0x33, 0x44, 0x55},
				initialMaxStreamIDParameterID:   []byte{0x33, 0x44, 0x55, 0x66},
				idleTimeoutParameterID:          []byte{0x13, 0x37},
			}
		})

		It("accepts the TransportParameters on the EncryptedExtensions message", func() {
			addClientHelloWithParameters(parameters)
			err := handler.Receive(mint.HandshakeTypeClientHello, &el)
			Expect(err).ToNot(HaveOccurred())
			var params TransportParameters
			Expect(paramsChan).To(Receive(&params))
			Expect(params.StreamFlowControlWindow).To(BeEquivalentTo(0x11223344))
		})

		It("errors if the ClientHello doesn't contain TransportParameters", func() {
			err := handler.Receive(mint.HandshakeTypeClientHello, &el)
			Expect(err).To(MatchError("ClientHello didn't contain a QUIC extension"))
		})

		It("ignores messages without TransportParameters, if they are not required", func() {
			err := handler.Receive(mint.HandshakeTypeCertificate, &el)
			Expect(err).ToNot(HaveOccurred())
		})

		It("errors if it can't unmarshal the TransportParameters", func() {
			err := el.Add(fakeBody)
			Expect(err).ToNot(HaveOccurred())
			err = handler.Receive(mint.HandshakeTypeClientHello, &el)
			Expect(err).To(HaveOccurred()) // this will be some kind of decoding error
		})

		It("rejects messages other than the ClientHello that contain TransportParameters", func() {
			addClientHelloWithParameters(parameters)
			err := handler.Receive(mint.HandshakeTypeCertificateRequest, &el)
			Expect(err).To(MatchError(fmt.Sprintf("Unexpected QUIC extension in handshake message %d", mint.HandshakeTypeCertificateRequest)))
		})

		It("rejects messages that contain a stateless reset token", func() {
			parameters[statelessResetTokenParameterID] = []byte("reset")
			addClientHelloWithParameters(parameters)
			err := handler.Receive(mint.HandshakeTypeClientHello, &el)
			Expect(err).To(MatchError("client sent a stateless reset token"))
		})

		Context("Version Negotiation", func() {
			It("accepts a ClientHello, when no version negotiation was performed", func() {
				handler.version = 42
				body, err := syntax.Marshal(clientHelloTransportParameters{
					NegotiatedVersion: 42,
					InitialVersion:    42,
					Parameters:        parameterMapToList(parameters),
				})
				Expect(err).ToNot(HaveOccurred())
				err = el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeClientHello, &el)
				Expect(err).ToNot(HaveOccurred())
			})

			It("accepts a valid version negotiation", func() {
				handler.version = 42
				handler.supportedVersions = []protocol.VersionNumber{13, 37, 42}
				body, err := syntax.Marshal(clientHelloTransportParameters{
					NegotiatedVersion: 42,
					InitialVersion:    22, // this must be an unsupported version
					Parameters:        parameterMapToList(parameters),
				})
				Expect(err).ToNot(HaveOccurred())
				err = el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeClientHello, &el)
				Expect(err).ToNot(HaveOccurred())
			})

			It("errors when the NegotiatedVersion field doesn't match the current version", func() {
				handler.version = 42
				body, err := syntax.Marshal(clientHelloTransportParameters{NegotiatedVersion: 43})
				Expect(err).ToNot(HaveOccurred())
				err = el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeClientHello, &el)
				Expect(err).To(MatchError("VersionNegotiationMismatch: Inconsistent negotiated version"))
			})

			It("errros when a version negotiation was performed, although we already support the inital version", func() {
				handler.supportedVersions = []protocol.VersionNumber{11, 12, 13}
				handler.version = 13
				body, err := syntax.Marshal(clientHelloTransportParameters{
					NegotiatedVersion: 13,
					InitialVersion:    11, // this is an supported version
				})
				Expect(err).ToNot(HaveOccurred())
				err = el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeClientHello, &el)
				Expect(err).To(MatchError("VersionNegotiationMismatch: Client should have used the initial version"))
			})
		})
	})
})
