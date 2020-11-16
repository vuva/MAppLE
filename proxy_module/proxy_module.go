package main

import "C"

import (
	"bytes"
	"crypto/tls"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/net/http2"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/logger"
)

func main() {}

const (
	// Prefix for PROXY specific messages
	logTag = "PROXY MODULE:"
)

var (
	/* Specify if the single connection between the proxy and
	 * the remote host is kept open between requests.
	 */
	keepAlive = true

	// Use QUIC instead of tcp
	useQUIC bool
	// Activate multipath, when QUIC is used
	useMP             bool
	schedulingScheme  string
	congestionControl string

	// FEC Config
	useFEC    bool
	fecConfig string

	/* Global HTTP/2 Client:
	* Only one is used for all incoming connections, for accessing
	* the transportion behaviour over a dedicated connection.
	 */
	hclient      *http.Client
	roundTripper *h2quic.RoundTripper

	// Specifiy wether the download rate should be logged periodically to file.
	loggerDeployed bool
	logFile        *os.File
	logStart       int64
	logTicker      *time.Ticker
	logStopChannel chan struct{}

	logLastTS     int64
	recvBytes     uint64
	lastRecvBytes uint64
)

//export ClientSetup
func ClientSetup(usequic, mp, keepalive bool, scheduler, cc string) {
	useQUIC = usequic
	useMP = mp
	keepAlive = keepalive
	schedulingScheme = scheduler
	congestionControl = cc
}

//export FECSetup
func FECSetup(use bool, config string) {
	useFEC = use
	fecConfig = config
}

//export CloseConnection
func CloseConnection() {
	if hclient != nil {
		hclient.CloseIdleConnections()
		hclient = nil
	}
	if roundTripper != nil {
		roundTripper.Close()
		roundTripper = nil
	}
}

//export DownloadSegment
func DownloadSegment(segmentURL string, filename string) int {

	if hclient == nil || !keepAlive {
		createRemoteClient()
	}

	// Send request to the remote host
	rsp, err := hclient.Get(segmentURL)
	if err != nil {
		log.Println(logTag, "error : ", err)
		return -1
	}

	// Synchronous (blocking) stream forwarding to buffer.
	// Ends on EOF or error.
	body := &bytes.Buffer{}
	_, err = io.Copy(body, rsp.Body)
	if err != nil {
		log.Println(logTag, "error : ", err)
		return -1
	}
	rsp.Body.Close()
	recvBytes += uint64(body.Len())

	if filename != "" {
		ioutil.WriteFile(filename, body.Bytes(), 0644)
	}

	if !keepAlive {
		hclient.CloseIdleConnections()
		hclient = nil
	}

	return body.Len()
}

// Create a HTTP/2.0 client with different transport protocols
func createRemoteClient() {

	// Accept any offered certificate chain
	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	if useQUIC {
		var maxPathID uint8 = 0
		if useMP {
			maxPathID = 2
		}

		fs, rc := quic.FECConfigFromString(fecConfig)

		quicConfig := quic.Config{
			MaxPathID:                   maxPathID,
			SchedulingSchemeName:        schedulingScheme,
			CongestionControlName:       congestionControl,
			FECScheme:                   fs,
			RedundancyController:        rc,
			ProtectReliableStreamFrames: useFEC,
			DisableFECRecoveredFrames:   false,
		}

		// Use a HTTP/2.0 connection via QUIC
		roundTripper = &h2quic.RoundTripper{
			TLSClientConfig: tlsConfig,
			QuicConfig:      &quicConfig,
		}

		hclient = &http.Client{
			Transport: roundTripper,
		}

		log.Printf("%s created http2 QUIC client (MP: %t, %s)", logTag, useMP, schedulingScheme)
	} else {
		// Use a HTTP/2.0 connection via TLS
		hclient = &http.Client{}

		// configure client to use http2
		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
		}
		err := http2.ConfigureTransport(transport)
		if err != nil {
			log.Printf("%s ConfigureTransport http2 %v", logTag, err)
		}
		hclient.Transport = transport

		log.Printf("%s created http2 TLS client", logTag)
	}
}

//export StartLogging
func StartLogging(period uint) {
	os.MkdirAll("proxy_log/", 0777)

	fecName := fecConfig
	if !useFEC {
		fecName = "none"
	}

	prefix := "proxy_log/" + schedulingScheme + "_" + fecName + "_" + strconv.FormatInt(time.Now().Unix(), 10)
	logger.InitExperimentationLogger(prefix)

	if logTicker == nil {
		logTicker = time.NewTicker(time.Duration(period) * time.Millisecond)
		logStopChannel = make(chan struct{})

		go logReceivings(logTicker, logStopChannel)
	}
}

//export StopLogging
func StopLogging() {
	logger.FlushExperimentationLogger()

	if logStopChannel != nil {
		logStopChannel <- struct{}{}
	}
}

// Periodic logging routine
func logReceivings(ticker *time.Ticker, stopChannel chan struct{}) {
	for {
		select {
		case <-ticker.C:
			// Received logging tick, perform logging routine
			if logFile == nil {
				logStart = time.Now().UnixNano()
				logLastTS = logStart

				// Open log file
				filename := "Client" + "_recv.log"
				var err error
				logFile, err = os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					return
				}
			}

			// Time measuring
			now := time.Now().UnixNano()
			elapsed := float64((now - logLastTS) / 1e6)
			logLastTS = now

			// Only read recvBytes variable once, since it is thread shared
			recvBytesCopy := recvBytes
			// Download rate over the last period in KBit/s
			sentDelta := recvBytesCopy - lastRecvBytes
			lastRecvBytes = recvBytesCopy
			sendRate := float64(sentDelta) * 8.0 / elapsed

			// Transform absolute to relative [ms] timestamp string
			timestring := strconv.FormatFloat(float64((now-logStart)/1e6), 'f', -1, 64)
			logLine := timestring + ";" + strconv.FormatFloat(sendRate, 'g', -1, 64) + "\n"
			logFile.WriteString(logLine)
		case <-stopChannel:
			// Stop logging
			ticker.Stop()
			return
		}
	}
}
