package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"

	"sync"

	// "errors"
	"flag"
	"fmt"
	"io"
	"log"

	// "math"
	"math/big"
	"math/rand"
	"net"

	// "net/http"
	// "encoding/base64"
	"os"
	"strconv"
	"strings"
	"time"

	quic "github.com/lucas-clemente/quic-go"

	// "github.com/lucas-clemente/quic-go/h2quic"
	// "github.com/lucas-clemente/quic-go/internal/testdata"
	// "github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"

	// "quic-go"
	//	"io/ioutil"
	"container/list"
)

type binds []string

type ServerLogRecord struct {
	timestamp   uint
	messageSize protocol.ByteCount
}

type ServerLog struct {
	data map[uint]ServerLogRecord
	lock sync.RWMutex
}

type TrafficGenConfig struct {
	Mode              string
	RunTime           uint
	StartDelay        uint
	CsizeDistro       string
	CsizeValue        float64
	ArrDistro         string
	ArrValue          float64
	Unlimited         bool
	Address           string
	Protocol          string
	LogFolder         string
	IsMultipath       bool
	IsMultiStream     bool
	Sched             string
	Debug             bool
	CongestionControl string
	IsBlockCall       bool
	IsReverse         bool
}

func (b binds) String() string {
	return strings.Join(b, ",")
}

func (b *binds) Set(v string) error {
	*b = strings.Split(v, ",")
	return nil
}

type MessageList struct {
	mess_list *list.List
	// isSending bool
	mutex sync.RWMutex
}

const BASE_SEQ_NO uint = 2147483648 // 0x80000000
var LOG_PREFIX string = ""

const SERVER_ADDRESS string = "10.1.1.2"
const SERVER_TCP_PORT int = 2121
const SERVER_QUIC_PORT int = 4343
const STREAM_TIMEOUT int = 5
const MB = 1 << 20
const MAX_SEND_BUFFER_SIZE = 4194304

type ClientManager struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
}

type Client struct {
	socket net.Conn
	data   chan []byte
}

func (manager *ClientManager) start() {
	for {
		select {
		case connection := <-manager.register:
			manager.clients[connection] = true
			fmt.Println("Added new connection!")
		case connection := <-manager.unregister:
			if _, ok := manager.clients[connection]; ok {
				close(connection.data)
				delete(manager.clients, connection)
				fmt.Println("A connection has terminated!")
			}
		case message := <-manager.broadcast:
			for connection := range manager.clients {
				select {
				case connection.data <- message:
				default:
					close(connection.data)
					delete(manager.clients, connection)
				}
			}
		}
	}
}

func (manager *ClientManager) communicate(client *Client, config *TrafficGenConfig) {
	if !config.IsReverse {
		receiveTCP(client.socket)
	} else {
		if config.Protocol == "tcp" {
			tcp_connection := client.socket.(*net.TCPConn)
			send(nil, tcp_connection, config)
		} else {

		}
	}
	manager.unregister <- client
}

func receiveTCP(socket net.Conn) {
	timeStamps := make(map[uint]ServerLogRecord)
	buffer := make([]byte, 0)
	for {
		message := make([]byte, 65536)
		length, err := socket.Read(message)
		if err != nil {
			log.Println(err)

			socket.Close()
			break
		}
		if length > 0 {
			message = message[0:length]
			// utils.Debugf("\n RECEIVED: %x \n", message)
			// manager.broadcast <- message
			eoc_byte_index := bytes.Index(message, intToBytes(uint(BASE_SEQ_NO-1), 4))
			// log.Println(eoc_byte_index)

			for eoc_byte_index != -1 {
				data_chunk := append(buffer, message[0:eoc_byte_index+4]...)
				//				seq_no := message[eoc_byte_index-4:eoc_byte_index]
				// utils.Debugf("\n CHUNK: %x \n  length %d \n", data_chunk, len(data_chunk))
				// Get data chunk ID and record receive timestampt
				seq_no := data_chunk[0:4]
				seq_no_int := bytesToInt(seq_no)
				timeStamps[seq_no_int] = ServerLogRecord{
					timestamp:   uint(time.Now().UnixNano()),
					messageSize: protocol.ByteCount(eoc_byte_index + 4),
				}
				//				buffer.Write(message[eoc_byte_index:length])

				// Cut out recorded chunk
				message = message[eoc_byte_index+4:]
				buffer = make([]byte, 0)
				eoc_byte_index = bytes.Index(message, intToBytes(uint(BASE_SEQ_NO-1), 4))
			}
			buffer = append(buffer, message...)
		}
	}

	writeToFile(LOG_PREFIX+"receiver-timestamp.log", timeStamps)
}

func (manager *ClientManager) send(client *Client) {
	defer client.socket.Close()
	for {
		select {
		case message, ok := <-client.data:
			if !ok {
				return
			}
			client.socket.Write(message)
		}
	}
}

func startServerMode(config *TrafficGenConfig) {
	fmt.Println("Starting server...")
	var listener net.Listener
	var err error
	manager := ClientManager{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
	go manager.start()

	switch config.Protocol {
	case "tcp":

		listener, err = net.Listen("tcp", config.Address)
		if err != nil {
			log.Println(err)
		}
		log.Println("TCP Listen ...")
		for {
			connection, _ := listener.Accept()
			tcp_connection := connection.(*net.TCPConn)
			tcp_connection.SetNoDelay(true)
			if err != nil {
				log.Println(err)
			}
			client := &Client{socket: tcp_connection, data: make(chan []byte)}
			manager.register <- client
			go manager.communicate(client, config)
			//		go manager.send(client)
		}
	case "quic":

		startQUICServer(config.Address, config.IsMultipath, config.IsMultiStream, config.Sched)

	}

}

func startClientMode(config *TrafficGenConfig) {
	fmt.Println("Starting client...")

	// var stream quic.Stream
	var quic_session quic.Session
	var connection *net.TCPConn
	var err error

	if config.Protocol == "quic" {
		addresses := []string{config.Address}
		quic_session, err = startQUICSession(addresses, config.Sched, config.IsMultipath)
		if err != nil {
			panic(err)
		}
		// defer stream.Close()
		defer quic_session.Close(nil)

	} else if config.Protocol == "tcp" {
		tcp_address := strings.Split(config.Address, ":")
		ip_add := net.ParseIP(tcp_address[0]).To4()
		port, _ := strconv.Atoi(tcp_address[1])
		connection, err = net.DialTCP("tcp", nil, &net.TCPAddr{IP: ip_add, Port: port})
		connection.SetNoDelay(true)
		defer connection.Close()

	}
	//	addr,_:=net.ResolveTCPAddr("tcp", address+":443")
	//	connection, error := net.DialTCP("tcp", nil, addr)

	if err != nil {
		log.Println(err)
	}
	if !config.IsReverse {
		send(quic_session, connection, config)
	} else {
		if config.Protocol == "tcp" {
			receiveTCP(connection)
		} else {

		}
	}

}

func send(quic_session quic.Session, connection *net.TCPConn, config *TrafficGenConfig) {
	sendingDone := make(chan bool)
	generatingDone := make(chan bool)
	var err error
	var run_time_duration time.Duration
	run_time_duration, err = time.ParseDuration(strconv.Itoa(int(config.RunTime)) + "ms")
	startDelay, err := time.ParseDuration(strconv.Itoa(int(config.StartDelay)) + "ms")
	if err != nil {
		log.Println(err)
	}

	startTime := time.Now().Add(startDelay)
	endTime := startTime.Add(run_time_duration)
	timeStamps := make(map[uint]ServerLogRecord)

	// writeTime := make(map[uint]uint)
	send_queue := MessageList{mess_list: list.New()}
	gen_finished := false

	go func() {
		gen_counter := 1
		gen_bytes := 0

		for i := 1; time.Now().Before(endTime); i++ {
			send_queue_size := 0
			for e := send_queue.mess_list.Front(); e != nil && e.Value != nil; e = e.Next() {
				send_queue_size += len(e.Value.([]byte))
			}

			if ((config.Protocol == "tcp" || config.IsBlockCall) && send_queue.mess_list.Len() > 0) || send_queue_size > MAX_SEND_BUFFER_SIZE {
				time.Sleep(time.Nanosecond)
				continue
			}
			// reader := bufio.NewReader(os.Stdin)
			// message, _ := reader.ReadString('\n')
			//			utils.Debugf("before: %d \n", time.Now().UnixNano())
			message, seq := generateMessage(uint(gen_counter), config.CsizeDistro, config.CsizeValue)
			gen_counter++
			gen_bytes += len(message)
			// send_queue = append(send_queue, message)
			// next_message := send_queue[0]

			// if !isBlockingCall {
			var wait_time uint
			if time.Now().Before(startTime) {
				wait_time = 1000000000
			} else {
				wait_time = uint(1000000000/getRandom(config.ArrDistro, config.ArrValue)) - (uint(time.Now().UnixNano()) - timeStamps[seq-1].timestamp)
			}

			if !config.Unlimited && wait_time > 0 {
				wait(wait_time)
			}
			// }

			// if !isBlockingCall {
			// Get time at the moment message generated
			timeStamps[seq] = ServerLogRecord{
				timestamp:   uint(time.Now().UnixNano()),
				messageSize: protocol.ByteCount(len(message)),
			}
			// utils.Debugf("Messages in queue: %d \n", len(send_queue))

			// }
			send_queue.mutex.Lock()
			send_queue.mess_list.PushBack(message)
			send_queue.mutex.Unlock()

			// writeTime[seq] = uint(time.Now().UnixNano()) - timeStamps[seq]

			// remove sent file from the queue
			// send_queue = send_queue[1:]

			// utils.Debugf("PUT: %d \n", seq)

		}
		utils.Debugf("Done after %dms", run_time_duration.Milliseconds())
		utils.Debugf("Generate total: %d messages, %d bytes", gen_counter, gen_bytes)
		gen_finished = true
		generatingDone <- true
	}()

	go func() {
		sent_counter := 0
		var current_stream quic.Stream

		for !gen_finished {
			time.Sleep(time.Nanosecond)
			if send_queue.mess_list.Len() == 0 {
				continue
			}
			queue_font := send_queue.mess_list.Front()
			message, _ := queue_font.Value.([]byte)
			// beforesent := time.Now()
			// if isBlockingCall {
			// 	// Get time at the moment message put in stream
			// 	timeStamps[bytesToInt(message[0:4])] = uint(time.Now().UnixNano())
			// }

			// send_queue.mutex.Lock()
			// send_queue.isSending = true
			// send_queue.mutex.Unlock()

			utils.Debugf("Message in queue: %d at %d \n", send_queue.mess_list.Len(), uint(time.Now().UnixNano()))
			if config.Protocol == "quic" {
				if config.IsMultiStream {

					go startQUICClientStream(quic_session, message)
				} else {
					if current_stream == nil || current_stream.StreamID() == 3 || current_stream.StreamID() == 1 {
						current_stream, err = quic_session.OpenStreamSync()
						if err != nil {
							utils.Debugf("Error OpenStreamSync:", err)
							return
						}

						defer current_stream.Close()
					}
					utils.Debugf("OpenStream count: %d, message %d", quic_session.GetOpenStreamNo(), bytesToInt(message[0:4]))
					// beforeWrite := time.Now()
					current_stream.Write(message)
					// utils.Debugf("StreamID: %d write %d", current_stream.StreamID(), time.Now().Sub(beforeWrite).Nanoseconds())

				}

			} else if config.Protocol == "tcp" {
				go connection.Write(message)

			}

			sent_counter++
			send_queue.mutex.Lock()
			// send_queue.isSending = false
			send_queue.mess_list.Remove(queue_font)
			send_queue.mutex.Unlock()

			// if isBlockingCall {
			// 	// utils.Debugf("Sent time: %d ", time.Now().Sub(beforesent).Nanoseconds())
			// 	var wait_time uint
			// 	if time.Now().Before(startTime) {
			// 		wait_time = 1000000000
			// 	} else {
			// 		wait_time = uint(1000000000/getRandom(arrival_distro, arrival_value)) - (uint(time.Now().UnixNano()) - timeStamps[bytesToInt(message[0:4])])
			// 		// wait_time = uint(1000000000/getRandom(arrival_distro, arrival_value)) - (uint(time.Now().UnixNano()) - timeStamps[seq-1])

			// 	}
			// 	if wait_time > 0 {
			// 		wait(wait_time)
			// 	}
			// }

		}
		utils.Debugf("Sent total: %d messages", sent_counter)

		sendingDone <- true

	}()
	<-generatingDone
	<-sendingDone
	writeToFile(LOG_PREFIX+"sender-timestamp.log", timeStamps)
	// writeToFile(LOG_PREFIX+"write-timegap.log", writeTime)
	os.Rename("sender-frame.log", LOG_PREFIX+"sender-frame.log")
	os.Rename("receiver-frame.log", LOG_PREFIX+"receiver-frame.log")

	// }()
}

func startQUICClientStream(quic_session quic.Session, message []byte) {
	beforeOpen := time.Now()
	stream, err := quic_session.OpenStreamSync()
	if err != nil {
		utils.Debugf("Error OpenStreamSync:", err)
		return
	}
	defer stream.Close()
	utils.Debugf("OpenStream count: %d at %d", quic_session.GetOpenStreamNo(), time.Now().UnixNano())
	beforeWrite := time.Now()
	stream.Write(message)
	utils.Debugf("StreamID: %d open %d write %d", stream.StreamID(), beforeWrite.Sub(beforeOpen).Nanoseconds(), time.Now().Sub(beforeWrite).Nanoseconds())
	quic_session.RemoveStream(stream.StreamID())
}

func startQUICServer(addr string, isMultipath bool, isMultiStream bool, scheduler string) error {
	var maxPathID uint8
	if isMultipath {
		maxPathID = 2
	}

	listener, err := quic.ListenAddr(addr, generateTLSConfig(), &quic.Config{
		MaxPathID:            maxPathID,
		SchedulingSchemeName: scheduler,
		// MaxReceiveStreamFlowControlWindow:     uint64(protocol.ByteCount(math.Floor(100 * MB))),
		// MaxReceiveConnectionFlowControlWindow: uint64(protocol.ByteCount(math.Floor(100 * MB))),
	})
	if err != nil {
		return err
	}
	sess, err := listener.Accept()
	if err != nil {
		return err
	}
	defer sess.Close(err)

	serverlog := ServerLog{
		data: make(map[uint]ServerLogRecord),
		lock: sync.RWMutex{},
	}

	// previous := BASE_SEQ_NO

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			utils.Errorf("AcceptStream: ", err)
			break
		}
		// defer stream.Close()
		go receiveQUICStream(sess, stream, isMultiStream, &serverlog)

	}

	writeToFile(LOG_PREFIX+"server-timestamp.log", serverlog.data)
	fmt.Printf("\nFinish receive: %d messages \n", len(serverlog.data))
	return err
}

func receiveQUICStream(sess quic.Session, stream quic.Stream, isMultistream bool, serverlog *ServerLog) {
	utils.Debugf("\n Get data from stream: %d \n at ", stream.StreamID(), time.Now().UnixNano())
	// beginstream := time.Now()
	buffer := make([]byte, 0)
	defer stream.Close()
	// prevTime := time.Now()
messageLoop:
	for {
		// readTime := time.Now()
		message := make([]byte, 65536)
		length, err := stream.Read(message)

		if length > 0 {
			message = message[0:length]
			// utils.Debugf("\n after %d RECEIVED from stream %d mes_len %d buffer %d: %x...%x \n", time.Now().Sub(prevTime).Nanoseconds(), stream.StreamID(), length, len(buffer), message[0:4], message[length-4:length])
			// prevTime = time.Now()
			eoc_byte_index := bytes.Index(message, intToBytes(uint(BASE_SEQ_NO-1), 4))
			// log.Println(eoc_byte_index)

			for eoc_byte_index != -1 {
				data_chunk := append(buffer, message[0:eoc_byte_index+4]...)
				//				seq_no := message[eoc_byte_index-4:eoc_byte_index]
				// utils.Debugf("\n CHUNK: %x...%x  \n  length %d \n", data_chunk[0:4], data_chunk[len(data_chunk)-4:len(data_chunk)], len(data_chunk))
				// Get data chunk ID and record receive timestampt
				seq_no := data_chunk[0:4]
				seq_no_int := bytesToInt(seq_no)

				// these lines to debug
				// if seq_no_int != previous+1 {
				// 	utils.Debugf("\n Unordered: %d \n", seq_no_int)
				// }
				// previous = seq_no_int
				//
				//				buffer.Write(message[eoc_byte_index:length])
				if seq_no_int >= BASE_SEQ_NO {
					utils.Debugf("\n Got seq: %d at %d \n", seq_no_int, time.Now().UnixNano())
					serverlog.lock.Lock()
					serverlog.data[seq_no_int] = ServerLogRecord{
						timestamp:   uint(time.Now().UnixNano()),
						messageSize: protocol.ByteCount(eoc_byte_index + 4),
					}
					serverlog.lock.Unlock()
					if isMultistream {
						break messageLoop

					}
				}

				// Cut out recorded chunk
				message = message[eoc_byte_index+4:]
				buffer = make([]byte, 0)
				eoc_byte_index = bytes.Index(message, intToBytes(uint(BASE_SEQ_NO-1), 4))
			}
			buffer = append(buffer, message...)
		}

		if err != nil {
			utils.Debugf("Error getting mess: ", err)

			break messageLoop
		}
	}
	sess.RemoveStream(stream.StreamID())
	utils.Debugf("\n Finish Stream: %d at %d \n", stream.StreamID(), time.Now().UnixNano())
}

func startQUICSession(urls []string, scheduler string, isMultipath bool) (sess quic.Session, err error) {
	var maxPathID uint8
	if isMultipath {
		maxPathID = 2
	}

	session, err := quic.DialAddr(urls[0], &tls.Config{InsecureSkipVerify: true}, &quic.Config{
		MaxPathID:            maxPathID,
		SchedulingSchemeName: scheduler,
		// MaxReceiveStreamFlowControlWindow:     uint64(protocol.ByteCount(math.Floor(100 * MB))),
		// MaxReceiveConnectionFlowControlWindow: uint64(protocol.ByteCount(math.Floor(100 * MB))),
	})

	if err != nil {
		return nil, err
	}

	return session, nil
}

// wait for interarrival_time nanosecond
func wait(interarrival_time uint) {
	waiting_time := time.Duration(interarrival_time) * time.Nanosecond
	// utils.Debugf("wait for %d ns \n", waiting_time.Nanoseconds())
	time.Sleep(waiting_time)
}

func getRandom(distro string, value float64) float64 {
	var retVal float64
	switch distro {
	case "c":
		retVal = value
	case "e":
		retVal = rand.ExpFloat64() * value
	case "g":
		retVal = rand.NormFloat64()*value/3 + value
		if retVal > 2*value {
			retVal = 2 * value
		} else if retVal < 0 {
			retVal = 0
		}

	case "b":

	case "wei":

	default:
		retVal = 1.0
	}

	return retVal
}

func generateMessage(offset_seq uint, csize_distro string, csize_value float64) ([]byte, uint) {
	//	utils.Debugf("Gen mess: %d \n", time.Now().UnixNano())
	seq_no := BASE_SEQ_NO + offset_seq
	seq_header := intToBytes(uint(seq_no), 4)
	eoc_header := intToBytes(uint(BASE_SEQ_NO-1), 4)

	csize := uint64(getRandom(csize_distro, csize_value))
	//chunk size must be a factor of 4 to avoid EOL fragmenting
	// Temporary set to a factor of 4 to match QUIC MTU 1350byte
	csize = csize - csize%2
	if csize < 12 {
		csize = 12
	}
	// utils.Debugf("Message size %d \n ", csize)
	pseudo_payload := make([]byte, (csize - 8))
	for i := 0; i < len(pseudo_payload); i++ {
		pseudo_payload[i] = 0x01
	}

	message := append(seq_header, pseudo_payload...)
	//	message = append(message, seq_header...)
	message = append(message, eoc_header...)

	return message, seq_no
}

func intToBytes(num uint, size uint) []byte {
	bs := make([]byte, size)
	binary.BigEndian.PutUint32(bs, uint32(num))
	return bs
}

func bytesToInt(b []byte) uint {
	return uint(binary.BigEndian.Uint32(b))
}

func writeToFile(filename string, data map[uint]ServerLogRecord) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for k, v := range data {
		line := fmt.Sprintf("%d %d %d\n", k, v.timestamp, v.messageSize)
		_, err = io.WriteString(file, line)
		if err != nil {
			return err
		}

	}

	return file.Sync()
}

type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("Server: Got '%x'\n", b)
	return w.Writer.Write(b)
}

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(crand.Reader, &template, &template, &key.PublicKey, key)

	if err != nil {
		panic(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	// pkcs1 := x509.MarshalPKCS1PrivateKey(key)
	// priv := base64.StdEncoding.EncodeToString(pkcs1)
	// pub := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&key.PublicKey))

	// utils.Debugf("pri key: %s", priv)
	// utils.Debugf("pub key: %s", pub)
	// key_file, _ := os.Create("id_rsa_trafficgen")

	// defer key_file.Close()
	// key_file.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")
	// key_file.WriteString(priv)
	// key_file.WriteString("\n-----END RSA PRIVATE KEY-----")

	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}

func schedNameConvert(protocol string, sched_name string) string {
	converted_name := sched_name
	if protocol == "quic" {
		switch sched_name {
		case "lrtt":
			converted_name = "lowRTT"
		case "rr":
			converted_name = "RR"
		case "opp":
			converted_name = "oppRedundant"

		case "nt":
			converted_name = "nineTails"
		case "re":
			converted_name = "redundant"
		case "sp":
			converted_name = "lowRTT"
		default:
			panic("no scheduler found")
		}
	}

	return converted_name
}

func main() {
	flagMode := flag.String("mode", "server", "start in client or server mode")
	flagTime := flag.Uint("t", 10000, "time to run (ms)")
	flagStartDelay := flag.Uint("d", 2000, "Start Delay (ms)")
	flagCsizeDistro := flag.String("csizedist", "c", "data chunk size distribution")
	flagCsizeValue := flag.Float64("csizeval", 1000, "data chunk size value")
	flagArrDistro := flag.String("arrdist", "c", "arrival distribution")
	flagArrValue := flag.Float64("arrval", 1000, "arrival value")
	flagUnlimited := flag.Bool("unlimited", false, "don't limit sending rate")
	flagAddress := flag.String("a", "localhost", "Destination address")
	flagProtocol := flag.String("p", "tcp", "TCP or QUIC")
	flagLog := flag.String("log", "", "Log folder")
	flagMultipath := flag.Bool("m", false, "Enable multipath")
	flagMultiStream := flag.Bool("mstr", false, "Enable multistream")
	flagSched := flag.String("sched", "lrtt", "Scheduler")
	flagDebug := flag.Bool("v", false, "Debug mode")
	flagCong := flag.String("cc", "olia", "Congestion control")
	flagBlock := flag.Bool("b", false, "Blocking call")
	flagReverse := flag.Bool("r", false, "Reverse send")
	flag.Parse()
	config := TrafficGenConfig{
		Mode:              *flagMode,
		RunTime:           *flagTime,
		CsizeDistro:       *flagCsizeDistro,
		CsizeValue:        *flagCsizeValue,
		ArrDistro:         *flagArrDistro,
		ArrValue:          *flagArrValue,
		Unlimited:         *flagUnlimited,
		Address:           *flagAddress,
		Protocol:          *flagProtocol,
		LogFolder:         *flagLog,
		IsMultipath:       *flagMultipath,
		IsMultiStream:     *flagMultiStream,
		Sched:             *flagSched,
		Debug:             *flagDebug,
		CongestionControl: *flagCong,
		IsBlockCall:       *flagBlock,
		IsReverse:         *flagReverse,
		StartDelay:        *flagStartDelay,
	}
	if *flagDebug {
		utils.SetLogLevel(utils.LogLevelDebug)
	}

	LOG_PREFIX = *flagLog
	//quic.SetCongestionControl(*flagCong)
	//sched := schedNameConvert(*flagProtocol, *flagSched)
	if strings.ToLower(*flagMode) == "server" {
		//quic.SetSchedulerAlgorithm(sched)
		startServerMode(&config)
	} else {
		startClientMode(&config)
	}
}
