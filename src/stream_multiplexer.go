package quic

import (
	//	"bytes"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"io"
	"log"
)

var MultiplexingPolicy string = ""

func CreateNewStream(quic_session Session) Stream {
	stream, err := quic_session.OpenStream()
	if err != nil {
		log.Println(err)
		return nil
	}
	return stream
}

func AddDataToStream(stream Stream, data []byte) int {
	n, err := stream.Write(data)

	if err != nil {
		log.Println(err)
		return 0
	}
	return n
}

func PolicyParallel(quic_sess Session) Stream {
	streamMap, err := quic_sess.GetStreamMap()
	if err != nil {
		return nil
	}
	streamMap.mutex.RLock()
	for id, datastream := range streamMap.streams {
		if datastream.LenOfDataForWriting() == 0 && datastream.StreamID()%2 == 1 {
			utils.Debugf("\n vuva: id %d stream %p", id, datastream)
			return datastream
		}
	}
	streamMap.mutex.Unlock()
	new_datastream := CreateNewStream(quic_sess)
	return new_datastream
}

func PolicyOneStream(quic_sess Session) Stream {
	streamMap, err := quic_sess.GetStreamMap()
	if err != nil {
		return nil
	}
	streamMap.mutex.RLock()
	for id, datastream := range streamMap.streams {
		if datastream.StreamID()%2 == 1 {
			utils.Debugf("\n vuva: id %d stream %p", id, datastream)
			return datastream
		}
	}
	streamMap.mutex.Unlock()
	new_datastream := CreateNewStream(quic_sess)
	return new_datastream

}
