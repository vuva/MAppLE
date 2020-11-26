package quic

import (
	//	"bytes"
	//"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	//"io"
)

//var multiplexingPolicy string = ""

func createNewStream(quic_session Session) Stream {
	utils.Debugf("\n Opening new stream ...")
	stream, err := quic_session.OpenStreamSync()
	if err != nil {
		utils.Errorf("\nOpenStream: %s", err)
		return nil
	}
	utils.Debugf("\n Stream %d created", stream.StreamID())
	return stream
}

func addDataToStream(stream Stream, data []byte) int {

	utils.Debugf("\n addDataToStream %d", stream.StreamID())
	n, err := stream.Write(data)

	if err != nil {
		utils.Errorf("\nStreamWrite: %s", err)
		return 0
	}
	return n
}

func MultiplexData(session Session, multiplexingPolicy string, data []byte) bool {
	var selected_stream Stream
	switch multiplexingPolicy {
	case "parallel":
		selected_stream = policyParallel(session)
	case "oneStream":
		selected_stream = policyOneStream(session)
	}

	if selected_stream != nil {
		addDataToStream(selected_stream, data)
		//defer selected_stream.Close()
		return true
	} else {
		return false
	}
}

func policyParallel(quic_sess Session) Stream {
	streamMap, err := quic_sess.GetStreamMap()
	if err != nil {
		return nil
	}
	//streamMap.mutex.RLock()
	streamList := streamMap.streams
	//streamMap.mutex.Unlock()

	count := 0
	for id, datastream := range streamList {
		if datastream.LenOfDataForWriting() == 0 && datastream.StreamID()%2 == 1 {
			utils.Debugf("\n policyParallel found avaiable stream %d id %d ", id, datastream.StreamID())
			return datastream
		}
	}

	utils.Debugf("\n policyParallel stream count %d", count)
	new_datastream := createNewStream(quic_sess)
	return new_datastream
}

func policyOneStream(quic_sess Session) Stream {

	streamMap, err := quic_sess.GetStreamMap()
	if err != nil {
		return nil
	}
	streamMap.mutex.RLock()
	defer streamMap.mutex.Unlock()
	for id, datastream := range streamMap.streams {
		if datastream.StreamID() > 0 {
			utils.Debugf("\n vuva: id %d stream %p", id, datastream)
			return datastream
		}
	}
	return createNewStream(quic_sess)

}
func TestMultiplexer(quic_session Session, message []byte) {
	//stream, err := quic_session.OpenStreamSync()
	stream := policyParallel(quic_session)
	//if err != nil {
	//utils.Debugf("Error OpenStreamSync:", err)
	//return
	//}
	defer stream.Close()
	stream.Write(message)
	quic_session.RemoveStream(stream.StreamID())
}
