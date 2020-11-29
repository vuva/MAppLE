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
	/*
	 *        n, err := stream.Write(data)
	 *
	 *        if err != nil {
	 *                utils.Errorf("\nStreamWrite: %s", err)
	 *                return 0
	 *        }
	 *	return n
	 */
	go stream.Write(data)
	// TODO: check if the data is sent of not
	return 1
}

func AllStreamsAreEmpty(quic_sess Session) bool {

	streamMap, err := quic_sess.GetStreamMap()
	if err != nil {
		return false
	}
	streamMap.mutex.RLock()

	for _, datastream := range streamMap.streams {
		if datastream.LenOfDataForWriting() > 0 && datastream.StreamID()%2 == 1 && datastream.StreamID() > 1 {
			streamMap.mutex.RUnlock()
			return false
		}
	}

	streamMap.mutex.RUnlock()
	return true
}

func CloseAllOutgoingStream(quic_session Session) {

	streamMap, err := quic_session.GetStreamMap()
	if err != nil {
		return
	}

	for _, datastream := range streamMap.streams {
		if datastream.StreamID()%2 == 1 {
			datastream.Close()
		}
	}
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
	streamMap.mutex.RLock()

	for id, datastream := range streamMap.streams {
		if datastream.LenOfDataForWriting() == 0 && datastream.StreamID()%2 == 1 && datastream.StreamID() > 1 {
			utils.Debugf("\n policyParallel found avaiable stream %d id %d ", id, datastream.StreamID())
			streamMap.mutex.RUnlock()
			return datastream
		}
	}

	streamMap.mutex.RUnlock()

	return createNewStream(quic_sess)

}

func policyOneStream(quic_sess Session) Stream {

	streamMap, err := quic_sess.GetStreamMap()
	if err != nil {
		return nil
	}

	streamMap.mutex.RLock()
	for id, datastream := range streamMap.streams {
		if datastream.StreamID()%2 == 1 && datastream.StreamID() > 1 {
			utils.Debugf("\n vuva: id %d stream %d", id, datastream.StreamID())
			streamMap.mutex.RUnlock()
			return datastream
		}
	}
	streamMap.mutex.RUnlock()
	return createNewStream(quic_sess)

}
