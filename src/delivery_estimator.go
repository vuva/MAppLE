package quic

import (
	"math"
	"sort"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)


func EstimateDelivery (congestionControl string, datalength protocol.ByteCount, paths map[protocol.PathID]*path) int{
	RTTList:= []int {}
	for id, path := range paths{
		pathRTT := int(path.rttStats.SmoothedRTT().Milliseconds())
		utils.Infof("\nEstimateDelivery: pathid %d RTT %d", id, pathRTT)
		for i:=0; i<100; i++ {
			RTTList = append(RTTList , i*pathRTT)
		}
	}
	sort.Ints(RTTList)

	return estimateReno(datalength, paths, RTTList)
}

func estimateReno(datalength protocol.ByteCount, paths map[protocol.PathID]*path, RTTList []int) int{
	var total_sent protocol.ByteCount
	for {
		for i:=0; i<len(RTTList);i++{
			for id, path := range paths{
				round := uint(RTTList[i]/int(path.rttStats.SmoothedRTT().Milliseconds()))
				currentCongestionWindow := path.GetCongestionWindow()
				slowStartThreshold := uint(path.sentPacketHandler.GetSendAlgorithm().SlowstartThreshold())

				var send_estimation protocol.ByteCount
				if currentCongestionWindow<<round < protocol.ByteCount(slowStartThreshold)*protocol.DefaultTCPMSS{
					send_estimation = currentCongestionWindow*(1<<round -1)
				}else{
					slowstart_round := uint(math.Ceil(math.Log2(float64(slowStartThreshold)*float64(protocol.DefaultTCPMSS)/float64(currentCongestionWindow))))
					avoidance_round := round - slowstart_round
					slowstart_sent := currentCongestionWindow*(1<<slowstart_round -1)
					avoidance_sent := protocol.ByteCount(((avoidance_round + slowStartThreshold)*(2*slowStartThreshold - avoidance_round -1 ))/(2*(slowStartThreshold-1))) * protocol.DefaultTCPMSS
					send_estimation += slowstart_sent+avoidance_sent

				}
				total_sent += send_estimation

				utils.Infof("\nEstimateReno: id %d RTTList[i] %d round %d currentCongestionWindow %d  slowStartThreshold %d send_estimation %d", id,RTTList[i], round, currentCongestionWindow, slowStartThreshold, send_estimation)
			}
			if total_sent >= datalength {
				return RTTList[i]
			}
		}

	}
}
