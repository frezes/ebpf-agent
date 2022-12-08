package exporter

import (
	"net"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/sirupsen/logrus"
)

var elog = logrus.WithField("component", "exporter/Echo")

type EchoProto struct {
}

func NewEchoProto() *EchoProto {
	return &EchoProto{}
}

func (e *EchoProto) ExportFlows(input <-chan []*flow.Record) {
	log := elog.WithField("collector", "echo")
	for inputRecords := range input {
		pbRecords := flowsToPB(inputRecords)
		for _, record := range pbRecords.Entries {
			if record.EthProtocol == ipv6 {
				log.Printf("%s: %v %s IP %s:%d > %s:%d: protocol:%s dir:%d bytes:%d packets:%d ends: %v\n",
					ipProto[record.EthProtocol],
					record.TimeFlowStart.AsTime().Local().Format("15:04:05.000000"),
					record.Interface,
					net.IP(record.Network.GetSrcAddr().GetIpv6()).To16(),
					record.Transport.SrcPort,
					net.IP(record.Network.GetDstAddr().GetIpv6()).To16(),
					record.Transport.DstPort,
					protocolByNumber[record.Transport.Protocol],
					record.Direction,
					record.Bytes,
					record.Packets,
					record.TimeFlowEnd.AsTime().Local().Format("15:04:05.000000"),
				)
			} else {
				log.Printf("%s: %v %s IP %s:%d > %s:%d: protocol:%s dir:%d bytes:%d packets:%d ends: %v\n",
					ipProto[record.EthProtocol],
					record.TimeFlowStart.AsTime().Local().Format("15:04:05.000000"),
					record.Interface,
					ipIntToNetIP(record.Network.GetSrcAddr().GetIpv4()).String(),
					record.Transport.SrcPort,
					ipIntToNetIP(record.Network.GetDstAddr().GetIpv4()).String(),
					record.Transport.DstPort,
					protocolByNumber[record.Transport.Protocol],
					record.Direction,
					record.Bytes,
					record.Packets,
					record.TimeFlowEnd.AsTime().Local().Format("15:04:05.000000"),
				)
			}
		}
	}

}

const ipv6 = 0x86DD

var protocolByNumber = map[uint32]string{
	1:  "icmp",
	2:  "igmp",
	6:  "tcp",
	17: "udp",
	58: "ipv6-icmp",
}

var ipProto = map[uint32]string{
	0x0800: "ipv4",
	0x0806: "arp",
	0x86DD: "ipv6",
}

func ipIntToNetIP(ipAsInt uint32) net.IP {
	var bytes [4]byte
	bytes[0] = byte(ipAsInt & 0xFF)
	bytes[1] = byte((ipAsInt >> 8) & 0xFF)
	bytes[2] = byte((ipAsInt >> 16) & 0xFF)
	bytes[3] = byte((ipAsInt >> 24) & 0xFF)

	return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0])
}
