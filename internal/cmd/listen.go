package cmd

import (
	"bytes"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	gopktPcap "github.com/google/gopacket/pcap"
	"github.com/hwipl/packet-go/pkg/pcap"
)

var (
	// serializeOpts are options for serialize layers
	serializeOpts = gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: true,
	}
)

type handler struct {
	outHandle *gopktPcap.Handle
}

func (h *handler) HandlePacket(packet gopacket.Packet) {
	// get first udp layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)
	if dport != 0 && udp.DstPort != dport {
		return
	}

	// get first ip layer and modify destination IP
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return // panic?
	}
	ip, _ := ipLayer.(*layers.IPv4)
	ip.DstIP = net.IPv4(192, 168, 1, 1)


	// serialize modified ip layer
	ipBuf := gopacket.NewSerializeBuffer()
	err := ip.SerializeTo(ipBuf, serializeOpts)
	if err != nil {
		log.Fatal(err)
	}

	// serialize udp layer to recalculate checksum
	udpBuf := gopacket.NewSerializeBuffer()
	udp.SetNetworkLayerForChecksum(ip)
	err = udp.SerializeTo(udpBuf, serializeOpts)
	if err != nil {
		log.Fatal(err)
	}

	// write all layers to buffer
	var buf bytes.Buffer
	l := packet.Layers()
	for _, layer := range l {
		fmt.Println(layer.LayerType())
		switch layer.LayerType() {
		case layers.LayerTypeIPv4:
			buf.Write(ipBuf.Bytes())
		case layers.LayerTypeUDP:
			buf.Write(udpBuf.Bytes())
		default:
			buf.Write(layer.LayerContents())
		}
	}
	fmt.Println(buf.Bytes())
	h.outHandle.WritePacketData(buf.Bytes())
}

// listen captures packets on the network interface and parses them
func listen() {
	// create handler
	var handler handler

	// configure pcap
	pcapFile := ""
	pcapDevice := "wg0"
	pcapFilter := "ip dst host 255.255.255.255"
	pcapSnaplen := 2048

	// create listener
	listener := pcap.Listener{
		PacketHandler: &handler,
		File:          pcapFile,
		Device:        pcapDevice,
		Filter:        pcapFilter,
		Snaplen:       pcapSnaplen,
	}

	// prepare listener and store pcap handle in handler
	listener.Prepare()
	handler.outHandle = listener.PcapHandle

	// enter listener loop
	listener.Loop()
}
