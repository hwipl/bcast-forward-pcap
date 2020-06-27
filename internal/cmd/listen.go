package cmd

import (
	"bytes"
	"fmt"
	"log"

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

	// get first ip layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return // panic?
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// print packet info to console
	fmt.Printf("Got packet: %s:%d -> %s:%d\n", ip.SrcIP,
		udp.SrcPort, ip.DstIP, udp.DstPort)

	// forward packet to all destination IPs
	for _, dest := range dests {
		// modify source and destination IP
		if srcIP != nil {
			ip.SrcIP = srcIP
		} else {
			ip.SrcIP = dest.srcIP
		}
		ip.DstIP = dest.ip

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
			switch layer.LayerType() {
			case layers.LayerTypeIPv4:
				buf.Write(ipBuf.Bytes())
			case layers.LayerTypeUDP:
				buf.Write(udpBuf.Bytes())
			default:
				buf.Write(layer.LayerContents())
			}
		}
		err = h.outHandle.WritePacketData(buf.Bytes())
		if err != nil {
			log.Fatal(err)
		}
	}
}

// listen captures packets on the network interface and parses them
func listen() {
	// create handler
	var handler handler

	// configure pcap
	pcapFile := ""
	pcapDevice := dev
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
