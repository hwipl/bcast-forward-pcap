package cmd

import (
	"bytes"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hwipl/packet-go/pkg/pcap"
)

var (
	// serializeOpts are options for serialize layers
	serializeOpts = gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: true,
	}

	// listeners maps device names to listeners
	listeners = make(map[string]*pcap.Listener)
)

// getEthernetLayer returns an ethernet layer of/for packet
func getEthernetLayer(packet gopacket.Packet) *layers.Ethernet {
	var eth *layers.Ethernet

	// check first layer in packet
	layer := packet.Layers()[0]
	switch layer.LayerType() {
	case layers.LayerTypeEthernet:
		// first layer is an ethernet layer, use it
		eth = layer.(*layers.Ethernet)
	case layers.LayerTypeIPv4:
		// first header is not an ethernet layer, construct one
		srcMAC, err := net.ParseMAC("00:00:00:00:00:00")
		if err != nil {
			log.Fatal(err)
		}
		dstMAC, err := net.ParseMAC("ff:ff:ff:ff:ff:ff")
		if err != nil {
			log.Fatal(err)
		}
		e := layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}
		eth = &e
	default:
		// unexpected header, fail
		log.Fatal("unexpected first layer in packet")
	}

	return eth
}

type handler struct {
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

	// get ethernet layer
	eth := getEthernetLayer(packet)

	// print packet info to console
	fmt.Printf("Got packet: %s:%d -> %s:%d\n", ip.SrcIP,
		udp.SrcPort, ip.DstIP, udp.DstPort)

	// forward packet to all destination IPs
	for _, dest := range dests {
		// modify source MAC address
		if dest.dev.HardwareAddr != nil {
			eth.SrcMAC = dest.dev.HardwareAddr
		}

		// serialize modified mac layer
		ethBuf := gopacket.NewSerializeBuffer()
		err := eth.SerializeTo(ethBuf, serializeOpts)
		if err != nil {
			log.Fatal(err)
		}

		// modify source and destination IP
		ip.SrcIP = dest.srcIP
		ip.DstIP = dest.ip

		// serialize modified ip layer
		ipBuf := gopacket.NewSerializeBuffer()
		err = ip.SerializeTo(ipBuf, serializeOpts)
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

		// write ethernet layer to buffer
		var buf bytes.Buffer
		if dest.handle.LinkType() == layers.LinkTypeEthernet {
			// ethBuf is padded to 60 bytes, only write header
			buf.Write(ethBuf.Bytes()[:14])
		}

		// write all other layers to buffer
		l := packet.Layers()
		for _, layer := range l {
			switch layer.LayerType() {
			case layers.LayerTypeEthernet:
				// skip original ethernet header
			case layers.LayerTypeIPv4:
				buf.Write(ipBuf.Bytes())
			case layers.LayerTypeUDP:
				buf.Write(udpBuf.Bytes())
			default:
				buf.Write(layer.LayerContents())
			}
		}
		err = dest.handle.WritePacketData(buf.Bytes())
		if err != nil {
			log.Fatal(err)
		}
	}
}

type outputHandler struct {
}

func (h *outputHandler) HandlePacket(packet gopacket.Packet) {
}

// getOutputListener gets a listener on device for sending packets to a
// forwarding destination
func getOutputListener(dev string) *pcap.Listener {
	// try to get an existing listener
	l := listeners[dev]
	if l != nil {
		return l
	}

	// listener does not exist, get a new one
	// configure pcap
	pcapDevice := dev
	pcapFilter := ""
	pcapSnaplen := 1024

	// create listener
	var handler outputHandler
	listener := pcap.Listener{
		PacketHandler: &handler,
		Device:        pcapDevice,
		Filter:        pcapFilter,
		Snaplen:       pcapSnaplen,
	}

	// prepare listener and add it to listeners
	listener.Prepare()
	listeners[listener.Device] = &listener

	return &listener
}

// listen captures packets on the network interface and parses them
func listen() {
	// create handler
	var handler handler

	// configure pcap
	pcapFile := ""
	pcapDevice := dev
	pcapFilter := "ip dst host 255.255.255.255 and udp"
	if dport != 0 {
		pcapFilter += fmt.Sprintf(" dst port %d", dport)
	}
	pcapSnaplen := 2048

	// create listener
	listener := pcap.Listener{
		PacketHandler: &handler,
		File:          pcapFile,
		Device:        pcapDevice,
		Filter:        pcapFilter,
		Snaplen:       pcapSnaplen,
	}

	// prepare listener and add it to listeners
	listener.Prepare()
	listeners[listener.Device] = &listener

	// get pcap handles for forwarding destinations
	for _, dest := range dests {
		l := getOutputListener(dest.dev.Name)
		if l == nil {
			log.Fatalf("error setting handle for destination %s",
				dest.ip)
		}
		dest.handle = l.PcapHandle

		// check link type
		if dest.handle.LinkType() != listener.PcapHandle.LinkType() {
			log.Fatalf("link type %s of %s and "+
				"link type %s of %s differ",
				listener.PcapHandle.LinkType(),
				listener.Device, dest.handle.LinkType(),
				l.Device)
		}
	}

	// print some info before entering main loop
	printInfo()

	// enter listener loop
	listener.Loop()
}
