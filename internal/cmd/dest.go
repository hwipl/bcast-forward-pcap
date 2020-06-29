package cmd

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket/pcap"
)

// dest stores information about a forwarding destination
type dest struct {
	dev   string
	ip    net.IP
	srcIP net.IP
}

// getSourceIP gets the source IP used for the forwarding destination
func (d *dest) getSourceIP() {
	// create dummy connection to retrieve local address
	addr := fmt.Sprintf("%s:%d", d.ip, dport)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// get local address of connection
	laddr := conn.LocalAddr().(*net.UDPAddr)
	d.srcIP = laddr.IP
}

// getDevice gets the device used for the forwarding destination
func (d *dest) getDevice() {
	// get all network devices
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// find the name of the device that uses the source IP address
	for _, dev := range devs {
		for _, addr := range dev.Addresses {
			if addr.IP.Equal(d.srcIP) {
				d.dev = dev.Name
				return
			}
		}
	}

	log.Fatalf("did not find device for destination %s", d.ip)
}

// newDest creates and returns a new dest
func newDest(addr string) *dest {
	var dest dest

	// parse IP address
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		// invalid IP, stop here
		return nil
	}
	dest.ip = ip

	// get source IP
	dest.getSourceIP()

	// get device for source IP
	dest.getDevice()

	return &dest
}
