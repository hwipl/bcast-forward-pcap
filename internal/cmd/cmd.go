package cmd

import (
	"flag"
	"log"

	"github.com/google/gopacket/layers"
)

// global variables set via command line arguments:
var (
	// dport is the destination port for packet matching
	dport layers.UDPPort
)

// parseCommandLine parses the command line arguments
func parseCommandLine() {
	var port = 6112

	// set command line arguments
	flag.IntVar(&port, "p", port,
		"only forward packets with this destination `port`")
	flag.Parse()

	// make sure port is valid
	if port < 1 || port > 65535 {
		log.Fatal("invalid port")
	}
	dport = layers.UDPPort(port)
}

// Run is the main entry point
func Run() {
	parseCommandLine()
	listen()
}
