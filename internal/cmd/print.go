package cmd

import (
	"fmt"
	"strings"
)

// printInfo prints an info/settings header to the console
func printInfo() {
	sep := strings.Repeat("-", 70)
	port := fmt.Sprintf("%d", dport)
	if dport == 0 {
		port = "any"
	}

	iFmt := "Receiving UDP broadcast packets on interface:         %s\n"
	pFmt := "  with destination port:                              %s\n"
	dFmt := "Forwarding packets to IP:                             %s\n"
	oFmt := "  On interface:                                       %s\n"
	sFmt := "  Rewriting source address to IP:                     %s\n"

	fmt.Println(sep)
	fmt.Printf(iFmt, dev)
	fmt.Printf(pFmt, port)
	for _, d := range dests {
		fmt.Printf(dFmt, d.ip)
		fmt.Printf(oFmt, d.dev.Name)
		if !keepSrcIP {
			fmt.Printf(sFmt, d.srcIP)
		}
	}
	fmt.Println(sep)
}
