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

	pFmt := "Receiving broadcast packets with destination port:    %s\n"
	dFmt := "Forwarding packets to IP:                             %s\n"
	iFmt := "  On interface:                                       %s\n"
	sFmt := "  Rewriting source address to IP:                     %s\n"

	fmt.Println(sep)
	fmt.Printf(pFmt, port)
	for _, d := range dests {
		fmt.Printf(dFmt, d.ip)
		fmt.Printf(iFmt, d.dev.Name)
		fmt.Printf(sFmt, d.srcIP)
	}
	fmt.Println(sep)
}
