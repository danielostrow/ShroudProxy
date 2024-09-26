package main

import (
	"fmt"
	"shroudproxy/server"
)

func main() {
	// Start the proxy server (handles connections and IP changes using counters)
	go server.StartProxyServer()

	// Keep the program running
	for {
		fmt.Println("Server running. Listening for Beacon connections and IP change requests...")
		// Sleep to avoid busy waiting
		select {} // Blocks forever, keeping the program alive
	}
}
