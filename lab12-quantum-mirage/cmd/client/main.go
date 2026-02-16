package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"lab12/internal/crypto"
	"lab12/internal/protocol"
)

const (
	PrimaryServer = "localhost:9999" // Simulated Unreachable
	BackupServer  = "localhost:9001"
)

func main() {
	var conn net.Conn
	var err error

	// 1. Try Primary Server
	log.Printf("Connecting to Primary Server (%s)...", PrimaryServer)
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err = d.Dial("tcp", PrimaryServer)

	if err != nil {
		log.Printf("[!] Primary Server Unreachable: %v", err)
		log.Printf("[*] Switching to Backup Server (%s)...", BackupServer)

		// 2. Try Backup Server (The Mirage)
		conn, err = net.Dial("tcp", BackupServer)
		if err != nil {
			log.Fatalf("Fatal: Backup Server also unreachable: %v", err)
		}
	} else {
		log.Println("[+] Connected to Primary Server.")
	}
	defer conn.Close()

	log.Println("Connected. Generating Hybrid Keys...")

	kp, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate keys: %v", err)
	}
	defer kp.Close()

	log.Println("Starting Handshake...")
	secret, err := protocol.ClientHandshake(conn, kp)
	if err != nil {
		log.Fatalf("Handshake failed: %v", err)
	}

	log.Printf("Secure Connection Established!")
	log.Printf("Session Secret: %s", hex.EncodeToString(secret))

	// Read welcome message
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	fmt.Printf("Server says: %s\n", string(buf[:n]))
}
