package main

import (
	"encoding/hex"
	"log"
	"net"

	"lab12/internal/protocol"
)

func handleConnection(conn net.Conn) {
	defer conn.Close()
	log.Printf("New connection from %s", conn.RemoteAddr())

	secret, err := protocol.ServerHandshake(conn)
	if err != nil {
		log.Printf("Handshake failed: %v", err)
		return
	}

	log.Printf("Secure Connection Established!")
	log.Printf("Session Secret: %s", hex.EncodeToString(secret))

	// Simulate secure communication
	conn.Write([]byte("Welcome to the Quantum Fortress!"))
}

func main() {
	port := "9000"
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to bind to port %s: %v", port, err)
	}
	defer listener.Close()

	log.Printf("Create Lab 12 Server listening on 0.0.0.0:%s", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}
