package protocol

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lab12/internal/crypto"
	"net"
)

// Messages
type ClientHello struct {
	ID        string `json:"id"`
	X25519Pub string `json:"x25519_pub"`
	KyberPub  string `json:"kyber_pub,omitempty"` // Optional!
}

type ServerHello struct {
	X25519EphemPub string `json:"x25519_ephem_pub"`
	KyberCT        string `json:"kyber_ct,omitempty"` // Optional!
}

// Global "State" for checking success (simplified)
var LastSharedSecret []byte

// Client performs the handshake
func ClientHandshake(conn net.Conn, kp *crypto.HybridKeyPair) ([]byte, error) {
	// 1. Send ClientHello
	hello := ClientHello{
		ID:        "Client-Mirage",
		X25519Pub: hex.EncodeToString(kp.X25519Pub),
		KyberPub:  hex.EncodeToString(kp.KyberPub),
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(hello); err != nil {
		return nil, err
	}

	// 2. Receive ServerHello
	var sHello ServerHello
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&sHello); err != nil {
		return nil, err
	}

	// 3. Derive Secret
	// Note: Client acts as "Encapsulator" logic usually, but here:
	// Client sent static keys (Consumer)
	// Server sent ephemeral keys (Producer / Encapsulator)
	// So Client must DECAPSULATE

	// Wait, usually ClientHello contains Ephemeral keys in TLS?
	// Let's stick to the simplest model:
	// A. Client sends Static Identity Keys (Pubs)
	// B. Server uses them to Encapsulate a secret

	ephemPub, _ := hex.DecodeString(sHello.X25519EphemPub)
	kyberCT, _ := hex.DecodeString(sHello.KyberCT)

	secret, err := kp.DecapsulateHybrid(ephemPub, kyberCT)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// Server performs the handshake
func ServerHandshake(conn net.Conn) ([]byte, error) {
	// 1. Receive ClientHello
	var cHello ClientHello
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&cHello); err != nil {
		return nil, err
	}

	// Parse keys from handshake message
	clientX25519, _ := hex.DecodeString(cHello.X25519Pub)
	clientKyber, _ := hex.DecodeString(cHello.KyberPub) // Empty if stripped

	if len(clientKyber) == 0 {
		fmt.Println("[!] Server: No Kyber Key received. Downgrading to Classical X25519.")
	} else {
		fmt.Println("[+] Server: Kyber Key Received. Proceeding with Hybrid.")
	}

	// 2. Encapsulate
	ephemPub, kyberCT, secret, err := crypto.EncapsulateHybrid(clientX25519, clientKyber)
	if err != nil {
		return nil, err
	}

	// 3. Send ServerHello
	sHello := ServerHello{
		X25519EphemPub: hex.EncodeToString(ephemPub),
		KyberCT:        hex.EncodeToString(kyberCT),
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(sHello); err != nil {
		return nil, err
	}

	return secret, nil
}
