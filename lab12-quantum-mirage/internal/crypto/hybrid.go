package crypto

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/kem/schemes"
	"golang.org/x/crypto/curve25519"
)

// HybridKeyPair holds keys.
type HybridKeyPair struct {
	X25519Pub  []byte
	X25519Priv []byte
	KyberPub   []byte
	KyberPriv  []byte
	KyberAlg   string
}

// Close is a no-op
func (kp *HybridKeyPair) Close() {}

// GenerateHybridKeyPair generates keys.
func GenerateHybridKeyPair() (*HybridKeyPair, error) {
	// 1. Classical
	priv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(priv); err != nil {
		return nil, fmt.Errorf("X25519 rand: %v", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("X25519 gen: %v", err)
	}

	// 2. Quantum (Real Circl Kyber512)
	scheme := schemes.ByName("Kyber512")
	if scheme == nil {
		return nil, fmt.Errorf("Kyber512 not supported by circl build")
	}

	kPk, kSk, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("Kyber gen: %v", err)
	}

	// Marshal keys to bytes
	kyberPubBytes, _ := kPk.MarshalBinary()
	kyberPrivBytes, _ := kSk.MarshalBinary()

	return &HybridKeyPair{
		X25519Pub:  pub,
		X25519Priv: priv,
		KyberPub:   kyberPubBytes,
		KyberPriv:  kyberPrivBytes,
		KyberAlg:   "Kyber512",
	}, nil
}

// EncapsulateHybrid Generates shared secret for the remote side
func EncapsulateHybrid(remoteX25519Pub []byte, remoteKyberPub []byte) ([]byte, []byte, []byte, error) {
	// 1. Classical ECDH
	ephemPriv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(ephemPriv); err != nil {
		return nil, nil, nil, fmt.Errorf("ephem rand: %v", err)
	}
	ephemPub, err := curve25519.X25519(ephemPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ephem pub gen: %v", err)
	}

	sharedX25519, err := curve25519.X25519(ephemPriv, remoteX25519Pub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ecdh: %v", err)
	}

	// 2. Quantum KEM Encap
	var sharedKyber []byte
	var ciphertext []byte

	if len(remoteKyberPub) > 0 {
		scheme := schemes.ByName("Kyber512")
		if scheme == nil {
			return nil, nil, nil, fmt.Errorf("Kyber512 scheme not found")
		}

		// Import remote public key
		kPk, err := scheme.UnmarshalBinaryPublicKey(remoteKyberPub)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("kyber pub import: %v", err)
		}

		// Encapsulate
		ct, ss, err := scheme.Encapsulate(kPk)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("kyber encap: %v", err)
		}

		ciphertext = ct
		sharedKyber = ss
	}

	// Combine secrets
	finalSecret := append([]byte{}, sharedX25519...)
	if len(sharedKyber) > 0 {
		finalSecret = append(finalSecret, sharedKyber...)
	}

	return ephemPub, ciphertext, finalSecret, nil
}

// DecapsulateHybrid (Server/Receiver side) involves:
// 1. Doing ECDH with remote ephemeral pub
// 2. Decapsulating Kyber ciphertext
func (kp *HybridKeyPair) DecapsulateHybrid(remoteEphemPub []byte, kyberCT []byte) ([]byte, error) {
	// 1. Classical ECDH
	sharedX25519, err := curve25519.X25519(kp.X25519Priv, remoteEphemPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %v", err)
	}

	// 2. Quantum KEM Decap
	var sharedKyber []byte
	if len(kyberCT) > 0 && len(kp.KyberPriv) > 0 {
		scheme := schemes.ByName("Kyber512")
		if scheme == nil {
			return nil, fmt.Errorf("Kyber512 scheme not found")
		}

		// Import private key
		kSk, err := scheme.UnmarshalBinaryPrivateKey(kp.KyberPriv)
		if err != nil {
			return nil, fmt.Errorf("kyber priv import: %v", err)
		}

		ss, err := scheme.Decapsulate(kSk, kyberCT)
		if err != nil {
			return nil, fmt.Errorf("decap: %v", err)
		}
		sharedKyber = ss
	}

	// Combine
	finalSecret := append([]byte{}, sharedX25519...)
	if len(sharedKyber) > 0 {
		finalSecret = append(finalSecret, sharedKyber...)
	}

	return finalSecret, nil
}
