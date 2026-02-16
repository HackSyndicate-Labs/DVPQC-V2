package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	"lab3-falcon-go-zerotrace/internal/falconreal"
	"lab3-falcon-go-zerotrace/internal/sigcheck"
	"lab3-falcon-go-zerotrace/pkg/config"
	"lab3-falcon-go-zerotrace/pkg/temporal"
)

func main() {
	// Cargar configuración (aunque no se use aún)
	_ = config.LoadConfig()

	// Check temporal
	temporal.Check()

	fmt.Println("System active.")

	// Generar Keypair
	pk, sk, err := falconreal.Keypair()
	if err != nil {
		panic(err)
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Message: ")
	msg, _ := reader.ReadBytes('\n')

	fmt.Print("Signature (hex): ")
	sigHex, _ := reader.ReadBytes('\n')
	sig := decodeHex(sigHex)

	// Verificación
	if !sigcheck.VerifySignature(pk, msg, sig) {
		fmt.Println("Denied")
		return
	}

	_ = sk // silenciar warning de variable no usada

	fmt.Println("OK")
}

// decodeHex convierte una entrada en hexadecimal a bytes
func decodeHex(b []byte) []byte {
	b = bytes.TrimSpace(b) // quitar espacios y salto de línea
	dst := make([]byte, hex.DecodedLen(len(b)))
	_, err := hex.Decode(dst, b)
	if err != nil {
		panic(err)
	}
	return dst
}
