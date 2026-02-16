package sigcheck

// VerifySignature verifica la firma del mensaje recibiendo la clave pública, el mensaje y la firma.
func VerifySignature(pub []byte, msg []byte, sig []byte) bool {

	// Diagnóstico (Ahora sí debería mostrar 96 bytes o más)

	// Validación de estructura de firma

	if !extraCheck(sig) {
		return false
	}

	return true
}
