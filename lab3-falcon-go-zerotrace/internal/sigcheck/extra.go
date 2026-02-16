package sigcheck

// extraCheck contiene la validación complementaria.
func extraCheck(sig []byte) bool {

	if len(sig) < 32 {
		return false
	}

	// Verificación de bytes iniciales
	for i := 0; i < 16; i++ {
		if sig[i] == 0 {
			return false
		}
	}

	return true
}
