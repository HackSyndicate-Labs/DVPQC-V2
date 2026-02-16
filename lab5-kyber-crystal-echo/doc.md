# 🔮 Lab 5: KYB-02 "Crystal Echo"

```
    ╔═══════════════════════════════════════════════════════════════════╗
    ║          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄           ║
    ║         ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██           ║
    ║         ██░ CRYSTAL LATTICE SECURITY SYSTEMS v2.1 ░██           ║
    ║         ██░    "Echo Chamber Key Exchange Module"  ░██           ║
    ║         ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██           ║
    ║          ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀           ║
    ╚═══════════════════════════════════════════════════════════════════╝
```

## 📋 Metadata

| Campo | Valor |
|-------|-------|
| **ID** | KYB-02 |
| **Nombre Código** | Crystal Echo |
| **Vulnerabilidad** | Incorrect IND-CCA Transform |
| **Algoritmo** | Kyber (ML-KEM) |
| **Librería** | liboqs |
| **Lenguaje** | Python (con bindings C) |
| **Dificultad** | Baja |
| **Técnica de Explotación** | Fuzzing + Chosen Ciphertext |

---

## 🎭 Lore: Los Ecos del Cristal

> *"En las profundidades del servidor Crystal Lattice, los ingenieros implementaron un módulo de intercambio de claves basado en el revolucionario algoritmo Kyber. El sistema fue diseñado para resistir los ataques cuánticos del futuro, pero algo salió mal..."*
>
> *"Durante las auditorías nocturnas, los administradores comenzaron a escuchar 'ecos' — respuestas del sistema que no deberían existir. Cada eco cristalino parecía revelar fragmentos del secreto compartido. Los rumores hablan de un fallo en la transformación de seguridad, una grieta en la armadura cuántica que permite a los ciphertexts malformados susurrar secretos al atacante paciente."*
>
> *"Tu misión: usar técnicas de fuzzing para encontrar los ciphertexts que generan estos ecos reveladores, y demostrar cómo una implementación incorrecta del transform IND-CCA puede destruir la seguridad de un sistema post-cuántico."*

---

## 🔬 Contexto Técnico

### La Transformación Fujisaki-Okamoto (FO)

Kyber utiliza la transformación Fujisaki-Okamoto para convertir un esquema CPA-seguro en uno CCA-seguro. El proceso de **decapsulación** correcto es:

```
1. Decifrar ciphertext → mensaje m'
2. Re-encriptar m' → ciphertext c'
3. Comparar c == c' (en tiempo constante)
4. Si coinciden: devolver K = H(m' || c)
5. Si NO coinciden: devolver K = H(z || c) donde z es un valor secreto
```

### La Vulnerabilidad

El módulo "Echo Chamber" implementa una **versión defectuosa** de la transformación FO:

1. **Re-encriptación incompleta**: El sistema no re-encripta correctamente bajo ciertas condiciones
2. **Comparación débil**: La comparación entre ciphertexts no cubre todos los casos
3. **Fuga de información**: El timing y comportamiento del sistema varía según el ciphertext
4. **Manejo de errores revelador**: Los errores de decodificación filtran información sobre el mensaje

Estas debilidades permiten un ataque de **ciphertext malleability** donde el atacante puede:
- Detectar si un ciphertext modificado descifra "correctamente"
- Obtener un oráculo de validación parcial
- Recuperar información sobre la clave secreta

---

## 📁 Estructura del Laboratorio

```
lab5-kyber-crystal-echo/
├── README.md                    # Este archivo
├── Makefile                     # Build system
├── requirements.txt             # Dependencias Python
│
├── src/                         # Código fuente vulnerable
│   ├── __init__.py
│   ├── crystal_kem.py          # Wrapper principal de Kyber KEM
│   ├── echo_chamber.py         # Módulo de intercambio de claves (VULNERABLE)
│   ├── fo_transform.py         # Transformación FO defectuosa
│   ├── key_store.py            # Almacenamiento de claves
│   └── protocol_handler.py     # Manejador del protocolo
│
├── include/
│   └── constants.py            # Constantes y configuración
│
├── tests/
│   ├── test_basic.py           # Tests básicos (pasan)
│   ├── test_compliance.py      # Tests de conformidad (pasan)
│   └── test_edge_cases.py      # Tests de casos extremos (NO cubren vuln)
│
├── fuzzing/                     # Infraestructura de fuzzing
│   ├── harness/
│   │   ├── fuzz_decaps.py      # Harness principal para AFL/Atheris
│   │   ├── fuzz_ciphertext.py  # Fuzzing de ciphertexts
│   │   └── differential_fuzz.py # Fuzzing diferencial
│   ├── corpus/
│   │   └── seed_ciphertexts/   # Seeds iniciales
│   ├── dictionaries/
│   │   └── kyber_tokens.dict   # Diccionario para mutaciones
│   └── README_FUZZING.md       # Guía de fuzzing
│
├── docs/
│   ├── ARCHITECTURE.md         # Documentación de arquitectura
│   ├── API_REFERENCE.md        # Referencia de API
│   └── VULNERABILITY_NOTES.md  # Notas sobre la vulnerabilidad (SPOILER)
│
├── exploits/
│   └── echo_oracle_stub.py     # Esqueleto de exploit (incompleto)
│
└── solution/
    ├── WRITEUP.md              # Solución completa
    ├── exploit_complete.py     # Exploit funcional
    └── fuzzing_strategy.md     # Estrategia de fuzzing
```

---

## 🚀 Instalación y Configuración

### Requisitos Previos

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv cmake ninja-build

# Instalar liboqs (debe estar disponible en el sistema)
# Ver: https://github.com/open-quantum-safe/liboqs
```

### Instalación

```bash
# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Verificar instalación
python -c "import oqs; print(oqs.get_enabled_KEM_mechanisms())"
```

### Ejecución de Tests

```bash
# Tests básicos (deberían pasar)
python -m pytest tests/test_basic.py -v

# Tests de conformidad (deberían pasar)
python -m pytest tests/test_compliance.py -v

# Tests de edge cases (pasan pero no detectan la vulnerabilidad)
python -m pytest tests/test_edge_cases.py -v
```

---

## 🎯 Objetivo del Laboratorio

Tu objetivo es:

1. **Analizar** el código fuente para entender la implementación
2. **Identificar** la vulnerabilidad en la transformación IND-CCA
3. **Configurar** un entorno de fuzzing apropiado
4. **Descubrir** mediante fuzzing los inputs que triggean el comportamiento anómalo
5. **Explotar** la vulnerabilidad para demostrar impacto real
6. **Documentar** tus hallazgos

### Pistas

- El archivo `fo_transform.py` contiene la lógica crítica
- Presta atención al manejo de ciphertexts "casi válidos"
- El timing de las operaciones puede revelar información
- Fuzzing diferencial contra una implementación de referencia es muy efectivo

---

## 🛠️ Herramientas de Fuzzing Recomendadas

### Python Fuzzing
- **Atheris** (Google): Fuzzer coverage-guided para Python
- **python-afl**: Bindings de AFL para Python

### Fuzzing Diferencial
- Comparar contra `oqs.KeyEncapsulation("Kyber768")` directamente

### Análisis de Timing
- **hyperfine**: Para benchmarks precisos
- Scripts personalizados de timing attack

---

## ⚠️ Disclaimer

Este laboratorio contiene código **intencionalmente vulnerable** para fines educativos.
**NO** uses este código en producción.
**NO** uses estas técnicas contra sistemas sin autorización.

---

## 📚 Referencias

- [CRYSTALS-Kyber Specification](https://pq-crystals.org/kyber/)
- [liboqs Documentation](https://openquantumsafe.org/liboqs/)
- [Fujisaki-Okamoto Transform](https://eprint.iacr.org/2017/604.pdf)
- [Side-Channel Attacks on Kyber](https://tches.iacr.org/index.php/TCHES/article/view/8592)

---

*Crystal Lattice Security Systems - "Quantum-Safe, Echo-Free"™*
