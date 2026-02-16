# 🔍 Fuzzing Guide for Crystal Echo

Este directorio contiene la infraestructura de fuzzing para descubrir la vulnerabilidad
en el módulo Crystal Echo.

## 🎯 Objetivo

Usar técnicas de fuzzing para descubrir que:

1. La transformación FO está incompleta
2. Ciertos ciphertexts triggean comportamientos diferentes
3. La comparación de ciphertexts no es constant-time
4. Los mensajes de error revelan información

## 🛠️ Herramientas de Fuzzing

### 1. Atheris (Recomendado para Python)

[Atheris](https://github.com/google/atheris) es el fuzzer de Google para Python,
basado en libFuzzer.

```bash
# Instalación
pip install atheris

# Ejecutar el harness
cd fuzzing/harness
python fuzz_decaps.py -max_len=1088 -runs=100000

# Con corpus inicial
python fuzz_decaps.py ../corpus/seed_ciphertexts/ -max_len=1088
```

**Opciones útiles de Atheris:**
- `-max_len=N`: Longitud máxima de input
- `-runs=N`: Número de iteraciones
- `-timeout=N`: Timeout por ejecución
- `-dict=file`: Diccionario de tokens
- `-jobs=N`: Paralelización

### 2. AFL++ con python-afl

[AFL++](https://github.com/AFLplusplus/AFLplusplus) es la versión mejorada de AFL.

```bash
# Instalación
pip install python-afl
apt-get install afl++

# Preparar corpus
mkdir -p corpus_in
echo -ne '\x00\x01\x02...' > corpus_in/seed1

# Ejecutar
py-afl-fuzz -i corpus_in -o corpus_out -- python fuzz_ciphertext_afl.py
```

### 3. Fuzzing Diferencial

El fuzzing diferencial compara la implementación vulnerable contra la referencia:

```bash
cd fuzzing/harness
python differential_fuzz.py -max_len=1088 -runs=50000
```

Esto detectará cuando las dos implementaciones producen resultados diferentes.

## 📁 Estructura

```
fuzzing/
├── harness/
│   ├── fuzz_decaps.py          # Harness principal (Atheris)
│   ├── fuzz_ciphertext.py      # Fuzzing de estructura de ciphertext
│   ├── fuzz_ciphertext_afl.py  # Harness para AFL
│   └── differential_fuzz.py    # Fuzzing diferencial
│
├── corpus/
│   └── seed_ciphertexts/       # Seeds iniciales
│       ├── valid_ct.bin        # Ciphertext válido
│       ├── zero_ct.bin         # All-zeros
│       ├── max_ct.bin          # All-0xFF
│       └── random_ct.bin       # Random bytes
│
└── dictionaries/
    └── kyber_tokens.dict       # Tokens para mutaciones
```

## 🚀 Guía Rápida

### Paso 1: Generar Seeds

```bash
cd fuzzing/corpus/seed_ciphertexts
python ../../../generate_seeds.py
```

### Paso 2: Ejecutar Fuzzer

**Opción A: Atheris (más fácil)**
```bash
cd fuzzing/harness
python fuzz_decaps.py ../corpus/seed_ciphertexts/ -max_len=1088
```

**Opción B: AFL++ (más potente)**
```bash
cd fuzzing
py-afl-fuzz -i corpus/seed_ciphertexts -o output -- python harness/fuzz_ciphertext_afl.py
```

### Paso 3: Analizar Crashes

Los crashes se guardarán en:
- Atheris: `crash-*` en el directorio actual
- AFL++: `output/crashes/`

Analizar un crash:
```python
with open('crash-xxxx', 'rb') as f:
    crash_input = f.read()
    
# Reproducir
from harness.fuzz_decaps import test_one_input
test_one_input(crash_input)
```

## 🎓 Qué Buscar

### Indicadores de Vulnerabilidad

1. **Timing Differences**
   - Algunos ciphertexts procesan más rápido que otros
   - La función `_should_skip_reencryption` crea fast path

2. **Different Code Paths**
   - Cobertura de código diferente según el input
   - El "entropy bypass" activa diferentes ramas

3. **Error Code Variations**
   - Diferentes tipos de error para inputs similares
   - `REENCRYPTION_MISMATCH` vs `SUCCESS`

4. **Differential Behavior**
   - La implementación vulnerable difiere de la referencia
   - Ciertos ciphertexts producen secretos diferentes

### Ciphertexts Interesantes

- **High entropy** (>200 bytes únicos): Bypasea re-encryption
- **Válidos modificados**: 1 bit flip en ciphertext válido
- **Boundary values**: Coeficientes NTT en límites

## 📊 Métricas de Fuzzing

### Cobertura

Usar `coverage.py` para medir cobertura:

```bash
pip install coverage
coverage run fuzz_decaps.py corpus/ -runs=10000
coverage report -m
coverage html
```

Buscar funciones con cobertura incompleta, especialmente:
- `fo_transform.py:_should_skip_reencryption`
- `fo_transform.py:_compare_ciphertexts`

### Crashes y Timeouts

Cada crash o timeout es potencialmente interesante:
- Crashes en `decapsulate` indican manejo incorrecto
- Timeouts pueden indicar loops infinitos

## 🔬 Fuzzing Avanzado

### Structure-Aware Fuzzing

Para fuzzing más efectivo, considerar la estructura de Kyber ciphertext:

```
Kyber768 Ciphertext (1088 bytes):
- u (comprimido): 960 bytes (3 * 320)
- v (comprimido): 128 bytes
```

Ver `fuzz_ciphertext.py` para mutaciones structure-aware.

### Fuzzing con Restricciones

Para encontrar ciphertexts que:
1. Pasen validación de longitud
2. Tengan "alta entropía"
3. Pero NO pasen re-encryption

```python
# En el harness
if len(data) != 1088:
    return  # Skip invalid length

if len(set(data)) < 200:
    return  # Skip low entropy

# Now fuzz the actual decapsulation
```

### Timing-Based Fuzzing

Para detectar timing leaks:

```python
import time

def time_decapsulation(ct):
    start = time.perf_counter_ns()
    ss, result = transform.decapsulate(ct, sk, pk)
    elapsed = time.perf_counter_ns() - start
    return elapsed, result

# Collect timing data for analysis
```

## 📚 Referencias

- [Atheris Documentation](https://github.com/google/atheris)
- [AFL++ Documentation](https://aflplus.plus/docs/)
- [Fuzzing Cryptographic Libraries](https://guidovranken.com/2020/01/04/fuzzing-cryptographic-libraries/)
- [libFuzzer Tutorial](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md)

---

*Happy Hunting! 🎯*
