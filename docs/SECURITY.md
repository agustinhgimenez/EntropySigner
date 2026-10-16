# EntropySigner — Seguridad

> Educational Hardware Wallet Prototype · Paso 19 — Security Hardening

Este documento reúne el modelo de amenazas, las políticas de seguridad que el
firmware implementa y las limitaciones que **no** resuelve. Complementa a
[`ARCHITECTURE.md`](ARCHITECTURE.md) (diseño) y [`HARDWARE.md`](HARDWARE.md)
(conexionado).

> **Advertencia.** EntropySigner es un prototipo académico. **No es una hardware
> wallet auditada** y no debe custodiar fondos reales. Cada afirmación de este
> documento indica qué está implementado, qué está verificado y qué queda fuera
> del alcance.

---

## Índice

1. [Alcance, activos y supuestos](#1-alcance-activos-y-supuestos)
2. [Modelo de amenazas](#2-modelo-de-amenazas)
3. [Política de ceroizado seguro de memoria](#3-política-de-ceroizado-seguro-de-memoria)
4. [Aislamiento air-gapped](#4-aislamiento-air-gapped)
5. [Justificación criptográfica del pipeline de entropía](#5-justificación-criptográfica-del-pipeline-de-entropía)
6. [Derivación de claves: decisiones de seguridad](#6-derivación-de-claves-decisiones-de-seguridad)
7. [Verificación y aseguramiento](#7-verificación-y-aseguramiento)
8. [Limitaciones del prototipo](#8-limitaciones-del-prototipo)
9. [Recomendaciones para un producto comercial](#9-recomendaciones-para-un-producto-comercial)
10. [Referencias](#10-referencias)

---

## 1. Alcance, activos y supuestos

### 1.1 Activos

| Activo | Tamaño | Sensibilidad | Vida en el dispositivo |
|---|---|---|---|
| Entropía acondicionada | 256 bits | **Crítica**: determina todo lo demás | Stack de `generateWallet()`, se borra tras codificar el mnemonic |
| Mnemonic BIP-39 (24 palabras) | ≤ 216 B | **Crítica**: equivale a la wallet | `g_session.mnemonic` (RAM), se borra al salir de la pantalla de backup |
| Seed BIP-39 | 512 bits | **Crítica** | Stack, se borra tras crear la master key |
| Master key BIP-32 (k, c) | 2 × 256 bits | **Crítica** | Stack, `bip32::wipe()` al terminar |
| Claves privadas BIP-44 derivadas | 256 bits c/u | **Crítica** | Locales a `derive*Address()`, se borran al obtener la pública |
| Claves públicas, direcciones BTC/ETH | — | Pública | `g_session`, pantalla y QR |
| Firmware | — | Integridad (no confidencialidad) | Flash |

Ningún secreto se escribe en flash: el firmware no usa NVS, `Preferences`,
EEPROM ni sistemas de archivos (verificable con
`grep -rn "nvs_\|Preferences\|EEPROM\|SPIFFS\|LittleFS" src/`).

### 1.2 Adversarios considerados

| Perfil | Capacidades | Tratamiento |
|---|---|---|
| **A1 — Remoto** | Red, malware en la PC del usuario | Mitigado por diseño: no existe canal de red (§4) |
| **A2 — Observador** | Ve la pantalla, controla la luz ambiente, accede a la PC conectada por USB | Mitigado parcialmente (§2, §5) |
| **A3 — Físico oportunista** | Tiene el dispositivo minutos: USB, JTAG, lectura de flash | **No mitigado** en el prototipo (§8) |
| **A4 — Laboratorio** | Osciloscopio, sondas EM, inyección de fallos, decapado | **Fuera de alcance**; se documentan las contramedidas comerciales (§9) |
| **A5 — Cadena de suministro** | Reemplaza firmware o hardware antes de la entrega | Fuera de alcance; ver kleptografía (§2.7) |

### 1.3 Supuestos de confianza

1. El RNG de hardware del ESP32-S3 se comporta como TRNG cuando su fuente de
   ruido física (SAR ADC) está habilitada (ver §5.2).
2. mbedTLS 2.28 (incluido en Arduino-ESP32 2.0.17 / ESP-IDF 4.4) implementa
   correctamente SHA-256, HMAC-SHA512, PBKDF2 y la aritmética de secp256k1.
3. El usuario genera la wallet en un entorno sin cámaras y guarda el backup en
   papel o metal, fuera de línea.
4. El firmware cargado es el compilado desde este repositorio (no hay Secure Boot, §8).

---

## 2. Modelo de amenazas

Cada amenaza se describe con su vector, impacto, la mitigación implementada y
el **riesgo residual**.

### 2.1 Ataques por canal lateral

| | |
|---|---|
| **Vector** | Medición de tiempo, consumo (SPA/DPA) o emanación electromagnética mientras el chip opera con secretos: multiplicación escalar en secp256k1 (`k·G`), HMAC-SHA512 de BIP-32, 2048 iteraciones de PBKDF2. También emanaciones del bus SPI del display mientras muestra las palabras. |
| **Impacto** | Recuperación total o parcial de una clave privada o del seed. |
| **Mitigación implementada** | `mbedtls_ecp_mul()` con **aleatorización de coordenadas proyectivas** (`src/bip32/bip32.cpp`), contramedida estándar contra DPA/SPA sobre ECC. La aritmética no constante en tiempo (`mbedtls_ecp_muladd()` en CKDpub, Base58, RIPEMD-160 y Keccak propios) solo procesa **datos públicos** (claves públicas, hashes, direcciones). Las operaciones con secretos se ejecutan una sola vez por sesión, lo que limita el número de trazas disponibles para un ataque diferencial. |
| **Riesgo residual** | **Alto frente a A4.** El DRBG de aleatorización se siembra en forma determinística con el propio escalar (réplica del fallback de mbedTLS 2.x): repetir la derivación produce trazas idénticas, que pueden promediarse. mbedTLS no está certificado contra canales laterales en el ESP32-S3, y los aceleradores SHA/AES del chip tampoco tienen contramedidas documentadas. |

### 2.2 Manipulación del sensor de luz (LDR)

| | |
|---|---|
| **Vector** | El atacante controla la luz que recibe el LDR: lo satura con una linterna (ADC fijo en 4095), lo cubre (oscuridad, ADC cerca de 0) o lo ilumina con un LED modulado para imponer un patrón conocido. Variante: medir la misma luz ambiente desde afuera para predecir las lecturas. |
| **Impacto** | Si la entropía dependiera del LDR, el atacante podría reducirla a ~0 bits o elegirla. |
| **Mitigación implementada** | 1. **Al LDR se le acreditan 0 bits** (política documentada en `ARCHITECTURE.md` §1 y en `entropy_pool.h`). La seguridad descansa en el RNG de hardware. 2. Combinación por **hash**: `SHA-256(tag ‖ RNG ‖ flag ‖ LDR)`. Una entrada controlada no puede reducir la entropía que aporta el RNG (§5.4). 3. **Orden de muestreo**: el LDR se lee **antes** que el RNG (`entropy_pool.cpp`), así que un atacante que controle la luz no puede adaptar su manipulación a la salida del RNG. 4. Análisis estadístico con `tools/entropy_analysis/analyze_entropy.py` (§5.3). |
| **Riesgo residual** | **Bajo**, siempre que el RNG de hardware sea sano. El firmware **no** ejecuta health tests en línea sobre el LDR (§8); un LDR saturado pasa inadvertido, aunque no afecta la seguridad por la política de crédito cero. |

Resultado de la simulación de ataque (fuente `ldr-attack`, N = 200 000):

| Fuente | H_MCV | H_Lag | H_I (min-entropía) | Repetition Count Test |
|---|---|---|---|---|
| LDR normal (simulado) | 5.85 bits | 3.16 bits | **3.16 bits/muestra** | OK |
| LDR saturado por linterna | 0.85 bits | 0.30 bits | **0.30 bits/muestra** | **FALLA** (racha de 29 > corte 21) |

### 2.3 Generador pseudoaleatorio predecible

| | |
|---|---|
| **Vector** | 1. `esp_random()` sin fuente física de ruido: con la radio apagada y sin SAR ADC, el RNG del ESP32-S3 **es solo pseudoaleatorio** (documentación de ESP-IDF). 2. Uso accidental de `rand()`/`random()` de la libc o de Arduino. 3. Semilla fija o reutilizada entre arranques. 4. Debilitamiento intencional del RNG (kleptografía, §2.7). |
| **Impacto** | Catastrófico: un mnemonic predecible permite a terceros reconstruir la wallet, como ocurrió con los incidentes históricos de wallets con RNG débil (Android `SecureRandom` 2013, "Milk Sad"/Libbitcoin Explorer 2023, con espacio de semillas de 32 bits). |
| **Mitigación implementada** | `hw_rng.cpp` envuelve cada lectura con `bootloader_random_enable()` / `bootloader_random_disable()`, que activa el SAR ADC como fuente de ruido físico aunque no haya radio. Solo se usa `esp_fill_random()`; no hay llamadas a `rand()` en el código criptográfico. La salida se acondiciona con SHA-256 junto con el LDR y un *domain tag*. Cada wallet se genera con entropía fresca: no hay estado de RNG persistente. |
| **Riesgo residual** | **Medio.** El ruido del RNG no es observable antes del post-procesamiento del chip, así que no puede evaluarse según SP 800-90B (§5.3, punto 4). No hay health tests en el firmware que detecten una falla del RNG en campo. |

### 2.4 Volcado de memoria flash / RAM

| | |
|---|---|
| **Vector** | 1. **Flash**: lectura por `esptool.py read_flash` (modo download por USB) o desoldando el chip SPI. 2. **RAM**: depuración por JTAG/USB-JTAG con el dispositivo encendido, *cold boot* (remanencia de la SRAM), volcado del *core dump* tras un crash. 3. **Display**: la GRAM del controlador ST7796 conserva la imagen de las palabras hasta que se redibuja. |
| **Impacto** | Flash: ninguno sobre secretos (no se persisten). RAM: exposición del mnemonic o de claves mientras residen en memoria. |
| **Mitigación implementada** | **Ningún secreto en flash** (§1.1). En RAM, **ceroizado explícito** de cada buffer secreto apenas deja de ser necesario (§3). La ventana de exposición más larga es la del mnemonic, que se borra al salir de la pantalla de backup. Las claves privadas viven solo durante la derivación (milisegundos). La pantalla siguiente sobrescribe la GRAM del display. |
| **Riesgo residual** | **Alto frente a A3.** JTAG y el modo download siguen habilitados (eFuses sin quemar), sin flash encryption ni Secure Boot. Un atacante con acceso USB puede **reemplazar el firmware** por uno malicioso (más grave que leerlo). El ceroizado no cubre copias que el compilador o mbedTLS dejen en registros o en el stack de funciones internas. |

### 2.5 Inyección de fallos (glitching)

| | |
|---|---|
| **Vector** | Perturbación de tensión (*voltage glitching*), reloj o pulsos electromagnéticos (EMFI) para saltear instrucciones: omitir una comparación, un borrado o una verificación. En la familia ESP32 hay ataques publicados de este tipo. Por ejemplo, LimitedResults (2019, CVE-2019-17391) leyó eFuses protegidas del ESP32 original, lo que comprometió Secure Boot y la flash encryption. |
| **Impacto** | Saltear el ceroizado, forzar una rama de error que deje secretos en RAM o corromper un cálculo. |
| **Mitigación implementada** | Mínima. Todas las funciones criptográficas **verifican su resultado** y ponen a cero la salida si fallan (contrato *fail-closed* de cada módulo). Las claves se validan contra el orden de la curva (`mbedtls_ecp_check_privkey`), las claves públicas descomprimidas se validan contra la ecuación de la curva y los mnemonics contra su checksum. El firmware **no firma transacciones**, así que no hay ataques de fallo sobre firmas (p. ej. Bellcore/RSA-CRT o ECDSA con nonces fallados) que puedan filtrar la clave. |
| **Riesgo residual** | **Alto frente a A4.** El ESP32-S3 tiene detector de *brownout*, pero no es un detector de glitches diseñado para resistir ataques. No hay redundancia temporal (calcular dos veces y comparar) ni verificación del flujo de control. |

### 2.6 Observación de pantalla y del backup

| | |
|---|---|
| **Vector** | *Shoulder surfing*, cámaras, fotos del backup, reflejos. |
| **Mitigación implementada** | Pantalla de advertencia obligatoria (`BACKUP_WARNING`) antes de mostrar las 24 palabras ("No saques fotos ni capturas"). El mnemonic se muestra en una pantalla dedicada y **nunca se codifica en QR**: el QR transporta solo direcciones públicas. En modo DEMO, el banner "DEMO MODE" marca que la wallet no es para uso real. |
| **Riesgo residual** | Depende del usuario. |

### 2.7 Kleptografía y firmware malicioso (fuera de alcance, documentado)

Un firmware alterado puede generar mnemonics que parezcan aleatorios, pero que
el fabricante pueda predecir: por ejemplo, `SHA-256(clave_secreta ‖ contador)`.
Ningún test estadístico lo detecta. La fuente sintética `sha256-counter` del
analizador lo demuestra: supera chi-cuadrado, autocorrelación y los estimadores
de min-entropía con **0 bits de entropía real**. La defensa exige builds
reproducibles, firmware firmado (Secure Boot) y, idealmente, que el usuario
pueda mezclar entropía propia (dados) y verificar el resultado en otro
dispositivo (§9).

### 2.8 Matriz de riesgo resumida

| Amenaza | A1 | A2 | A3 | A4 | Estado |
|---|---|---|---|---|---|
| Exfiltración por red | ✔ | ✔ | — | — | Eliminada (sin radio) |
| Fuga por logs serie | — | ✔ | ✔ | — | Mitigada (PRODUCTION sin logs de debug, sin secretos en ningún modo) |
| Manipulación del LDR | — | ✔ | ✔ | ✔ | Mitigada (crédito 0 + hash) |
| RNG predecible | ✔ | — | — | ✔ | Mitigada parcialmente (SAR ADC, sin health tests) |
| Volcado de flash | — | — | ✔ | ✔ | Sin impacto en secretos; firmware reemplazable |
| Volcado de RAM en vivo | — | — | ✘ | ✘ | **No mitigada** (JTAG abierto) |
| Canal lateral | — | — | — | ✘ | Parcial (blinding determinístico) |
| Glitching | — | — | — | ✘ | **No mitigada** |
| Cadena de suministro | — | — | — | — | Fuera de alcance |

✔ = cubierto · ✘ = no cubierto · — = no aplica

---

## 3. Política de ceroizado seguro de memoria

### 3.1 Problema

En C/C++, un `memset(buf, 0, n)` sobre un buffer que no vuelve a leerse es un
*dead store*, y el optimizador puede eliminarlo legalmente, porque la regla
*as-if* solo obliga a preservar el comportamiento observable. GCC lo hace con
`-O2` cuando el buffer está por salir de alcance, y LTO puede hacerlo incluso a
través de unidades de compilación. El resultado es que la clave permanece en el
stack y una función posterior puede filtrarla, igual que un volcado de memoria.

### 3.2 Implementación: `es::security::secureMemzero()`

[`src/security/secure_mem.h`](../src/security/secure_mem.h):

```cpp
inline void secureMemzero(void* ptr, size_t len) {
    if (ptr == nullptr) return;
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) *p++ = 0;                                  // (1)
#if defined(__GNUC__)
    __asm__ __volatile__("" : : "r"(ptr) : "memory");        // (2)
#endif
}
```

1. **Escritura a través de un puntero `volatile`.** Cada acceso a un objeto
   `volatile` es un efecto observable (C++ [intro.execution]), así que el
   compilador debe emitir cada store.
2. **Barrera de optimización.** El `asm volatile` vacío, con clobber `"memory"`
   y el puntero como operando de entrada, hace suponer al compilador que el
   bloque *lee* esa memoria. Así, ni GCC ni LTO pueden mover o descartar los
   stores previos.

Es la misma técnica de `explicit_bzero()` (glibc, OpenBSD) y de
`mbedtls_platform_zeroize()`. Se eligió una versión propia, header-only, para
que el módulo sea C++ puro y testeable en el host (`tests/test_crypto`).

### 3.3 Reglas de aplicación

| Regla | Dónde se cumple |
|---|---|
| Todo buffer con material secreto se borra **en todos los caminos de salida**, incluidos los de error | Patrón `ok = a && b && c; secureMemzero(...); return ok;` en `entropy_pool.cpp`, `bip39.cpp`, `bip32.cpp` |
| Si una función falla, su salida se pone a cero (contrato *fail-closed*) | Documentado en cada header: `bip32.h`, `bip39.h`, `base58.h`, `keccak256.h`, `entropy_pool.h` |
| Las estructuras de clave se borran completas (clave, chain code y metadatos) | `bip32::wipe(ExtendedPrivateKey*)`, `bip32::wipe(ExtendedPublicKey*)` |
| Los contextos de mbedTLS se liberan con su función `*_free()`, que hace zeroize interno | Wrappers RAII `Mpi`/`Point` en `bip32.cpp`; `mbedtls_hmac_drbg_free()` |
| Un secreto vive lo mínimo indispensable | Entropía: se borra tras `entropyToMnemonic()`. Seed: tras `createMasterKey()`. Claves BIP-44: tras calcular la pública (`bitcoin.cpp`, `ethereum.cpp`) |
| El mnemonic se borra al abandonar el backup o tras inactividad | `enterState()`: al salir de `SHOW_MNEMONIC`, por timeout de inactividad (2 min) o por botón CANCELAR; `wipeSession()` al volver a `IDLE` o si falla la generación |
| En PRODUCTION no se loguean direcciones públicas por USB | Protegido con `#if defined(ES_MODE_DEMO)` para evitar correlación de identidad con una PC conectada (A2) |
| Nunca se pasan secretos a `ES_LOG_*` | Política en `secure_log.h`. Solo se loguean estados de la UI y direcciones públicas (en modo DEMO) |

### 3.4 Lo que el ceroizado no garantiza

- Copias en **registros** o *spills* que el compilador genere dentro de
  funciones de biblioteca (mbedTLS, libc). Mitigarlo requiere borrar el stack
  completo (*stack scrubbing*) al salir de la operación sensible.
- Datos en la **GRAM del display**, que se sobrescriben recién al redibujar.
- Protección frente a un atacante que lee la RAM **mientras** el secreto está
  vivo (JTAG, §2.4). El ceroizado reduce la *ventana*, no la elimina.

---

## 4. Aislamiento air-gapped

### 4.1 Superficie de comunicación

| Canal | Dirección | Contenido | Estado |
|---|---|---|---|
| Wi-Fi 802.11 b/g/n | — | — | **Nunca inicializado** |
| Bluetooth LE 5 | — | — | **Nunca inicializado** |
| Pantalla TFT | Salida | Estado de la UI, mnemonic (solo en backup), direcciones | Único canal que muestra secretos, siempre a pedido explícito |
| Códigos QR | Salida | **Solo direcciones públicas** BTC/ETH | `qr::renderQr()` recibe únicamente `g_session.btc_address` / `eth_address` |
| Pantalla táctil | Entrada | Navegación | Sin entrada de datos arbitrarios |
| LDR (ADC) | Entrada | Luz ambiente | Entrada no confiable, crédito de entropía 0 |
| USB-UART | Bidireccional | Logs de estado y flasheo | Sin secretos; DEBUG compilado fuera en PRODUCTION |

### 4.2 Cómo se garantiza la ausencia de radio

- El firmware **no incluye** `WiFi.h`, `BLEDevice.h`, `esp_wifi.h` ni
  `esp_bt.h`. Arduino-ESP32 no arranca la radio si no se usan esas APIs, así
  que el subsistema RF permanece apagado. Es verificable con
  `grep -rnE "WiFi|BLEDevice|esp_wifi|esp_bt|BluetoothSerial" src/` (sin resultados).
- Por eso el RNG **no puede** apoyarse en el ruido de RF y usa explícitamente
  el SAR ADC (§2.3).
- La salida pública por QR es **unidireccional y óptica**: no existe protocolo
  ni handshake que un atacante pueda explotar para enviar datos *al*
  dispositivo. El QR se genera offline con `ricmoo/QRCode`, sin dependencias de
  red.

### 4.3 Limitaciones del air-gap

- El hardware de radio **existe físicamente**: un firmware malicioso podría
  activarlo. El air-gap es una propiedad del firmware, no del hardware
  (no hay Secure Boot, §8).
- El cable USB es un canal bidireccional mientras está conectado. En operación
  normal el dispositivo debería alimentarse con una fuente o batería, sin PC.
- Canales encubiertos físicos (EM, acústicos, LED) quedan fuera de alcance.

### 4.4 Modos DEMO y PRODUCTION

Se seleccionan en **tiempo de compilación** (`platformio.ini`), y
`build_config.h` aborta la compilación si no se define exactamente uno. En
PRODUCTION, `ES_LOG_DEBUG` se expande a una sentencia vacía, así que el código
de depuración **no existe** en el binario (no es un *flag* que se pueda
reactivar). `CORE_DEBUG_LEVEL=0` silencia además los logs del core de Arduino.

---

## 5. Justificación criptográfica del pipeline de entropía

### 5.1 Construcción

```
entropy (256 bits) = SHA-256( "EntropySigner/entropy-pool/v1"   29 B  domain tag
                            ‖ RNG_HW                             64 B  esp_fill_random + SAR ADC
                            ‖ include_ldr                         1 B  0x00 / 0x01
                            ‖ LDR[0..127]                       256 B  uint16 little-endian )
n_in = 2800 bits  →  n_out = 256 bits
```

| Decisión | Justificación |
|---|---|
| **Domain tag** | Separación de dominios: esta invocación de SHA-256 no puede coincidir con otro uso de SHA-256 en el sistema (checksum BIP-39, Base58Check). |
| **Campos de longitud fija + flag** | Codificación sin ambigüedad: dos combinaciones distintas de (RNG, LDR, modo) no pueden producir la misma cadena de entrada. |
| **LDR antes que RNG** | Requisito de hardware (el SAR ADC no puede servir al RNG y al driver ADC a la vez) y además de seguridad: la entrada controlable se fija antes de que exista la salida del RNG (§5.4). |
| **SHA-256** | Función hash aprobada (FIPS 180-4) y componente de acondicionamiento aprobado según SP 800-90B §3.1.5.1.1. Está acelerada por hardware en el ESP32-S3 vía mbedTLS. |

### 5.2 Fuentes

- **RNG de hardware (fuente principal).** Según la documentación de ESP-IDF,
  el RNG del ESP32-S3 entrega números verdaderamente aleatorios solo si mezcla
  ruido físico: el subsistema RF o el SAR ADC habilitado con
  `bootloader_random_enable()`. El firmware usa la segunda opción.
- **LDR (fuente complementaria).** Divisor resistivo leído por ADC1 a 12 bits.
  No se le acredita entropía (§5.3).

### 5.3 Evaluación según NIST SP 800-90B

`tools/entropy_analysis/analyze_entropy.py` implementa los estimadores
**6.3.1 Most Common Value**, **6.3.2 Collision** (sobre el bitstring) y
**6.3.8 Lag Prediction**, combinados según §3.1.3:
`H_I = min(H_original, n × H_bitstring)`. Además calcula la entropía de
Shannon, el test chi-cuadrado, la autocorrelación (lags 1–10) y los health
tests §4.4 (Repetition Count y Adaptive Proportion).

```
python tools/entropy_analysis/analyze_entropy.py --synthetic all
python tools/entropy_analysis/analyze_entropy.py --file captura_ldr.txt --bits 12
```

Resultados sobre las fuentes simuladas (N = 200 000, semilla 2026):

| Fuente | bits | H_MCV | H_Lag | H_I | H_I/bit | Shannon | Lags significativos |
|---|---|---|---|---|---|---|---|
| `trng` (os.urandom) | 8 | 7.75 | 7.90 | 7.29 | 0.91 | 8.00 | 0 |
| `ldr` | 12 | 5.85 | 3.16 | 3.16 | 0.26 | 6.37 | 10/10 (r₁ = 0.98) |
| `ldr-attack` | 12 | 0.85 | 0.30 | 0.30 | 0.02 | 1.73 | 10/10 |
| `sha256-counter` | 8 | 7.72 | 7.94 | 7.32 | 0.92 | 8.00 | 0 |

Las fuentes simuladas son reproducibles con `--seed`, salvo `trng`, que usa el
CSPRNG del sistema operativo y varía en ±0.1 bits entre ejecuciones. El
estimador Collision es conservador: incluso con datos ideales reporta ~0.91
bits/bit con este N, lo que fija el techo de H_I/bit de las fuentes de 8 bits.

Conclusiones:

1. **La métrica relevante es la min-entropía**, H∞ = −log₂ p_max, porque acota
   la probabilidad de acertar el secreto en el primer intento. La entropía de
   Shannon la sobrestima: en el LDR, 6.37 bits frente a 3.16 bits.
2. **El LDR no es IID.** Su autocorrelación de lag 1 es 0.98 (deriva lenta y
   parpadeo de 100 Hz de la red de 50 Hz). El estimador MCV, que ignora el
   orden, sobrestima en un 85 % lo que mide el predictor Lag. SP 800-90B obliga
   a usar la vía non-IID para fuentes así.
3. **El LDR es controlable por el atacante** (§2.2) y no existe un modelo
   estocástico validado del sensor, como exige SP 800-90B §3.2.2 para acreditar
   entropía. Lo poco que varía es sobre todo ruido térmico y de cuantización
   del ADC, no información sobre la luz. **Por eso se le acreditan 0 bits.**
4. **Los tests estadísticos no prueban aleatoriedad.** `sha256-counter` es
   indistinguible de `trng` en todas las métricas y tiene entropía nula. Por la
   misma razón, analizar la salida ya post-procesada de `esp_random()` solo
   sirve como prueba de cordura. SP 800-90B exige evaluar el **ruido crudo**,
   que el ESP32-S3 no expone.
5. **Alcance.** Se implementan 3 de los 10 estimadores non-IID; los omitidos
   solo pueden bajar la estimación. Una evaluación formal requiere la
   herramienta oficial de NIST (`ea_non_iid`, `ea_restart`) sobre ≥ 1 000 000
   de muestras crudas y una matriz de 1000 reinicios × 1000 muestras.

### 5.4 SHA-256 como extractor: qué garantiza y qué no

**No crea entropía.** Para cualquier función determinística f,
H∞(f(X)) ≤ H∞(X), y además H∞(SHA-256(X)) ≤ 256. Un hash *acondiciona*:
comprime una entrada larga con entropía dispersa en una salida corta casi
uniforme, y oculta la estructura (sesgo, correlación) de la fuente.

**Entropía de salida (SP 800-90B §3.1.5.1.2).** Para un componente aprobado
con entrada de n_in bits y h_in bits de entropía, con n = min(n_out, nw):

```
P_high = 2^(−h_in)          P_low = (1 − P_high) / (2^n_in − 1)
ψ = 2^(n_in − n)·P_low + P_high
U = 2^(n_in − n) + sqrt(2·n·2^(n_in − n)·ln 2)        ω = U·P_low
h_out = −log2( max(ψ, ω) )
```

Valores teóricos para el acondicionamiento (con n_out = nw = 256):

| Escenario | h_in (bits) | h_out (bits) | Estado en EntropySigner |
|---|---|---|---|
| RNG HW a 32 bytes (256 bits nom.), LDR acreditado en 0 | 256 | 255.0 | Versión previa (pérdida fraccionaria teórica) |
| **RNG HW a 64 bytes (512 bits)**, LDR acreditado en 0 | **≥ 320** | **256.0** | **Implementación actual:** cumple criterio SP 800-90C ($h_{in} \ge n_{out} + 64$) |
| RNG degradado a 128 bits | 128 | 128.0 | Tolerancia a fallos parciales |
| RNG comprometido, LDR medido sin atacante | 403.9 | 256.0 | Escenario optimista (**no acreditado por política**) |
| RNG comprometido y LDR saturado | 0 | 0.0 | Falla total de fuentes físicas |

Al muestrear `kHwRngBytes = 64` (512 bits) del TRNG por hardware del ESP32-S3, la entrada aporta sobradamente más de los 320 bits de min-entropía requeridos por la recomendación NIST SP 800-90C para garantizar que el valor resultante del digest SHA-256 alcance **256.0 bits completos de min-entropía** sin déficit fraccionario. Además, `initLdr()` reestablece la atenuación del ADC en cada ciclo de muestreo para prevenir cualquier descalibración originada tras el ciclo del SAR ADC del TRNG.

**Combinación de fuentes.** Si X (RNG) es impredecible e independiente de Y
(LDR), modelando SHA-256 como oráculo aleatorio, la salida es casi uniforme
para *cualquier* valor de Y, incluso uno elegido por el atacante: H∞(X, Y) ≥ H∞(X)
y la entropía de X no se pierde por concatenar Y. El supuesto crítico es la
**independencia**: un atacante que viera la salida del RNG y luego eligiera el
LDR podría hacer *grinding*, es decir, probar 2^t configuraciones y sesgar t
bits de la salida. El firmware lo impide por diseño, porque el LDR se muestrea
**antes** de leer el RNG.

**Fundamento teórico.** El *Leftover Hash Lemma* garantiza la extracción para
familias de hash universales con semilla. Para una función fija como SHA-256,
la justificación es computacional: Dodis, Gennaro, Håstad, Krawczyk y Rabin
(CRYPTO 2004) analizan los extractores basados en compresión iterada y HMAC, y
HKDF (RFC 5869) formaliza el paradigma *extract-then-expand*. SP 800-90B toma
la decisión normativa de aceptar SHA-256 como *vetted conditioning component*.

### 5.5 Margen de seguridad

secp256k1 ofrece ~128 bits de seguridad (algoritmo rho de Pollard sobre un
grupo de orden ≈ 2²⁵⁶). Generar 256 bits de entropía da un margen de 2× sobre
el eslabón más débil: incluso si el RNG aportara solo la mitad de su entropía
nominal, el adversario genérico seguiría enfrentando ~2¹²⁸ operaciones.

---

## 6. Derivación de claves: decisiones de seguridad

| Elemento | Decisión | Consecuencia de seguridad |
|---|---|---|
| **BIP-39, 24 palabras** | Solo 256 bits (`bip39.h`) | Máximo estándar. El checksum de 8 bits **detecta errores** de transcripción (falla 1 de cada 256 mnemonics al azar), no es un mecanismo de seguridad |
| **Validación estricta del mnemonic** | `mnemonicToSeed()` exige un mnemonic válido | BIP-39 derivaría un seed de cualquier cadena; en una wallet, un typo produciría en silencio una wallet vacía distinta |
| **Passphrase BIP-39** | Solo ASCII imprimible (NFKD trivial); la UI no la usa todavía | Sin normalizador Unicode en el dispositivo; restringir el alfabeto evita seeds no estándar |
| **PBKDF2 con 2048 iteraciones** | Valor fijado por BIP-39 | Es *key stretching* débil, pero irrelevante con 256 bits de entropía. Solo importaría para passphrases de baja entropía |
| **BIP-32 endurecido** | `m/44'/coin'/0'` endurecidos, `/0/0` normales (BIP-44) | Con la clave privada de un hijo **no endurecido** y el *xpub* del padre se recupera la clave privada del padre. El firmware **nunca exporta xpubs** ni claves privadas |
| **Rechazo de claves inválidas** | I_L ≥ n o k = 0 → error, sin "saltar" de índice en silencio | Cumple BIP-32 y evita devolver claves de un índice distinto al pedido |
| **Direcciones** | BTC P2PKH (`1…`), ETH con checksum EIP-55 | El checksum (4 bytes SHA256d / mayúsculas EIP-55) detecta errores al copiar la dirección |

---

## 7. Verificación y aseguramiento

| Capa | Herramienta | Qué demuestra |
|---|---|---|
| Unitaria en hardware | Unity, `tests/test_*` (`pio test -e esp32s3-demo`) | Ejecución sobre el ESP32-S3: valida drivers, aceleración SHA, hardware RNG, ADC, display y la suite de tests C++ contra vectores estándar |
| Cruzada independiente (host) | `python tools/verification/verify_cross.py` | Implementación independiente en Python que valida 172 checks contra los estándares oficiales y confirma que los 123 literales esperados en `tests/*.cpp` concuerdan bit a bit |
| Estadística | `python tools/entropy_analysis/analyze_entropy.py` | Comportamiento de las fuentes según SP 800-90B (§5.3) y análisis del acondicionador SHA-256 |

La verificación cruzada no depende del firmware. RIPEMD-160, Keccak-f[1600] y
secp256k1 se implementaron en Python a partir de sus especificaciones, y la
permutación Keccak se valida además contra `hashlib.sha3_256` (misma
permutación, padding FIPS 202 `0x06`). Resultado actual: **172 checks PASS,
0 FAIL, 123 literales confirmados** en los tests C++. Juntas demuestran la equivalencia matemática rigurosa entre las especificaciones oficiales, el modelo de referencia en Python y los tests del firmware.

> **Hallazgo.** La primera ejecución de `verify_cross.py` detectó que el vector
> NIST de SHA-256 para el mensaje de 448 bits (`"abcdbcdecdef…nopq"`) en
> `tests/test_crypto/test_main.cpp` tenía los últimos 10 bytes mal transcriptos
> (`…64ff21a7f7b70bc00f80a647` en lugar de `…64ff2167f6ecedd419db06c1`, FIPS
> 180-2 Apéndice B.2). El test `test_sha256_nist_multi_block` habría fallado
> contra un SHA-256 correcto. El vector quedó corregido. El caso ilustra el
> valor de verificar con una implementación independiente.

---

## 8. Limitaciones del prototipo

| # | Limitación | Impacto |
|---|---|---|
| L1 | **Sin Secure Element.** Los secretos se procesan en la SRAM del microcontrolador de propósito general | Expuestos a JTAG, canales laterales y fallos |
| L2 | **Sin Secure Boot ni flash encryption.** eFuses sin quemar, JTAG y modo download habilitados | Cualquiera con acceso USB puede reemplazar el firmware (incluso por uno kleptográfico) |
| L3 | **Sin health tests en línea** (SP 800-90B §4.4) sobre el RNG ni el LDR | Una fuente fallada no se detecta en campo; los tests existen solo en la herramienta de análisis |
| L4 | **Ruido crudo del RNG inaccesible** | No es posible una evaluación SP 800-90B del RNG principal; se confía en el fabricante |
| L5 | **Blinding ECC determinístico** (DRBG sembrado con el escalar) | Trazas repetibles por clave (§2.1) |
| L6 | **Sin PIN ni autenticación del usuario** | Quien tenga el dispositivo encendido opera la UI |
| L7 | **Sin detección de manipulación física** (anti-tamper) | Apertura y sondeo sin rastro |
| L8 | **Sin redundancia frente a fallos** (doble cálculo, verificación del flujo de control) | Vulnerable a glitching |
| L9 | **Análisis del LDR sobre datos simulados** hasta capturar muestras reales | Las cifras de §5.3 ilustran el método, no caracterizan el hardware |
| L10 | **Implementaciones propias** de RIPEMD-160, Keccak-256 y Base58 | Solo procesan datos públicos (mitiga canales laterales); su corrección se respalda con vectores y verificación cruzada, no con auditoría |
| L11 | **Sin firma de transacciones** | Limita la funcionalidad, pero también elimina la superficie de ataques sobre firmas |

---

## 9. Recomendaciones para un producto comercial

### 9.1 Hardware

| Recomendación | Mitiga | Detalle |
|---|---|---|
| **Secure Element** certificado (Common Criteria EAL5+/EAL6+) | L1, L5, L7, §2.1, §2.5 | La entropía, el seed y las claves se generan y operan **dentro** del SE (p. ej. familias ST33, Infineon OPTIGA Trust M, NXP SE050, Microchip ATECC608B) con contramedidas certificadas contra DPA/EMFI. El MCU solo maneja la UI |
| **TRNG certificado** (AIS-31 PTG.2/PTG.3 o validación SP 800-90B con *entropy source* ESV) | L3, L4 | Acceso al ruido crudo, health tests de arranque y continuos en hardware |
| **Anti-tamper** | L7, §2.4 | Malla conductora, encapsulado en epoxi (*potting*), sensores de apertura, luz y temperatura que **borren** los secretos al dispararse |
| **Detectores de glitch** de tensión y reloj, osciladores internos | §2.5 | Además del *brownout*, reset ante transitorios anómalos |
| **Memoria cifrada** | §2.4 | RAM/PSRAM cifrada con claves efímeras; en el ESP32-S3, flash encryption XTS-AES-256 para el firmware |
| **Sin radio en el BOM** | §4.3 | MCU sin RF o con la antena físicamente ausente, para que el air-gap sea una propiedad del hardware |

### 9.2 Firmware y proceso

1. **Secure Boot v2 + flash encryption** en modo *release*. Quemar eFuses
   `DIS_USB_JTAG`, `DIS_PAD_JTAG`, `DIS_DOWNLOAD_MODE` (o
   `ENABLE_SECURITY_DOWNLOAD`) y deshabilitar la consola ROM.
2. **Health tests de SP 800-90B §4.4 en el firmware**: Repetition Count y
   Adaptive Proportion sobre la fuente, en el arranque y en cada generación,
   con bloqueo si fallan. El analizador ya incluye el cálculo de los cortes.
3. **Biblioteca ECC constante en tiempo y auditada** (`libsecp256k1` de Bitcoin
   Core) con *blinding* aleatorio tomado del TRNG, no determinístico.
4. **Redundancia contra fallos**: derivar la dirección dos veces y comparar,
   verificar la clave pública contra la privada antes de mostrarla, usar
   contadores de flujo de control.
5. **PIN con límite de intentos** y borrado tras N fallos. El seed, si se
   persiste, va cifrado dentro del SE.
6. **Builds reproducibles y firmware firmado**, con *attestation* del
   dispositivo para que el usuario verifique la autenticidad (anti-kleptografía).
7. **Entropía del usuario** (p. ej. 99 tiradas de dado) mezclada por hash y
   verificable offline. Para firmas, protocolo **anti-exfil** (*sign-to-contract*)
   que impida filtrar la clave por los nonces.
8. **Stack scrubbing** al salir de las operaciones sensibles y uso exclusivo de
   la SRAM interna (no PSRAM) para secretos.
9. **Certificación** del módulo criptográfico (FIPS 140-3 o Common Criteria) y
   auditoría externa del firmware.

---

## 10. Referencias

- NIST SP 800-90B, *Recommendation for the Entropy Sources Used for Random Bit Generation*, 2018.
- NIST SP 800-90C, *Recommendation for Random Bit Generator (RBG) Constructions*.
- NIST FIPS 180-4, *Secure Hash Standard*; FIPS 202, *SHA-3 Standard*.
- BIP-32 (*Hierarchical Deterministic Wallets*), BIP-39 (*Mnemonic code*), BIP-44 (*Multi-Account Hierarchy*), EIP-55 (*Mixed-case checksum address encoding*).
- SEC 2 v2, *Recommended Elliptic Curve Domain Parameters* (secp256k1).
- H. Dobbertin, A. Bosselaers, B. Preneel, *RIPEMD-160: A Strengthened Version of RIPEMD*, FSE 1996.
- G. Bertoni, J. Daemen, M. Peeters, G. Van Assche, *The Keccak Reference*, v3.0.
- Y. Dodis, R. Gennaro, J. Håstad, H. Krawczyk, T. Rabin, *Randomness Extraction and Key Derivation Using the CBC, Cascade and HMAC Modes*, CRYPTO 2004.
- H. Krawczyk, RFC 5869, *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*, 2010.
- Espressif, *ESP32-S3 Technical Reference Manual* (Random Number Generator, eFuse, Secure Boot v2, Flash Encryption) y documentación de ESP-IDF v4.4 (`esp_random`, `bootloader_random_enable`).
- LimitedResults, *Pwn the ESP32 Forever: Flash Encryption and Sec. Boot Keys Extraction*, 2019 (CVE-2019-17391).
- AIS 20/31 (BSI), *Functionality classes and evaluation methodology for random number generators*.
