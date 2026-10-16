---
marp: true
theme: default
paginate: true
size: 16:9
header: 'EntropySigner · Criptografía y Seguridad 2026'
footer: 'Educational Hardware Wallet Prototype · no usar con fondos reales'
style: |
  section { font-size: 24px; }
  section.lead h1 { font-size: 56px; }
  pre { font-size: 17px; line-height: 1.25; }
  table { font-size: 19px; }
---

<!-- _class: lead -->
<!-- _header: '' -->

![w:520](../assets/logo.svg)

# EntropySigner

### Hardware wallet educativa sobre ESP32-S3

Generación de entropía · BIP-39 · BIP-32/44 · Bitcoin y Ethereum

Criptografía y Seguridad — 2026, 2.º semestre

---

## 1. El problema

Una wallet de criptomonedas **es** su clave privada.

- Quien conoce la semilla controla los fondos: no hay banco ni "olvidé mi contraseña".
- La seguridad completa depende de **un número de 256 bits** generado una sola vez.
- Fallas reales por mala aleatoriedad:
  - Android `SecureRandom` (2013): firmas con nonces repetidos.
  - "Milk Sad" / Libbitcoin Explorer (2023): semillas de **32 bits** de entropía real.

**Pregunta del trabajo:** ¿cómo se genera, se respalda y se usa esa semilla en un
dispositivo que nunca se conecta a la red?

---

## 2. Objetivos

1. Generar **256 bits de entropía** con una fuente de hardware y medir su calidad.
2. Implementar el estándar **BIP-39** (24 palabras + seed) y **BIP-32/44** (derivación jerárquica).
3. Obtener direcciones reales de **Bitcoin** (P2PKH) y **Ethereum** (EIP-55).
4. Mostrar sólo datos públicos (direcciones y QR) en un dispositivo **air-gapped**.
5. Verificar cada primitiva contra **vectores oficiales** y una implementación independiente.
6. Documentar **honestamente** qué protege y qué no.

> Inspiración conceptual: SeedSigner. Diseño e implementación propios.

---

## 3. Hardware

![bg right:45% w:520](../assets/circuit.svg)

| Componente | Elección |
|---|---|
| MCU | ESP32-S3 (2 núcleos, 240 MHz, aceleradores SHA/AES) |
| Display | IPS 320×480 ST7796S (SPI 40 MHz) |
| Touch | Capacitivo FT6336U (I²C) |
| Entropía física | LDR GL5528 + 10 kΩ → ADC1 |

- **Sin WiFi ni Bluetooth**: la radio nunca se inicializa.
- Pines validados en **tiempo de compilación** (`static_assert`): sin strapping, USB ni flash.

---

## 4. Arquitectura en capas

```
┌───────────────────────────────────────────────────────────┐
│ ui/        máquina de estados táctil · qr/ (sólo públicos) │
├──────────────┬──────────────┬─────────────────────────────┤
│ bitcoin/     │ ethereum/    │ security/ memzero · logs     │
├──────────────┴──────────────┴─────────────────────────────┤
│ bip32/ secp256k1 (mbedTLS ECP)   bip39/ mnemonic · PBKDF2  │
├───────────────────────────────────────────────────────────┤
│ crypto/ SHA-256 · RIPEMD-160 · Keccak-256 · Base58Check    │
├───────────────────────────────────────────────────────────┤
│ entropy/ ldr_entropy · hw_rng · entropy_pool               │
├───────────────────────────────────────────────────────────┤
│ Arduino-ESP32 2.0.17 · ESP-IDF 4.4 · mbedTLS 2.28          │
└───────────────────────────────────────────────────────────┘
```

- Las capas criptográficas **no dependen de Arduino** → testeables con vectores.
- Dos builds: **DEMO** (banner, logs) y **PRODUCTION** (el código de debug no existe en el binario).

---

## 5. Entropía: el principio central

```
LDR ──► ADC (128 muestras) ─┐
                            ├──► SHA-256(tag ‖ RNG ‖ flag ‖ LDR) ──► 256 bits
ESP32 HW RNG (64 B) ────────┘     (SAR ADC como fuente de ruido)
```

- **Fuente principal: RNG de hardware.** Sin radio, el RNG del ESP32-S3 es sólo
  pseudoaleatorio → se activa el **SAR ADC** con `bootloader_random_enable()`.
- **LDR: fuente adicional con crédito de 0 bits.** Defensa en profundidad.
- **SHA-256 no crea entropía:** H∞(SHA-256(X)) ≤ min(256, H∞(X)).
- **Orden:** el LDR se lee **antes** que el RNG → un atacante que controla la luz
  no puede adaptarla a la salida del RNG.

---

## 6. ¿Cuánta entropía tiene el LDR? (NIST SP 800-90B)

Estimadores 6.3.1 MCV · 6.3.2 Collision · 6.3.8 Lag Prediction (N = 200 000)

| Fuente | H_I (min-entropía) | Comentario |
|---|---|---|
| `trng` (referencia) | 7.29 bits/byte | |
| `ldr` | 3.16 bits/muestra | **No IID**: autocorrelación r₁ = 0.98 |
| `ldr-attack` (linterna) | **0.30** bits/muestra | Repetition Count Test **FALLA** |
| `sha256-counter` | 7.32 bits/byte | **0 bits reales** |

- Shannon (6.37) sobrestima: la métrica correcta es la **min-entropía**.
- **Los tests estadísticos no prueban aleatoriedad**: un contador hasheado los pasa todos.
- Conclusión: el LDR es manipulable → **crédito 0**, confirmado con datos.

---

## 7. BIP-39: de bits a palabras

```
256 bits de entropía
   │  SHA-256 → primeros 8 bits = checksum
   ▼
264 bits ──► 24 grupos de 11 bits ──► índices 0..2047 ──► 24 palabras
   │
   ▼
PBKDF2-HMAC-SHA512( mnemonic, "mnemonic" ‖ passphrase, 2048 iter. )
   │
   ▼
seed de 512 bits
```

- El checksum **detecta errores** de transcripción (1 de cada 256 mnemonics al azar pasa).
- `mnemonicToSeed()` **exige** un mnemonic válido: un typo no crea en silencio otra wallet.
- Lista oficial de 2048 palabras, verificada por su SHA-256.

---

## 8. BIP-32 / BIP-44: un árbol de claves

```
seed ──HMAC-SHA512("Bitcoin seed")──► master (k, c)
                                         │
                       m / 44' / coin' / 0' / 0 / 0
                       ─────── endurecidos ─────  normales
                                         │
              ┌──────────────────────────┴───────────────────────┐
     m/44'/0'/0'/0/0  (Bitcoin)                       m/44'/60'/0'/0/0  (Ethereum)
     pub comprimida → HASH160                         pub sin comprimir → Keccak-256
     → Base58Check(0x00) → 1…                         → últimos 20 B → EIP-55 → 0x…
```

- CKDpriv: `I = HMAC-SHA512(c, data ‖ index)`, `k_hijo = (I_L + k) mod n`.
- **Hardened** (`'`): con la clave privada de un hijo normal + el xpub del padre se
  recupera la privada del padre → el firmware **nunca exporta xpubs**.

---

## 9. Lo que tuvimos que implementar nosotros

| Primitiva | Origen | Motivo |
|---|---|---|
| SHA-256, HMAC-SHA512, PBKDF2 | mbedTLS (acelerado por HW) | Biblioteca confiable |
| secp256k1 | mbedTLS ECP | + descompresión propia de puntos |
| RIPEMD-160 | **Propia** | Deshabilitada en el mbedTLS de Arduino-ESP32 |
| Keccak-256 | **Propia** | mbedTLS 2.28 no trae SHA-3; padding `0x01`, no `0x06` |
| Base58Check | **Propia** | No existe en mbedTLS |

Regla: **no inventar criptografía**. Lo propio sólo procesa **datos públicos**
(hashes de claves públicas) y se valida con vectores + verificación cruzada.

---

## 10. Interfaz y flujo de la wallet

```
BOOT ─► IDLE ─[GENERAR]─► GENERATING ─► BACKUP_WARNING ─[MOSTRAR]─► SHOW_MNEMONIC
         ▲                    │ error                                   │ [YA LAS ANOTE]
         │                    ▼                                         ▼
         └──[VOLVER]──── ERROR          [TERMINAR] ◄── SHOW_BTC ◄──► SHOW_ETH
```

- IDLE muestra la lectura del LDR en vivo ("pasá la mano sobre el sensor").
- **Advertencia obligatoria** antes de mostrar las 24 palabras.
- El mnemonic se **borra de la RAM** al salir de su pantalla.
- El QR transporta **sólo direcciones públicas**; nada se guarda en flash.

---

## 11. Gestión de secretos en memoria

```cpp
inline void secureMemzero(void* ptr, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) *p++ = 0;                              // stores observables
    __asm__ __volatile__("" : : "r"(ptr) : "memory");    // barrera para GCC/LTO
}
```

- Un `memset` antes de salir de una función es un *dead store*: el optimizador lo elimina.
- Patrón *fail-closed*: si una función falla, su salida queda en cero.
- Vida de cada secreto: entropía → seed → master key → claves BIP-44, cada una
  borrada apenas se obtiene la siguiente. Ventana más larga: el mnemonic en pantalla.

---

## 12. Verificación

| Capa | Herramienta | Resultado |
|---|---|---|
| Unitaria | 49 tests Unity en 6 suites | Compilan; ejecución en placa pendiente |
| Cruzada | `verify_cross.py`: Python independiente (RIPEMD, Keccak, secp256k1 desde la spec) | **172 PASS · 0 FAIL** |
| Literal | Cada valor esperado figura textual en `tests/*.cpp` | 123 literales |
| Estadística | `analyze_entropy.py` (SP 800-90B) | Ver diapositiva 6 |

**Hallazgo real:** la verificación cruzada encontró un vector NIST de SHA-256
**mal transcripto** en nuestros propios tests. Sin la implementación
independiente, ese test habría fallado contra un SHA-256 correcto.

Referencia: `abandon … about` → `1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA` /
`0x9858EfFD232B4033E47d90003D41EC34EcaEda94`

---

## 13. Modelo de amenazas

| Amenaza | Estado |
|---|---|
| Exfiltración por red | **Eliminada** (sin radio) |
| Fuga por logs serie | Mitigada (sin secretos; PRODUCTION sin debug) |
| Manipulación del LDR | Mitigada (crédito 0 + hash + orden de muestreo) |
| RNG predecible | Parcial (SAR ADC activado; sin health tests en línea) |
| Volcado de flash | Sin secretos en flash; pero el firmware es reemplazable |
| Volcado de RAM / JTAG | **No mitigada** |
| Canal lateral (DPA/EM) | Parcial (blinding de mbedTLS, determinístico) |
| Glitching | **No mitigada** |

---

## 14. Limitaciones (lo que **no** es)

- **No es una hardware wallet auditada.** No usar con fondos reales.
- Sin **Secure Element**, sin **Secure Boot** ni flash encryption: con USB se reemplaza el firmware.
- Sin PIN, sin recuperación desde mnemonic, sin firma de transacciones.
- El ruido crudo del RNG del ESP32-S3 **no es accesible** → no se puede evaluar formalmente.
- El análisis del LDR usa datos **simulados** hasta capturar muestras reales.

### Qué haría un producto comercial

Secure Element certificado (EAL5+/6+) · TRNG con health tests AIS-31 / SP 800-90B ·
Secure Boot + eFuses JTAG deshabilitados · `libsecp256k1` constante en tiempo ·
PIN con borrado · entropía del usuario (dados) · builds reproducibles.

---

## 15. Conclusiones

1. La seguridad de una wallet se decide en **la generación de la entropía**; el resto es
   matemática determinística y verificable.
2. **Medir antes de acreditar:** el LDR parece aleatorio (Shannon 6.37) pero un atacante
   lo reduce a 0.30 bits. Por eso no se le acredita entropía.
3. **Los tests estadísticos no prueban aleatoriedad**; sólo el diseño de la fuente lo hace.
4. La **verificación independiente** encuentra errores que los tests solos no ven.
5. Un prototipo honesto documenta sus límites: el camino a producto es hardware seguro.

---

<!-- _class: lead -->

# Demo y preguntas

Generar wallet → advertencia → 24 palabras → BTC → ETH → QR

Repositorio: `README.md` · `docs/SECURITY.md` · `tools/`

**Gracias**
