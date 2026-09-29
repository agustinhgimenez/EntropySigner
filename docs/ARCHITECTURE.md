# EntropySigner — Architecture

> Educational Hardware Wallet Prototype · Paso 0 — Arquitectura

Diagrama general: [`assets/architecture.svg`](../assets/architecture.svg)

---

## 1. Visión general

EntropySigner es un dispositivo **offline** (air-gapped por diseño): genera una
semilla, deriva claves y muestra **sólo información pública** (direcciones y QR).
Los secretos nunca salen del dispositivo.

```
                 LDR
                  │
                  ▼
                 ADC
                  │
                  ├──────────────┐
                  │              │
                  ▼              ▼
             LDR DATA       ESP32 RNG
                  │              │
                  └──────┬───────┘
                         ▼
               SHA-256 (conditioning)
                         │
                         ▼
                 256 bits de entropía
                         │
                         ▼
          BIP-39: SHA-256 → checksum 8 bits
                         │
                         ▼
          264 bits → 24 × 11 bits → 24 palabras
                         │
                         ▼
        PBKDF2-HMAC-SHA512 (2048 iter.) → seed 512 bits
                         │
                         ▼
          BIP-32: master key + chain code
                         │
                         ▼
                    BIP-44
               ┌─────────┴─────────┐
      m/44'/0'/0'/0/0      m/44'/60'/0'/0/0
          Bitcoin               Ethereum
               │                   │
               ▼                   ▼
        dirección + QR      dirección + QR
               └─────────┬─────────┘
                         ▼
                  DISPLAY + TOUCH
                         │
                        USER
```

### Principio de seguridad fundamental

- La **fuente criptográfica principal** es el **RNG de hardware del ESP32**.
- El **LDR** es una fuente física **adicional** de variabilidad. **No** se afirma que aporte 256 bits.
- **SHA-256 no crea entropía.** Un hash acondiciona los datos (mezcla, uniformiza,
  oculta estructura), pero la entropía de la salida está acotada por la entropía
  real de la entrada: \(H_{out} \le \min(256,\ H_{LDR} + H_{RNG})\).
- Combinar con hash tiene una propiedad útil: si **una** de las fuentes es buena
  y la otra es mala (pero no controlada adversarialmente con conocimiento de la
  otra), la salida sigue siendo impredecible. El LDR nunca puede *empeorar* un
  RNG bueno; en el mejor caso agrega defensa en profundidad.

---

## 2. Decisión de framework

| Opción | Evaluación |
|---|---|
| **PlatformIO + Arduino (ESP32 core)** | ✅ **Elegida.** Build reproducible (`platformio.ini`), gestión de librerías con versiones fijas, tests unitarios integrados (Unity) tanto en **host (`native`)** como en **dispositivo**, y acceso igualmente a las APIs de ESP-IDF (`esp_random`, `esp_adc`, mbedTLS). |
| ESP-IDF puro | Control total, pero mayor complejidad; no hay una razón técnica fuerte que lo exija. Arduino-ESP32 está construido sobre ESP-IDF, así que las APIs críticas siguen disponibles. |
| Arduino IDE | Sin builds reproducibles ni tests: descartado. |

La versión exacta de la plataforma `espressif32` y del core Arduino se fijará en
`platformio.ini` en el Paso 1 y se documentará aquí.

---

## 3. Capas del firmware

```
┌──────────────────────────────────────────────────────────────┐
│  ui/          Pantallas, componentes, navegación táctil      │
├──────────────────────────────────────────────────────────────┤
│  wallet (app) Orquestación: crear wallet, backup, mostrar    │
│               direcciones. Modo DEMO / PRODUCTION            │
├───────────────┬───────────────┬──────────────┬───────────────┤
│  bitcoin/     │  ethereum/    │  qr/         │  security/    │
│  P2WPKH bech32│  Keccak-256   │  encoder QR  │  memzero,     │
│               │  EIP-55       │  (sólo datos │  modos, logs  │
│               │               │   públicos)  │               │
├───────────────┴───────────────┴──────────────┴───────────────┤
│  bip32/  (HD keys, secp256k1)      bip39/ (mnemonic, seed)   │
├──────────────────────────────────────────────────────────────┤
│  crypto/   SHA-256, HMAC-SHA512, PBKDF2, RIPEMD-160, Keccak  │
│            (bibliotecas confiables: mbedTLS, etc.)           │
├──────────────────────────────────────────────────────────────┤
│  entropy/  ldr_source · hw_rng · entropy_pool (conditioning) │
├──────────────────────────────────────────────────────────────┤
│  hal/config  board_config.h (pines), drivers display/touch   │
├──────────────────────────────────────────────────────────────┤
│  Arduino-ESP32 core  ·  ESP-IDF  ·  FreeRTOS  ·  mbedTLS     │
└──────────────────────────────────────────────────────────────┘
```

Reglas de dependencia:

- Las capas sólo dependen de capas **inferiores**.
- `crypto/`, `bip39/`, `bip32/`, `bitcoin/`, `ethereum/` **no dependen de Arduino**:
  son C/C++ puro para poder testearlos en la PC (`pio test -e native`) contra
  vectores oficiales.
- `ui/` nunca recibe claves privadas ni seed: sólo direcciones públicas y, en el
  flujo de backup, las palabras (con advertencia).

### Módulos previstos

| Directorio | Responsabilidad | Paso |
|---|---|---|
| `src/main.cpp` | Arranque, inicialización, loop | 1 |
| `src/config/` | `board_config.h` (pines), `build_config.h` (modo) | 1 |
| `src/ui/` | Driver gráfico, pantallas, botones, navegación | 2–3, 15 |
| `src/entropy/` | LDR (ADC), RNG de hardware, pool/conditioning | 4–6 |
| `src/crypto/` | Wrappers sobre SHA-256, HMAC, PBKDF2, RIPEMD-160, Keccak-256 | 7, 10 |
| `src/bip39/` | Wordlist oficial, entropy → mnemonic, validación, seed | 8–10 |
| `src/bip32/` | Master key, derivación hardened/normal, secp256k1 | 11 |
| `src/bitcoin/` | BIP-44 `m/44'/0'/0'/0/0`, dirección | 12 |
| `src/ethereum/` | BIP-44 `m/44'/60'/0'/0/0`, Keccak-256, EIP-55 | 13 |
| `src/qr/` | Generación y render de QR | 14 |
| `src/security/` | Borrado seguro de memoria, modos, política de logs | 1, 19 |
| `tests/` | Unity: `native` (host) y `esp32s3` (dispositivo) | 5+ |
| `tools/entropy_analysis/` | Captura y análisis de muestras LDR (Python) | 4, 17 |
| `tools/verification/` | Verificación cruzada con implementaciones independientes (Python) | 8+ |
| `firmware/esp32/` | Tabla de particiones, defaults de configuración, scripts de flasheo | 1+ |

> Nota de estructura: PlatformIO usa `src/` en la raíz como fuente del firmware,
> por eso el código vive en `src/` y `firmware/esp32/` queda para artefactos
> específicos de la placa. Los tests viven en `tests/` (se configurará
> `test_dir = tests` en `platformio.ini`).

---

## 4. Bibliotecas (a confirmar en cada paso)

Regla: **no implementar criptografía desde cero** si existe una biblioteca
confiable; documentar biblioteca y versión.

| Función | Candidata principal | Alternativa | Paso |
|---|---|---|---|
| Gráficos display | LovyanGFX (soporta ST7796 + FT6336) | TFT_eSPI | 2 |
| UI de alto nivel | Propia sobre LovyanGFX | LVGL | 2, 15 |
| SHA-256 / HMAC / PBKDF2 | **mbedTLS** (incluida en ESP-IDF, con aceleración HW) | — | 7, 10 |
| secp256k1 | libsecp256k1 (bitcoin-core) | trezor-crypto | 11 |
| RIPEMD-160 | trezor-crypto / mbedTLS (si está habilitado) | — | 12 |
| Keccak-256 | trezor-crypto (`sha3.c` con `keccak_256`) | — | 13 |
| QR | `ricmoo/QRCode` | Nayuki QR-Code-generator | 14 |
| Verificación en PC | `mnemonic` (Trezor), `bip_utils` | `embit` | 8+ |

---

## 5. Modos de operación

Seleccionados en **tiempo de compilación** (dos entornos de PlatformIO), para que
el código de depuración directamente **no exista** en el binario de producción.

| | DEMO (`-D ES_MODE_DEMO`) | PRODUCTION (`-D ES_MODE_PRODUCTION`) |
|---|---|---|
| Banner en pantalla | **"DEMO MODE"** visible siempre | — |
| Mnemonic / claves de prueba | Permitidos (vectores públicos) | No |
| Secretos por Serial | Permitido para depurar | **Nunca** |
| Logs | Verbosos | Mínimos |
| WiFi / Bluetooth | Deshabilitados | **Deshabilitados** |
| Persistencia de secretos | No | No |

---

## 6. Modelo de amenazas (preliminar)

| Amenaza | Mitigación prevista |
|---|---|
| Baja entropía / RNG predecible | RNG HW como fuente principal + LDR adicional + conditioning; health tests básicos (Paso 17/19) |
| Correlación / predicción del LDR | No se le atribuye entropía completa; análisis estadístico (Paso 17) |
| Filtración de mnemonic por Serial/red | Modo PRODUCTION sin logs sensibles; radio deshabilitada |
| Secretos persistidos en flash | No se guardan; se regeneran/ingresan en cada sesión |
| Secretos residuales en RAM | Borrado explícito de buffers (`mbedtls_platform_zeroize`) |
| Foto / observación del backup | Advertencia en pantalla antes de mostrar las 24 palabras |
| Ataques físicos (side-channel, glitching, lectura de flash) | **Fuera de alcance** — documentado como limitación |

EntropySigner **no es una hardware wallet auditada** ni comercial. Es un
prototipo académico.

---

## 7. Estrategia de testing

1. **Host (`native`)**: módulos criptográficos puros contra vectores oficiales
   (SHA-256 "abc", vectores BIP-39 de Trezor, BIP-32 test vectors 1–3, etc.).
2. **Dispositivo (`esp32s3`)**: RNG, ADC, integración con aceleradores HW.
3. **Verificación cruzada** con scripts Python en `tools/verification/`.
4. **Propiedades**: cambiar 1 bit de entropía / 1 palabra cambia el resultado.
