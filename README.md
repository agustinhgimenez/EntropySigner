<p align="center">
  <img src="assets/logo.svg" alt="EntropySigner" width="620">
</p>

# 🔐 EntropySigner

## ESP32 Educational Hardware Wallet

> **Open-source ESP32 hardware wallet prototype exploring physical entropy, hardware random generation, BIP-39 and hierarchical wallet derivation.**

**Descripción académica:** Diseño e implementación de un prototipo de Hardware
Wallet basado en ESP32 para el estudio de generación de entropía, BIP-39,
derivación jerárquica de claves y gestión de direcciones para Bitcoin y Ethereum.

> ⚠️ **Educational Hardware Wallet Prototype.** EntropySigner no es una
> hardware wallet comercial ni auditada. **No usar con fondos reales.**
> Inspiración conceptual: proyectos open-source como SeedSigner; la
> implementación, el diseño y la identidad de EntropySigner son propios.

---

## Features

| Feature | Descripción | Estado |
|---|---|---|
| ESP32 | ESP32-S3 con PSRAM y USB nativo | Propuesto |
| Physical entropy | LDR leído por ADC1 como fuente adicional | Pendiente |
| Hardware RNG | RNG de hardware del ESP32 como fuente principal | Pendiente |
| SHA-256 | Acondicionamiento de entropía y checksum BIP-39 | Pendiente |
| BIP-39 | Mnemonic de 24 palabras + validación + seed | Pendiente |
| BIP-32 | Derivación jerárquica de claves | Pendiente |
| BIP-44 | Rutas estándar multi-moneda | Pendiente |
| ₿ Bitcoin | `m/44'/0'/0'/0/0` | Pendiente |
| Ξ Ethereum | `m/44'/60'/0'/0/0` + Keccak-256 | Pendiente |
| Touch UI | Pantalla IPS táctil con navegación | Pendiente |
| QR codes | Sólo direcciones públicas de recepción | Pendiente |
| Entropy analysis | Herramientas Python, metodología NIST SP 800-90B | Pendiente |

---

## Architecture

<p align="center">
  <img src="assets/architecture.svg" alt="EntropySigner architecture" width="560">
</p>

```
LDR --> ADC --> LDR DATA --+
                           +--> SHA-256 (conditioning) --> 256 bits
        ESP32 HW RNG ------+

256 bits --> SHA-256 --> 8-bit checksum --> 264 bits --> 24 x 11 bits --> 24 words

24 words --> PBKDF2-HMAC-SHA512 (2048) --> 512-bit seed --> BIP-32 --> BIP-44
                                                                        |
                          +---------------------------------------------+
                          |                                             |
                 Bitcoin m/44'/0'/0'/0/0                    Ethereum m/44'/60'/0'/0/0
                          |                                             |
                   address --> QR                                address --> QR
```

**Principio de seguridad:** la fuente criptográfica principal es el **RNG de
hardware del ESP32**. El **LDR es una fuente física adicional** de variabilidad;
no se afirma que aporte 256 bits. **SHA-256 no crea entropía**: acondiciona los
datos y oculta estructura, pero no puede convertir una fuente pobre en una rica.

Detalle: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

---

## Hardware

| Componente | Propuesta |
|---|---|
| MCU | ESP32-S3-DevKitC-1 (N16R8) |
| Display | 3.5"–4.0" IPS · ST7796S · 320×480 · SPI |
| Touch | Capacitivo FT6336U · I²C |
| Entropía física | LDR GL5528 + 10 kΩ (divisor) → GPIO1 / ADC1_CH0 |
| Alimentación | USB-C 5 V → LDO 3.3 V |

<p align="center">
  <img src="assets/circuit.svg" alt="EntropySigner wiring" width="720">
</p>

Detalle, pinout, BOM y alternativas: [`docs/HARDWARE.md`](docs/HARDWARE.md)

---

## Project Status

- [x] Paso 0 — Hardware analysis
- [ ] Paso 1 — Project foundation
- [ ] Paso 2 — Display
- [ ] Paso 3 — Touchscreen
- [ ] Paso 4 — LDR
- [ ] Paso 5 — Hardware RNG
- [ ] Paso 6 — Entropy conditioning
- [ ] Paso 7 — SHA-256
- [ ] Paso 8 — BIP-39
- [ ] Paso 9 — Mnemonic validation
- [ ] Paso 10 — PBKDF2
- [ ] Paso 11 — BIP-32
- [ ] Paso 12 — Bitcoin
- [ ] Paso 13 — Ethereum
- [ ] Paso 14 — QR
- [ ] Paso 15 — Wallet UI
- [ ] Paso 16 — Seed backup
- [ ] Paso 17 — Entropy analysis
- [ ] Paso 18 — Cryptographic tests
- [ ] Paso 19 — Security hardening
- [ ] Paso 20 — Final documentation
- [ ] Paso 21 — Presentation

### Criterios de finalización

- [ ] Hardware documentado *(propuesto; falta confirmar el hardware comprado)*
- [ ] ESP32 funcionando
- [ ] Display funcionando
- [ ] Touch funcionando
- [ ] LDR funcionando
- [ ] RNG funcionando
- [ ] Entropy pipeline funcionando
- [ ] SHA-256 validado
- [ ] BIP-39 validado
- [ ] 24 words funcionando
- [ ] Checksum funcionando
- [ ] PBKDF2 funcionando
- [ ] BIP-32 funcionando
- [ ] BIP-44 funcionando
- [ ] Bitcoin funcionando
- [ ] Ethereum funcionando
- [ ] QR funcionando
- [ ] UI funcionando
- [ ] Recovery flow funcionando
- [ ] Entropy analysis funcionando
- [ ] Tests completos
- [ ] Security review
- [ ] README completo
- [ ] Diagramas *(arquitectura y conexiones creados; faltan BIP-39, derivación y sistema completo)*
- [ ] Presentación
- [ ] Guion de exposición
- [ ] Referencias
- [ ] Limitaciones documentadas

---

## Repository structure

```
EntropySigner/
|-- README.md, LICENSE, .gitignore, .editorconfig
|-- platformio.ini              (Paso 1)
|-- firmware/esp32/             particiones, config de placa, scripts de flasheo
|-- src/
|   |-- main.cpp                (Paso 1)
|   |-- config/  entropy/  crypto/  bip39/  bip32/
|   `-- bitcoin/  ethereum/  qr/  ui/  security/
|-- tests/                      Unity (native + esp32s3)
|-- tools/
|   |-- entropy_analysis/       captura y análisis LDR (Python)
|   `-- verification/           verificación cruzada (Python)
|-- docs/                       HARDWARE, ARCHITECTURE, ENTROPY, BIP39, ...
|-- hardware/                   schematic/, pcb/, enclosure/
|-- presentation/               slides, speaker notes, assets
`-- assets/                     logo.svg, architecture.svg, circuit.svg, ...
```

---

## Development Steps (bitácora)

### Paso 0 — Hardware analysis

**Objetivo.** Inspeccionar el proyecto y el entorno, definir hardware y
arquitectura, y crear la estructura inicial del repositorio. Sin código de wallet.

**Implementación.**

- Inspección del workspace: vacío, sin código, sin Git, sin framework.
- Inspección del entorno: Git 2.55 y Python 3.13.7 instalados; **PlatformIO no
  instalado**; **ningún ESP32 conectado** por USB.
- Hardware propuesto: ESP32-S3-DevKitC-1 + display IPS ST7796S 320×480 SPI con
  touch capacitivo FT6336U + LDR GL5528 con divisor de 10 kΩ en GPIO1 (ADC1).
- Framework elegido: **PlatformIO + Arduino (ESP32)**, con acceso a las APIs de ESP-IDF.
- Arquitectura en capas; los módulos criptográficos serán independientes de
  Arduino para poder testearlos en la PC contra vectores oficiales.
- Hallazgo de diseño: en ESP32-S3 la fuente de entropía interna del RNG (sin
  radio) usa el SAR ADC, así que el muestreo del LDR y la lectura del RNG deben
  **secuenciarse** (se valida en el Paso 5).
- Hallazgo de entorno: el proyecto está en una **ruta UNC de red con espacios**;
  la terminal no responde de forma confiable en esa ruta y el editor guardó
  algunos archivos en Windows-1252. Se recomienda trabajar en una ruta local
  corta (p. ej. `C:\dev\EntropySigner`). Se agregó `.editorconfig` (UTF-8, LF).
- Identidad visual inicial (logo) y diagramas de arquitectura y de conexiones.

**Archivos creados.**

`README.md`, `LICENSE`, `.gitignore`, `.editorconfig`, `docs/HARDWARE.md`,
`docs/ARCHITECTURE.md`, `assets/logo.svg`, `assets/architecture.svg`,
`assets/circuit.svg`, y `.gitkeep` en las carpetas de la estructura.

**Cómo probar.**

1. Abrir los SVG de `assets/` en el navegador y verificar que se renderizan.
2. Revisar `docs/HARDWARE.md` y confirmar/ajustar el hardware a comprar.
3. Preparar el entorno para el Paso 1:
   ```powershell
   python -m pip install --user platformio
   python -m platformio --version
   ```
4. Conectar la ESP32-S3 con un cable USB-C **de datos** y verificar que aparezca
   un puerto COM (“USB JTAG/serial debug unit” o CP210x/CH34x) en el
   Administrador de dispositivos, o con `python -m platformio device list`.

**Resultado.** Estructura y documentación base creadas. No hay firmware para
compilar ni tests para ejecutar todavía (llegan en el Paso 1). Archivos
verificados como UTF-8 y SVG verificados como XML bien formado.

**Commit.** `docs: add hardware analysis and system architecture`

---

## Installation

*(Paso 1)* Requisitos previstos: PlatformIO Core o la extensión PlatformIO IDE,
Python 3.10+, cable USB-C de datos.

## Security

Principios y modelo de amenazas preliminar en
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). `docs/SECURITY.md` se crea en el Paso 19.

## Limitations

- Prototipo académico, **no auditado**; no usar con fondos reales.
- Sin protección contra ataques físicos (side-channel, glitching, lectura de flash).
- El LDR no se considera fuente criptográfica suficiente por sí mismo.

## Academic Context

Proyecto de la materia **Criptografía y Seguridad** (2026, 2.º semestre).

## License

[MIT](LICENSE)
