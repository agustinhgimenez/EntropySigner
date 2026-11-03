# EntropySigner — Hardware

> Educational Hardware Wallet Prototype · Paso 0 — Hardware analysis

Este documento registra el **hardware detectado**, el **hardware propuesto**, las
**conexiones** y las **alternativas evaluadas** para EntropySigner.

---

## 1. Estado actual (inspección del Paso 0)

Inspección realizada el 2026-09-28 sobre el workspace y la PC de desarrollo:

| Ítem | Resultado | Observación |
|---|---|---|
| Código existente | **Ninguno** | Directorio vacío, sin `.git` |
| Framework | **No definido** | Sin `platformio.ini`, `CMakeLists.txt` ni `.ino` |
| ESP32 conectado | **No detectado** | Sólo COM1 / LPT1 de la placa madre; ningún CP210x / CH340 / USB-JTAG de Espressif |
| Display | **No definido** | — |
| Touchscreen | **No definido** | — |
| Git | Instalado (2.55) | — |
| Python | Instalado (3.13.7) | Útil para `tools/` y para instalar PlatformIO Core |
| PlatformIO | **No instalado** | Requerido desde el Paso 1 |
| Arduino CLI / ESP-IDF / esptool | **No instalados** | No son necesarios si se usa PlatformIO |

**Conclusión:** no existe hardware definido. Se propone una plataforma y se deja
el firmware preparado para que el modelo exacto de pantalla pueda confirmarse
antes del Paso 2 sin rehacer la arquitectura.

### ⚠️ Advertencia sobre la ubicación del proyecto

El proyecto está en una **ruta de red UNC con espacios**:

```
\\Criptoaprendices\d\Facultad\2026\CURSANDO 2026\2DO SEMESTRE\Criptografia y Seguridad\EntropySigner
```

Las toolchains de ESP32 en Windows tienen problemas conocidos con:

- rutas UNC (`cmd.exe` no acepta UNC como directorio de trabajo);
- rutas largas (límite de 260 caracteres en builds con muchos objetos);
- espacios en la ruta (algunos scripts de la toolchain).

**Recomendación:** antes del Paso 1, clonar/trabajar el repositorio en una ruta
local corta, por ejemplo `C:\dev\EntropySigner` (o mapear la unidad de red a una
letra, p. ej. `D:`), y usar Git para sincronizar.

---

## 2. Hardware propuesto

### 2.1 Microcontrolador — ESP32-S3

**Recomendado:** placa **ESP32-S3-DevKitC-1** (módulo ESP32-S3-WROOM-1 **N16R8**:
16 MB flash, 8 MB PSRAM octal) o clon equivalente.

| Criterio | ESP32 clásico (WROOM-32) | **ESP32-S3** |
|---|---|---|
| CPU | 2× Xtensa LX6 240 MHz | 2× Xtensa **LX7** 240 MHz |
| SRAM / PSRAM | 520 KB / opcional | 512 KB / **hasta 8 MB octal** |
| USB nativo | No (requiere puente USB-UART) | **Sí** (USB-Serial/JTAG) |
| Aceleradores | SHA, AES, RSA | SHA, AES, RSA, HMAC, Digital Signature |
| Soporte ADC | ADC1 + ADC2 (ADC2 ocupado con WiFi) | ADC1 (GPIO1–10) + ADC2 |
| Framebuffer para UI | Justo | **Holgado** (PSRAM) |

Motivos de la elección:

1. **PSRAM**: permite UI con buffers de pantalla completos (LVGL/LovyanGFX) y QR grandes.
2. **USB nativo**: flasheo y monitor serie sin chip puente; también depuración JTAG.
3. **Hardware RNG** documentado por Espressif (`esp_random()` / `esp_fill_random()`).
4. **Aceleración SHA** por hardware, usada por mbedTLS de ESP-IDF.
5. Amplio soporte en PlatformIO + Arduino.

### 2.2 Display + touchscreen

Requisitos para una hardware wallet:

- color, **IPS** (buen ángulo de visión, lectura de las 24 palabras);
- **≥ 320 px** en el lado corto (QR escaneable de direcciones);
- 2.8"–4";
- **touch capacitivo** preferido (sin calibración, más preciso);
- interfaz **SPI** para display e **I²C** para touch (pocos pines, cableado en protoboard).

**Recomendado:** módulo **3.5"–4.0" IPS, controlador ST7796S, 320×480, SPI, con touch
capacitivo FT6336U (I²C)**.

| Parámetro | Valor |
|---|---|
| Tamaño | 3.5"–4.0" |
| Panel | TFT IPS |
| Controlador display | ST7796S |
| Resolución | 320 × 480 (RGB565) |
| Interfaz display | SPI (4 hilos + DC) |
| Controlador touch | FT6336U (capacitivo, I²C, dirección típica 0x38) |
| Alimentación | 3.3 V lógica (verificar si el módulo acepta 5 V en VCC por regulador propio) |

> ⚠️ **Verificar con la hoja de datos del vendedor** antes de comprar: existen
> módulos ST7796 con touch **resistivo** (XPT2046) y otros con **capacitivo**
> (FT6336U). El firmware soportará ambos mediante una capa de configuración de
> placa, pero se prefiere capacitivo.

**¿Por qué 320×480 alcanza para el QR?** Una dirección Bitcoin bech32 (42 caracteres)
en modo alfanumérico entra en un QR versión 2–3 (25–29 módulos por lado). Con
8 px por módulo + margen (quiet zone) ocupa ≈ 264 px, dentro de los 320 px de ancho.
Una dirección Ethereum (42 caracteres) es similar.

### 2.3 Fuente de entropía — RNG de hardware interno

La única fuente de entropía es el **RNG de hardware del propio ESP32**: no hace
falta ningún componente externo.

Según la documentación de ESP-IDF, el RNG produce números verdaderamente
aleatorios cuando el RF (WiFi/BT) está activo **o** cuando se habilita la fuente
de entropía interna con `bootloader_random_enable()`, que usa el ruido térmico
del **SAR ADC**. Como el firmware nunca enciende WiFi ni Bluetooth, usa la
segunda opción. Mientras esa fuente está habilitada **no debe usarse el ADC**
con el driver normal (`analogRead()`); el firmware no usa el ADC para nada más.

### 2.4 Alimentación

| Rail | Fuente | Consumidores |
|---|---|---|
| 5 V | USB-C de la DevKit (PC o power bank) | Regulador de la placa; VCC del display si el módulo lo admite |
| 3.3 V | LDO de la DevKit (≈ 500–800 mA según modelo) | ESP32-S3, lógica del display, touch |

Consumo estimado: ESP32-S3 sin radio ≈ 40–80 mA + backlight ≈ 40–100 mA →
**< 250 mA**, dentro de lo que entrega un puerto USB 2.0 (500 mA).

Se usa **USB sólo como alimentación y consola de desarrollo**. En modo producción
no se transmiten secretos por Serial, WiFi ni Bluetooth.

---

## 3. Conexiones

Diagrama: [`assets/circuit.svg`](../assets/circuit.svg)

Pines elegidos para ESP32-S3-DevKitC-1 evitando:
strapping (GPIO0, 3, 45, 46), USB (GPIO19, 20), flash/PSRAM octal (GPIO26–37).

### 3.1 Display ST7796S (SPI2 / FSPI)

| Señal módulo | ESP32-S3 | Notas |
|---|---|---|
| VCC | 3V3 (o 5V según módulo) | Verificar hoja de datos |
| GND | GND | |
| SCK / SCL | **GPIO12** | FSPI CLK |
| SDI / MOSI | **GPIO11** | FSPI MOSI |
| SDO / MISO | **GPIO13** | Opcional (lectura del display) |
| CS | **GPIO10** | |
| DC / RS | **GPIO9** | Data/Command |
| RST | **GPIO8** | |
| LED / BL | **GPIO7** | PWM (LEDC) para brillo |

### 3.2 Touch FT6336U (I²C)

| Señal módulo | ESP32-S3 | Notas |
|---|---|---|
| CTP_SDA | **GPIO15** | Pull-up 4.7 kΩ si el módulo no los trae |
| CTP_SCL | **GPIO16** | |
| CTP_INT | **GPIO17** | Interrupción de toque |
| CTP_RST | **GPIO18** | |

### 3.3 Resumen de pines

| GPIO | Función |
|---|---|
| 7 | Backlight PWM |
| 8 | Display RST |
| 9 | Display DC |
| 10 | Display CS |
| 11 | SPI MOSI |
| 12 | SPI SCLK |
| 13 | SPI MISO |
| 15 | I²C SDA (touch) |
| 16 | I²C SCL (touch) |
| 17 | Touch INT |
| 18 | Touch RST |

Estos pines se centralizarán en `src/config/board_config.h` (Paso 1) para poder
cambiar de placa sin tocar el resto del firmware.

---

## 4. Lista de materiales (BOM)

| # | Componente | Cant. | Estado |
|---|---|---|---|
| 1 | ESP32-S3-DevKitC-1 N16R8 (o N8R8) | 1 | **Necesario** |
| 2 | Display 3.5"–4.0" IPS ST7796S 320×480 SPI + touch capacitivo FT6336U | 1 | **Necesario** |
| 3 | Resistencias 4.7 kΩ (pull-up I²C) | 2 | Opcional |
| 4 | Protoboard 830 puntos | 1 | **Necesario** |
| 5 | Cables Dupont macho-macho / macho-hembra | ~30 | **Necesario** |
| 6 | Cable USB-C **de datos** | 1 | **Necesario** |
| 7 | Carcasa impresa 3D | 1 | Opcional (`hardware/enclosure/`) |

---

## 5. Alternativas evaluadas

| Opción | Pros | Contras | Veredicto |
|---|---|---|---|
| **ESP32-S3 DevKit + ST7796S 3.5–4" IPS + FT6336U** | IPS, 320×480, touch capacitivo, PSRAM, modular | Más cableado | ✅ **Recomendada** |
| ESP32-S3 DevKit + ILI9488 3.5" + XPT2046 | Muy común y barato | Suele ser TN; ILI9488 por SPI usa 18 bits/píxel (lento); touch resistivo | Aceptable |
| ESP32-S3 DevKit + ILI9341 / ST7789 2.8" 240×320 | Barato, rápido | QR y texto más ajustados | Aceptable |
| Placa integrada ESP32-S3 + pantalla táctil (p. ej. Waveshare ESP32-S3-Touch-LCD-3.5, Makerfabs ESP32-S3 Parallel TFT) | Sin cableado, prolija | Pinout fijo; verificar modelo exacto | Buena alternativa |
| "Cheap Yellow Display" ESP32-2432S028R | Todo en uno, barato | ESP32 clásico sin PSRAM, 2.8" TN 240×320, touch resistivo | Sólo para pruebas |
| ESP-IDF puro en vez de Arduino | Control total, APIs oficiales | Curva de aprendizaje mayor | No por ahora (ver `ARCHITECTURE.md`) |

---

## 6. Qué falta

1. **Comprar/confirmar** ESP32-S3 y el módulo de pantalla exacto (enviar link o
   modelo para validar controlador y tipo de touch).
2. Conseguir protoboard, cables Dupont y cable USB-C de datos.
3. Instalar **PlatformIO** (extensión o PlatformIO Core vía `pip`).
4. Mover el proyecto a una **ruta local corta** (ver advertencia arriba).
