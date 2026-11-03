# EntropySigner — Preguntas y Respuestas para la Defensa Oral

> Banco de preguntas esperadas del tribunal académico (Materia Criptografía y Seguridad)
> con respuestas concisas, fundamentos matemáticos y referencias directas al código.

---

### P1: ¿Por qué alcanza con una sola fuente de entropía, el RNG del ESP32?
**R:** Porque es una fuente física documentada por el fabricante y la usamos en las condiciones que Espressif exige para que sea verdaderamente aleatoria:
1. El TRM (cap. 18) describe dos fuentes de ruido combinadas por XOR: el **ruido térmico del SAR ADC** y la diferencia de fase entre dos relojes independientes (`RC_FAST_CLK` de 8 MHz y APB de 80 MHz). Espressif lo validó con la batería **Dieharder** sobre 2 GB.
2. Lo leemos con `bootloader_random_enable()` activo (sin radio, es la única forma de que sea TRNG) y esperamos **2 µs entre palabras** para que cada una incorpore ruido nuevo.
3. Pedimos **512 bits para sacar 256**: aunque el RNG entregara sólo la mitad de la entropía nominal, la salida de SHA-256 seguiría teniendo ≈ 255 bits (SP 800-90B §3.1.5.1.2).
Agregar fuentes externas fáciles de manipular (un sensor de luz, por ejemplo) no suma seguridad medible y agrega superficie de ataque y cableado.

---

### P2: ¿Por qué SHA-256 no puede "crear" entropía?
**R:** Por el principio de conservación de la información y la desigualdad fundamental de Rényi/Shannon: la entropía de la salida de una función determinística está acotada superiormente por la entropía de la entrada:
$$H_{\min}(\text{salida}) \le \min(256, H_{\min}(\text{entrada}))$$
SHA-256 actúa como un **acondicionador/extractor de entropía aprobado por NIST SP 800-90B (§3.1.5.1)**: comprime 744 bits de entrada (512 del RNG + un tag fijo) con posible sesgo en un bloque uniforme e impredecible de 256 bits, destruyendo dependencias estadísticas, pero si la entrada carece de entropía real (ej. un contador predecible), la salida es matemáticamente determinística.

---

### P3: ¿Cómo se asegura que el compilador no elimine el borrado de claves privadas en RAM?
**R:** Los compiladores modernos con optimización `-O2` o `-O3` realizan *Dead Store Elimination* (DSE): si una variable local o buffer es sobrescrito con ceros e inmediatamente sale del ámbito, el compilador considera que la escritura no tiene efecto observable y la elimina del binario.
En `src/security/secure_mem.h`, implementamos `secureMemzero` con dos defensas:
1. Puntero `volatile uint8_t*`: obliga al compilador a emitir cada escritura a memoria en el orden exacto.
2. Barrera de compilador inline assembly:
   ```cpp
   __asm__ __volatile__("" : : "r"(ptr) : "memory");
   ```
   Indica a GCC que toda la memoria apuntada pudo haber sido leída o alterada arbitrariamente, impidiendo que el optimizador descarte las escrituras previas o las mueva de lugar durante Link-Time Optimization (LTO).

---

### P4: ¿Por qué se utilizó `secp256k1` y no `Ed25519` (Edwards-curve)?
**R:** Por estricta compatibilidad con los estándares canónicos de las redes objetivo:
- **Bitcoin** (Satoshi Nakamoto) definió `secp256k1` (curva de Koblitz $y^2 = x^3 + 7 \pmod p$) para firmas ECDSA y direcciones BIP-32/BIP-44.
- **Ethereum** utiliza exactamente la misma curva `secp256k1` para sus pares de claves y direcciones derivadas de Keccak-256.
`Ed25519` es una excelente curva moderna (utilizada en Cardano, Solana, Monero), pero incompatible con los estándares nativos de Bitcoin y Ethereum legacy sin esquemas híbridos.

---

### P5: En el ESP32-S3, ¿cómo se garantiza que el RNG de hardware entregue entropía verdadera si el Wi-Fi y Bluetooth están apagados?
**R:** En los chips Espressif ESP32, cuando la radio está encendida, el ruido térmico del receptor RF alimenta el generador analógico de ruido. Si la radio está apagada (nuestro diseño air-gapped), el ESP32-S3 conmuta internamente el SAR ADC para muestrear ruido térmico analógico.
Para asegurar que este muestreo esté encendido, en `src/entropy/hw_rng.cpp` envolvemos cada lectura con:
```cpp
bootloader_random_enable();
// por cada palabra de 32 bits: delayMicroseconds(2); esp_random();
bootloader_random_disable();
```
Mientras esa fuente está activa el ADC no puede usarse para otra cosa (`analogRead()`); el firmware no usa el ADC para nada más, así que no hay contienda de periféricos.

---

### P6: ¿Por qué en Ethereum se usa Keccak-256 y no SHA3-256 de NIST (FIPS 202)?
**R:** Cuando el equipo de Ethereum (Vitalik Buterin, Gavin Wood) adoptó la función hash para Ethereum en 2014-2015, el estándar FIPS 202 de NIST aún no estaba finalizado. Posteriormente, NIST modificó el byte de relleno (*domain separation padding*) de `0x01` a `0x06` al estandarizar SHA3-256.
Ethereum mantuvo el Keccak-256 original con padding `0x01` para no romper la compatibilidad con todas las direcciones y contratos ya desplegados. Nuestra implementación en `src/crypto/keccak256.cpp` implementa fielmente Keccak-256 con padding `0x01` verificado con los vectores oficiales de la Ethereum Foundation.

---

### P7: ¿Qué protege el dispositivo y cuáles son sus limitaciones frente a un producto comercial?
**R:** 
**Lo que sí protege:**
- Dispositivo 100% offline (air-gapped): cero código de radio, cero conexión física con hosts para transferencia de secretos.
- Cero almacenamiento persistente: ningún secreto toca memoria Flash ni EEPROM; se regeneran o se ingresan en RAM en cada sesión.
- Ceroizado sistemático: claves privadas y semillas se borran apenas se obtienen las direcciones públicas o se confirma el respaldo.

**Limitaciones académicas (para no usar con fondos reales):**
- Sin *Secure Element* (ATECC608A o ST33): vulnerable a lectura física de RAM o glitching de voltaje si un atacante obtiene posesión física del ESP32.
- Sin *Secure Boot* ni *Flash Encryption* activos: cualquier persona con cable USB conectado al puerto de flasheo podría reemplazar el firmware.
- Sin defensas avanzadas contra análisis de consumo o canal lateral (DPA/SPA) en las operaciones de curva elíptica.
