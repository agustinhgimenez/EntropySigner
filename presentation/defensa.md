# EntropySigner — Preguntas y Respuestas para la Defensa Oral

> Banco de preguntas esperadas del tribunal académico (Materia Criptografía y Seguridad)
> con respuestas concisas, fundamentos matemáticos y referencias directas al código.

---

### P1: ¿Por qué no confiar en el LDR como fuente principal de entropía?
**R:** Un fotorresistor (LDR) mide la luz ambiental incidente, que es un proceso físico macroscópico, lento y predecible. Bajo luz diurna o artificial, la señal está dominada por componentes de baja frecuencia (incluyendo el rizado de 100 Hz de la red de 50 Hz). Además:
1. Es **manipulable externamente**: un atacante con una linterna o cubriendo el sensor satura el ADC a 4095 o 0, reduciendo la entropía a casi cero (demostrado en `tools/entropy_analysis/analyze_entropy.py --synthetic ldr-attack`).
2. No cumple el requisito de la norma **NIST SP 800-90B (§3.2.2)** de contar con un modelo estocástico riguroso del fenómeno físico.
3. Las muestras están altamente correlacionadas ($\text{autocorrelación} > 0.98$).
Por ello, el firmware le asigna **crédito de entropía 0**. Toda la seguridad descansa en el **TRNG de hardware del ESP32-S3**; el LDR sólo agrega variabilidad complementaria que no puede degradar un RNG sano.

---

### P2: ¿Por qué SHA-256 no puede "crear" entropía?
**R:** Por el principio de conservación de la información y la desigualdad fundamental de Rényi/Shannon: la entropía de la salida de una función determinística está acotada superiormente por la entropía de la entrada:
$$H_{\min}(\text{salida}) \le \min(256, H_{\min}(\text{entrada}))$$
SHA-256 actúa como un **acondicionador/extractor de entropía aprobado por NIST SP 800-90B (§3.1.5.1)**: comprime 2544 bits de entrada con correlación y sesgo en un bloque uniforme e impredecible de 256 bits, destruyendo dependencias estadísticas, pero si la entrada carece de entropía real (ej. un contador predecible), la salida es matemáticamente determinística.

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
esp_fill_random(out, len);
bootloader_random_disable();
```
Y como el SAR ADC se comparte, en `src/entropy/entropy_pool.cpp` secuenciamos estrictamente: primero se leen las muestras del LDR con el ADC libre, y luego se activa el RNG de hardware, evitando cualquier contienda de periféricos.

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
