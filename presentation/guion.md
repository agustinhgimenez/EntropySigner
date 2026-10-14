# EntropySigner — Guion de exposición

> Duración objetivo: **20 minutos** de exposición + demo, y luego preguntas.
> Diapositivas: [`slides.md`](slides.md). Preguntas de la defensa: [`defensa.md`](defensa.md).

## Reparto de tiempo

| # | Diapositiva | Tiempo | Acumulado |
|---|---|---|---|
| 0 | Portada | 0:30 | 0:30 |
| 1 | El problema | 1:30 | 2:00 |
| 2 | Objetivos | 1:00 | 3:00 |
| 3 | Hardware | 1:00 | 4:00 |
| 4 | Arquitectura | 1:00 | 5:00 |
| 5 | Entropía: principio central | 2:00 | 7:00 |
| 6 | SP 800-90B | 2:00 | 9:00 |
| 7 | BIP-39 | 1:30 | 10:30 |
| 8 | BIP-32 / BIP-44 | 2:00 | 12:30 |
| 9 | Implementaciones propias | 1:00 | 13:30 |
| 10 | Interfaz | 0:30 | 14:00 |
| 11 | Secretos en memoria | 1:00 | 15:00 |
| 12 | Verificación | 1:00 | 16:00 |
| 13–14 | Amenazas y limitaciones | 1:30 | 17:30 |
| 15 | Conclusiones | 0:30 | 18:00 |
| 16 | Demo | 2:00 | 20:00 |

Si el tiempo se acorta, recortar 3, 9 y 11 (quedan cubiertos en la defensa).
**No recortar 5, 6 ni 13–14**: son el núcleo criptográfico y la honestidad del trabajo.

---

## 0 · Portada (0:30)

> "EntropySigner es un prototipo educativo de hardware wallet sobre un ESP32-S3.
> El objetivo no fue hacer un producto, sino entender y construir de punta a
> punta cómo nace una clave privada: desde una fuente física de ruido hasta una
> dirección de Bitcoin y de Ethereum."

## 1 · El problema (1:30)

- Idea fuerza: **la wallet es la clave**. No hay recuperación institucional.
- Todo depende de un único número de 256 bits generado una vez.
- Ejemplo Milk Sad: "Libbitcoin Explorer sembraba su generador con 32 bits de
  tiempo. Eso son cuatro mil millones de posibilidades: se recorren en horas.
  Las direcciones eran válidas y se veían aleatorias; simplemente no lo eran."
- Cerrar con la pregunta de la diapositiva.

## 2 · Objetivos (1:00)

- Leer los seis rápido; remarcar el 5 (verificar) y el 6 (documentar límites).
- Aclarar la inspiración en SeedSigner: sólo conceptual.

## 3 · Hardware (1:00)

- Por qué ESP32-S3: aceleradores SHA/AES, RNG de hardware, barato, documentado.
- "La radio existe en el chip, pero el firmware nunca la inicializa." (Volver a
  esto en limitaciones: el air-gap es del firmware, no del hardware.)
- Mencionar los `static_assert` de pines: un error de cableado lógico no compila.

## 4 · Arquitectura (1:00)

- Las capas sólo dependen de capas inferiores.
- Lo criptográfico no depende de Arduino: por eso se puede testear con vectores.
- DEMO vs PRODUCTION: "en producción el código de depuración **no existe** en el
  binario; no es una bandera que se pueda volver a activar".

## 5 · Entropía: principio central (2:00) — diapositiva clave

Explicar en este orden:

1. **Fuente principal = RNG de hardware.** Dato no obvio: según Espressif, sin la
   radio encendida el RNG es pseudoaleatorio. Como no usamos radio, activamos el
   SAR ADC como fuente de ruido con `bootloader_random_enable()`.
2. **LDR = 0 bits acreditados.** "Lo usamos, pero no confiamos en él."
3. **SHA-256 no crea entropía.** Frase para decir textual: *"Un hash no puede
   sacar de la entrada más imprevisibilidad de la que la entrada tiene."*
4. **Orden de muestreo.** LDR primero, RNG después: si el atacante pudiera ver el
   RNG antes de elegir la luz, podría probar variantes y sesgar la salida
   (*grinding*). Así, no puede.

## 6 · SP 800-90B (2:00) — diapositiva clave

- Min-entropía = −log₂ de la probabilidad del valor más probable = "cuánto le
  cuesta al atacante adivinar en el primer intento". Shannon mide el promedio,
  y al atacante no le importa el promedio.
- LDR: 6.37 bits de Shannon frente a 3.16 de min-entropía. Y no es IID: cada
  muestra se parece mucho a la anterior (r₁ = 0.98).
- **Linterna:** cae a 0.30 bits y el health test lo detecta.
- **Golpe final:** `sha256-counter` es un contador hasheado: 0 bits reales y
  pasa todas las métricas. *"Los tests estadísticos sólo pueden rechazar una
  fuente, nunca certificarla."*
- Aclarar que los datos del LDR son **simulados** (todavía no hay muestras de
  la placa) y que se implementan 3 de los 10 estimadores non-IID.

## 7 · BIP-39 (1:30)

- Recorrer el diagrama: 256 + 8 = 264 = 24 × 11.
- El checksum es para errores humanos, **no** es seguridad.
- PBKDF2 con 2048 iteraciones: estiramiento débil, pero irrelevante con 256 bits.
- Decisión propia: no se acepta un mnemonic inválido para derivar el seed.

## 8 · BIP-32 / BIP-44 (2:00)

- Master: HMAC-SHA512 con la clave "Bitcoin seed".
- Una derivación: sumar I_L a la clave padre módulo n.
- Por qué existen los índices *hardened*: explicar el ataque xpub + hijo normal
  en una frase y decir que por eso no se exportan xpubs.
- Bitcoin y Ethereum comparten la semilla y difieren en ruta y codificación.

## 9 · Implementaciones propias (1:00)

- "La regla fue no inventar criptografía." Lo propio aparece sólo donde la
  biblioteca de la plataforma no lo trae, y sólo toca datos públicos.
- Detalle Keccak: Ethereum usa el Keccak original (padding `0x01`), no el
  SHA3-256 estandarizado (`0x06`). Mismo núcleo, distinta salida.

## 10 · Interfaz (0:30)

- Recorrer el diagrama de estados; la demo lo muestra en vivo.

## 11 · Secretos en memoria (1:00)

- El problema del *dead store* en una frase.
- `volatile` + barrera `asm` = la técnica de `explicit_bzero`.
- Admitir el límite: no borra copias en registros ni dentro de mbedTLS.

## 12 · Verificación (1:00)

- Tres capas: tests con vectores oficiales, implementación Python independiente,
  y comprobación de que los valores esperados son literalmente los de los tests.
- **Contar el hallazgo:** "nuestra propia verificación encontró un vector NIST mal
  copiado en nuestros tests". Es la mejor evidencia de que la metodología sirve.
- Ser explícitos: los tests compilan, pero todavía no se ejecutaron en la placa.

## 13–14 · Amenazas y limitaciones (1:30)

- Leer la tabla de abajo hacia arriba: primero lo que **no** se mitiga.
- "Con un cable USB se puede reemplazar el firmware. Eso es más grave que leerlo."
- Cerrar con qué haría un producto real: Secure Element primero.

## 15 · Conclusiones (0:30)

- Leer las cinco; enfatizar la 2 ("medir antes de acreditar") y la 3.

## 16 · Demo (2:00)

---

## Guion de la demo

### Preparación (antes de entrar)

- [ ] Firmware **DEMO** flasheado (`python -m platformio run -e esp32s3-demo -t upload`).
- [ ] Monitor serie abierto (`python -m platformio device monitor`) en una
      ventana visible: muestra los cambios de estado y las direcciones.
- [ ] Teléfono con un lector QR genérico (cámara), **sin** apps de wallet.
- [ ] Linterna del teléfono para mostrar el LDR saturándose.
- [ ] Terminal con el repositorio abierto para el plan B.

### Pasos

1. **Arranque.** Pantalla de boot con el banner **DEMO MODE**. *"Este banner está
   siempre: una wallet de demo no tiene que confundirse con una real."*
2. **IDLE.** Pasar la mano sobre el LDR: el valor cambia. Encender la linterna:
   se satura cerca de 4095. *"Por esto el LDR no cuenta como entropía."*
3. **GENERAR WALLET.** Mostrar el progreso de los seis pasos.
4. **Advertencia.** Leerla en voz alta. Tocar **MOSTRAR**.
5. **24 palabras.** *"En una wallet real, ahora nadie debería estar mirando."*
   Tocar **YA LAS ANOTE** y señalar en el monitor serie que no se imprimió el mnemonic.
6. **Bitcoin.** Escanear el QR con el teléfono: aparece una dirección `1…`.
7. **Ethereum.** Escanear: aparece una dirección `0x…` con mayúsculas y minúsculas (EIP-55).
8. **TERMINAR.** Vuelve a IDLE: la wallet se descartó.

### Plan B (sin placa o si falla el hardware)

```powershell
python tools/verification/verify_cross.py
python tools/entropy_analysis/analyze_entropy.py --synthetic all
```

1. `verify_cross.py`: mostrar el resumen `172 PASS | 0 FAIL` y las líneas
   `direccion BTC m/44'/0'/0'/0/0 (abandon...about)` y `direccion ETH …`.
   El valor esperado (`1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA`) está en
   `tests/test_bitcoin/test_main.cpp`; contrastarlo con cualquier wallet pública
   (Trezor, Ledger, MetaMask) que use ese mnemonic de prueba.
2. `analyze_entropy.py`: mostrar la tabla resumen y comparar `ldr` con
   `ldr-attack` y `sha256-counter` (diapositiva 6).
3. Abrir `src/ui/wallet_ui.cpp` en `enterState()` para mostrar dónde se borra el mnemonic.

---

## Frases para tener a mano

- "SHA-256 acondiciona, no crea entropía."
- "Al LDR le acreditamos cero bits: si es bueno, suma; si es malo, no resta."
- "Los tests estadísticos sólo pueden rechazar una fuente, nunca certificarla."
- "El air-gap es una propiedad del firmware, no del hardware."
- "No es una hardware wallet auditada: es un prototipo para entender cómo se construye una."
