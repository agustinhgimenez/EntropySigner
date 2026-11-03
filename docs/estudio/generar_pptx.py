#!/usr/bin/env python3
"""Builds presentation/EntropySigner_RNG.pptx from the figures of docs/estudio/img.

    python docs/estudio/generar_figuras.py   # figures first
    python docs/estudio/generar_pptx.py
"""

from __future__ import annotations

from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN
from pptx.util import Emu, Inches, Pt

HERE = Path(__file__).resolve().parent
IMG = HERE / "img"
OUT = HERE.parents[1] / "presentation" / "EntropySigner_RNG.pptx"

BG = RGBColor(0x0B, 0x12, 0x20)
PANEL = RGBColor(0x15, 0x20, 0x33)
FG = RGBColor(0xE6, 0xED, 0xF3)
MUTED = RGBColor(0x8B, 0x98, 0xA9)
CYAN = RGBColor(0x00, 0xE5, 0xFF)
GREEN = RGBColor(0x00, 0xFF, 0x9C)
AMBER = RGBColor(0xFF, 0xC8, 0x57)
RED = RGBColor(0xFF, 0x53, 0x70)

W, H = Inches(13.333), Inches(7.5)

prs = Presentation()
prs.slide_width, prs.slide_height = W, H
BLANK = prs.slide_layouts[6]


def new_slide(title: str, presenter: str | None = None, notes: str = ""):
    s = prs.slides.add_slide(BLANK)
    s.background.fill.solid()
    s.background.fill.fore_color.rgb = BG
    bar = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, W, Inches(0.08))
    bar.fill.solid()
    bar.fill.fore_color.rgb = CYAN
    bar.line.fill.background()
    if title:
        text(s, title, Inches(0.6), Inches(0.35), Inches(11), Inches(0.9), 30, CYAN, bold=True)
    if presenter:
        text(s, presenter, Inches(10.3), Inches(0.42), Inches(2.6), Inches(0.4), 12, MUTED, align=PP_ALIGN.RIGHT)
    if notes:
        s.notes_slide.notes_text_frame.text = notes
    return s


def text(s, content, x, y, w, h, size=18, color=FG, bold=False, align=PP_ALIGN.LEFT, font="Segoe UI"):
    tb = s.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    lines = content if isinstance(content, list) else [content]
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        r = p.add_run()
        r.text = line
        r.font.size = Pt(size)
        r.font.color.rgb = color
        r.font.bold = bold
        r.font.name = font
    return tb


def bullets(s, items, x=Inches(0.7), y=Inches(1.5), w=Inches(12), h=Inches(5.5), size=20):
    tb = s.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    for i, item in enumerate(items):
        level = 1 if item.startswith("  ") else 0
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.space_after = Pt(10 if level == 0 else 4)
        r = p.add_run()
        r.text = ("•  " if level == 0 else "–  ") + item.strip()
        r.font.size = Pt(size if level == 0 else size - 3)
        r.font.color.rgb = FG if level == 0 else MUTED
        r.font.name = "Segoe UI"
    return tb


def picture(s, name, x, y, w=None, h=None):
    return s.shapes.add_picture(str(IMG / name), x, y, width=w, height=h)


def panel(s, x, y, w, h, title, body, color=CYAN, size=15):
    box = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, w, h)
    box.fill.solid()
    box.fill.fore_color.rgb = PANEL
    box.line.color.rgb = color
    box.line.width = Pt(2)
    box.adjustments[0] = 0.08
    text(s, title, x + Inches(0.2), y + Inches(0.12), w - Inches(0.4), Inches(0.5), size + 3, color, bold=True)
    text(s, body, x + Inches(0.2), y + Inches(0.65), w - Inches(0.4), h - Inches(0.8), size, FG)


def table(s, rows, x, y, w, col_widths, size=13, header_color=RGBColor(0x1D, 0x2B, 0x44), highlight=None):
    shape = s.shapes.add_table(len(rows), len(rows[0]), x, y, w, Inches(0.42 * len(rows)))
    tbl = shape.table
    for j, cw in enumerate(col_widths):
        tbl.columns[j].width = Emu(int(w * cw))
    for i, row in enumerate(rows):
        for j, val in enumerate(row):
            cell = tbl.cell(i, j)
            cell.text = val
            cell.fill.solid()
            cell.fill.fore_color.rgb = header_color if i == 0 else PANEL
            if highlight and (i, j) in highlight:
                cell.fill.fore_color.rgb = highlight[(i, j)]
            for p in cell.text_frame.paragraphs:
                for r in p.runs:
                    r.font.size = Pt(size)
                    r.font.color.rgb = CYAN if i == 0 else FG
                    r.font.bold = i == 0
                    r.font.name = "Segoe UI"
    return tbl


P1, P2, P3 = "Integrante 1", "Integrante 2", "Integrante 3"

# 1 ---------------------------------------------------------------- cover
s = new_slide("", notes="Presentación general (cualquiera de los tres). Presentar el equipo y el objetivo: "
              "mostrar de dónde sale la aleatoriedad de nuestra wallet y cómo la verificamos.")
text(s, "EntropySigner", Inches(0.8), Inches(2.0), Inches(11.5), Inches(1.2), 54, CYAN, bold=True)
text(s, "¿De dónde sale la aleatoriedad de una wallet?", Inches(0.8), Inches(3.2), Inches(11.5), Inches(0.8), 28, FG)
text(s, "El RNG de hardware del ESP32 y su verificación con NIST SP 800-22 y SP 800-90B",
     Inches(0.8), Inches(3.95), Inches(11.5), Inches(0.6), 20, MUTED)
text(s, f"{P1}  ·  {P2}  ·  {P3}", Inches(0.8), Inches(5.6), Inches(11.5), Inches(0.5), 18, GREEN)

# 2 ---------------------------------------------------------------- agenda
s = new_slide("Agenda", notes="Explicar el reparto: cada integrante presenta un bloque.")
panel(s, Inches(0.6), Inches(1.6), Inches(3.9), Inches(4.8), f"1 · El problema ({P1})",
      ["Por qué una wallet necesita aleatoriedad", "", "Casos reales de robos", "", "Entropía y min-entropía", "",
       "TRNG vs PRNG"], CYAN)
panel(s, Inches(4.72), Inches(1.6), Inches(3.9), Inches(4.8), f"2 · El RNG del ESP32 ({P2})",
      ["De dónde sale el ruido", "", "¿Verdadero o pseudoaleatorio?", "", "Cómo lo usa el firmware", "",
       "Lo que corregimos leyendo el manual"], GREEN)
panel(s, Inches(8.84), Inches(1.6), Inches(3.9), Inches(4.8), f"3 · La demostración ({P3})",
      ["NIST SP 800-22 y SP 800-90B", "", "Experimento con 5 generadores", "", "Qué prueban y qué no", "",
       "BIP-39 y demo en vivo"], AMBER)

# ============================================================ PART 1
s = new_slide("Una wallet es un número de 256 bits", P1,
              "Idea central: toda la wallet sale de 256 bits. Si un atacante los adivina, regenera las claves y roba "
              "los fondos. La criptografía posterior (SHA-256, curvas elípticas) no protege si la entropía es mala.")
bullets(s, ["La frase de 24 palabras codifica 256 bits de entropía",
            "De ahí salen todas las claves privadas (BIP-32/44)",
            "Quien adivine esos 256 bits, controla los fondos",
            "2²⁵⁶ ≈ 10⁷⁷ posibilidades: imposible por fuerza bruta…",
            "  …solo si los bits son realmente impredecibles",
            "Si la fuente tiene 32 bits reales, son 4.300 millones de intentos: minutos en una GPU"], size=22)

s = new_slide("Casos reales: falló la entropía, no la criptografía", P1,
              "Recalcar que en los cuatro casos SHA-256 y ECDSA estaban bien. Milk Sad usaba Mersenne Twister, "
              "que más adelante vamos a ver que pasa todas las pruebas estadísticas.")
table(s, [["Año", "Caso", "Qué pasó"],
          ["2008", "Debian OpenSSL", "Solo el PID como entropía: 32.768 claves posibles"],
          ["2013", "Android SecureRandom", "PRNG mal inicializado → firmas repetidas → bitcoins robados"],
          ["2022", "Profanity (Ethereum)", "Semilla de 32 bits → Wintermute pierde ~160 M USD"],
          ["2023", "Milk Sad (bx seed)", "Mersenne Twister sembrado con la hora → ~900 mil USD robados"]],
      Inches(0.6), Inches(1.6), Inches(12.1), [0.08, 0.25, 0.67], size=17)
text(s, "En todos los casos SHA-256 y ECDSA estaban bien: lo que falló fue la aleatoriedad.",
     Inches(0.6), Inches(4.4), Inches(12), Inches(0.6), 20, AMBER, bold=True)

s = new_slide("Entropía: Shannon vs min-entropía", P1,
              "Shannon es un promedio; el atacante prueba primero lo más probable, por eso para claves se usa "
              "min-entropía. Ejemplo de la moneda cargada: 0,47 vs 0,15 bits.")
panel(s, Inches(0.6), Inches(1.6), Inches(5.9), Inches(2.4), "Shannon", ["H = −Σ pᵢ · log₂ pᵢ", "",
      "Incertidumbre promedio"], CYAN, 18)
panel(s, Inches(6.8), Inches(1.6), Inches(5.9), Inches(2.4), "Min-entropía", ["H∞ = −log₂(p_max)", "",
      "Esfuerzo del atacante que prueba lo más probable"], GREEN, 18)
panel(s, Inches(0.6), Inches(4.3), Inches(12.1), Inches(2.4), "Ejemplo: moneda que sale cara el 90%",
      ["Shannon: 0,47 bits por tirada    ·    Min-entropía: 0,15 bits por tirada", "",
       "H∞ ≤ H siempre: Shannon sobrestima la seguridad. Para claves se usa min-entropía."], AMBER, 18)

s = new_slide("TRNG vs PRNG", P1,
              "Un PRNG nunca crea entropía: si la semilla tiene 32 bits, la salida también, aunque sean gigabytes. "
              "Los sistemas serios usan un TRNG para la semilla y un CSPRNG para la velocidad.")
table(s, [["Tipo", "Cómo funciona", "¿Predecible?", "Ejemplo"],
          ["TRNG", "Mide un fenómeno físico (ruido térmico, jitter)", "No", "SAR ADC del ESP32"],
          ["PRNG", "Algoritmo determinista a partir de una semilla", "Sí, con la semilla", "rand(), Mersenne Twister"],
          ["CSPRNG / DRBG", "PRNG resistente a predicción (NIST SP 800-90A)", "Solo con la semilla", "/dev/urandom, HMAC-DRBG"]],
      Inches(0.6), Inches(1.6), Inches(12.1), [0.17, 0.43, 0.17, 0.23], size=16)
text(s, "Un PRNG nunca crea entropía: solo estira la de su semilla.", Inches(0.6), Inches(4.0), Inches(12), Inches(0.6),
     22, AMBER, bold=True)

# ============================================================ PART 2
s = new_slide("Nuestro pipeline", P2,
              "Recorrer el diagrama: 64 bytes del RNG + 128 lecturas del LDR entran a SHA-256 con una etiqueta de "
              "dominio; salen 256 bits que se convierten en 24 palabras y luego en claves.")
picture(s, "pipeline.png", Inches(0.5), Inches(1.7), w=Inches(12.3))
text(s, "Todo depende del primer bloque: el RNG de hardware.", Inches(0.6), Inches(5.6), Inches(12), Inches(0.6), 22,
     GREEN, bold=True)

s = new_slide("El RNG de hardware del ESP32", P2,
              "Fuente: Technical Reference Manual v5.9, capítulo 18. Ruido térmico del SAR ADC, ADC de alta velocidad "
              "de la radio y jitter entre el oscilador RC de 8 MHz y el reloj de 80 MHz. Todo entra por XOR al estado "
              "interno; se lee en RNG_DATA_REG (0x3FF75144).")
picture(s, "rng_hardware.png", Inches(0.9), Inches(1.4), w=Inches(11.5))
text(s, "“Every 32-bit value read from RNG_DATA_REG is a true random number… based on the thermal noise in the system "
        "and the asynchronous clock mismatch.” — ESP32 TRM, cap. 18", Inches(0.9), Inches(6.35), Inches(11.5),
     Inches(0.8), 13, MUTED)

s = new_slide("¿Verdadero o pseudoaleatorio?", P2,
              "Respuesta: depende. Es un generador con estado interno realimentado por ruido. Con fuente activa es "
              "verdadero; sin fuente, Espressif dice textualmente que es pseudoaleatorio.")
table(s, [["Situación", "Resultado"],
          ["WiFi o Bluetooth encendidos", "Verdadero (ADC de alta velocidad)"],
          ["bootloader_random_enable() activo", "Verdadero (SAR ADC)"],
          ["Durante el bootloader", "Verdadero"],
          ["Ninguna de las anteriores", "“should be considered as pseudo-random only”"]],
      Inches(0.6), Inches(1.6), Inches(12.1), [0.45, 0.55], size=18,
      highlight={(4, 0): RGBColor(0x4A, 0x14, 0x20), (4, 1): RGBColor(0x4A, 0x14, 0x20),
                 (2, 0): RGBColor(0x0F, 0x3D, 0x2E), (2, 1): RGBColor(0x0F, 0x3D, 0x2E)})
text(s, "Nuestro dispositivo es offline (sin WiFi/BT): sin hacer nada, sería PSEUDOaleatorio.",
     Inches(0.6), Inches(4.4), Inches(12), Inches(0.6), 21, AMBER, bold=True)
text(s, "Fuente: ESP-IDF Programming Guide, “Random Number Generation”", Inches(0.6), Inches(5.1), Inches(12),
     Inches(0.5), 13, MUTED)

s = new_slide("Cómo lo usa nuestro firmware", P2,
              "Encendemos el ruido del SAR ADC solo durante la lectura. Mientras está encendido no se puede usar el "
              "ADC, por eso el LDR se lee antes. Borramos cada palabra de la pila después de copiarla.")
code = ["void fillRandomBytes(uint8_t* out, size_t len) {",
        "    bootloader_random_enable();         // enciende el ruido del SAR ADC",
        "    for (offset = 0; offset < len; offset += 4) {",
        "        delayMicroseconds(2);           // <= 500 kHz (TRM 18.3)",
        "        uint32_t word = esp_random();",
        "        memcpy(out + offset, &word, ...);",
        "        secureMemzero(&word, 4);        // sin copias en la pila",
        "    }",
        "    bootloader_random_disable();        // libera el ADC para el LDR",
        "}"]
box = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.6), Inches(1.5), Inches(12.1), Inches(4.0))
box.fill.solid()
box.fill.fore_color.rgb = RGBColor(0x05, 0x0A, 0x14)
box.line.color.rgb = PANEL
box.adjustments[0] = 0.04
text(s, code, Inches(0.9), Inches(1.7), Inches(11.6), Inches(3.7), 17, GREEN, font="Consolas")
text(s, "src/entropy/hw_rng.cpp  ·  el LDR se lee ANTES porque el ADC no puede usarse mientras alimenta al RNG",
     Inches(0.6), Inches(5.75), Inches(12), Inches(0.5), 14, MUTED)

s = new_slide("Lo que encontramos leyendo el manual", P2,
              "esp_random() en el ESP32 clásico espera 16 ciclos de APB (5 MHz), pensado para la radio. Sin radio "
              "el manual pide 500 kHz. A 5 MHz entran ~3,2 bits de ruido nuevo por palabra: en el peor caso ~51 bits "
              "para 64 bytes. Con 2 µs por palabra entran 32 bits por palabra. Commit bf1f085.")
panel(s, Inches(0.6), Inches(1.6), Inches(5.9), Inches(3.3), "Antes: ~5 MHz",
      ["esp_random() espera 16 ciclos de APB (200 ns)", "", "1,6 ciclos de 8 MHz × 2 bits", "≈ 3,2 bits nuevos por palabra",
       "", "64 bytes → ~51 bits (peor caso)"], RED, 16)
panel(s, Inches(6.8), Inches(1.6), Inches(5.9), Inches(3.3), "Después: ≤ 500 kHz",
      ["2 µs entre palabras", "", "16 ciclos de 8 MHz × 2 bits", "= 32 bits nuevos por palabra", "",
       "64 bytes → ≥ 512 bits"], GREEN, 16)
text(s, "TRM 18.3: con el SAR ADC entran 2 bits por ciclo de RC_FAST_CLK (8 MHz) → leer a 500 kHz como máximo.",
     Inches(0.6), Inches(5.2), Inches(12), Inches(0.5), 16, FG)
text(s, "Lección: no alcanza con llamar a “random()”: hay que leer la documentación del hardware.",
     Inches(0.6), Inches(5.85), Inches(12), Inches(0.6), 20, AMBER, bold=True)

s = new_slide("Acondicionamiento con SHA-256", P2,
              "SHA-256 concentra 2800 bits de entrada en 256 uniformes. SP 800-90C pide 64 bits de margen: por eso "
              "leemos 512 bits del RNG. SHA-256 nunca crea entropía. El LDR tiene 0 bits acreditados: una linterna "
              "lo controla.")
table(s, [["Entropía que entra", "Entropía que sale", "Situación"],
          ["512 bits", "256,0", "RNG completo (diseño)"],
          ["256 bits", "255,0", "Sin margen"],
          ["128 bits", "128,0", "RNG degradado"],
          ["~51 bits", "~51", "Peor caso antes de la corrección"]],
      Inches(0.6), Inches(1.6), Inches(6.6), [0.33, 0.27, 0.40], size=15)
bullets(s, ["h_out ≤ min(h_in, 256): un hash no crea entropía",
            "SP 800-90C: entrada ≥ salida + 64 bits",
            "LDR: 0 bits acreditados (manipulable con una linterna)"], Inches(7.5), Inches(1.6), Inches(5.3),
        Inches(3.5), 17)
picture(s, "ldr.png", Inches(0.6), Inches(4.25), w=Inches(9.3))

# ============================================================ PART 3
s = new_slide("¿Cómo se demuestra? Los estándares del NIST", P3,
              "SP 800-22 mira la salida del generador con pruebas estadísticas. SP 800-90B estima cuánta entropía "
              "tiene la fuente de ruido e incluye los health tests que corren en el dispositivo.")
table(s, [["Documento", "Qué cubre"],
          ["SP 800-22", "15 pruebas estadísticas sobre la SALIDA de un generador"],
          ["SP 800-90B", "Estimar la min-entropía de la FUENTE de ruido + health tests"],
          ["SP 800-90A", "Generadores deterministas aprobados (DRBG)"],
          ["SP 800-90C", "Cómo combinar fuentes y DRBG"]],
      Inches(0.6), Inches(1.6), Inches(12.1), [0.2, 0.8], size=18,
      highlight={(1, 0): RGBColor(0x0F, 0x3D, 0x2E), (2, 0): RGBColor(0x0F, 0x3D, 0x2E)})
text(s, "Implementamos 9 pruebas de SP 800-22 y 3 estimadores de SP 800-90B, verificados contra los ejemplos del NIST.",
     Inches(0.6), Inches(4.2), Inches(12), Inches(0.8), 19, GREEN)

s = new_slide("P-valor y criterio de aprobación", P3,
              "H0: la secuencia es aleatoria. P < 0,01 rechaza. Con α = 0,01 una fuente perfecta falla 1% de las "
              "veces, por eso se miran 80 secuencias: deben pasar al menos 77 y los P-valores deben ser uniformes.")
panel(s, Inches(0.6), Inches(1.6), Inches(5.9), Inches(4.6), "Una prueba",
      ["H₀: “la secuencia es aleatoria”", "", "P-valor < 0,01 → se rechaza", "P-valor ≥ 0,01 → no se rechaza", "",
       "“No rechazar” NO prueba que sea aleatoria"], CYAN, 17)
panel(s, Inches(6.8), Inches(1.6), Inches(5.9), Inches(4.6), "Criterio NIST (§4.2)",
      ["80 secuencias de 100.000 bits (1 MB)", "", "Proporción: ≥ 77 de 80 deben pasar", "(1−α) − 3·√(α(1−α)/m) = 0,9566",
       "", "Uniformidad: P-valores parejos en [0,1)", "(chi-cuadrado, P ≥ 0,0001)"], GREEN, 17)

s = new_slide("Experimento: 5 generadores, las mismas pruebas", P3,
              "LCG falla todo, el sesgado falla 8 de 10: las pruebas detectan generadores malos. Mersenne Twister y "
              "SHA-256(contador) pasan todo y son 100% predecibles. os.urandom falló una por azar (falso positivo "
              "del 1%; además la prueba DFT tiene un defecto conocido).")
picture(s, "nist_tabla.png", Inches(0.4), Inches(1.5), w=Inches(12.5))
text(s, "Mersenne Twister y SHA-256(contador) pasan TODO… y son 100% predecibles.", Inches(0.6), Inches(5.3),
     Inches(12), Inches(0.6), 21, AMBER, bold=True)
text(s, "os.urandom falló DFT por azar (76/80): con α = 1% es esperable de vez en cuando.", Inches(0.6), Inches(5.95),
     Inches(12), Inches(0.5), 16, MUTED)

s = new_slide("Los bits como imagen", P3,
              "Cada pixel es un bit. El LCG muestra rayas: período corto en los bits bajos. Mersenne Twister se ve "
              "igual de aleatorio que os.urandom aunque es predecible.")
picture(s, "bitmaps.png", Inches(0.4), Inches(1.7), w=Inches(12.5))

s = new_slide("La conclusión más importante", P3,
              "Frase para memorizar. Las pruebas refutan, no prueban. Por eso nos apoyamos en la física documentada.")
text(s, "Las pruebas estadísticas pueden demostrar que un generador es MALO,", Inches(0.8), Inches(2.3),
     Inches(11.8), Inches(0.8), 30, FG, bold=True, align=PP_ALIGN.CENTER)
text(s, "pero nunca que es BUENO.", Inches(0.8), Inches(3.1), Inches(11.8), Inches(0.8), 30, AMBER, bold=True,
     align=PP_ALIGN.CENTER)
text(s, "La seguridad se apoya en una fuente física justificada, no en que “los números parezcan aleatorios”.",
     Inches(0.8), Inches(4.4), Inches(11.8), Inches(0.8), 20, MUTED, align=PP_ALIGN.CENTER)

s = new_slide("SP 800-90B: min-entropía y health tests", P3,
              "Tres estimadores (MCV, Collision, Lag Prediction); se toma el mínimo. El ataque con linterna lleva la "
              "min-entropía del LDR a 0,3 bits y dispara los health tests: es justo lo que deben detectar.")
table(s, [["Fuente (200.000 muestras)", "Bits", "Min-entropía", "% del máximo", "Health tests"],
          ["CSPRNG de referencia", "8", "7,42", "93%", "ok"],
          ["LDR con luz ambiente (modelo)", "12", "3,16", "26%", "ok"],
          ["LDR con linterna (ataque)", "12", "0,30", "2,5%", "FALLA"],
          ["SHA-256(contador)", "8", "7,32", "92%", "ok"]],
      Inches(0.6), Inches(1.6), Inches(12.1), [0.36, 0.1, 0.18, 0.18, 0.18], size=16,
      highlight={(3, 4): RGBColor(0x4A, 0x14, 0x20), (3, 2): RGBColor(0x4A, 0x14, 0x20)})
bullets(s, ["Repetition Count Test: el mismo valor repetido demasiadas veces seguidas",
            "Adaptive Proportion Test: un valor demasiado frecuente en 512 muestras",
            "Corren dentro del dispositivo, en cada uso"], Inches(0.6), Inches(4.1), Inches(12), Inches(2.5), 18)

s = new_slide("El límite honesto: tres pilares", P3,
              "SP 800-90B pide el ruido crudo y el ESP32 no lo expone: solo vemos la salida procesada. Por eso "
              "argumentamos con tres pilares y no solo con pruebas.")
panel(s, Inches(0.6), Inches(1.6), Inches(3.9), Inches(4.0), "1 · Física documentada",
      ["Fuentes y tasas de entropía en el TRM", "", "El firmware cumple las condiciones: fuente activa y ≤ 500 kHz"], GREEN, 16)
panel(s, Inches(4.72), Inches(1.6), Inches(3.9), Inches(4.0), "2 · Pruebas NIST",
      ["SP 800-22 sobre la salida", "", "Descartan sesgo, periodicidad, fuente apagada"], CYAN, 16)
panel(s, Inches(8.84), Inches(1.6), Inches(3.9), Inches(4.0), "3 · Diseño defensivo",
      ["512 bits para 256 (margen 90C)", "", "SHA-256 como acondicionador", "", "LDR extra, 0 bits acreditados"], AMBER, 16)
text(s, "El ruido crudo del ESP32 no es accesible: medir entropía sobre la salida es un control de cordura, no una "
        "certificación.", Inches(0.6), Inches(5.9), Inches(12), Inches(0.8), 16, MUTED)

s = new_slide("Con la placa real", P3,
              "Mostrar la consola o el simulador conectado. Los comandos solo existen en el firmware DEMO y nunca "
              "envían secretos. Si hay tiempo, correr la captura y la batería NIST en vivo.")
table(s, [["Comando USB (firmware DEMO)", "Respuesta"],
          ["ES:PING", "ES:PONG 0.1.0 DEMO ESP32-D0WD-V3"],
          ["ES:RNG 64", "64 bytes distintos en cada pedido"],
          ["ES:LDR 16 200", "lecturas del ADC en GPIO34"]],
      Inches(0.6), Inches(1.6), Inches(12.1), [0.4, 0.6], size=17)
code = ["python tools/entropy_analysis/capture_esp32.py --port COM4 --rng 1000000 --out esp32_rng.bin",
        "python tools/entropy_analysis/nist_sp800_22.py --file esp32_rng.bin"]
text(s, code, Inches(0.6), Inches(3.7), Inches(12.1), Inches(1.0), 14, GREEN, font="Consolas")
text(s, "El simulador web arma la wallet con esos bytes y se niega a generar si la placa no está conectada.",
     Inches(0.6), Inches(4.9), Inches(12), Inches(0.6), 18, FG)

s = new_slide("BIP-39: de 256 bits a 24 palabras", P3,
              "256 + 8 de checksum = 264 = 24 × 11. Cada palabra son 11 bits (2048 palabras). La última lleva 3 bits "
              "de entropía y 8 de checksum: solo 8 últimas palabras válidas. Mostrarlo en el laboratorio.")
bullets(s, ["256 bits de entropía + 8 bits de checksum (SHA-256) = 264 bits",
            "264 = 24 × 11 → cada palabra es un índice de 11 bits en una lista de 2048",
            "Última palabra: 3 bits de entropía + 8 de checksum → solo 8 válidas",
            "PBKDF2-HMAC-SHA512 × 2048 → seed de 512 bits",
            "BIP-32/44: m/44'/0'/0'/0/0 (BTC) y m/44'/60'/0'/0/0 (ETH)",
            "secp256k1 → dirección Base58Check (BTC) y Keccak-256 + EIP-55 (ETH)"], size=20)

s = new_slide("Conclusiones", notes="Cierre: repasar las cuatro ideas y abrir a preguntas.")
bullets(s, ["El RNG del ESP32 es verdadero solo con una fuente de ruido activa: sin WiFi hay que encender el SAR ADC",
            "Leímos el manual y corregimos el ritmo de lectura (5 MHz → 500 kHz)",
            "SHA-256 concentra la entropía pero no la crea; el LDR no se acredita",
            "NIST SP 800-22 detecta generadores malos, pero no demuestra que uno sea bueno",
            "La seguridad se apoya en física documentada + pruebas + diseño defensivo"], size=22)

s = new_slide("¿Preguntas?", notes="Referencias por si las piden.")
text(s, ["ESP32 Technical Reference Manual v5.9, cap. 18 · ESP-IDF “Random Number Generation”",
         "NIST SP 800-22 Rev. 1a · SP 800-90A/B/C",
         "Kim et al. 2004 · Pareschi et al. 2012 (defectos de SP 800-22)",
         "BIP-39 · BIP-32 · BIP-44 · EIP-55",
         "",
         "Código: github.com/agustinhgimenez/EntropySigner"], Inches(0.8), Inches(2.0), Inches(11.8), Inches(4), 18, MUTED)

OUT.parent.mkdir(exist_ok=True)
prs.save(OUT)
print("PowerPoint generado:", OUT, "-", len(prs.slides), "diapositivas")
