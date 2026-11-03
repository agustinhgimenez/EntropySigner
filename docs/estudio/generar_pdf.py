#!/usr/bin/env python3
"""Renders docs/estudio/ESTUDIO_RNG.md to ESTUDIO_RNG.pdf (Markdown -> HTML -> Edge/Chrome headless).

    python docs/estudio/generar_pdf.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import markdown

HERE = Path(__file__).resolve().parent
SRC = HERE / "ESTUDIO_RNG.md"
HTML = HERE / "ESTUDIO_RNG.html"
PDF = HERE / "ESTUDIO_RNG.pdf"

CSS = """
@page { size: A4; margin: 18mm 16mm 18mm 16mm; }
body { font-family: "Segoe UI", Arial, sans-serif; font-size: 10.5pt; line-height: 1.45; color: #1b1f24; }
h1 { font-size: 24pt; color: #0b3d5c; margin: 0 0 4px; }
h1 + h2 { font-size: 14pt; color: #00838f; border: none; margin-top: 0; page-break-before: avoid; }
h2 { font-size: 15pt; color: #0b3d5c; border-bottom: 2px solid #00acc1; padding-bottom: 3px; margin-top: 22px;
     page-break-after: avoid; }
h2:not(:first-of-type) { page-break-before: always; }
h3 { font-size: 12pt; color: #00695c; margin-top: 16px; page-break-after: avoid; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 12px; font-size: 9.3pt; page-break-inside: avoid; }
th { background: #0b3d5c; color: white; text-align: left; padding: 5px 7px; }
td { border: 1px solid #c9d3dc; padding: 4px 7px; vertical-align: top; }
tr:nth-child(even) td { background: #f2f7fa; }
code { font-family: Consolas, monospace; font-size: 9pt; background: #eef2f5; padding: 1px 4px; border-radius: 3px; }
pre { background: #0b1220; color: #e6edf3; padding: 10px 12px; border-radius: 6px; font-size: 8.6pt;
      page-break-inside: avoid; white-space: pre-wrap; }
pre code { background: none; color: inherit; padding: 0; }
blockquote { border-left: 4px solid #ffb300; background: #fff8e1; margin: 10px 0; padding: 6px 12px; }
img { max-width: 100%; display: block; margin: 8px auto; border-radius: 6px; page-break-inside: avoid; }
hr { border: none; border-top: 1px solid #c9d3dc; margin: 14px 0; }
"""


def find_browser() -> str:
    candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    for name in ("msedge", "google-chrome", "chromium", "chrome"):
        if shutil.which(name):
            return shutil.which(name)
    sys.exit("No se encontro Edge ni Chrome para imprimir el PDF.")


def main() -> None:
    body = markdown.markdown(SRC.read_text(encoding="utf-8"), extensions=["tables", "fenced_code", "sane_lists"])
    HTML.write_text(f"<!DOCTYPE html><html lang='es'><head><meta charset='utf-8'><title>EntropySigner - Guia de estudio"
                    f"</title><style>{CSS}</style></head><body>{body}</body></html>", encoding="utf-8")
    subprocess.run([find_browser(), "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                    f"--print-to-pdf={PDF}", HTML.as_uri()], check=True, timeout=120)
    HTML.unlink()
    print("PDF generado:", PDF)


if __name__ == "__main__":
    main()
