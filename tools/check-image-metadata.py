#!/usr/bin/env python3
"""Fail if any image in the repository carries metadata.

Images can leak author names, software, GPS location, or timestamps. This
check allows only the PNG chunks needed to render an image, rejects JPEG
EXIF/XMP/comment segments, and rejects SVG metadata and editor attributes.
Standard library only; no network access.

Usage: python3 -I tools/check-image-metadata.py
"""
import os
import re
import struct
import sys

PNG_ALLOWED = {b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"IEND", b"gAMA", b"sRGB", b"cHRM", b"pHYs"}
SKIP_DIRS = {".git", "target", "node_modules"}
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def check_png(data):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return ["not a valid PNG signature"]
    problems, i = [], 8
    while i + 8 <= len(data):
        length = struct.unpack(">I", data[i:i + 4])[0]
        kind = data[i + 4:i + 8]
        if kind not in PNG_ALLOWED:
            problems.append("chunk %s not allowed" % kind.decode("latin-1"))
        i += 12 + length
    return problems


def check_jpeg(data):
    problems, i = [], 2
    while i + 4 <= len(data) and data[i] == 0xFF:
        marker = data[i + 1]
        if marker in (0xD9, 0xDA):  # end of image / start of scan
            break
        length = struct.unpack(">H", data[i + 2:i + 4])[0]
        if 0xE1 <= marker <= 0xEF or marker == 0xFE:  # APP1..APP15 (EXIF, XMP...) or comment
            problems.append("JPEG segment 0x%02X (metadata) not allowed" % marker)
        i += 2 + length
    return problems


SVG_FORBIDDEN = re.compile(rb"<metadata|<rdf:|sodipodi:|inkscape:|xmlns:dc=|<dc:|<cc:|adobe:ns|<!--", re.I)


def check_svg(data):
    return ["SVG contains metadata, editor attributes, or comments"] if SVG_FORBIDDEN.search(data) else []


CHECKS = {".png": check_png, ".jpg": check_jpeg, ".jpeg": check_jpeg, ".svg": check_svg}
FORBIDDEN_EXT = {".gif", ".webp", ".heic", ".tif", ".tiff", ".bmp", ".psd", ".ai", ".pdf"}


def main():
    failed = False
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            path = os.path.relpath(os.path.join(dirpath, name), ROOT)
            if ext in FORBIDDEN_EXT:
                print("FAIL: %s: file type not allowed (convert to clean PNG or SVG)" % path)
                failed = True
            elif ext in CHECKS:
                with open(os.path.join(dirpath, name), "rb") as fh:
                    problems = CHECKS[ext](fh.read())
                for p in problems:
                    print("FAIL: %s: %s" % (path, p))
                    failed = True
    if not failed:
        print("OK: no image metadata found.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
