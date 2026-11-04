#!/usr/bin/env python3
"""Regenerate synthetic plist fixtures; no app or account data is included."""
from pathlib import Path
import plistlib

destination = Path(__file__).with_name("fixtures")
destination.mkdir(exist_ok=True)
fixtures = {
    "Info.binary.plist": {
        "CFBundleExecutable": "LegacyGame",
        "CFBundleSignature": "TEST",
        "DTCompiler": "example.compiler",
    },
    "Info.unicode.binary.plist": {
        "CFBundleExecutable": "Épreuve-Executable-Long",
        "DTCompiler": "example.compiler",
    },
    "Manifest.binary.plist": {
        "SinfPaths": [
            "SC_Info/PrimaryExecutable.sinf",
            "PlugIns/Widget.appex/SC_Info/WidgetExecutable.sinf",
        ],
        "SinfReplicationPaths": ["SC_Info/PrimaryExecutable.sinf"],
    },
}
for name, value in fixtures.items():
    (destination / name).write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_BINARY))
