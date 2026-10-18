#!/usr/bin/env python3
"""Check compiled artifact format/size, without claiming a console boot test."""
import hashlib
import json
from pathlib import Path
import struct
import shutil
import subprocess
import sys


def verify(payload, ap_blob):
    elf = Path(payload).read_bytes()
    blob = Path(ap_blob).read_bytes()
    if len(elf) < 64 or elf[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected a little-endian ELF64 payload")
    elf_type, machine = struct.unpack_from("<HH", elf, 16)
    if machine != 62 or elf_type not in (2, 3):
        raise ValueError("expected an x86-64 executable/shared ELF")
    if not 0 < len(blob) <= 0xF00:
        raise ValueError("AP payload would overlap its parameter block")
    if b"13.60 ESCAPE DIAGNOSTIC ONLY" not in elf:
        raise ValueError("diagnostic identity is missing from the payload")
    if b"FW1360_DIAGNOSTIC_V2" not in elf:
        raise ValueError("fail-closed diagnostic identity is missing")
    objdump = shutil.which("llvm-objdump") or shutil.which("objdump")
    if not objdump:
        raise ValueError("an objdump supporting ELF is required")
    main_asm = subprocess.run(
        [objdump, "--disassemble-symbols=main", str(payload)],
        check=True, capture_output=True, text=True,
    ).stdout
    if "<main>:" not in main_asm:
        raise ValueError("compiled main function could not be inspected")
    for forbidden in ("fetch_linux", "prepare_resume", "hv_defeat_1320"):
        if forbidden in main_asm:
            raise ValueError("diagnostic main contains forbidden call: " + forbidden)
    return {
        "artifact": Path(payload).name,
        "machine": "AMD x86-64",
        "elf_type": elf_type,
        "payload_bytes": len(elf),
        "ap_blob_bytes": len(blob),
        "ap_blob_limit_bytes": 0xF00,
        "sha256": hashlib.sha256(elf).hexdigest(),
        "linux_boot_verified": False,
        "hardware_escape_verified": False,
        "purpose": "single-cycle firmware-13.60 non-Pro escape diagnostic",
        "compiled_main_has_linux_fallback": False,
        "runtime_firmware_gate": True,
    }


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify_fw1360_artifact.py PAYLOAD.elf BREAK_HV.bin")
    print(json.dumps(verify(sys.argv[1], sys.argv[2]), indent=2))
