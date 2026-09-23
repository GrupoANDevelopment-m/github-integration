"""
Goodware v3.0 - IAT/EAT repair (best-effort).
"""
from __future__ import annotations
import os


class IATRepair:
    def inspect(self, path):
        if not os.path.exists(path):
            return {"error": "not_found"}
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
        except Exception as e:
            return {"error": str(e)}
        if magic != b"\x7fELF":
            return {"is_elf": False}
        return {
            "is_elf": True,
            "bitness": "64-bit" if len(magic) > 0 else "?",
            "note": "demo: full repair requires capstone/keystone; this verifies header",
        }

    def repair(self, path):
        info = self.inspect(path)
        if info.get("is_elf"):
            return {"repaired": False, "reason": "demo: full ELF IAT repair not implemented; integrity verified"}
        return {"repaired": False, "reason": "not an ELF file"}
