"""Análisis estático de shellcode / blobs binarios con Capstone."""

from __future__ import annotations

import re

from core.hashing import entropy
from tools.base import FindingDraft, ToolContext, ToolOutput

# (patrón, arquitectura, descripción)
PROLOGUES = [
    (b"\x55\x8b\xec", "x86", "push ebp; mov ebp, esp"),
    (b"\x48\x89\xe5", "x64", "mov rbp, rsp"),
    (b"\x31\xc0", "x86", "xor eax, eax"),
    (b"\x64\xa1\x30\x00\x00\x00", "x86", "fs:[0x30] (PEB)"),
    (b"\x65\x48\x8b\x04\x25", "x64", "gs:[0x30] (PEB)"),
    (b"\xfc\xe8", "x86", "cld; call"),
    (b"\xe8\x00\x00\x00\x00", "any", "call $+5 (truco de posición)"),
    (b"\xcd\x80", "x86", "int 0x80"),
    (b"\x0f\x05", "x64", "syscall"),
]

STRINGS_RE = re.compile(rb"[\x20-\x7e]{5,}")


def _guess_arch(data: bytes) -> tuple[str, int, list[str]]:
    hits: dict[str, int] = {}
    notes: list[str] = []
    for pattern, arch, description in PROLOGUES:
        count = data.count(pattern)
        if count:
            if arch != "any":
                hits[arch] = hits.get(arch, 0) + count
            if count and description not in notes:
                notes.append(description)
    if not hits:
        return "desconocida", 0, notes
    arch = max(hits, key=lambda k: hits[k])
    return arch, (64 if arch == "x64" else 32 if arch == "x86" else 0), notes


def _disassemble(data: bytes, arch: str, bits: int) -> tuple[list[dict], str]:
    try:
        import capstone
    except ImportError:
        return [], "capstone no disponible"
    cs_arch = {
        "x86": capstone.CS_ARCH_X86,
        "x64": capstone.CS_ARCH_X86,
    }.get(arch)
    if cs_arch is None:
        return [], f"arquitectura no soportada por el desensamblador: {arch}"
    mode = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32
    try:
        md = capstone.Cs(cs_arch, mode)
        md.detail = False
        instructions = []
        for insn in md.disasm(data[:4096], 0):
            instructions.append(
                {"address": f"0x{insn.address:x}", "mnemonic": insn.mnemonic, "op_str": insn.op_str}
            )
            if len(instructions) >= 40:
                break
        return instructions, ""
    except Exception as exc:  # noqa: BLE001
        return [], f"error de desensamblado: {exc}"


def scan(ctx: ToolContext) -> ToolOutput:
    data = ctx.data[:1_000_000]
    arch, bits, notes = _guess_arch(data)
    instructions, error = _disassemble(data, arch, bits)
    strings = [s.decode("latin-1") for s in STRINGS_RE.findall(data)[:15]]

    findings: list[FindingDraft] = []
    if arch != "desconocida":
        findings.append(
            FindingDraft(
                category="architecture",
                description=f"Shellcode compatible con {arch} ({bits} bits); "
                f"patrones: {', '.join(notes[:4])}",
                suspicious=True,
                score=2.0,
            )
        )
    if instructions:
        findings.append(
            FindingDraft(
                category="disassembly",
                description=f"{len(instructions)} instrucciones desensambladas (primeras 4096 bytes)",
                suspicious=False,
                score=0.5,
            )
        )
    syscall_like = sum(1 for insn in instructions if insn["mnemonic"] in {"syscall", "int"})
    if syscall_like:
        findings.append(
            FindingDraft(
                category="syscall",
                description=f"{syscall_like} instrucciones de llamada a sistema (syscall/int)",
                suspicious=True,
                score=1.5,
            )
        )
    if entropy(data) > 7.0:
        findings.append(
            FindingDraft(
                category="entropy",
                description="Alta entropía: payload comprimido o cifrado",
                suspicious=True,
                score=1.0,
            )
        )

    warnings = [error] if error else []
    if arch == "desconocida":
        warnings.append("No se pudo inferir la arquitectura; el blob puede no ser código")

    return ToolOutput(
        status="ok" if arch != "desconocida" else "partial",
        findings=findings,
        warnings=warnings,
        data={
            "architecture": arch,
            "bits": bits,
            "pattern_notes": notes,
            "instructions": instructions,
            "strings": strings,
            "entropy": round(entropy(data), 3),
            "size": len(data),
            "note": "Desensamblado estático; no se ejecutó el código",
        },
        metrics={"instructions": float(len(instructions))},
    )
