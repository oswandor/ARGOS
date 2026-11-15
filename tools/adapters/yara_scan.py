"""YARA: reglas propias del MVP (PDF, Office, JS, shellcode)."""

from __future__ import annotations

from tools.base import FindingDraft, ToolContext, ToolOutput

RULES = r"""
rule ARGOS_PDF_JS_AUTOACTION
{
    meta:
        description = "PDF con JavaScript y acción automática"
        weight = 5
    strings:
        $js = "/JavaScript" ascii
        $oa = "/OpenAction" ascii
    condition:
        $js and $oa
}

rule ARGOS_PDF_LAUNCH
{
    meta:
        description = "PDF con acción /Launch"
        weight = 4
    strings:
        $launch = "/Launch" ascii
    condition:
        $launch
}

rule ARGOS_PDF_EMBEDDED
{
    meta:
        description = "PDF con archivo embebido"
        weight = 2
    strings:
        $ef = "/EmbeddedFile" ascii
    condition:
        $ef
}

rule ARGOS_OFFICE_VBA_AUTOEXEC
{
    meta:
        description = "Proyecto VBA con macro de ejecución automática"
        weight = 5
    strings:
        $vba = "vbaProject.bin" ascii nocase
        $a1 = "AutoOpen" ascii nocase
        $a2 = "Document_Open" ascii nocase
        $a3 = "Workbook_Open" ascii nocase
    condition:
        any of ($a*) and ($vba or filesize < 10MB)
}

rule ARGOS_JS_DOWNLOADER
{
    meta:
        description = "JavaScript con descarga y escritura de archivos"
        weight = 4
    strings:
        $http = "MSXML2.XMLHTTP" ascii nocase
        $stream = "ADODB.Stream" ascii nocase
        $shell = "WScript.Shell" ascii nocase
    condition:
        2 of them
}

rule ARGOS_SHELLCODE_X86_PROLOGUE
{
    meta:
        description = "Patrones de shellcode x86"
        weight = 3
    strings:
        $a = { 55 8B EC }
        $b = { 31 C0 }
        $c = { CD 80 }
        $d = { 64 A1 30 00 00 00 }
    condition:
        2 of ($a, $b, $c, $d)
}

rule ARGOS_OBFUSCATED_JS
{
    meta:
        description = "JavaScript empaquetado (eval + fromCharCode)"
        weight = 1
    strings:
        $eval = "eval(function(p,a,c,k,e,d)" ascii
        $charcode = "String.fromCharCode" ascii
    condition:
        $eval or ($charcode and filesize < 5MB)
}
"""


def scan(ctx: ToolContext) -> ToolOutput:
    import yara

    try:
        rules = yara.compile(source=RULES)
    except yara.Error as exc:
        return ToolOutput(status="error", warnings=[f"reglas YARA inválidas: {exc}"])

    matches = rules.match(data=ctx.data)
    findings: list[FindingDraft] = []
    details: list[dict] = []
    for match in matches:
        weight = float(match.meta.get("weight", 1))
        description = str(match.meta.get("description", match.rule))
        details.append(
            {
                "rule": match.rule,
                "description": description,
                "tags": match.tags,
                "weight": weight,
            }
        )
        findings.append(
            FindingDraft(
                category="yara",
                description=f"YARA: {match.rule} — {description}",
                suspicious=True,
                score=weight,
            )
        )

    return ToolOutput(
        findings=findings,
        data={"matches": details, "rules_evaluated": 7},
        metrics={"matches": float(len(matches))},
    )
