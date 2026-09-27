"""
Goodware v3.0 — Multimodal support.

Processa diferentes tipos de input para o LLM:
- Texto
- Imagens (PNG, JPG)
- PDF
- Audio (WAV, MP3)
- Video (MP4)

Para imagens e PDFs, extrai features básicos (dimensões, hash)
e envia como blocos para o LLM via content blocks.

Para audio/video, extrai metadata e (opcionalmente) transcrição.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import mimetypes
import os
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

log = logging.getLogger("goodware.llm.multimodal")


def detect_mime(path: str) -> str:
    mime, _ = mimetypes.guess_type(path)
    return mime or "application/octet-stream"


def detect_kind(path: str) -> str:
    mime = detect_mime(path)
    if mime.startswith("image/"):
        return "image"
    if mime.startswith("audio/"):
        return "audio"
    if mime.startswith("video/"):
        return "video"
    if mime == "application/pdf":
        return "pdf"
    if mime.startswith("text/") or mime in ("application/json", "application/xml"):
        return "text"
    return "binary"


def read_image_metadata(path: str) -> Dict[str, Any]:
    """Lê dimensões e hash de imagem."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        sha = hashlib.sha256(data).hexdigest()
        info = {"path": path, "size": len(data), "sha256": sha, "kind": "image"}

        # PNG header
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            w, h = struct.unpack(">II", data[16:24])
            info["width"] = w
            info["height"] = h
            info["format"] = "PNG"
        # JPEG
        elif data[:2] == b"\xff\xd8":
            info["format"] = "JPEG"
            # Procurar SOF marker
            i = 2
            while i < len(data) - 9:
                if data[i] == 0xff and 0xc0 <= data[i+1] <= 0xcf and data[i+1] not in (0xc4, 0xc8, 0xcc):
                    h, w = struct.unpack(">HH", data[i+5:i+9])
                    info["width"] = w
                    info["height"] = h
                    break
                i += 1
        # GIF
        elif data[:6] in (b"GIF87a", b"GIF89a"):
            w, h = struct.unpack("<HH", data[6:10])
            info["width"] = w
            info["height"] = h
            info["format"] = "GIF"
        return info
    except Exception as e:
        return {"path": path, "error": str(e)}


def read_pdf_metadata(path: str) -> Dict[str, Any]:
    """Lê metadata básico de PDF."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        sha = hashlib.sha256(data).hexdigest()
        info = {"path": path, "size": len(data), "sha256": sha, "kind": "pdf", "format": "PDF"}

        # Tentar extrair metadados básicos (Title, Author)
        try:
            text = data.decode("latin1", errors="ignore")
            import re
            for key in ["Title", "Author", "Subject", "Keywords", "Creator"]:
                m = re.search(rf"/{key}\s*\(([^)]+)\)", text)
                if m:
                    info[key.lower()] = m.group(1)
        except Exception:
            pass
        return info
    except Exception as e:
        return {"path": path, "error": str(e)}


def read_audio_metadata(path: str) -> Dict[str, Any]:
    """Lê metadata de audio."""
    try:
        size = os.path.getsize(path)
        info = {"path": path, "size": size, "kind": "audio"}
        with open(path, "rb") as f:
            header = f.read(16)
        if header[:3] == b"ID3":
            info["format"] = "MP3 (ID3)"
        elif header[:2] == b"\xff\xfb":
            info["format"] = "MP3"
        elif header[:4] == b"RIFF" and header[8:12] == b"WAVE":
            info["format"] = "WAV"
        elif header[4:8] == b"ftyp":
            info["format"] = "MP4/M4A"
        else:
            info["format"] = "unknown"
        return info
    except Exception as e:
        return {"path": path, "error": str(e)}


def make_content_block(path: str) -> Dict[str, Any]:
    """Cria content block para input multimodal."""
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    kind = detect_kind(path)
    if kind == "image":
        info = read_image_metadata(path)
        with open(path, "rb") as f:
            data = f.read()
        return {
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": detect_mime(path),
                "data": base64.b64encode(data).decode(),
            },
            "metadata": info,
        }
    elif kind == "pdf":
        info = read_pdf_metadata(path)
        return {
            "type": "document",
            "source": {
                "type": "base64",
                "media_type": "application/pdf",
                "data": base64.b64encode(open(path, "rb").read()).decode(),
            },
            "metadata": info,
        }
    elif kind == "text":
        with open(path, "rb") as f:
            data = f.read()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin1", errors="ignore")
        return {"type": "text", "text": text, "metadata": {"path": path, "kind": "text"}}
    elif kind in ("audio", "video"):
        if kind == "audio":
            info = read_audio_metadata(path)
        else:
            info = {"path": path, "size": os.path.getsize(path), "kind": "video"}
        return {"type": kind, "metadata": info, "path": path}
    else:
        # Binary — devolve hash + base64 truncado
        with open(path, "rb") as f:
            data = f.read(1024)
        return {
            "type": "binary",
            "path": path,
            "metadata": {
                "path": path,
                "size": os.path.getsize(path),
                "sha256": hashlib.sha256(open(path, "rb").read()).hexdigest(),
                "preview_b64": base64.b64encode(data).decode(),
            },
        }


def multimodal_analysis_prompt(text: str, files: List[str]) -> str:
    """Constrói prompt multimodal com arquivos."""
    blocks = [{"type": "text", "text": text}]
    for path in files:
        try:
            block = make_content_block(path)
            blocks.append(block)
        except Exception as e:
            log.warning(f"Failed to load {path}: {e}")
    return blocks  # Devolve lista de content blocks
