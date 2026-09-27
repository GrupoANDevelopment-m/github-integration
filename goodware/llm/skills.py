"""
Goodware v3.0 — Skills Registry (extensibilidade do DeepSeek Harness).

O Harness suporta "skills" (capacidades descartáveis que podem ser instaladas).
Este módulo gere as skills do Goodware.

Conceito:
- Skill = conjunto nomeado de capacidades + prompt que activa esse comportamento
- Skills podem ser instaladas em runtime
- Skills são descobertas via filesystem (goodware/llm/skills/<name>/SKILL.md)
- Cada skill adiciona tools e/ou system prompts ao brain

Formatos suportados (compatíveis com Cordis/Harness):
- "slash command": /<name> invoca skill
- "automatic": activado por trigger no prompt
- "manual": invocado explicitamente
"""
from __future__ import annotations

import json
import logging
import os
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("goodware.llm.skills")


SKILLS_DIR = Path(__file__).parent / "skills"


class Skill:
    """Representa uma skill do Goodware."""

    def __init__(self, name: str, manifest: Dict[str, Any], skills_dir: Path):
        self.name = name
        self.manifest = manifest
        self._dir = skills_dir
        self._body: Optional[str] = None
        self._tools: Optional[List[Dict[str, Any]]] = None

    @property
    def description(self) -> str:
        return self.manifest.get("description", "")

    @property
    def trigger(self) -> str:
        return self.manifest.get("trigger", "manual")

    @property
    def body(self) -> str:
        """Corpo da skill (markdown)."""
        if self._body is None:
            skill_md = self._dir / "SKILL.md"
            if skill_md.exists():
                self._body = skill_md.read_text(encoding="utf-8")
            else:
                self._body = ""
        return self._body

    @property
    def tools(self) -> List[Dict[str, Any]]:
        """Tools adicionais que esta skill adiciona."""
        if self._tools is None:
            tools_file = self._dir / "tools.json"
            if tools_file.exists():
                try:
                    self._tools = json.loads(tools_file.read_text())
                except Exception:
                    self._tools = []
            else:
                self._tools = []
        return self._tools

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "trigger": self.trigger,
            "tools": self.tools,
            "body_length": len(self.body),
        }


class SkillsRegistry:
    """Registo global de skills disponíveis."""

    def __init__(self, skills_dir: Optional[Path] = None):
        self._dir = skills_dir or SKILLS_DIR
        self._skills: Dict[str, Skill] = {}
        self.reload()

    def reload(self) -> None:
        """Recarrega skills do filesystem."""
        self._skills.clear()
        if not self._dir.exists():
            log.warning(f"Skills dir não existe: {self._dir}")
            return
        for entry in sorted(self._dir.iterdir()):
            if not entry.is_dir():
                continue
            manifest_file = entry / "skill.yaml"
            if not manifest_file.exists():
                continue
            try:
                manifest = yaml.safe_load(manifest_file.read_text(encoding="utf-8"))
                if not isinstance(manifest, dict):
                    continue
                name = manifest.get("name") or entry.name
                self._skills[name] = Skill(name, manifest, entry)
                log.info(f"Skill carregada: {name}")
            except Exception as e:
                log.warning(f"Falha a carregar skill em {entry}: {e}")

    def list(self) -> List[Skill]:
        return list(self._skills.values())

    def get(self, name: str) -> Optional[Skill]:
        return self._skills.get(name)

    def names(self) -> List[str]:
        return list(self._skills.keys())

    def install(self, source_path: Path, name: Optional[str] = None) -> Skill:
        """Instala uma skill a partir de um path."""
        name = name or source_path.name
        target = self._dir / name
        target.mkdir(parents=True, exist_ok=True)
        # Copy files
        import shutil
        if source_path.is_dir():
            for item in source_path.iterdir():
                shutil.copy2(item, target / item.name)
        else:
            shutil.copy2(source_path, target / source_path.name)
        self.reload()
        return self.get(name)

    def uninstall(self, name: str) -> bool:
        target = self._dir / name
        if target.exists():
            import shutil
            shutil.rmtree(target)
            self.reload()
            return True
        return False

    def build_system_prompt_addon(self) -> str:
        """Constrói addon ao system prompt com info sobre skills."""
        if not self._skills:
            return ""
        lines = ["\n\nSKILLS DISPONÍVEIS:"]
        for s in self._skills.values():
            lines.append(f"- **{s.name}**: {s.description}")
        return "\n".join(lines)


# Singleton
_registry: Optional[SkillsRegistry] = None


def get_skills_registry() -> SkillsRegistry:
    global _registry
    if _registry is None:
        _registry = SkillsRegistry()
    return _registry
