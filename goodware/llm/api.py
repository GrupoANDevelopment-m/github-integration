"""
Goodware v3.0 — API REST completa do LLM Brain (DeepSeek Harness oficial).

Endpoints (todos exigem Bearer token via header Authorization):
- GET  /api/llm/status           — estado do Harness + stats
- POST /api/llm/explain          — explicar evento
- POST /api/llm/triage           — triage automático (JSON)
- POST /api/llm/decide           — decidir acção (JSON)
- POST /api/llm/summarise        — sumário executivo
- POST /api/llm/generate-yara    — gerar regra YARA
- POST /api/llm/investigate      — iniciar investigação multi-turn
- POST /api/llm/continue         — continuar investigação existente
- GET  /api/llm/sessions         — listar sessões activas
- POST /api/llm/run              — execução livre de prompt
- POST /api/llm/shutdown         — fechar Harness
- GET  /api/llm/skills           — listar skills instaladas
- POST /api/llm/skills/install   — instalar skill
- POST /api/llm/skills/uninstall — desinstalar skill
- GET  /api/llm/mcp              — listar MCP servers
- POST /api/llm/mcp/start        — iniciar MCP server
- POST /api/llm/tools/execute    — executar tool directamente
- GET  /api/llm/tools            — listar tools disponíveis

Sem fallbacks. Se o Harness não estiver disponível, devolve 503.
"""
from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

log = logging.getLogger("goodware.llm.api")


def register_llm_routes(app):
    """Adiciona rotas LLM ao Flask app."""
    from flask import request, jsonify, send_file
    from goodware.llm.brain import get_brain, shutdown_brain
    from goodware.llm.harness_adapter import get_harness, init_harness, shutdown_harness
    from goodware.llm.skills import get_skills_registry
    from goodware.llm.mcp import get_mcp_registry
    from goodware.llm.tools import list_tools, execute_tool, get_tool_schema, get_all_schemas

    # ===== Status =====

    @app.get("/api/llm/status")
    def llm_status():
        a = init_harness()
        if a is None:
            return jsonify({
                "available": False,
                "error": "Harness não pôde ser inicializado. "
                         "Verifique DEEPSEEK_API_KEY / NVIDIA_API_KEY e se o runtime "
                         "dsh-jsonrpc-agent está disponível.",
            }), 503
        s = a.stats()
        return jsonify({
            "available": True,
            "model": a.config.model,
            "provider": a.config.provider,
            "stats": s,
            "active_sessions": a.list_sessions(),
        })

    # ===== Explica / Triage / Decide / Summarise / YARA =====

    @app.post("/api/llm/explain")
    def llm_explain():
        data = request.json or {}
        session_id = data.get("session_id")
        brain = get_brain()
        if brain is None:
            return jsonify({"error": "Harness não disponível"}), 503
        try:
            return jsonify(brain.explain_event(data, session_id=session_id))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/llm/triage")
    def llm_triage():
        data = request.json or {}
        session_id = data.get("session_id")
        brain = get_brain()
        if brain is None:
            return jsonify({"error": "Harness não disponível"}), 503
        try:
            return jsonify(brain.triage(data, session_id=session_id))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/llm/decide")
    def llm_decide():
        data = request.json or {}
        threat = data.get("threat", {})
        actions = data.get("available_actions")
        session_id = data.get("session_id")
        brain = get_brain()
        if brain is None:
            return jsonify({"error": "Harness não disponível"}), 503
        try:
            return jsonify(brain.decide(threat, actions, session_id=session_id))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/llm/summarise")
    def llm_summarise():
        data = request.json or {}
        incidents = data.get("incidents", [])
        period = data.get("period", "24h")
        session_id = data.get("session_id")
        brain = get_brain()
        if brain is None:
            return jsonify({"error": "Harness não disponível"}), 503
        try:
            return jsonify(brain.summarise_incidents(incidents, period, session_id=session_id))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/llm/generate-yara")
    def llm_generate_yara():
        data = request.json or {}
        sample = data.get("sample", {})
        description = data.get("description", "")
        session_id = data.get("session_id")
        brain = get_brain()
        if brain is None:
            return jsonify({"error": "Harness não disponível"}), 503
        try:
            return jsonify(brain.generate_yara_rule(sample, description, session_id=session_id))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ===== Investigação multi-turn =====

    @app.post("/api/llm/investigate")
    def llm_investigate():
        data = request.json or {}
        threat_id = data.get("threat_id")
        context = data.get("context", {})
        if not threat_id:
            return jsonify({"error": "threat_id required"}), 400
        brain = get_brain()
        if brain is None:
            return jsonify({"error": "Harness não disponível"}), 503
        try:
            response = brain.investigate(threat_id, context)
            return jsonify({"response": response})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/llm/continue")
    def llm_continue():
        data = request.json or {}
        session_id = data.get("session_id")
        followup = data.get("message", "")
        if not session_id or not followup:
            return jsonify({"error": "session_id and message required"}), 400
        brain = get_brain()
        if brain is None:
            return jsonify({"error": "Harness não disponível"}), 503
        try:
            response = brain.continue_investigation(session_id, followup)
            return jsonify({"response": response, "session_id": session_id})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.get("/api/llm/sessions")
    def llm_sessions():
        a = init_harness()
        if a is None:
            return jsonify({"error": "Harness não disponível"}), 503
        return jsonify({"sessions": a.list_sessions()})

    # ===== Run livre =====

    @app.post("/api/llm/run")
    def llm_run():
        data = request.json or {}
        prompt = data.get("prompt", "")
        system_prompt = data.get("system_prompt")
        session_id = data.get("session_id")
        return_json = data.get("json", False)
        if not prompt:
            return jsonify({"error": "prompt required"}), 400
        brain = get_brain()
        if brain is None:
            return jsonify({"error": "Harness não disponível"}), 503
        try:
            return jsonify({"result": brain.run_custom(prompt, system_prompt=system_prompt, session_id=session_id, return_json=return_json)})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/llm/shutdown")
    def llm_shutdown():
        shutdown_brain()
        return jsonify({"ok": True})

    # ===== Skills =====

    @app.get("/api/llm/skills")
    def llm_skills_list():
        reg = get_skills_registry()
        return jsonify({
            "skills": [s.to_dict() for s in reg.list()],
            "count": len(reg),
        })

    @app.post("/api/llm/skills/install")
    def llm_skills_install():
        data = request.json or {}
        name = data.get("name")
        manifest = data.get("manifest", {})
        if not name or not manifest:
            return jsonify({"error": "name and manifest required"}), 400
        reg = get_skills_registry()
        skills_dir = Path(__file__).parent / "skills"
        target = skills_dir / name
        target.mkdir(parents=True, exist_ok=True)
        # Save manifest
        try:
            import yaml
            (target / "skill.yaml").write_text(yaml.safe_dump(manifest))
            reg.reload()
            return jsonify({"ok": True, "skill": name})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/llm/skills/uninstall")
    def llm_skills_uninstall():
        data = request.json or {}
        name = data.get("name")
        if not name:
            return jsonify({"error": "name required"}), 400
        reg = get_skills_registry()
        ok = reg.uninstall(name)
        return jsonify({"ok": ok})

    # ===== MCP =====

    @app.get("/api/llm/mcp")
    def llm_mcp_list():
        reg = get_mcp_registry()
        return jsonify({"servers": [s.to_dict() for s in reg.list()]})

    @app.post("/api/llm/mcp/start")
    def llm_mcp_start():
        data = request.json or {}
        name = data.get("name")
        if not name:
            return jsonify({"error": "name required"}), 400
        reg = get_mcp_registry()
        srv = reg.get(name)
        if not srv:
            return jsonify({"error": "server not found"}), 404
        ok = srv.start()
        return jsonify({"ok": ok, "running": srv._running})

    @app.post("/api/llm/mcp/start-all")
    def llm_mcp_start_all():
        reg = get_mcp_registry()
        n = reg.start_all()
        return jsonify({"started": n})

    @app.post("/api/llm/mcp/stop-all")
    def llm_mcp_stop_all():
        reg = get_mcp_registry()
        reg.stop_all()
        return jsonify({"ok": True})

    @app.post("/api/llm/mcp/add")
    def llm_mcp_add():
        data = request.json or {}
        name = data.get("name")
        if not name:
            return jsonify({"error": "name required"}), 400
        reg = get_mcp_registry()
        reg.add(
            name=name,
            command=data.get("command", ""),
            args=data.get("args", []),
            env=data.get("env", {}),
            description=data.get("description", ""),
            tools=data.get("tools", []),
        )
        return jsonify({"ok": True, "server": name})

    @app.post("/api/llm/mcp/remove")
    def llm_mcp_remove():
        data = request.json or {}
        name = data.get("name")
        if not name:
            return jsonify({"error": "name required"}), 400
        reg = get_mcp_registry()
        ok = reg.remove(name)
        return jsonify({"ok": ok})

    # ===== Tools =====

    @app.get("/api/llm/tools")
    def llm_tools_list():
        return jsonify({
            "tools": list_tools(),
            "schemas": get_all_schemas(),
            "count": len(list_tools()),
        })

    @app.post("/api/llm/tools/execute")
    def llm_tools_execute():
        data = request.json or {}
        name = data.get("name")
        params = data.get("params", {})
        if not name:
            return jsonify({"error": "name required"}), 400
        result = execute_tool(name, params)
        return jsonify(result)
