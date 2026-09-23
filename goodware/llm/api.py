"""
Goodware v3.0 — API REST do LLM Brain (DeepSeek Harness oficial).

Endpoints:
- GET  /api/llm/status — estado do Harness
- POST /api/llm/explain — explicar evento
- POST /api/llm/triage — triage automático
- POST /api/llm/decide — decidir acção
- POST /api/llm/summarise — sumário executivo
- POST /api/llm/generate-yara — gerar regra YARA

Sem fallbacks. Se o Harness não estiver disponível, devolve 503.
"""
from __future__ import annotations


def register_llm_routes(app):
    """Adiciona rotas LLM ao Flask app."""
    from flask import request, jsonify
    from goodware.llm.brain import get_brain, shutdown_brain
    from goodware.llm.harness_adapter import get_harness, init_harness, shutdown_harness

    @app.get("/api/llm/status")
    def llm_status():
        # tentar inicializar se ainda não foi
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
        })

    @app.post("/api/llm/explain")
    def llm_explain():
        event = request.json or {}
        brain = get_brain()
        if brain is None:
            return jsonify({"error": "Harness não disponível"}), 503
        try:
            return jsonify(brain.explain_event(event))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/llm/triage")
    def llm_triage():
        event = request.json or {}
        brain = get_brain()
        if brain is None:
            return jsonify({"error": "Harness não disponível"}), 503
        try:
            return jsonify(brain.triage(event))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/llm/decide")
    def llm_decide():
        threat = request.json or {}
        brain = get_brain()
        if brain is None:
            return jsonify({"error": "Harness não disponível"}), 503
        try:
            return jsonify(brain.decide(threat))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/llm/summarise")
    def llm_summarise():
        data = request.json or {}
        incidents = data.get("incidents", [])
        period = data.get("period", "24h")
        brain = get_brain()
        if brain is None:
            return jsonify({"error": "Harness não disponível"}), 503
        try:
            return jsonify(brain.summarise_incidents(incidents, period))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/llm/generate-yara")
    def llm_generate_yara():
        data = request.json or {}
        sample = data.get("sample", {})
        description = data.get("description", "")
        brain = get_brain()
        if brain is None:
            return jsonify({"error": "Harness não disponível"}), 503
        try:
            return jsonify(brain.generate_yara_rule(sample, description))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/llm/shutdown")
    def llm_shutdown():
        shutdown_brain()
        return jsonify({"ok": True})
