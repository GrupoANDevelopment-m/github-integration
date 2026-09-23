"""Goodware v3.0 - Decision module."""
from .risk_assessment import RiskAssessor
from .predictive_engine import PredictiveEngine
from .quorum import Quorum
from .policy_engine import PolicyEngine


class DecisionManager:
    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.risk = RiskAssessor(config)
        self.engine_decision = PredictiveEngine("decision-engine", config)
        self.quorum = Quorum()
        self.policy = PolicyEngine()
        self.engine_decision.attach(engine)
        engine.register(self.engine_decision.name, self.engine_decision)

    def start(self):
        try:
            self.engine_decision.start()
        except Exception as e:
            self.engine.logger.error(f"decision start: {e}")

    def stop(self):
        try:
            self.engine_decision.stop()
        except Exception:
            pass

    def decide(self, event):
        risk = self.risk.assess(event)
        action = "allow"
        requires_human = risk > self.config.get("decision.human_in_loop_above", 0.85)
        requires_multiparty = risk > 0.95
        if risk > 0.9:
            action = "block"
        elif risk > 0.7:
            action = "quarantine"
        elif risk > 0.4:
            action = "alert"
        matches = []
        try:
            matches = self.policy.evaluate(event)
        except Exception:
            pass
        return {
            "risk": risk,
            "action": action,
            "requires_human": requires_human,
            "requires_multiparty": requires_multiparty,
            "explanation": f"risk={risk:.2f} -> {action}",
            "policy_matches": matches,
        }
