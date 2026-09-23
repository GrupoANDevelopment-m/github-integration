"""
Goodware v3.0 - Human Factor Security layer.
"""
from .behavioral_biometrics import BehavioralBiometrics
from .context_risk import ContextRiskScorer
from .multi_party import MultiPartyAuthorization
from .out_of_band import OutOfBandVerifier


class HumanFactorManager:
    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.biometrics = BehavioralBiometrics()
        self.context = ContextRiskScorer()
        self.multiparty = MultiPartyAuthorization()
        self.oob = OutOfBandVerifier(engine, config)

    def start(self):
        try:
            self.biometrics.ensure_default_baseline("admin")
        except Exception as e:
            self.engine.logger.error(f"human factor start: {e}")
        return True

    def stop(self):
        pass

    def evaluate(self, action):
        behavior_score = 0.9
        try:
            user = action.get("user", "admin")
            result = self.biometrics.verify(user, {
                "dwell_times": [0.1] * 5,
                "flight_times": [0.05] * 3,
                "mouse_speed_samples": [1.0] * 5,
            })
            behavior_score = result.get("score", 0.9)
        except Exception:
            pass
        ctx = self.context.score(action, behavior_score)
        risk = ctx["risk"]
        threshold = self.config.get("human_factor.context_risk_threshold", 0.7)
        multi_threshold = self.config.get("human_factor.multi_party_threshold", 0.9)
        decision = "allow"
        request_id = None
        if risk > multi_threshold:
            decision = "block"
            request_id = self.multiparty.request(action, required_approvals=2, total_approvers=3)
        elif risk > threshold:
            decision = "verify"
            request_id = self.multiparty.request(action, required_approvals=1, total_approvers=2)
            try:
                self.oob.request_verification(action, request_id)
            except Exception:
                pass
        return {
            "decision": decision,
            "risk_score": risk,
            "reason": ctx["rationale"],
            "factors": ctx["factors"],
            "request_id": request_id,
        }

    def approve(self, request_id, admin_id):
        return self.multiparty.approve(request_id, admin_id)

    def reject(self, request_id, admin_id):
        return self.multiparty.reject(request_id, admin_id)

    def status(self):
        return {
            "pending_multiparty": self.multiparty.list_pending(),
            "behavioral_users": self.biometrics.list_users(),
        }
