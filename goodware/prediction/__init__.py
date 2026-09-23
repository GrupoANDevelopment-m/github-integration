"""Goodware v3.0 - Predictive AI layer"""
from .threat_predictor import ThreatPredictor
from .anomaly_forecast import AnomalyForecast
from .attack_simulator import AttackSimulator


class PredictionManager:
    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.threat = ThreatPredictor("threat", config)
        self.anomaly = AnomalyForecast("anomaly", config)
        self.simulator = AttackSimulator("simulator", config)
        for c in [self.threat, self.anomaly, self.simulator]:
            c.attach(engine)
            engine.register(c.name, c)

    def start_all(self):
        for c in [self.threat, self.anomaly, self.simulator]:
            try:
                c.start()
            except Exception as e:
                self.engine.logger.error(f"{c.name} start: {e}")

    def stop_all(self):
        for c in [self.threat, self.anomaly, self.simulator]:
            try:
                c.stop()
            except Exception:
                pass

    def status(self):
        return {
            "threat": self.threat.status(),
            "anomaly": self.anomaly.status(),
            "simulator": self.simulator.status(),
        }
