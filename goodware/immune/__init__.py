"""Goodware v3.0 - Adaptive immune response."""
from .adaptive_response import AdaptiveImmuneResponse
from .mutation_detector import MutationDetector
from .zero_day import ZeroDayPredictor


class ImmuneManager:
    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.adaptive = AdaptiveImmuneResponse("adaptive", config)
        self.mutation = MutationDetector("mutation", config)
        self.zero_day = ZeroDayPredictor("zero_day", config)
        for c in [self.adaptive, self.mutation, self.zero_day]:
            c.attach(engine)
            engine.register(c.name, c)

    def start_all(self):
        for c in [self.adaptive, self.mutation, self.zero_day]:
            try:
                c.start()
            except Exception as e:
                self.engine.logger.error(f"{c.name} start: {e}")

    def stop_all(self):
        for c in [self.adaptive, self.mutation, self.zero_day]:
            try:
                c.stop()
            except Exception:
                pass

    def evolve_now(self):
        return self.adaptive.evolve()

    def status(self):
        return {
            "adaptive_rules": len(self.engine.state.list_rules()) if self.engine else 0,
            "mutation_families": self.mutation.family_count(),
            "zero_day_predictions": len(self.zero_day.predict_now()),
        }
