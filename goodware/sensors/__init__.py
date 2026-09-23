"""
Goodware v3.0 - Sensors layer (7 sensors).
"""
from .base import BaseSensor
from .filesystem import FileSystemSensor
from .process import ProcessSensor
from .network import NetworkSensor
from .memory import MemorySensor
from .config import ConfigSensor
from .behavior import BehaviorSensor
from .quantum import QuantumSensor


class SensorManager:
    """Gere os 7 sensores em conjunto."""

    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.sensors = []
        definitions = [
            ("filesystem", FileSystemSensor),
            ("process", ProcessSensor),
            ("network", NetworkSensor),
            ("memory", MemorySensor),
            ("config", ConfigSensor),
            ("behavior", BehaviorSensor),
            ("quantum", QuantumSensor),
        ]
        for name, cls in definitions:
            if config.get(f"sensors.{name}.enabled", True):
                inst = cls(name, config)
                inst.attach(engine)
                engine.register(name, inst)
                self.sensors.append(inst)

    def start_all(self):
        for s in self.sensors:
            try:
                s.start()
            except Exception as e:
                self.engine.logger.error(f"sensor {s.name} start failed: {e}")

    def stop_all(self):
        for s in self.sensors:
            try:
                s.stop()
            except Exception:
                pass

    def status(self):
        return [{"name": s.name, "running": getattr(s, "_running", False)} for s in self.sensors]
