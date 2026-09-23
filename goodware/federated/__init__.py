"""Goodware v3.0 - Federated Learning layer"""
from .client import FederatedClient
from .server import FederatedServer
from .aggregation import SecureAggregator, DifferentialPrivacy


class FederatedManager:
    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.server = FederatedServer(engine, config)
        self.client = FederatedClient(engine, config)
        engine.register("federated-server", self.server)
        engine.register("federated-client", self.client)

    def start_all(self):
        try:
            self.server.start()
        except Exception as e:
            self.engine.logger.error(f"federated server start: {e}")
        try:
            self.client.start()
        except Exception as e:
            self.engine.logger.error(f"federated client start: {e}")

    def stop_all(self):
        try:
            self.client.stop()
        except Exception:
            pass
        try:
            self.server.stop()
        except Exception:
            pass

    def push_now(self):
        return self.client.push_update()

    def status(self):
        return {"server": self.server.status(), "client": self.client.status()}
