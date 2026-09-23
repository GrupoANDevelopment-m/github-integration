"""Goodware v3.0 - Supply chain security."""
from .sbom import SBOMManager
from .signing import CodeSigning
from .verifier import ZeroTrustVerifier


class SupplyChainManager:
    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.sbom = SBOMManager(config.get("supply_chain.sbom_path", "sbom/sbom.json"))
        self.signing = CodeSigning(engine)
        self.verifier = ZeroTrustVerifier(self.sbom, self.signing, engine)

    def start(self):
        if not self.sbom.exists():
            self.sbom.generate(["goodware"])
        return self.verify_all()

    def stop(self):
        pass

    def verify_all(self):
        return self.verifier.verify_all()

    def add_component(self, name, version, source, sha256):
        self.sbom.add_component(name, version, source, sha256)
        return {"added": name, "version": version}
