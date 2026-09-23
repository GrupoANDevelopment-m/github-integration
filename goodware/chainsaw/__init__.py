"""Goodware v3.0 - Chainsaw malware removal (real YARA/ClamAV/rootkit/CIS)."""
from .analyzer import MalwareAnalyzer
from .sandbox import SandboxRunner
from .remover import MaliciousCodeRemover
from .iat_repair import IATRepair
from .real_scanner import YaraScanner, ClamAVScanner, RootkitDetector, CISBenchmark


class ChainsawManager:
    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.analyzer = MalwareAnalyzer()
        self.sandbox = SandboxRunner()
        self.remover = MaliciousCodeRemover(engine)
        self.iat = IATRepair()
        # REAL
        self.yara = YaraScanner()
        self.clamav = ClamAVScanner()
        self.rootkit = RootkitDetector()
        self.cis = CISBenchmark()

    def start(self):
        return True

    def stop(self):
        pass

    def process_file(self, path):
        result = {"path": path, "stages": []}
        # static analysis (demo)
        try:
            result["analysis"] = self.analyzer.analyze(path)
            result["stages"].append("analyze")
        except Exception as e:
            result["analysis_error"] = str(e)
        # YARA (REAL if installed)
        try:
            result["yara"] = self.yara.scan(path)
            result["stages"].append("yara")
        except Exception as e:
            result["yara_error"] = str(e)
        # ClamAV (REAL if installed)
        try:
            result["clamav"] = self.clamav.scan(path)
            result["stages"].append("clamav")
        except Exception as e:
            result["clamav_error"] = str(e)
        # sandbox só para executáveis
        if path.endswith((".sh", ".py", ".bin", ".elf")):
            try:
                result["sandbox"] = self.sandbox.run(path, timeout=5)
                result["stages"].append("sandbox")
            except Exception as e:
                result["sandbox_error"] = str(e)
        # remoção
        try:
            indicators = result.get("analysis", {}).get("indicators", [])
            if indicators and result["analysis"].get("risk", 0) > 0.4:
                result["removal"] = self.remover.remove(path, indicators)
                result["stages"].append("remove")
        except Exception as e:
            result["removal_error"] = str(e)
        return result

    def scan_rootkit(self):
        """Escaneia rootkits reais."""
        return self.rootkit.scan()

    def run_cis(self):
        """Corre benchmark CIS real."""
        return self.cis.run()

    def quarantine_file(self, path, reason):
        return self.remover.quarantine(path, reason)

    def list_quarantined(self):
        return self.engine.state.list_quarantined() if self.engine else []

    def status(self):
        return {
            "quarantined": len(self.list_quarantined()),
            "yara_available": self.yara._have_python_yara or self.yara._have_yara,
            "clamav_available": self.clamav._have_clamscan or self.clamav._have_clamdscan,
        }
