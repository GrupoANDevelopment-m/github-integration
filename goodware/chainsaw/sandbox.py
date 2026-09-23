"""
Goodware v3.0 - Sandbox runner.
"""
from __future__ import annotations
import os
import subprocess
import time


class SandboxRunner:
    def run(self, path, timeout=5):
        if not os.path.exists(path):
            return {"error": "not_found"}
        env = os.environ.copy()
        env["chainsaw_offline"] = "1"
        start = time.time()
        try:
            if path.endswith(".sh"):
                cmd = ["bash", path]
            elif path.endswith(".py"):
                cmd = ["python3", path]
            else:
                cmd = ["file", path]
            r = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env, text=True)
            return {
                "exit_code": r.returncode,
                "stdout": (r.stdout or "")[:500],
                "stderr": (r.stderr or "")[:500],
                "elapsed": round(time.time() - start, 2),
            }
        except subprocess.TimeoutExpired:
            return {"timeout": True, "elapsed": timeout}
        except FileNotFoundError:
            return {"error": "interpreter_not_found"}
        except Exception as e:
            return {"error": str(e)}
