"""
Advanced Example: Custom YARA rule + scan workflow.

Writes a YARA rule, registers it, and scans a file.
"""
import requests

BASE = "http://localhost:8443"
TOKEN = "<login-token>"

CUSTOM_RULE = '''
rule my_custom_detector {
    meta:
        description = "Detects my custom pattern"
    strings:
        $a = "MY_SECRET_PATTERN"
        $b = { 4D 5A 90 00 }  // PE header
    condition:
        any of them
}
'''

def register_rule():
    r = requests.post(f"{BASE}/api/yara/rules",
                      headers={"Authorization": f"Bearer {TOKEN}"},
                      json={"name": "my_custom", "content": CUSTOM_RULE})
    print(f"Rule registered: {r.json()}")

def scan_file(path):
    with open(path, 'rb') as f:
        r = requests.post(f"{BASE}/api/yara/scan",
                          headers={"Authorization": f"Bearer {TOKEN}"},
                          files={"file": f})
        print(f"Scan result: {r.json()}")

register_rule()
scan_file("/tmp/suspicious_binary")
