"""Run documented CLI examples and verify their expected exit statuses."""
import json
import subprocess
import sys
from pathlib import Path

def main():
    root = Path(__file__).resolve().parent
    checks = json.loads((root / "checks.json").read_text(encoding="utf-8"))
    if not isinstance(checks, list) or not checks:
        raise SystemExit("checks.json must contain example checks")
    for check in checks:
        result = subprocess.run([sys.executable, *check["args"]], cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        if result.returncode != check["exit"]:
            print("Example failed:", check["args"], "expected", check["exit"], "got", result.returncode, file=sys.stderr)
            print(result.stdout, result.stderr, file=sys.stderr)
            return 1
        print("PASS", " ".join(check["args"]), "exit", result.returncode)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
