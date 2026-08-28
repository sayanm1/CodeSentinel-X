import json
import os
import subprocess
import tempfile
import sys


def run_semgrep(code: str):
    """
    Run Semgrep security analysis on supplied Python source code.
    Returns normalized findings.
    """

    temp_dir = None
    temp_file = None

    try:
        # Create temporary directory
        temp_dir = tempfile.mkdtemp(prefix="codesentinel_semgrep_")

        # Create temporary Python file
        temp_file = os.path.join(temp_dir, "target.py")

        with open(temp_file, "w", encoding="utf-8") as file:
            file.write(code)

        # Run Semgrep with Python security rules
        result = subprocess.run(
            [
                "semgrep",
                "scan",
                "--config",
                "p/python",
                "--json",
                "--quiet",
                temp_dir
            ],
            capture_output=True,
            text=True
        )

        output = result.stdout.strip()

        if not output:
            return []

        data = json.loads(output)

        findings = []

        for result_item in data.get("results", []):

            extra = result_item.get("extra", {})

            metadata = extra.get("metadata", {})

            findings.append({
                "line": result_item.get("start", {}).get("line"),
                "test_id": result_item.get("check_id"),
                "vulnerability": metadata.get(
                    "category",
                    result_item.get("check_id", "Security Issue")
                ),
                "severity": metadata.get(
                    "severity",
                    "WARNING"
                ).upper(),
                "confidence": "HIGH",
                "description": extra.get(
                    "message",
                    "Potential security vulnerability detected."
                ),
                "source": "Semgrep"
            })

        return findings

    except json.JSONDecodeError:
        return [{
            "line": None,
            "test_id": None,
            "vulnerability": "Semgrep JSON Error",
            "severity": "ERROR",
            "confidence": "HIGH",
            "description": "Semgrep returned invalid JSON.",
            "source": "Semgrep"
        }]

    except Exception as error:
        return [{
            "line": None,
            "test_id": None,
            "vulnerability": "Semgrep Scanner Error",
            "severity": "ERROR",
            "confidence": "HIGH",
            "description": str(error),
            "source": "Semgrep"
        }]

    finally:
        # Remove temporary directory
        if temp_dir and os.path.exists(temp_dir):
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)