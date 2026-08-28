import json
import os
import subprocess
import tempfile
import sys


def run_bandit(code: str):
    """Run Bandit on supplied Python source code."""

    temp_file = None

    try:
        # Create temporary Python file
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8"
        ) as file:
            file.write(code)
            temp_file = file.name

        # Use the exact Python executable running CodeSentinel-X
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "bandit",
                "-r",
                temp_file,
                "-f",
                "json"
            ],
            capture_output=True,
            text=True
        )

        output = result.stdout.strip()

        if not output:
            return []

        data = json.loads(output)

        findings = []

        for issue in data.get("results", []):
            findings.append({
                "line": issue.get("line_number"),
                "test_id": issue.get("test_id"),
                "vulnerability": issue.get(
                    "test_name",
                    "Security Issue"
                ),
                "severity": issue.get(
                    "issue_severity",
                    "UNKNOWN"
                ),
                "confidence": issue.get(
                    "issue_confidence",
                    "UNKNOWN"
                ),
                "description": issue.get(
                    "issue_text",
                    "Potential security vulnerability detected."
                ),
                "source": "Bandit"
            })

        return findings

    except json.JSONDecodeError as error:
        return [{
            "line": None,
            "test_id": None,
            "vulnerability": "Bandit JSON Error",
            "severity": "ERROR",
            "confidence": "HIGH",
            "description": str(error),
            "source": "Bandit"
        }]

    except Exception as error:
        return [{
            "line": None,
            "test_id": None,
            "vulnerability": "Bandit Scanner Error",
            "severity": "ERROR",
            "confidence": "HIGH",
            "description": str(error),
            "source": "Bandit"
        }]

    finally:
        if temp_file and os.path.exists(temp_file):
            os.remove(temp_file)