"""
CodeSentinel-X Automated Repair Engine

Provides deterministic security repair recommendations and
safe candidate generation for supported vulnerability classes.

Supported CWEs:
    CWE-798 - Use of Hard-coded Credentials
    CWE-78  - OS Command Injection
    CWE-95  - Eval Injection / Code Injection
    CWE-502 - Deserialization of Untrusted Data
"""

from __future__ import annotations

import ast
import re
from typing import Any, Dict, List, Optional


# ============================================================
# Repair Rules
# ============================================================

REPAIR_RULES: Dict[str, Dict[str, Any]] = {
    "CWE-798": {
        "vulnerability": "Hardcoded Secret",
        "root_cause": (
            "Sensitive credentials or secrets are embedded directly "
            "in the source code."
        ),
        "strategy": (
            "Move sensitive values to environment variables or a "
            "dedicated secret-management system."
        ),
        "secure_example": (
            'password = os.environ.get("APP_PASSWORD")'
        ),
    },

    "CWE-78": {
        "vulnerability": "Command Injection",
        "root_cause": (
            "User-controlled input is passed to a system command "
            "through an unsafe subprocess configuration."
        ),
        "strategy": (
            "Avoid shell interpretation and use a fixed executable "
            "with a list of validated arguments."
        ),
        "secure_example": (
            'subprocess.run(["program", argument], shell=False, check=True)'
        ),
    },

    "CWE-95": {
        "vulnerability": "Code Injection",
        "root_cause": (
            "Untrusted input is evaluated as executable Python code "
            "through eval() or exec()."
        ),
        "strategy": (
            "Avoid dynamic code execution. For structured data, use "
            "safe parsers such as ast.literal_eval()."
        ),
        "secure_example": (
            "value = ast.literal_eval(user_input)"
        ),
    },

    "CWE-502": {
        "vulnerability": "Unsafe Deserialization",
        "root_cause": (
            "Untrusted serialized data is deserialized using an "
            "unsafe mechanism such as pickle."
        ),
        "strategy": (
            "Use a safe data interchange format such as JSON and "
            "validate the resulting data before use."
        ),
        "secure_example": (
            "data = json.loads(user_input)"
        ),
    },
}


# ============================================================
# Utility Functions
# ============================================================

def _normalize_cwe(cwe_id: Any) -> Optional[str]:
    """
    Normalize CWE identifiers into the format CWE-XXX.
    """
    if cwe_id is None:
        return None

    value = str(cwe_id).strip().upper()

    if not value:
        return None

    if value.startswith("CWE-"):
        number = value.replace("CWE-", "", 1)
    elif value.startswith("CWE"):
        number = value.replace("CWE", "", 1).strip("-")
    else:
        number = value

    if number.isdigit():
        return f"CWE-{number}"

    return value


def _resolve_cwe(finding: Optional[Dict[str, Any]]) -> Optional[str]:
    """
    Resolve a CWE from a finding dictionary.
    """
    if not finding:
        return None

    possible_keys = [
        "cwe",
        "cwe_id",
        "CWE",
        "CWE-ID",
        "cweId",
    ]

    for key in possible_keys:
        value = finding.get(key)

        if value:
            normalized = _normalize_cwe(value)

            if normalized in REPAIR_RULES:
                return normalized

    vulnerability = str(
        finding.get("vulnerability")
        or finding.get("type")
        or finding.get("issue")
        or finding.get("title")
        or ""
    ).lower()

    if "hardcoded" in vulnerability or "hard-coded" in vulnerability:
        return "CWE-798"

    if "command injection" in vulnerability:
        return "CWE-78"

    if "code injection" in vulnerability or "eval" in vulnerability:
        return "CWE-95"

    if "deserialization" in vulnerability or "deserialisation" in vulnerability:
        return "CWE-502"

    return None


# ============================================================
# Generate Repair Recommendation
# ============================================================

def generate_repair(
    finding: Optional[Dict[str, Any]] = None,
    vulnerability: Optional[str] = None,
    cwe_id: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Generate a deterministic repair recommendation.

    Parameters
    ----------
    finding:
        Optional finding dictionary produced by the security scanner.

    vulnerability:
        Optional vulnerability name.

    cwe_id:
        Optional CWE identifier.

    Returns
    -------
    dict
        Repair recommendation and metadata.
    """

    finding = finding or {}

    resolved_cwe = _normalize_cwe(cwe_id)

    if resolved_cwe not in REPAIR_RULES:
        resolved_cwe = _resolve_cwe(finding)

    if resolved_cwe not in REPAIR_RULES and vulnerability:
        vulnerability_lower = vulnerability.lower()

        if "hardcoded" in vulnerability_lower:
            resolved_cwe = "CWE-798"

        elif "command injection" in vulnerability_lower:
            resolved_cwe = "CWE-78"

        elif (
            "code injection" in vulnerability_lower
            or "eval" in vulnerability_lower
        ):
            resolved_cwe = "CWE-95"

        elif "deserialization" in vulnerability_lower:
            resolved_cwe = "CWE-502"

    if resolved_cwe not in REPAIR_RULES:
       return {
            "status": "REPAIR_NOT_AVAILABLE",
            "repair_status": "REPAIR_NOT_AVAILABLE",
            "vulnerability": (
                vulnerability
                or finding.get("vulnerability")
                or "Unknown"
            ),
        "cwe": resolved_cwe,
        "cwe_id": resolved_cwe,
        "root_cause": "No supported deterministic repair rule found.",
        "strategy": "Manual security review is required for this finding.",
        "repair_strategy": "Manual security review is required for this finding.",
        "secure_example": None,
        "repair_confidence": 0.0,
        }

    rule = REPAIR_RULES[resolved_cwe]

    return {
    "status": "REPAIR_AVAILABLE",
    "repair_status": "REPAIR_AVAILABLE",
    "vulnerability": rule["vulnerability"],
    "cwe": resolved_cwe,
    "cwe_id": resolved_cwe,
    "root_cause": rule["root_cause"],
    "strategy": rule["strategy"],
    "repair_strategy": rule["strategy"],
    "secure_example": rule["secure_example"],
    "repair_confidence": 0.95,
    }


# ============================================================
# Apply Repair
# ============================================================

def apply_repair(
    code: str,
    finding: Dict[str, Any],
) -> str:
    """
    Apply the deterministic repair corresponding to a finding.
    """

    if not isinstance(code, str):
        raise TypeError("code must be a string")

    if not isinstance(finding, dict):
        raise TypeError("finding must be a dictionary")

    cwe_id = _resolve_cwe(finding)

    if cwe_id == "CWE-798":
        return _repair_hardcoded_secret(code)

    if cwe_id == "CWE-78":
        return _repair_command_injection(code)

    if cwe_id == "CWE-95":
        return _repair_code_injection(code)

    if cwe_id == "CWE-502":
        return _repair_deserialization(code)

    return code


# ============================================================
# CWE-798 - Hardcoded Secret
# ============================================================

def _repair_hardcoded_secret(code: str) -> str:
    """
    Replace common hardcoded secret assignments with an
    environment-variable lookup.
    """

    lines = code.splitlines()

    output: List[str] = []

    import_os_present = bool(
        re.search(r"^\s*import\s+os\s*$", code, re.MULTILINE)
        or re.search(
            r"^\s*from\s+os\s+import\s+",
            code,
            re.MULTILINE,
        )
    )

    for line in lines:
        stripped = line.strip()

        # Match assignments such as:
        # password = "secret"
        # api_key = "secret"
        # token = "secret"
        # secret = "secret"

        pattern = re.compile(
            r"""
            ^(?P<indent>\s*)
            (?P<name>
                password|
                passwd|
                secret|
                api_key|
                apikey|
                token
            )
            (?P<spacing>\s*=\s*)
            (?P<quote>["'])
            (?P<value>.*?)
            (?P=quote)
            \s*$
            """,
            re.IGNORECASE | re.VERBOSE,
        )

        match = pattern.match(line)

        if match:
            indent = match.group("indent")
            name = match.group("name")

            environment_name = "APP_PASSWORD"

            if "api" in name.lower():
                environment_name = "APP_API_KEY"

            elif "token" in name.lower():
                environment_name = "APP_TOKEN"

            elif "secret" in name.lower():
                environment_name = "APP_SECRET"

            elif "passwd" in name.lower():
                environment_name = "APP_PASSWORD"

            output.append(
                f'{indent}{name} = os.environ.get("{environment_name}")'
            )
        else:
            output.append(line)

    repaired = "\n".join(output)

    if not import_os_present and "os.environ.get(" in repaired:
        repaired = "import os\n" + repaired

    return repaired


# ============================================================
# CWE-78 - Command Injection
# ============================================================

def _repair_command_injection(code: str) -> str:
    """
    Remove shell=True from subprocess calls.

    This is intentionally deterministic and conservative.
    """

    repaired = re.sub(
        r",\s*shell\s*=\s*True",
        ", shell=False",
        code,
        flags=re.IGNORECASE,
    )

    repaired = re.sub(
        r"\bshell\s*=\s*True",
        "shell=False",
        repaired,
        flags=re.IGNORECASE,
    )

    return repaired


# ============================================================
# CWE-95 - Code Injection
# ============================================================

def _repair_code_injection(code: str) -> str:
    """
    Replace eval() with ast.literal_eval() and add the ast import.
    """

    repaired = re.sub(
        r"\beval\s*\(",
        "ast.literal_eval(",
        code,
    )

    if repaired != code:
        import_present = bool(
            re.search(
                r"^\s*import\s+ast\s*$",
                repaired,
                re.MULTILINE,
            )
            or re.search(
                r"^\s*from\s+ast\s+import\s+",
                repaired,
                re.MULTILINE,
            )
        )

        if not import_present:
            repaired = "import ast\n" + repaired

    return repaired


# ============================================================
# CWE-502 - Unsafe Deserialization
# ============================================================

def _repair_deserialization(code: str) -> str:
    """
    Replace pickle.loads() with json.loads() and ensure json
    is imported.

    Direct pickle import is removed if it is no longer referenced.
    """

    repaired = re.sub(
        r"\bpickle\.loads\s*\(",
        "json.loads(",
        code,
    )

    if repaired != code:
        import_json_present = bool(
            re.search(
                r"^\s*import\s+json\s*$",
                repaired,
                re.MULTILINE,
            )
            or re.search(
                r"^\s*from\s+json\s+import\s+",
                repaired,
                re.MULTILINE,
            )
        )

        if not import_json_present:
            repaired = "import json\n" + repaired

        # Remove direct pickle import if pickle is no longer used.
        if "pickle." not in repaired:
            repaired = re.sub(
                r"^\s*import\s+pickle\s*$\n?",
                "",
                repaired,
                flags=re.MULTILINE,
            )

            repaired = re.sub(
                r"^\s*from\s+pickle\s+import\s+.*$\n?",
                "",
                repaired,
                flags=re.MULTILINE,
            )

    return repaired


# ============================================================
# Generate Repaired Code
# ============================================================

def generate_repaired_code(
    code: str,
    findings: list,
) -> str:
    """
    Apply all supported repairs to the supplied source code.

    Findings are processed sequentially.
    """

    if not isinstance(code, str):
        raise TypeError("code must be a string")

    if not isinstance(findings, list):
        raise TypeError("findings must be a list")

    repaired_code = code

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        repaired_code = apply_repair(
            repaired_code,
            finding,
        )

    return repaired_code


# ============================================================
# Repair Validation
# ============================================================

def validate_repair(
    original_code: str,
    repaired_code: str,
) -> Dict[str, Any]:
    """
    Validate the generated repair candidate.

    The validation checks are deterministic and designed to verify
    the four supported repair transformations.
    """

    result: Dict[str, Any] = {
        "syntax_valid": False,
        "shell_true_removed": False,
        "eval_removed": False,
        "pickle_removed": False,
        "environment_variable_used": False,
        "ast_literal_eval_used": False,
        "json_loads_used": False,
        "all_passed": False,
    }

    # --------------------------------------------------------
    # Syntax validation
    # --------------------------------------------------------

    try:
        ast.parse(repaired_code)
        result["syntax_valid"] = True

    except (SyntaxError, ValueError, TypeError):
        result["syntax_valid"] = False

    # --------------------------------------------------------
    # Command Injection validation
    # --------------------------------------------------------

    result["shell_true_removed"] = (
        "shell=True" not in repaired_code
        and "shell = True" not in repaired_code
    )

    # --------------------------------------------------------
    # Code Injection validation
    # --------------------------------------------------------

    result["eval_removed"] = not bool(
        re.search(
            r"(?<!literal_)\beval\s*\(",
            repaired_code,
        )
    )

    # --------------------------------------------------------
    # Unsafe Deserialization validation
    # --------------------------------------------------------

    result["pickle_removed"] = not bool(
        re.search(
            r"\bpickle\.loads\s*\(",
            repaired_code,
        )
    )

    # --------------------------------------------------------
    # Hardcoded Secret validation
    # --------------------------------------------------------

    result["environment_variable_used"] = (
        "os.environ.get(" in repaired_code
        or "os.getenv(" in repaired_code
    )

    # --------------------------------------------------------
    # Safe parser validation
    # --------------------------------------------------------

    result["ast_literal_eval_used"] = (
        "ast.literal_eval(" in repaired_code
    )

    # --------------------------------------------------------
    # Safe deserialization validation
    # --------------------------------------------------------

    result["json_loads_used"] = (
        "json.loads(" in repaired_code
    )

    # --------------------------------------------------------
    # IMPORTANT:
    # Do NOT use all(result.values()) here.
    #
    # result["all_passed"] is itself one of the values and is
    # initially False, which would make all_passed permanently
    # False.
    # --------------------------------------------------------

    validation_checks = [
        result["syntax_valid"],
        result["shell_true_removed"],
        result["eval_removed"],
        result["pickle_removed"],
        result["environment_variable_used"],
        result["ast_literal_eval_used"],
        result["json_loads_used"],
    ]

    result["all_passed"] = all(validation_checks)

    return result


# ============================================================
# Backward-Compatible Aliases
# ============================================================

repair_finding = generate_repair

generate_repair_candidate = generate_repair