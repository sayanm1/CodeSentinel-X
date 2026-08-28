"""
CodeSentinel-X Automated Code Repair Engine

Provides deterministic security repair rules for findings
identified by the CodeSentinel-X security pipeline.

Supported vulnerabilities:
    CWE-798 - Hardcoded Secret
    CWE-78  - Command Injection
    CWE-95  - Code Injection
    CWE-502 - Unsafe Deserialization
"""

import ast
import re
from typing import Any, Dict, Optional


# ============================================================
# REPAIR RULES
# ============================================================

REPAIR_RULES = {
    "CWE-798": {
        "vulnerability": "Hardcoded Secret",
        "root_cause": (
            "Sensitive credentials are embedded directly in source code "
            "instead of being retrieved securely from the execution "
            "environment or a secrets manager."
        ),
        "strategy": (
            "Replace the hardcoded credential with an environment variable "
            "or a dedicated secrets-management mechanism."
        ),
        "secure_example": (
            "import os\n\n"
            "password = os.environ.get('APP_PASSWORD')"
        ),
        "confidence": 0.95,
    },

    "CWE-78": {
        "vulnerability": "Command Injection",
        "root_cause": (
            "Untrusted input is passed to an operating-system command "
            "through a shell-enabled subprocess call."
        ),
        "strategy": (
            "Disable shell execution and convert the command into a "
            "validated structured argument list whenever possible."
        ),
        "secure_example": (
            "import subprocess\n\n"
            "subprocess.run(\n"
            "    ['ping', '-c', '1', hostname],\n"
            "    shell=False,\n"
            "    check=True\n"
            ")"
        ),
        "confidence": 0.95,
    },

    "CWE-95": {
        "vulnerability": "Code Injection",
        "root_cause": (
            "The application dynamically evaluates a string as Python code "
            "using eval() or a similar execution mechanism."
        ),
        "strategy": (
            "Remove dynamic code execution and use ast.literal_eval() "
            "when literal Python data must be parsed."
        ),
        "secure_example": (
            "import ast\n\n"
            "value = ast.literal_eval(user_input)"
        ),
        "confidence": 0.95,
    },

    "CWE-502": {
        "vulnerability": "Unsafe Deserialization",
        "root_cause": (
            "Untrusted serialized data is loaded using a deserialization "
            "mechanism capable of executing attacker-controlled code."
        ),
        "strategy": (
            "Replace unsafe pickle deserialization with JSON and validate "
            "the resulting data against an expected schema."
        ),
        "secure_example": (
            "import json\n\n"
            "value = json.loads(untrusted_data)"
        ),
        "confidence": 0.95,
    },
}


# ============================================================
# CWE RESOLUTION
# ============================================================

VULNERABILITY_TO_CWE = {
    "hardcoded secret": "CWE-798",
    "hardcoded credential": "CWE-798",
    "hardcoded password": "CWE-798",

    "command injection": "CWE-78",
    "shell injection": "CWE-78",

    "code injection": "CWE-95",
    "dynamic code execution": "CWE-95",

    "unsafe deserialization": "CWE-502",
    "insecure deserialization": "CWE-502",
}


def _resolve_cwe(finding: Dict[str, Any]) -> Optional[str]:
    """
    Resolve CWE from the finding.

    Priority:
        1. cwe_id
        2. cwe
        3. CWE
        4. vulnerability name
    """

    cwe = (
        finding.get("cwe_id")
        or finding.get("cwe")
        or finding.get("CWE")
    )

    if cwe:
        cwe = str(cwe).strip().upper()

        if not cwe.startswith("CWE-"):
            cwe = f"CWE-{cwe}"

        return cwe

    vulnerability = str(
        finding.get("vulnerability")
        or finding.get("type")
        or finding.get("name")
        or ""
    ).strip().lower()

    return VULNERABILITY_TO_CWE.get(vulnerability)


# ============================================================
# GENERATE REPAIR
# ============================================================

def generate_repair(
    finding: Optional[Dict[str, Any]] = None,
    vulnerability: Optional[str] = None,
    cwe_id: Optional[str] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Generate a deterministic repair recommendation.

    This function is intentionally exposed as `generate_repair`
    because test_repair_engine.py imports it directly.
    """

    if finding is None:
        finding = {}

    # --------------------------------------------------------
    # Resolve CWE
    # --------------------------------------------------------

    if cwe_id:
        resolved_cwe = str(cwe_id).strip().upper()

        if not resolved_cwe.startswith("CWE-"):
            resolved_cwe = f"CWE-{resolved_cwe}"

    else:
        resolved_cwe = _resolve_cwe(finding)

    # --------------------------------------------------------
    # Resolve vulnerability
    # --------------------------------------------------------

    resolved_vulnerability = (
        vulnerability
        or finding.get("vulnerability")
        or finding.get("type")
        or finding.get("name")
        or "Unknown Vulnerability"
    )

    resolved_vulnerability = str(
        resolved_vulnerability
    ).strip()

    # --------------------------------------------------------
    # Find repair rule
    # --------------------------------------------------------

    rule = REPAIR_RULES.get(resolved_cwe)

    if rule is None:

        return {
            "vulnerability": resolved_vulnerability,
            "cwe_id": resolved_cwe,
            "repair_status": "REPAIR_UNAVAILABLE",
            "root_cause": (
                "No deterministic repair rule is currently "
                "available for this vulnerability."
            ),
            "repair_strategy": (
                "Manual security review is required."
            ),
            "secure_example": "",
            "repair_confidence": 0.0,
        }

    # --------------------------------------------------------
    # Return repair candidate
    # --------------------------------------------------------

    return {
        "vulnerability": rule["vulnerability"],
        "cwe_id": resolved_cwe,
        "repair_status": "REPAIR_AVAILABLE",
        "root_cause": rule["root_cause"],
        "repair_strategy": rule["strategy"],
        "secure_example": rule["secure_example"],
        "repair_confidence": rule["confidence"],
    }


# ============================================================
# APPLY REPAIR
# ============================================================

def apply_repair(
    code: str,
    finding: Dict[str, Any],
) -> str:
    """
    Apply a deterministic repair to Python source code.

    The function performs targeted replacements and preserves
    unrelated source code as much as possible.
    """

    if not isinstance(code, str):
        return code

    cwe = _resolve_cwe(finding)

    if cwe == "CWE-798":
        return _repair_hardcoded_secret(code)

    if cwe == "CWE-78":
        return _repair_command_injection(code)

    if cwe == "CWE-95":
        return _repair_code_injection(code)

    if cwe == "CWE-502":
        return _repair_deserialization(code)

    return code


# ============================================================
# CWE-798
# ============================================================

def _repair_hardcoded_secret(code: str) -> str:
    """
    Replace common hardcoded password/secret assignments.

    Example:

        password = "admin123"

    becomes:

        password = os.environ.get('APP_PASSWORD')
    """

    if "import os" not in code:
        code = "import os\n" + code

    patterns = [
        r"(?m)^(\s*password\s*=\s*)(['\"]).*?\2\s*$",
        r"(?m)^(\s*passwd\s*=\s*)(['\"]).*?\2\s*$",
        r"(?m)^(\s*secret\s*=\s*)(['\"]).*?\2\s*$",
        r"(?m)^(\s*api_key\s*=\s*)(['\"]).*?\2\s*$",
        r"(?m)^(\s*apikey\s*=\s*)(['\"]).*?\2\s*$",
    ]

    for pattern in patterns:

        replacement = (
            r"\1os.environ.get('APP_PASSWORD')"
        )

        code = re.sub(
            pattern,
            replacement,
            code
        )

    return code


# ============================================================
# CWE-78
# ============================================================

def _repair_command_injection(code: str) -> str:
    """
    Remove shell=True from subprocess calls.

    This is intentionally conservative. It does not attempt
    unsafe automatic command rewriting.
    """

    code = re.sub(
        r",\s*shell\s*=\s*True",
        ", shell=False",
        code,
        flags=re.IGNORECASE
    )

    code = re.sub(
        r"shell\s*=\s*True\s*,",
        "shell=False,",
        code,
        flags=re.IGNORECASE
    )

    code = re.sub(
        r"shell\s*=\s*True",
        "shell=False",
        code,
        flags=re.IGNORECASE
    )

    return code


# ============================================================
# CWE-95
# ============================================================

def _repair_code_injection(code: str) -> str:
    """
    Replace eval(expression) with ast.literal_eval(expression).

    Also ensures that ast is imported.
    """

    if re.search(r"\beval\s*\(", code):

        if not re.search(
            r"^\s*import\s+ast\b",
            code,
            flags=re.MULTILINE
        ):
            code = "import ast\n" + code

        code = re.sub(
            r"\beval\s*\(",
            "ast.literal_eval(",
            code
        )

    return code


# ============================================================
# CWE-502
# ============================================================

def _repair_deserialization(code: str) -> str:
    """
    Replace pickle.loads(...) with json.loads(...).

    Remove pickle import when it is no longer used.
    """

    if re.search(
        r"\bpickle\.loads\s*\(",
        code
    ):

        if not re.search(
            r"^\s*import\s+json\b",
            code,
            flags=re.MULTILINE
        ):
            code = "import json\n" + code

        code = re.sub(
            r"\bpickle\.loads\s*\(",
            "json.loads(",
            code
        )

    # Remove direct pickle import if pickle is no longer referenced.
    if "pickle." not in code:

        code = re.sub(
            r"(?m)^\s*import\s+pickle\s*\n?",
            "",
            code
        )

    return code


# ============================================================
# GENERATE REPAIRED CODE
# ============================================================

def generate_repaired_code(
    code: str,
    findings: list,
) -> str:
    """
    Apply all applicable repair rules to the supplied code.

    Findings are processed in their supplied order.
    """

    repaired_code = code

    for finding in findings:

        repaired_code = apply_repair(
            repaired_code,
            finding
        )

    return repaired_code


# ============================================================
# VALIDATE REPAIR
# ============================================================

def validate_repair(
    original_code: str,
    repaired_code: str,
) -> Dict[str, Any]:
    """
    Validate the repaired source code.

    Checks:
        - Python syntax
        - shell=True removal
        - eval() removal
        - pickle.loads() removal
        - environment variable usage
        - ast.literal_eval usage
        - json.loads usage
    """

    result = {
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
    # Syntax
    # --------------------------------------------------------

    try:
        ast.parse(repaired_code)
        result["syntax_valid"] = True

    except SyntaxError:
        result["syntax_valid"] = False

    # --------------------------------------------------------
    # Security validations
    # --------------------------------------------------------

    result["shell_true_removed"] = (
        "shell=True" not in repaired_code
    )

    # Important:
    # ast.literal_eval contains the text "eval(".
    # Therefore do NOT simply check "eval(".
    result["eval_removed"] = not bool(
        re.search(
            r"(?<!literal_)\beval\s*\(",
            repaired_code
        )
    )

    result["pickle_removed"] = not bool(
        re.search(
            r"\bpickle\.loads\s*\(",
            repaired_code
        )
    )

    result["environment_variable_used"] = (
        "os.environ.get(" in repaired_code
        or "os.getenv(" in repaired_code
    )

    result["ast_literal_eval_used"] = (
        "ast.literal_eval(" in repaired_code
    )

    result["json_loads_used"] = (
        "json.loads(" in repaired_code
    )

    # --------------------------------------------------------
    # Overall validation
    # --------------------------------------------------------

    result["all_passed"] = all(
        result.values()
    )

    return result


# ============================================================
# BACKWARD COMPATIBILITY ALIASES
# ============================================================

repair_finding = generate_repair
generate_repair_candidate = generate_repair