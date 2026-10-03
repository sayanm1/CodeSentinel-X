"""
CodeSentinel-X Automated Repair Engine

Provides deterministic repair strategies for supported
security vulnerabilities and validates the generated repairs.
"""

import ast
import re
from typing import Any, Dict, List, Optional


# ============================================================
# REPAIR RULES
# ============================================================

REPAIR_RULES = {
    "CWE-798": {
        "vulnerability": "Hardcoded Secret",
        "root_cause": (
            "Sensitive credentials or secrets are embedded directly "
            "in source code."
        ),
        "strategy": (
            "Replace hardcoded credentials with environment-variable "
            "lookups."
        ),
        "secure_example": (
            "password = os.environ.get('PASSWORD')"
        ),
    },

    "CWE-78": {
        "vulnerability": "Command Injection",
        "root_cause": (
            "User-controlled input is passed to an operating-system "
            "command through a shell."
        ),
        "strategy": (
            "Disable shell execution and pass command arguments as a "
            "structured argument list."
        ),
        "secure_example": (
            "subprocess.run(['echo', user_input], shell=False)"
        ),
    },

    "CWE-95": {
        "vulnerability": "Code Injection",
        "root_cause": (
            "Untrusted input is executed dynamically using eval() "
            "or exec()."
        ),
        "strategy": (
            "Avoid dynamic code execution. Use safe parsing such as "
            "ast.literal_eval() or JSON parsing."
        ),
        "secure_example": (
            "value = ast.literal_eval(user_input)"
        ),
    },

    "CWE-502": {
        "vulnerability": "Unsafe Deserialization",
        "root_cause": (
            "Untrusted serialized data is deserialized using pickle."
        ),
        "strategy": (
            "Replace unsafe pickle deserialization with a safe "
            "data format such as JSON."
        ),
        "secure_example": (
            "data = json.loads(user_input)"
        ),
    },
}


# ============================================================
# CWE RESOLUTION
# ============================================================

def _resolve_cwe(
    finding: Optional[Dict[str, Any]] = None,
    vulnerability: Optional[str] = None,
    cwe_id: Optional[str] = None,
) -> Optional[str]:
    """
    Resolve the CWE identifier from a finding, vulnerability name,
    or explicitly supplied CWE.
    """

    if cwe_id:
        cwe_id = str(cwe_id).upper()

        if cwe_id.startswith("CWE-"):
            return cwe_id

        if cwe_id.isdigit():
            return f"CWE-{cwe_id}"

    if finding:
        for key in ("cwe", "cwe_id", "CWE", "CWE-ID"):
            value = finding.get(key)

            if value:
                value = str(value).upper()

                if value.startswith("CWE-"):
                    return value.split(":", 1)[0].strip()

                if value.isdigit():
                    return f"CWE-{value}"

    vulnerability_value = vulnerability

    if vulnerability_value is None and finding:
        vulnerability_value = (
            finding.get("vulnerability")
            or finding.get("type")
            or finding.get("name")
        )

    if vulnerability_value:
        normalized = str(vulnerability_value).lower()

        if "hardcoded" in normalized or "hard-coded" in normalized:
            return "CWE-798"

        if "command injection" in normalized:
            return "CWE-78"

        if "code injection" in normalized:
            return "CWE-95"

        if "unsafe deserialization" in normalized:
            return "CWE-502"

    return None


# ============================================================
# REPAIR GENERATION
# ============================================================

def generate_repair(
    finding: Optional[Dict[str, Any]] = None,
    vulnerability: Optional[str] = None,
    cwe_id: Optional[str] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Generate a deterministic repair recommendation.

    Supports both:

        generate_repair(finding)

    and:

        generate_repair(
            vulnerability="Hardcoded Secret",
            cwe_id="CWE-798"
        )
    """

    resolved_cwe = _resolve_cwe(
        finding=finding,
        vulnerability=vulnerability,
        cwe_id=cwe_id,
    )

    if resolved_cwe not in REPAIR_RULES:
        return {
            "status": "REPAIR_UNAVAILABLE",
            "repair_status": "REPAIR_UNAVAILABLE",
            "vulnerability": vulnerability
            or (finding or {}).get("vulnerability", "Unknown"),
            "cwe": resolved_cwe,
            "cwe_id": resolved_cwe,
            "reason": (
                "No deterministic repair rule is available "
                "for this vulnerability."
            ),
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
# HARD-CODED SECRET REPAIR
# ============================================================

def _repair_hardcoded_secret(code: str) -> str:
    """
    Replace hardcoded credential/secret assignments with
    environment-variable lookups.

    Examples:

        password = "admin123"

    becomes:

        password = os.environ.get('PASSWORD')


        database_password = "ProdPassword123"

    becomes:

        database_password = os.environ.get('DATABASE_PASSWORD')


        api_key = "secret-key"

    becomes:

        api_key = os.environ.get('API_KEY')


        secret_token = "token-value"

    becomes:

        secret_token = os.environ.get('SECRET_TOKEN')
    """

    # --------------------------------------------------------
    # Make sure os is imported
    # --------------------------------------------------------

    if not re.search(
        r"(?m)^\s*import\s+os\b",
        code,
    ):
        code = "import os\n" + code

    # --------------------------------------------------------
    # Match simple assignments:
    #
    # password = "..."
    # database_password = "..."
    # api_key = "..."
    # secret_token = "..."
    #
    # The current AST scanner detects hardcoded string literals
    # assigned to variables, so this repair intentionally targets
    # that same pattern.
    # --------------------------------------------------------

    assignment_pattern = re.compile(
        r"""^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*
            (["'])(.*?)\3\s*$""",
        re.VERBOSE,
    )

    # --------------------------------------------------------
    # Sensitive variable-name pattern
    # --------------------------------------------------------

    sensitive_pattern = re.compile(
        r"(password|passwd|secret|api_key|apikey|token)",
        re.IGNORECASE,
    )

    repaired_lines = []

    for line in code.splitlines():

        match = assignment_pattern.match(line)

        # Not a simple assignment
        if not match:
            repaired_lines.append(line)
            continue

        indentation = match.group(1)
        variable_name = match.group(2)

        # Not a sensitive variable
        if not sensitive_pattern.search(variable_name):
            repaired_lines.append(line)
            continue

        # Convert variable name to environment-variable format
        environment_key = variable_name.upper()

        repaired_line = (
            f"{indentation}"
            f"{variable_name} = "
            f"os.environ.get('{environment_key}')"
        )

        repaired_lines.append(repaired_line)

    return "\n".join(repaired_lines)


# ============================================================
# COMMAND INJECTION REPAIR
# ============================================================

def _repair_command_injection(code: str) -> str:
    """
    Repair command-injection patterns conservatively.

    The repair:
    1. Removes shell=True.
    2. Converts simple subprocess calls that directly execute a
       user-controlled variable into a fixed executable with the
       variable supplied as an argument.
    3. Keeps shell=False explicitly.

    Example:

        subprocess.call(user, shell=True)

    becomes:

        subprocess.run(["echo", user], shell=False, check=True)

    The executable is no longer controlled by user input.
    """

    repaired_code = code

    # --------------------------------------------------------
    # 1. Replace shell=True with shell=False
    # --------------------------------------------------------

    repaired_code = re.sub(
        r"\bshell\s*=\s*True\b",
        "shell=False",
        repaired_code,
    )

    # --------------------------------------------------------
    # 2. Repair simple direct subprocess execution
    #
    # Example:
    #     subprocess.call(user, shell=False)
    #
    # ->:
    #     subprocess.run(["echo", user], shell=False, check=True)
    #
    # The user-controlled value becomes an argument rather than
    # the executable/command itself.
    # --------------------------------------------------------

    repaired_code = re.sub(
        r"""
        subprocess\.
        (?:call|run|Popen|check_call|check_output)
        \s*\(
        \s*([A-Za-z_]\w*)
        \s*,
        \s*shell\s*=\s*False
        \s*\)
        """,
        r'subprocess.run(["echo", \1], shell=False, check=True)',
        repaired_code,
        flags=re.VERBOSE,
    )

    return repaired_code


# ============================================================
# CODE INJECTION REPAIR
# ============================================================

def _repair_code_injection(code: str) -> str:
    """
    Replace simple eval()/exec() usage with safer parsing.

    eval(user_input)
        ->
    ast.literal_eval(user_input)

    For exec(), the safest deterministic fallback is also to
    use ast.literal_eval() rather than dynamically executing code.
    """

    if not re.search(
        r"(?m)^\s*import\s+ast\b",
        code,
    ):
        code = "import ast\n" + code

    # --------------------------------------------------------
    # eval(...)
    # --------------------------------------------------------

    code = re.sub(
        r"\beval\s*\(",
        "ast.literal_eval(",
        code,
    )

    # --------------------------------------------------------
    # exec(...)
    # --------------------------------------------------------

    code = re.sub(
        r"\bexec\s*\(",
        "ast.literal_eval(",
        code,
    )

    return code


# ============================================================
# UNSAFE DESERIALIZATION REPAIR
# ============================================================

def _repair_deserialization(code: str) -> str:
    """
    Replace pickle.loads()/pickle.load() with JSON parsing.

    pickle.loads(data)
        ->
    json.loads(data)

    pickle.load(file)
        ->
    json.load(file)
    """

    if not re.search(
        r"(?m)^\s*import\s+json\b",
        code,
    ):
        code = "import json\n" + code

    # --------------------------------------------------------
    # pickle.loads(...)
    # --------------------------------------------------------

    code = re.sub(
        r"\bpickle\.loads\s*\(",
        "json.loads(",
        code,
    )

    # --------------------------------------------------------
    # pickle.load(...)
    # --------------------------------------------------------

    code = re.sub(
        r"\bpickle\.load\s*\(",
        "json.load(",
        code,
    )

    return code


# ============================================================
# APPLY SINGLE REPAIR
# ============================================================

def apply_repair(
    code: str,
    finding: Dict[str, Any],
) -> str:
    """
    Apply the appropriate deterministic repair to source code.
    """

    cwe = _resolve_cwe(finding=finding)

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
# GENERATE REPAIRED CODE
# ============================================================

def generate_repaired_code(
    code: str,
    findings: List[Dict[str, Any]],
) -> str:
    """
    Apply repairs sequentially to all findings.

    Findings are processed in the order provided.
    """

    repaired_code = code

    for finding in findings:
        repaired_code = apply_repair(
            repaired_code,
            finding,
        )

    return repaired_code


# ============================================================
# REPAIR VALIDATION
# ============================================================

def validate_repair(
    original_code: str,
    repaired_code: str,
    findings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Validate the repaired source code using only checks that are
    applicable to vulnerabilities actually present in the original
    source code.

    This prevents unrelated checks from causing a false FAIL. For
    example, a file containing only a hardcoded password does not
    need ast.literal_eval() or json.loads().
    """

    result: Dict[str, Any] = {
        "syntax_valid": False,
        "shell_true_removed": "N/A",
        "eval_removed": "N/A",
        "pickle_removed": "N/A",
        "environment_variable_used": "N/A",
        "ast_literal_eval_used": "N/A",
        "json_loads_used": "N/A",
    }

    # --------------------------------------------------------
    # Determine applicable security checks from original source
    # --------------------------------------------------------

    original = original_code if isinstance(original_code, str) else ""
    repaired = repaired_code if isinstance(repaired_code, str) else ""

    applicable = {
        "shell_true_removed": bool(
            re.search(r"\bshell\s*=\s*True\b", original)
        ),
        "eval_removed": bool(
            re.search(r"(?<![\w.])(?:eval|exec)\s*\(", original)
        ),
        "pickle_removed": bool(
            re.search(r"\bpickle\.(?:load|loads)\s*\(", original)
        ),
        "environment_variable_used": bool(
            re.search(
                r"(?m)^\s*(?:password|passwd|secret|api[_-]?key|apikey|token)\s*=\s*['\"]",
                original,
            )
        ),
        "ast_literal_eval_used": bool(
            re.search(r"(?<![\w.])(?:eval|exec)\s*\(", original)
        ),
        "json_loads_used": bool(
            re.search(r"\bpickle\.(?:load|loads)\s*\(", original)
        ),
    }

    # If findings were supplied, use their CWEs as an additional source
    # of applicability. This makes validation robust for normalized
    # scanner output and large files.
    if findings:
        cwes = {
            str(f.get("cwe") or f.get("cwe_id") or "").upper()
            for f in findings
            if isinstance(f, dict)
        }

        if "CWE-78" in cwes:
            applicable["shell_true_removed"] = True

        if "CWE-95" in cwes:
            applicable["eval_removed"] = True
            applicable["ast_literal_eval_used"] = True

        if "CWE-502" in cwes:
            applicable["pickle_removed"] = True
            applicable["json_loads_used"] = True

        if "CWE-798" in cwes:
            applicable["environment_variable_used"] = True

    # --------------------------------------------------------
    # Syntax validation is always required
    # --------------------------------------------------------

    try:
        ast.parse(repaired)
        result["syntax_valid"] = True
    except (SyntaxError, TypeError):
        result["syntax_valid"] = False

    # --------------------------------------------------------
    # Applicable security checks
    # --------------------------------------------------------

    if applicable["shell_true_removed"]:
        result["shell_true_removed"] = not bool(
            re.search(r"\bshell\s*=\s*True\b", repaired)
        )

    if applicable["eval_removed"]:
        result["eval_removed"] = not bool(
            re.search(r"(?<![\w.])(?:eval|exec)\s*\(", repaired)
        )

    if applicable["pickle_removed"]:
        result["pickle_removed"] = not bool(
            re.search(r"\bpickle\.(?:load|loads)\s*\(", repaired)
        )

    if applicable["environment_variable_used"]:
        result["environment_variable_used"] = bool(
            re.search(r"os\.environ(?:\.get)?\s*\(", repaired)
        )

    if applicable["ast_literal_eval_used"]:
        result["ast_literal_eval_used"] = bool(
            re.search(r"\bast\.literal_eval\s*\(", repaired)
        )

    if applicable["json_loads_used"]:
        result["json_loads_used"] = bool(
            re.search(r"\bjson\.loads\s*\(", repaired)
        )

    # --------------------------------------------------------
    # Final validation status
    # --------------------------------------------------------

    validation_checks = [result["syntax_valid"]]

    for key, is_applicable in applicable.items():
        if is_applicable:
            validation_checks.append(result[key] is True)

    result["all_passed"] = all(validation_checks)
    result["applicable_checks"] = [
        key for key, is_applicable in applicable.items()
        if is_applicable
    ]

    return result


# ============================================================
# COMPATIBILITY ALIASES
# ============================================================

repair_finding = generate_repair

generate_repair_candidate = generate_repair


# ============================================================
# OPTIONAL MODULE TEST
# ============================================================

if __name__ == "__main__":

    vulnerable_code = """
import pickle
import subprocess

password = "CompanyAdmin@123"
database_password = "ProdDatabasePassword123"
api_key = "sk-company-demo-123456789"
secret_token = "enterprise-secret-token"

user = input("Command: ")

subprocess.call(
    user,
    shell=True
)

result = eval(user)

data = pickle.loads(user)
"""

    findings = [
        {
            "vulnerability": "Hardcoded Secret",
            "cwe": "CWE-798",
        },
        {
            "vulnerability": "Command Injection",
            "cwe": "CWE-78",
        },
        {
            "vulnerability": "Code Injection",
            "cwe": "CWE-95",
        },
        {
            "vulnerability": "Unsafe Deserialization",
            "cwe": "CWE-502",
        },
    ]

    print("=" * 70)
    print("CodeSentinel-X Repair Engine Demo")
    print("=" * 70)

    print("\n--- ORIGINAL CODE ---")
    print(vulnerable_code)

    repaired = generate_repaired_code(
        vulnerable_code,
        findings,
    )

    print("\n--- REPAIRED CODE ---")
    print(repaired)

    validation = validate_repair(
        vulnerable_code,
        repaired,
    )

    print("\n--- VALIDATION ---")

    for key, value in validation.items():
        print(f"{key}: {value}")

    print("\n" + "=" * 70)

    if validation["all_passed"]:
        print("OVERALL RESULT: PASS")
    else:
        print("OVERALL RESULT: FAIL")

    print("=" * 70)
