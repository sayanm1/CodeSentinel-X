# security/unified_scanner.py

import ast
import re


# ============================================================
# CWE MAPPING
# ============================================================

CWE_MAP = {
    "command_injection": "CWE-78",
    "command_execution": "CWE-78",
    "subprocess": "CWE-78",
    "subprocess_with_shell": "CWE-78",
    "subprocess_popen_shell": "CWE-78",

    "code_injection": "CWE-95",
    "eval": "CWE-95",
    "exec": "CWE-95",

    "unsafe_deserialization": "CWE-502",
    "pickle": "CWE-502",

    "hardcoded_secret": "CWE-798",
    "hardcoded_password": "CWE-798",
}


# ============================================================
# VULNERABILITY NORMALIZATION
# ============================================================

def normalize_vulnerability(name):

    if not name:
        return "Security Vulnerability"

    value = str(name).lower().strip()

    if "pickle" in value or "deserial" in value:
        return "Unsafe Deserialization"

    if (
        "hardcoded" in value
        or "password" in value
        or "secret" in value
        or "credential" in value
    ):
        return "Hardcoded Secret"

    if (
        "eval" in value
        or "exec" in value
        or "code injection" in value
    ):
        return "Code Injection"

    if (
        "subprocess" in value
        or "command injection" in value
        or "command execution" in value
    ):
        return "Command Injection"

    return str(name).replace("_", " ").title()


# ============================================================
# CWE INFERENCE
# ============================================================

def infer_cwe(vulnerability, message=""):

    text = f"{vulnerability} {message}".lower()

    if (
        "pickle" in text
        or "deserialize" in text
        or "deserialization" in text
    ):
        return "CWE-502"

    if (
        "hardcoded" in text
        or "password" in text
        or "api key" in text
        or "secret" in text
        or "credential" in text
    ):
        return "CWE-798"

    if (
        "eval(" in text
        or "exec(" in text
        or "code injection" in text
        or "dynamically evaluated" in text
    ):
        return "CWE-95"

    if (
        "shell=true" in text
        or "command injection" in text
        or "command execution" in text
        or "subprocess" in text
        or "os.system" in text
    ):
        return "CWE-78"

    return None


# ============================================================
# SEVERITY
# ============================================================

def normalize_severity(
    severity,
    vulnerability="",
    message=""
):

    if severity:

        severity = str(
            severity
        ).upper().strip()

        if severity == "WARNING":
            severity = "MEDIUM"

        if severity in {
            "INFO",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }:
            return severity

    text = f"{vulnerability} {message}".lower()

    if (
        "shell=true" in text
        or "eval(" in text
        or "exec(" in text
    ):
        return "HIGH"

    if "pickle" in text:
        return "HIGH"

    if (
        "password" in text
        or "secret" in text
    ):
        return "HIGH"

    return "MEDIUM"


# ============================================================
# FINDING NORMALIZATION
# ============================================================

def normalize_finding(finding):

    if not isinstance(finding, dict):
        return None

    raw_vulnerability = (
        finding.get("vulnerability")
        or finding.get("type")
        or finding.get("rule")
        or finding.get("name")
        or "Security Vulnerability"
    )

    message = (
        finding.get("description")
        or finding.get("message")
        or finding.get("issue")
        or ""
    )

    vulnerability = normalize_vulnerability(
        raw_vulnerability
    )

    cwe = (
        finding.get("cwe")
        or finding.get("cwe_id")
    )

    if not cwe:
        cwe = infer_cwe(
            vulnerability,
            message
        )

    severity = normalize_severity(
        finding.get("severity"),
        vulnerability,
        message
    )

    line = (
        finding.get("line")
        or finding.get("line_number")
        or finding.get("lineno")
        or 0
    )

    normalized = dict(finding)

    normalized.update({
        "vulnerability": vulnerability,
        "cwe": cwe,
        "cwe_id": cwe,
        "severity": severity,
        "line": line,
        "description": message,
    })

    return normalized


# ============================================================
# DUPLICATE REMOVAL
# ============================================================

def deduplicate_findings(findings):

    unique = {}

    severity_order = {
        "INFO": 1,
        "LOW": 2,
        "MEDIUM": 3,
        "HIGH": 4,
        "CRITICAL": 5,
    }

    for finding in findings:

        normalized = normalize_finding(
            finding
        )

        if normalized is None:
            continue

        key = (
            normalized.get("cwe"),
            normalized.get("line"),
            normalized.get("vulnerability"),
        )

        if key not in unique:

            unique[key] = normalized

        else:

            old = unique[key]

            old_score = severity_order.get(
                old.get("severity"),
                0
            )

            new_score = severity_order.get(
                normalized.get("severity"),
                0
            )

            if new_score > old_score:
                unique[key] = normalized

    return list(unique.values())


# ============================================================
# MAIN SECURITY ANALYZER
# ============================================================

def analyze_security(
    code,
    filename="unknown.py"
):

    findings = []

    # --------------------------------------------------------
    # Validate source
    # --------------------------------------------------------

    if not isinstance(code, str):

        return [{
            "vulnerability": "Invalid Source",
            "cwe": None,
            "cwe_id": None,
            "line": 0,
            "severity": "INFO",
            "description": "Source code must be a string.",
            "filename": filename,
        }]

    # --------------------------------------------------------
    # Parse AST
    # --------------------------------------------------------

    try:

        tree = ast.parse(code)

    except SyntaxError as error:

        return [{
            "vulnerability": "Syntax Error",
            "cwe": None,
            "cwe_id": None,
            "line": getattr(
                error,
                "lineno",
                0
            ),
            "severity": "INFO",
            "description": str(error),
            "filename": filename,
        }]

    # --------------------------------------------------------
    # AST traversal
    # --------------------------------------------------------

    for node in ast.walk(tree):

        # ====================================================
        # FUNCTION CALLS
        # ====================================================

        if isinstance(node, ast.Call):

            # ------------------------------------------------
            # EVAL
            # ------------------------------------------------

            if (
                isinstance(
                    node.func,
                    ast.Name
                )
                and node.func.id == "eval"
            ):

                findings.append({
                    "vulnerability":
                        "Code Injection",

                    "cwe":
                        "CWE-95",

                    "line":
                        node.lineno,

                    "severity":
                        "HIGH",

                    "description":
                        "Use of eval() can execute "
                        "attacker-controlled Python code.",

                    "filename":
                        filename,
                })

            # ------------------------------------------------
            # EXEC
            # ------------------------------------------------

            if (
                isinstance(
                    node.func,
                    ast.Name
                )
                and node.func.id == "exec"
            ):

                findings.append({
                    "vulnerability":
                        "Code Injection",

                    "cwe":
                        "CWE-95",

                    "line":
                        node.lineno,

                    "severity":
                        "HIGH",

                    "description":
                        "Use of exec() can execute "
                        "attacker-controlled Python code.",

                    "filename":
                        filename,
                })

            # ------------------------------------------------
            # SUBPROCESS
            # ------------------------------------------------

            if (
                isinstance(
                    node.func,
                    ast.Attribute
                )
                and isinstance(
                    node.func.value,
                    ast.Name
                )
                and node.func.value.id == "subprocess"
            ):

                function_name = node.func.attr

                shell_true = False

                for keyword in node.keywords:

                    if keyword.arg == "shell":

                        if (
                            isinstance(
                                keyword.value,
                                ast.Constant
                            )
                            and keyword.value.value is True
                        ):
                            shell_true = True

                # ------------------------------------------------
                # IMPORTANT:
                # Only shell=True is treated as an actual
                # Command Injection vulnerability.
                #
                # shell=False is considered safe enough for
                # this deterministic scanner and is NOT reported.
                # ------------------------------------------------

                if shell_true:

                    findings.append({
                        "vulnerability":
                            "Command Injection",

                        "cwe":
                            "CWE-78",

                        "line":
                            node.lineno,

                        "severity":
                            "HIGH",

                        "description":
                            f"subprocess.{function_name}() "
                            "uses shell=True. This may allow "
                            "command injection when attacker-"
                            "controlled input reaches the command.",

                        "filename":
                            filename,
                    })

            # ------------------------------------------------
            # PICKLE
            # ------------------------------------------------

            if (
                isinstance(
                    node.func,
                    ast.Attribute
                )
                and isinstance(
                    node.func.value,
                    ast.Name
                )
                and node.func.value.id == "pickle"
            ):

                if node.func.attr in {
                    "load",
                    "loads",
                }:

                    findings.append({
                        "vulnerability":
                            "Unsafe Deserialization",

                        "cwe":
                            "CWE-502",

                        "line":
                            node.lineno,

                        "severity":
                            "HIGH",

                        "description":
                            "pickle can execute arbitrary "
                            "code when loading untrusted data.",

                        "filename":
                            filename,
                    })

        # ====================================================
        # HARD-CODED PASSWORD / SECRET
        # ====================================================

        if isinstance(
            node,
            ast.Assign
        ):

            for target in node.targets:

                if isinstance(
                    target,
                    ast.Name
                ):

                    variable = target.id.lower()

                    sensitive_names = [
                        "password",
                        "passwd",
                        "secret",
                        "api_key",
                        "apikey",
                        "token",
                    ]

                    if any(
                        word in variable
                        for word in sensitive_names
                    ):

                        if isinstance(
                            node.value,
                            ast.Constant
                        ):

                            if isinstance(
                                node.value.value,
                                str
                            ):

                                findings.append({
                                    "vulnerability":
                                        "Hardcoded Secret",

                                    "cwe":
                                        "CWE-798",

                                    "line":
                                        node.lineno,

                                    "severity":
                                        "HIGH",

                                    "description":
                                        "Possible hardcoded "
                                        "sensitive value stored "
                                        f"in '{target.id}'.",

                                    "filename":
                                        filename,
                                })

    # --------------------------------------------------------
    # Normalize and deduplicate
    # --------------------------------------------------------

    findings = deduplicate_findings(
        findings
    )

    return findings


# ============================================================
# ALIAS
# ============================================================

def unified_scan(
    code,
    filename="unknown.py"
):

    return analyze_security(
        code,
        filename
    )


# ============================================================
# COMMAND-LINE TEST
# ============================================================

if __name__ == "__main__":

    test_code = """
import subprocess
import pickle

password = "admin123"

user = input("Enter command: ")

subprocess.call(
    user,
    shell=True
)

eval(user)

pickle.loads(user)
"""

    results = analyze_security(
        test_code,
        "test.py"
    )

    print("=" * 60)
    print("       CodeSentinel-X Unified Security Scanner")
    print("=" * 60)

    print(
        f"\\nTotal findings: {len(results)}"
    )

    for index, finding in enumerate(
        results,
        start=1
    ):

        print("-" * 60)
        print(
            f"Finding #{index}"
        )
        print(
            "Vulnerability:",
            finding.get("vulnerability")
        )
        print(
            "CWE:",
            finding.get("cwe")
        )
        print(
            "Severity:",
            finding.get("severity")
        )
        print(
            "Line:",
            finding.get("line")
        )
        print(
            "Description:",
            finding.get("description")
        )