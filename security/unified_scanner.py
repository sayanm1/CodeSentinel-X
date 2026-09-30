# security/unified_scanner.py

import ast
import re


# ============================================================
# CWE MAPPING
# ============================================================

CWE_MAP = {
    # Existing detectors
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

    # Batch 1 — Injection
    "cross_site_scripting": "CWE-79",
    "xss": "CWE-79",

    "sql_injection": "CWE-89",
    "sql": "CWE-89",

    "server_side_template_injection": "CWE-1336",
    "ssti": "CWE-1336",

    # Batch 2 — File & Network Security
    "path_traversal": "CWE-22",
    "directory_traversal": "CWE-22",
    "path_traversal_attack": "CWE-22",
}


# ============================================================
# CWE NAMES
# ============================================================

CWE_NAMES = {
    "CWE-22":
        "Improper Limitation of a Pathname to a Restricted Directory",

    "CWE-78":
        "Improper Neutralization of Special Elements used in an OS Command",

    "CWE-79":
        "Improper Neutralization of Input During Web Page Generation",

    "CWE-89":
        "Improper Neutralization of Special Elements used in an SQL Command",

    "CWE-95":
        "Improper Neutralization of Directives in Dynamically Evaluated Code",

    "CWE-502":
        "Deserialization of Untrusted Data",

    "CWE-798":
        "Use of Hard-coded Credentials",

    "CWE-1336":
        "Improper Neutralization of Special Elements Used in a Template Engine",
}


# ============================================================
# VULNERABILITY NORMALIZATION
# ============================================================

def normalize_vulnerability(name):

    if not name:
        return "Security Vulnerability"

    value = str(name).lower().strip()

    # --------------------------------------------------------
    # Batch 2 — Path Traversal
    # --------------------------------------------------------

    if (
        "path traversal" in value
        or "directory traversal" in value
        or "path_traversal" in value
    ):
        return "Path Traversal"

    # --------------------------------------------------------
    # Batch 1 — XSS
    # --------------------------------------------------------

    if (
        "xss" in value
        or "cross-site scripting" in value
        or "cross site scripting" in value
    ):
        return "Cross-Site Scripting"

    # --------------------------------------------------------
    # Batch 1 — SQL Injection
    # --------------------------------------------------------

    if (
        "sql injection" in value
        or "sql_injection" in value
    ):
        return "SQL Injection"

    # --------------------------------------------------------
    # Batch 1 — SSTI
    # --------------------------------------------------------

    if (
        "ssti" in value
        or "server-side template injection" in value
        or "server side template injection" in value
    ):
        return "Server-Side Template Injection"

    # --------------------------------------------------------
    # Existing — Unsafe Deserialization
    # --------------------------------------------------------

    if "pickle" in value or "deserial" in value:
        return "Unsafe Deserialization"

    # --------------------------------------------------------
    # Existing — Hardcoded Secret
    # --------------------------------------------------------

    if (
        "hardcoded" in value
        or "password" in value
        or "secret" in value
        or "credential" in value
    ):
        return "Hardcoded Secret"

    # --------------------------------------------------------
    # Existing — Code Injection
    # --------------------------------------------------------

    if (
        "eval" in value
        or "exec" in value
        or "code injection" in value
    ):
        return "Code Injection"

    # --------------------------------------------------------
    # Existing — Command Injection
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Batch 2 — Path Traversal
    # --------------------------------------------------------

    if (
        "path traversal" in text
        or "directory traversal" in text
        or "pathname" in text
        or "restricted directory" in text
    ):
        return "CWE-22"

    # --------------------------------------------------------
    # Batch 1 — XSS
    # --------------------------------------------------------

    if (
        "xss" in text
        or "cross-site scripting" in text
        or "cross site scripting" in text
        or "web page generation" in text
    ):
        return "CWE-79"

    # --------------------------------------------------------
    # Batch 1 — SQL Injection
    # --------------------------------------------------------

    if (
        "sql injection" in text
        or (
            "sql" in text
            and "injection" in text
        )
    ):
        return "CWE-89"

    # --------------------------------------------------------
    # Batch 1 — SSTI
    # --------------------------------------------------------

    if (
        "ssti" in text
        or "server-side template injection" in text
        or "server side template injection" in text
        or "template injection" in text
    ):
        return "CWE-1336"

    # --------------------------------------------------------
    # Existing — Unsafe Deserialization
    # --------------------------------------------------------

    if (
        "pickle" in text
        or "deserialize" in text
        or "deserialization" in text
    ):
        return "CWE-502"

    # --------------------------------------------------------
    # Existing — Hardcoded Secret
    # --------------------------------------------------------

    if (
        "hardcoded" in text
        or "password" in text
        or "api key" in text
        or "secret" in text
        or "credential" in text
    ):
        return "CWE-798"

    # --------------------------------------------------------
    # Existing — Code Injection
    # --------------------------------------------------------

    if (
        "eval(" in text
        or "exec(" in text
        or "code injection" in text
        or "dynamically evaluated" in text
    ):
        return "CWE-95"

    # --------------------------------------------------------
    # Existing — Command Injection
    # --------------------------------------------------------

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

    # High-risk injection vulnerabilities
    if (
        "shell=true" in text
        or "eval(" in text
        or "exec(" in text
        or "sql injection" in text
        or "cross-site scripting" in text
        or "xss" in text
        or "template injection" in text
        or "ssti" in text
    ):
        return "HIGH"

    # Path traversal
    if (
        "path traversal" in text
        or "directory traversal" in text
    ):
        return "HIGH"

    # Existing unsafe deserialization
    if "pickle" in text:
        return "HIGH"

    # Existing hardcoded secrets
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

    # --------------------------------------------------------
    # CWE NAME
    # --------------------------------------------------------

    cwe_name = CWE_NAMES.get(
        cwe,
        "Unknown"
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
        "cwe_name": cwe_name,
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
# HELPER FUNCTIONS FOR BATCH 1 / BATCH 2
# ============================================================

def _get_source_segment(code, node):
    """
    Safely retrieve source text for an AST node.

    This is used by injection detectors to inspect expressions
    without executing the submitted code.
    """

    try:
        return ast.get_source_segment(
            code,
            node
        ) or ""
    except Exception:
        return ""


def _contains_user_input(node):
    """
    Conservative AST check for expressions that appear to use
    externally supplied input.

    This is intentionally pattern-based.
    It does not execute code.
    """

    for child in ast.walk(node):

        # input(...)
        if isinstance(child, ast.Call):

            if (
                isinstance(child.func, ast.Name)
                and child.func.id == "input"
            ):
                return True

            # request.args / request.form /
            # request.values / request.data / etc.
            if isinstance(child.func, ast.Attribute):

                if isinstance(
                    child.func.value,
                    ast.Attribute
                ):

                    base = child.func.value

                    if (
                        isinstance(
                            base.value,
                            ast.Name
                        )
                        and base.value.id in {
                            "request",
                            "req",
                        }
                        and base.attr in {
                            "args",
                            "form",
                            "values",
                            "data",
                            "json",
                            "query_params",
                        }
                    ):
                        return True

                if (
                    isinstance(
                        child.func.value,
                        ast.Name
                    )
                    and child.func.value.id in {
                        "input",
                        "request",
                        "req",
                    }
                ):
                    return True

        # Variables commonly populated from input()
        if isinstance(child, ast.Name):

            if child.id.lower() in {
                "user_input",
                "userinput",
                "input_data",
                "query",
                "query_string",
                "user_query",
                "request_data",
                "filename",
                "file_name",
                "filepath",
                "file_path",
                "path",
                "user_path",
                "requested_path",
            }:
                return True

    return False


def _expression_contains_string_formatting(node):
    """
    Detect string construction that combines a string literal with
    another expression.

    Used as a conservative signal for SQL/XSS/SSTI detection.
    """

    if isinstance(node, ast.JoinedStr):
        return True

    if isinstance(node, ast.BinOp):

        if isinstance(
            node.op,
            (ast.Add, ast.Mod)
        ):
            return True

    if isinstance(node, ast.Call):

        if isinstance(
            node.func,
            ast.Attribute
        ):

            if node.func.attr in {
                "format",
                "format_map",
            }:
                return True

    return False


def _is_sql_string_expression(node, code):
    """
    Determine whether an expression looks like dynamically
    constructed SQL.

    Detection is deliberately conservative and focuses on
    SQL keywords plus dynamic string construction.
    """

    source = _get_source_segment(
        code,
        node
    ).lower()

    sql_keywords = (
        "select ",
        "insert ",
        "update ",
        "delete ",
        "drop ",
        "alter ",
        "create ",
        "replace ",
        "truncate ",
        "union ",
    )

    has_sql_keyword = any(
        keyword in source
        for keyword in sql_keywords
    )

    dynamic = _expression_contains_string_formatting(
        node
    )

    return has_sql_keyword and dynamic


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
            "cwe_name": "Unknown",
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
            "cwe_name": "Unknown",
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

            # =================================================
            # BATCH 2 — PATH TRAVERSAL
            # =================================================

            file_functions = {
                "open",
            }

            if (
                isinstance(
                    node.func,
                    ast.Name
                )
                and node.func.id in file_functions
            ):

                if node.args:

                    path_argument = node.args[0]

                    user_controlled = _contains_user_input(
                        path_argument
                    )

                    if user_controlled:

                        findings.append({

                            "vulnerability":
                                "Path Traversal",

                            "cwe":
                                "CWE-22",

                            "line":
                                node.lineno,

                            "severity":
                                "HIGH",

                            "description":
                                "User-controlled path is passed "
                                "to a file operation and may allow "
                                "path traversal outside the intended "
                                "directory.",

                            "filename":
                                filename,
                        })

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

                # Only shell=True is treated as an actual
                # Command Injection vulnerability.

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

            # =================================================
            # BATCH 1 — SQL INJECTION
            # =================================================

            sql_functions = {
                "execute",
                "executemany",
                "executescript",
            }

            if (
                isinstance(
                    node.func,
                    ast.Attribute
                )
                and node.func.attr in sql_functions
            ):

                if node.args:

                    query_argument = node.args[0]

                    if _is_sql_string_expression(
                        query_argument,
                        code
                    ):

                        findings.append({

                            "vulnerability":
                                "SQL Injection",

                            "cwe":
                                "CWE-89",

                            "line":
                                node.lineno,

                            "severity":
                                "HIGH",

                            "description":
                                "Dynamically constructed SQL "
                                "query passed to database execution "
                                "may allow SQL injection.",

                            "filename":
                                filename,
                        })

            # =================================================
            # BATCH 1 — XSS
            # =================================================

            xss_functions = {
                "write",
                "writeln",
                "render_template_string",
            }

            if (
                isinstance(
                    node.func,
                    ast.Attribute
                )
                and node.func.attr in xss_functions
            ):

                if node.args:

                    output_argument = node.args[0]

                    dynamic = (
                        _expression_contains_string_formatting(
                            output_argument
                        )
                    )

                    user_controlled = _contains_user_input(
                        output_argument
                    )

                    if dynamic or user_controlled:

                        findings.append({

                            "vulnerability":
                                "Cross-Site Scripting",

                            "cwe":
                                "CWE-79",

                            "line":
                                node.lineno,

                            "severity":
                                "HIGH",

                            "description":
                                "Potentially untrusted dynamic "
                                "content is written to a web response "
                                "without evidence of output encoding.",

                            "filename":
                                filename,
                        })

            # Flask-style render_template_string(...)
            if (
                isinstance(
                    node.func,
                    ast.Name
                )
                and node.func.id == "render_template_string"
            ):

                if node.args:

                    template_argument = node.args[0]

                    if (
                        _expression_contains_string_formatting(
                            template_argument
                        )
                        or _contains_user_input(
                            template_argument
                        )
                    ):

                        findings.append({

                            "vulnerability":
                                "Cross-Site Scripting",

                            "cwe":
                                "CWE-79",

                            "line":
                                node.lineno,

                            "severity":
                                "HIGH",

                            "description":
                                "Dynamic content is passed to "
                                "render_template_string() and may "
                                "allow cross-site scripting.",

                            "filename":
                                filename,
                        })

            # =================================================
            # BATCH 1 — SERVER-SIDE TEMPLATE INJECTION
            # =================================================

            template_functions = {
                "render_template_string",
                "from_string",
                "Template",
            }

            if (
                isinstance(
                    node.func,
                    ast.Name
                )
                and node.func.id in template_functions
            ):

                if node.args:

                    template_argument = node.args[0]

                    dynamic = (
                        _expression_contains_string_formatting(
                            template_argument
                        )
                    )

                    user_controlled = _contains_user_input(
                        template_argument
                    )

                    if dynamic or user_controlled:

                        findings.append({

                            "vulnerability":
                                "Server-Side Template Injection",

                            "cwe":
                                "CWE-1336",

                            "line":
                                node.lineno,

                            "severity":
                                "HIGH",

                            "description":
                                "Dynamically constructed template "
                                "content may allow server-side template "
                                "injection.",

                            "filename":
                                filename,
                        })

            # Jinja2 Environment.from_string(...)
            if (
                isinstance(
                    node.func,
                    ast.Attribute
                )
                and node.func.attr == "from_string"
            ):

                if node.args:

                    template_argument = node.args[0]

                    dynamic = (
                        _expression_contains_string_formatting(
                            template_argument
                        )
                    )

                    user_controlled = _contains_user_input(
                        template_argument
                    )

                    if dynamic or user_controlled:

                        findings.append({

                            "vulnerability":
                                "Server-Side Template Injection",

                            "cwe":
                                "CWE-1336",

                            "line":
                                node.lineno,

                            "severity":
                                "HIGH",

                            "description":
                                "Dynamically constructed template "
                                "passed to from_string() may allow "
                                "server-side template injection.",

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

        # ====================================================
        # BATCH 1 — SQL STRING ASSIGNMENT
        # ====================================================

        if isinstance(
            node,
            ast.Assign
        ):

            if isinstance(
                node.value,
                (ast.BinOp, ast.JoinedStr)
            ):

                source = _get_source_segment(
                    code,
                    node.value
                ).lower()

                sql_keywords = (
                    "select ",
                    "insert ",
                    "update ",
                    "delete ",
                    "drop ",
                    "alter ",
                    "create ",
                    "union ",
                )

                if any(
                    keyword in source
                    for keyword in sql_keywords
                ):

                    for target in node.targets:

                        if isinstance(
                            target,
                            ast.Name
                        ):

                            target_name = target.id.lower()

                            if any(
                                keyword in target_name
                                for keyword in {
                                    "sql",
                                    "query",
                                    "statement",
                                }
                            ):

                                findings.append({

                                    "vulnerability":
                                        "SQL Injection",

                                    "cwe":
                                        "CWE-89",

                                    "line":
                                        node.lineno,

                                    "severity":
                                        "HIGH",

                                    "description":
                                        "SQL statement is dynamically "
                                        "constructed using string "
                                        "interpolation or concatenation.",

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
import sqlite3

password = "admin123"

user = input("Enter command: ")

subprocess.call(
    user,
    shell=True
)

eval(user)

pickle.loads(user)

query = "SELECT * FROM users WHERE name = '" + user + "'"

conn.execute(
    query
)

response.write(
    "<html>" + user + "</html>"
)

from jinja2 import Template

template = Template(
    "<h1>" + user + "</h1>"
)

with open(user, "r") as file:
    data = file.read()
"""

    results = analyze_security(
        test_code,
        "test.py"
    )

    print("=" * 60)
    print(
        "       CodeSentinel-X Unified Security Scanner"
    )
    print("=" * 60)

    print(
        f"\nTotal findings: {len(results)}"
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
            "CWE Name:",
            finding.get("cwe_name")
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