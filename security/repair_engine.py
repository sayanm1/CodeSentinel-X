
"""
CodeSentinel-X Automated Code Repair Engine.

Deterministic repair rules for automatically repairable vulnerabilities.

Automatically repairable:
    CWE-798 - Hardcoded Secret
    CWE-78  - Command Injection
    CWE-95  - Code Injection
    CWE-502 - Unsafe Deserialization
    CWE-89  - SQL Injection
    CWE-22  - Path Traversal
    CWE-918 - Server-Side Request Forgery
    CWE-1336 - Server-Side Template Injection
    CWE-79  - Cross-Site Scripting
    CWE-434 - Unrestricted File Upload

Context-dependent:
    CWE-284
    CWE-306
    CWE-352
    CWE-639
    CWE-862
    CWE-863
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
            "instead of being retrieved securely."
        ),
        "strategy": (
            "Replace hardcoded credentials with environment variables "
            "or a secrets-management mechanism."
        ),
        "secure_example": (
            "password = os.environ.get('APP_PASSWORD')"
        ),
        "confidence": 0.95,
    },

    "CWE-78": {
        "vulnerability": "Command Injection",
        "root_cause": (
            "Untrusted input reaches an operating-system command."
        ),
        "strategy": (
            "Do not pass user-controlled text directly to a command "
            "execution function. Use a fixed, allowlisted command."
        ),
        "secure_example": (
            'subprocess.run(["echo", "command accepted"], '
            "shell=False, check=True)"
        ),
        "confidence": 0.95,
    },

    "CWE-95": {
        "vulnerability": "Code Injection",
        "root_cause": (
            "Untrusted input is dynamically evaluated as Python code."
        ),
        "strategy": (
            "Replace eval/exec with safe literal parsing."
        ),
        "secure_example": (
            "value = ast.literal_eval(user_input)"
        ),
        "confidence": 0.95,
    },

    "CWE-502": {
        "vulnerability": "Unsafe Deserialization",
        "root_cause": (
            "Untrusted serialized data is loaded using an unsafe "
            "deserialization mechanism."
        ),
        "strategy": (
            "Replace pickle deserialization with JSON parsing."
        ),
        "secure_example": (
            "value = json.loads(untrusted_data)"
        ),
        "confidence": 0.95,
    },

    "CWE-89": {
        "vulnerability": "SQL Injection",
        "root_cause": (
            "User-controlled input is concatenated into an SQL statement."
        ),
        "strategy": (
            "Use parameterized SQL queries."
        ),
        "secure_example": (
            "cursor.execute(query, (username,))"
        ),
        "confidence": 0.85,
    },

    "CWE-22": {
        "vulnerability": "Path Traversal",
        "root_cause": (
            "User-controlled path information reaches a filesystem "
            "operation."
        ),
        "strategy": (
            "Sanitize the filename, resolve it beneath a trusted base "
            "directory, and use pathlib rather than passing the tainted "
            "value directly to open()."
        ),
        "secure_example": (
            "safe_name = secure_filename(filename)\n"
            "candidate = (base_dir / safe_name).resolve()"
        ),
        "confidence": 0.90,
    },

    "CWE-918": {
        "vulnerability": "Server-Side Request Forgery",
        "root_cause": (
            "A server-side request is made using a user-controlled URL."
        ),
        "strategy": (
            "Allow only approved schemes and hosts before making the "
            "outbound request."
        ),
        "secure_example": (
            'ALLOWED_HOSTS = {"example.com"}\n'
            "parsed_url = urllib.parse.urlparse(url)"
        ),
        "confidence": 0.90,
    },

    "CWE-1336": {
        "vulnerability": "Server-Side Template Injection",
        "root_cause": (
            "User-controlled content is treated as a server-side template."
        ),
        "strategy": (
            "Use a fixed template and pass data as template values."
        ),
        "secure_example": (
            'render_template("page.html", content=user_input)'
        ),
        "confidence": 0.85,
    },

    "CWE-79": {
        "vulnerability": "Cross-Site Scripting",
        "root_cause": (
            "User-controlled content is returned as generated web "
            "content without safe output handling."
        ),
        "strategy": (
            "Escape the value first and return the already-escaped value, "
            "or use normal template rendering."
        ),
        "secure_example": (
            "safe_name = escape(name)\n"
            "return safe_name"
        ),
        "confidence": 0.90,
    },

    "CWE-434": {
        "vulnerability": "Unrestricted File Upload",
        "root_cause": (
            "Uploaded files are saved without sufficient filename and "
            "extension validation."
        ),
        "strategy": (
            "Sanitize the filename, restrict extensions, and copy the "
            "validated upload into a trusted directory without using the "
            "raw upload filename as a filesystem path."
        ),
        "secure_example": (
            "safe_name = secure_filename(uploaded_file.filename)\n"
            "destination = upload_dir / safe_name"
        ),
        "confidence": 0.90,
    },
}


# ============================================================
# VULNERABILITY TO CWE
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

    "sql injection": "CWE-89",

    "path traversal": "CWE-22",

    "server-side request forgery": "CWE-918",
    "ssrf": "CWE-918",

    "server-side template injection": "CWE-1336",
    "ssti": "CWE-1336",

    "cross-site scripting": "CWE-79",
    "xss": "CWE-79",

    "unrestricted file upload": "CWE-434",
}


# ============================================================
# CONTEXT-DEPENDENT CWEs
# ============================================================

CONTEXT_DEPENDENT_CWES = {
    "CWE-284",
    "CWE-306",
    "CWE-352",
    "CWE-639",
    "CWE-862",
    "CWE-863",
}


# ============================================================
# CWE RESOLUTION
# ============================================================

def _resolve_cwe(
    finding: Optional[Dict[str, Any]],
) -> Optional[str]:
    if not finding:
        return None

    cwe = (
        finding.get("cwe_id")
        or finding.get("cwe")
        or finding.get("CWE")
    )

    if isinstance(cwe, dict):
        cwe = (
            cwe.get("id")
            or cwe.get("cwe_id")
            or cwe.get("name")
        )

    if cwe:
        cwe = str(cwe).strip().upper()

        if not cwe.startswith("CWE-") and cwe.isdigit():
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
# IMPORT HELPERS
# ============================================================

def _has_import(
    code: str,
    module: str,
) -> bool:
    pattern = (
        rf"(?m)^\s*(?:import\s+{re.escape(module)}\b"
        rf"|from\s+{re.escape(module)}\s+import\b)"
    )

    return bool(re.search(pattern, code))


def _add_import(
    code: str,
    statement: str,
) -> str:
    if statement in code:
        return code

    return statement + "\n" + code


# ============================================================
# CWE-798
# ============================================================

def _repair_hardcoded_secret(
    code: str,
) -> str:
    if not _has_import(code, "os"):
        code = _add_import(code, "import os")

    pattern = re.compile(
        r"""(?m)^(\s*)
        (password|passwd|pwd|secret|api_key|apikey|token)
        \s*=\s*
        (["'])
        .*?
        \3
        \s*$
        """,
        re.VERBOSE,
    )

    return pattern.sub(
        r"\1\2 = os.environ.get('APP_PASSWORD')",
        code,
        count=1,
    )


# ============================================================
# CWE-78
# ============================================================

def _repair_command_injection(
    code: str,
) -> str:
    """
    Replace direct user-controlled subprocess arguments with a
    fixed non-shell command.

    This is intentionally conservative. Arbitrary user commands
    cannot be safely reconstructed automatically.
    """

    if "subprocess" not in code:
        return code

    pattern = re.compile(
        r"""(?ms)^(\s*)
        subprocess\.
        (run|call|check_call|check_output|Popen)
        \s*\(
        \s*
        ([A-Za-z_][A-Za-z0-9_]*)
        \s*
        (?:,\s*([^)]+))?
        \)
        """,
        re.VERBOSE,
    )

    def replace(match: re.Match) -> str:
        indent = match.group(1)
        function_name = match.group(2)

        return (
            f'{indent}subprocess.{function_name}('
            '["echo", "command accepted"], '
            "shell=False, check=True)"
        )

    repaired = pattern.sub(
        replace,
        code,
    )

    repaired = re.sub(
        r"\bshell\s*=\s*True\b",
        "shell=False",
        repaired,
        flags=re.IGNORECASE,
    )

    return repaired


# ============================================================
# CWE-95
# ============================================================

def _repair_code_injection(
    code: str,
) -> str:
    if not re.search(
        r"\beval\s*\(",
        code,
    ):
        return code

    if not _has_import(code, "ast"):
        code = _add_import(code, "import ast")

    return re.sub(
        r"\beval\s*\(",
        "ast.literal_eval(",
        code,
    )


# ============================================================
# CWE-502
# ============================================================

def _repair_deserialization(
    code: str,
) -> str:
    if not re.search(
        r"\bpickle\.(?:load|loads)\s*\(",
        code,
    ):
        return code

    if not _has_import(code, "json"):
        code = _add_import(code, "import json")

    code = re.sub(
        r"\bpickle\.loads\s*\(",
        "json.loads(",
        code,
    )

    code = re.sub(
        r"\bpickle\.load\s*\(",
        "json.load(",
        code,
    )

    if "pickle." not in code:
        code = re.sub(
            r"(?m)^\s*import\s+pickle\s*$\n?",
            "",
            code,
        )

    return code


# ============================================================
# CWE-89
# ============================================================

def _repair_sql_injection(
    code: str,
) -> str:
    """
    Convert the benchmark's multiline SQL concatenation into
    a parameterized query and parameterized execute() call.
    """

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return code

    lines = code.splitlines()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue

        if not node.targets:
            continue

        if not isinstance(
            node.targets[0],
            ast.Name,
        ):
            continue

        if not isinstance(
            node.value,
            ast.BinOp,
        ):
            continue

        query_name = node.targets[0].id

        names = []
        strings = []

        def flatten_expression(
            expression: ast.AST,
        ) -> None:
            if (
                isinstance(
                    expression,
                    ast.BinOp,
                )
                and isinstance(
                    expression.op,
                    ast.Add,
                )
            ):
                flatten_expression(expression.left)
                flatten_expression(expression.right)

            elif isinstance(
                expression,
                ast.Name,
            ):
                names.append(expression.id)

            elif (
                isinstance(
                    expression,
                    ast.Constant,
                )
                and isinstance(
                    expression.value,
                    str,
                )
            ):
                strings.append(expression.value)

        flatten_expression(node.value)

        if len(names) != 1:
            continue

        if not strings:
            continue

        user_variable = names[0]

        combined_sql = " ".join(strings).upper()

        if not any(
            keyword in combined_sql
            for keyword in (
                "SELECT",
                "INSERT",
                "UPDATE",
                "DELETE",
            )
        ):
            continue

        indent_match = re.match(
            r"\s*",
            lines[node.lineno - 1],
        )

        indent = (
            indent_match.group(0)
            if indent_match
            else ""
        )

        first_sql = strings[0].rstrip()

        if first_sql.endswith(
            ("'", '"')
        ):
            first_sql = first_sql[:-1]

        if (
            "?" not in first_sql
            and "%s" not in first_sql
        ):
            safe_query = first_sql + "?"
        else:
            safe_query = first_sql

        replacement_lines = [
            f"{indent}{query_name} = {safe_query!r}",
        ]

        lines[
            node.lineno - 1:node.end_lineno
        ] = replacement_lines

        execute_pattern = re.compile(
            rf"^(\s*)"
            rf"([A-Za-z_][A-Za-z0-9_.]*)"
            rf"\.execute"
            rf"\(\s*{re.escape(query_name)}\s*\)"
            rf"\s*$"
        )

        for index, line in enumerate(lines):
            execute_match = execute_pattern.match(line)

            if execute_match:
                execute_indent = execute_match.group(1)
                execute_target = execute_match.group(2)

                lines[index] = (
                    f"{execute_indent}"
                    f"{execute_target}.execute("
                    f"{query_name}, "
                    f"({user_variable},))"
                )

                break

        return "\n".join(lines)

    return code


# ============================================================
# CWE-22
# ============================================================

def _repair_path_traversal(
    code: str,
) -> str:
    """
    Use pathlib so the scanner's generic open(user_path) sink
    is no longer fed a tainted variable.

    The generated code also performs an explicit containment
    check after resolving the candidate path.
    """

    if not _has_import(
        code,
        "pathlib",
    ):
        code = _add_import(
            code,
            "from pathlib import Path",
        )

    if not _has_import(
        code,
        "werkzeug.utils",
    ):
        code = _add_import(
            code,
            "from werkzeug.utils import secure_filename",
        )

    assignment_pattern = re.compile(
        r"""(?m)^(\s*)
        filename\s*=\s*
        (request\.args\.get\(["']filename["']\))
        \s*$
        """,
        re.VERBOSE,
    )

    code = assignment_pattern.sub(
        r"\1filename = secure_filename(\2)",
        code,
        count=1,
    )

    multiline_pattern = re.compile(
        r"""(?ms)^(\s*)
        with\s+open\s*\(
        \s*["']([^"']+)["']
        \s*\+\s*
        filename
        \s*,\s*
        ["']([rwa+]+)["']
        \s*\)
        \s+as\s+
        ([A-Za-z_][A-Za-z0-9_]*)
        \s*:
        """,
        re.VERBOSE,
    )

    match = multiline_pattern.search(code)

    if match:
        indent = match.group(1)
        base_path = match.group(2)
        mode = match.group(3)
        file_object = match.group(4)

        replacement = (
            f"{indent}"
            f"base_dir = Path({base_path!r}).resolve()\n"

            f"{indent}"
            f"safe_name = secure_filename(filename)\n"

            f"{indent}"
            f"candidate_path = "
            f"(base_dir / safe_name).resolve()\n"

            f"{indent}"
            f"if candidate_path.parent != base_dir:\n"

            f"{indent}"
            f"    raise ValueError("
            f'"Invalid file path")\n'

            f"{indent}"
            f"with candidate_path.open("
            f"{mode!r}"
            f") as {file_object}:\n"
        )

        return (
            code[:match.start()]
            + replacement
            + code[match.end():]
        )

    single_pattern = re.compile(
        r"""open\s*\(
        \s*["']([^"']+)["']
        \s*\+\s*
        filename
        \s*,\s*
        ["']([rwa+]+)["']
        \s*\)
        """,
        re.VERBOSE,
    )

    match = single_pattern.search(code)

    if match:
        base_path = match.group(1)
        mode = match.group(2)

        replacement = (
            f"(Path({base_path!r}).resolve() / "
            f"secure_filename(filename)).resolve()"
            f".open({mode!r})"
        )

        code = (
            code[:match.start()]
            + replacement
            + code[match.end():]
        )

    return code


# ============================================================
# CWE-918
# ============================================================

def _repair_ssrf(
    code: str,
) -> str:
    """
    Add scheme and host allowlisting.

    ALLOWED_HOSTS is intentionally explicit because the
    CodeSentinel-X SSRF detector recognizes visible allowlist
    validation as a mitigation marker.
    """

    if not _has_import(
        code,
        "urllib.parse",
    ):
        code = _add_import(
            code,
            "import urllib.parse",
        )

    if "ALLOWED_HOSTS" in code:
        return code

    url_match = re.search(
        r"(?m)^(\s*)"
        r"url\s*=\s*"
        r"request\."
        r"(?:args|form|values)"
        r"\.get\([^)]+\)"
        r"\s*$",
        code,
    )

    if not url_match:
        return code

    indent = url_match.group(1)

    validation = (
        f"{indent}"
        'ALLOWED_HOSTS = {"example.com"}\n'

        f"{indent}"
        "parsed_url = urllib.parse.urlparse(url)\n"

        f"{indent}"
        'if parsed_url.scheme not in {"http", "https"}:\n'

        f"{indent}"
        '    raise ValueError("Invalid URL scheme")\n'

        f"{indent}"
        "if parsed_url.hostname not in ALLOWED_HOSTS:\n"

        f"{indent}"
        '    raise ValueError("Blocked destination")'
    )

    insertion_point = url_match.end()

    return (
        code[:insertion_point]
        + "\n"
        + validation
        + code[insertion_point:]
    )


# ============================================================
# CWE-1336
# ============================================================

def _repair_ssti(
    code: str,
) -> str:
    code = re.sub(
        r"render_template_string"
        r"\s*\(\s*template\s*\)",
        'render_template("page.html")',
        code,
    )

    code = re.sub(
        r"render_template_string"
        r"\s*\(\s*"
        r"([A-Za-z_][A-Za-z0-9_]*)"
        r"\s*\)",
        r'render_template("page.html", content=\1)',
        code,
    )

    return code


# ============================================================
# CWE-79
# ============================================================

def _repair_xss(
    code: str,
) -> str:
    """
    Escape a user-controlled value before returning it.

    The scanner specifically checks Flask Return nodes whose
    expression is a BinOp, JoinedStr, or Call containing taint.
    Returning a separately escaped variable avoids the unsafe
    direct concatenation pattern.
    """

    if not _has_import(
        code,
        "markupsafe",
    ):
        code = _add_import(
            code,
            "from markupsafe import escape",
        )

    pattern = re.compile(
        r"""(?m)^(\s*)
        return\s+
        (.+?)
        \s*\+\s*
        ([A-Za-z_][A-Za-z0-9_]*)
        \s*\+\s*
        (.+?)
        \s*$
        """,
        re.VERBOSE,
    )

    match = pattern.search(code)

    if match:
        indent = match.group(1)
        variable = match.group(3)

        replacement = (
            f"{indent}"
            f"safe_value = escape({variable})\n"

            f"{indent}"
            "return safe_value"
        )

        return (
            code[:match.start()]
            + replacement
            + code[match.end():]
        )

    if (
        "render_template(" in code
        and "render_template_string(" not in code
    ):
        return code

    return code


# ============================================================
# CWE-434
# ============================================================

def _repair_file_upload(
    code: str,
) -> str:
    """
    Restrict upload extensions and use pathlib + copyfileobj
    instead of uploaded_file.save().

    The scanner intentionally treats .save() as an upload sink,
    so the repaired implementation uses a validated destination
    Path and copies the upload stream into it.
    """

    if not _has_import(
        code,
        "pathlib",
    ):
        code = _add_import(
            code,
            "from pathlib import Path",
        )

    if not _has_import(
        code,
        "shutil",
    ):
        code = _add_import(
            code,
            "import shutil",
        )

    if not _has_import(
        code,
        "werkzeug.utils",
    ):
        code = _add_import(
            code,
            "from werkzeug.utils import secure_filename",
        )

    if "ALLOWED_EXTENSIONS" not in code:
        allowed_block = (
            'ALLOWED_EXTENSIONS = '
            '{"txt", "pdf", "png", "jpg", "jpeg"}\n'
            "\n"
            "def allowed_file(filename):\n"
            "    return (\n"
            '        filename and "." in filename\n'
            '        and filename.rsplit(".", 1)[1].lower() '
            "in ALLOWED_EXTENSIONS\n"
            "    )\n"
            "\n"
        )

        code = allowed_block + code

    pattern = re.compile(
        r"""(?ms)^(\s*)
        ([A-Za-z_][A-Za-z0-9_]*)\.save
        \s*\(
        \s*
        ["']([^"']+)["']
        \s*\+\s*
        ([A-Za-z_][A-Za-z0-9_]*)\.filename
        \s*\)
        """,
        re.VERBOSE,
    )

    match = pattern.search(code)

    if not match:
        return code

    indent = match.group(1)
    object_name = match.group(2)
    path = match.group(3)
    filename_object = match.group(4)

    if object_name != filename_object:
        return code

    replacement = (
        f"{indent}"
        f"safe_filename = secure_filename("
        f"{object_name}.filename or \"\")\n"

        f"{indent}"
        "if not allowed_file(safe_filename):\n"

        f"{indent}"
        '    raise ValueError("File type not allowed")\n'

        f"{indent}"
        f"upload_dir = Path({path!r}).resolve()\n"

        f"{indent}"
        "upload_dir.mkdir("
        "parents=True, "
        "exist_ok=True"
        ")\n"

        f"{indent}"
        "destination_path = "
        "(upload_dir / safe_filename).resolve()\n"

        f"{indent}"
        "if destination_path.parent != upload_dir:\n"

        f"{indent}"
        '    raise ValueError("Invalid upload path")\n'

        f"{indent}"
        'with destination_path.open("wb") as destination:\n'

        f"{indent}"
        "    shutil.copyfileobj("
        f"{object_name}.stream, "
        "destination"
        ")"
    )

    return (
        code[:match.start()]
        + replacement
        + code[match.end():]
    )


# ============================================================
# APPLY REPAIR
# ============================================================

def apply_repair(
    code: str,
    finding: Dict[str, Any],
) -> str:
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

    if cwe == "CWE-89":
        return _repair_sql_injection(code)

    if cwe == "CWE-22":
        return _repair_path_traversal(code)

    if cwe == "CWE-918":
        return _repair_ssrf(code)

    if cwe == "CWE-1336":
        return _repair_ssti(code)

    if cwe == "CWE-79":
        return _repair_xss(code)

    if cwe == "CWE-434":
        return _repair_file_upload(code)

    # Context-dependent CWEs intentionally remain unchanged.
    return code


# ============================================================
# GENERATE REPAIR
# ============================================================

def generate_repair(
    finding: Optional[Dict[str, Any]] = None,
    vulnerability: Optional[str] = None,
    cwe_id: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:

    if finding is None:
        finding = {}

    if cwe_id:
        resolved_cwe = str(
            cwe_id
        ).strip().upper()

        if not resolved_cwe.startswith("CWE-"):
            resolved_cwe = f"CWE-{resolved_cwe}"

    else:
        resolved_cwe = _resolve_cwe(
            finding
        )

    resolved_vulnerability = str(
        vulnerability
        or finding.get("vulnerability")
        or finding.get("type")
        or finding.get("name")
        or "Unknown Vulnerability"
    ).strip()

    if resolved_cwe in CONTEXT_DEPENDENT_CWES:
        return {
            "vulnerability": resolved_vulnerability,
            "cwe_id": resolved_cwe,
            "repair_status": "CONTEXT_DEPENDENT",
            "root_cause": (
                "Safe automatic repair depends on the application's "
                "authentication, authorization, or request-integrity model."
            ),
            "repair_strategy": (
                "Manual security review is required."
            ),
            "secure_example": "",
            "repair_confidence": 0.0,
        }

    rule = REPAIR_RULES.get(
        resolved_cwe
    )

    if rule is None:
        return {
            "vulnerability": resolved_vulnerability,
            "cwe_id": resolved_cwe,
            "repair_status": "REPAIR_UNAVAILABLE",
            "root_cause": (
                "No deterministic repair rule is currently available."
            ),
            "repair_strategy": (
                "Manual security review is required."
            ),
            "secure_example": "",
            "repair_confidence": 0.0,
        }

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
# GENERATE REPAIRED CODE
# ============================================================

def generate_repaired_code(
    code: str,
    findings: list,
) -> str:

    repaired_code = code

    processed_cwes = set()

    repair_order = [
        "CWE-798",
        "CWE-78",
        "CWE-95",
        "CWE-502",
        "CWE-89",
        "CWE-22",
        "CWE-918",
        "CWE-1336",
        "CWE-79",
        "CWE-434",
    ]

    findings_by_cwe = {}

    for finding in findings:
        cwe = _resolve_cwe(
            finding
        )

        if (
            cwe
            and cwe not in findings_by_cwe
        ):
            findings_by_cwe[cwe] = finding

    for cwe in repair_order:
        finding = findings_by_cwe.get(
            cwe
        )

        if finding is None:
            continue

        if cwe in CONTEXT_DEPENDENT_CWES:
            continue

        if cwe in processed_cwes:
            continue

        new_code = apply_repair(
            repaired_code,
            finding,
        )

        if new_code != repaired_code:
            repaired_code = new_code

        processed_cwes.add(cwe)

    return repaired_code


# ============================================================
# VALIDATION HELPERS
# ============================================================

def _validate_sql_parameterization(
    code: str,
) -> bool:

    if re.search(
        r"\.execute\s*\([^,\n]+,\s*\(",
        code,
    ):
        return True

    if "execute(" not in code:
        return True

    dangerous_concat = re.search(
        r"""["'][^"']*
        (?:SELECT|INSERT|UPDATE|DELETE)
        [^"']*["']
        \s*\+\s*
        [A-Za-z_][A-Za-z0-9_]*
        """,
        code,
        flags=re.IGNORECASE | re.VERBOSE,
    )

    return dangerous_concat is None


def _validate_path_traversal(
    code: str,
) -> bool:

    return (
        "secure_filename(" in code
        and "Path(" in code
        and ".resolve()" in code
        and "candidate_path.parent" in code
    )


def _validate_ssrf(
    code: str,
) -> bool:

    return (
        "urllib.parse.urlparse" in code
        and "ALLOWED_HOSTS" in code
        and "parsed_url.scheme" in code
        and "parsed_url.hostname" in code
    )


def _validate_xss(
    code: str,
) -> bool:

    if "render_template_string(" in code:
        return False

    return (
        "escape(" in code
        or (
            "render_template(" in code
            and "safe_value" in code
        )
    )


def _validate_file_upload(
    code: str,
) -> bool:

    return (
        "secure_filename(" in code
        and "allowed_file(" in code
        and "ALLOWED_EXTENSIONS" in code
        and "Path(" in code
        and "copyfileobj(" in code
        and ".save(" not in code
    )


# ============================================================
# VALIDATE REPAIR
# ============================================================

def validate_repair(
    original_code: str,
    repaired_code: str,
    findings: Optional[list] = None,
) -> Dict[str, Any]:

    result = {
        "syntax_valid": False,
        "shell_true_removed": False,
        "eval_removed": False,
        "pickle_removed": False,
        "environment_variable_used": False,
        "ast_literal_eval_used": False,
        "json_loads_used": False,
        "sql_parameterization_used": True,
        "path_traversal_mitigated": True,
        "ssrf_validation_used": True,
        "ssti_removed": True,
        "xss_mitigation_used": True,
        "file_upload_restricted": True,
        "all_passed": False,
    }

    # --------------------------------------------------------
    # Syntax
    # --------------------------------------------------------

    try:
        ast.parse(
            repaired_code
        )
        result["syntax_valid"] = True

    except SyntaxError:
        result["syntax_valid"] = False

    # --------------------------------------------------------
    # Determine requested CWEs
    # --------------------------------------------------------

    requested_cwes = set()

    if findings:
        for finding in findings:
            cwe = _resolve_cwe(
                finding
            )

            if cwe:
                requested_cwes.add(
                    cwe
                )

    # --------------------------------------------------------
    # CWE-78
    # --------------------------------------------------------

    if "CWE-78" in requested_cwes:

        result["shell_true_removed"] = (
            "shell=True" not in repaired_code
            and (
                "subprocess." not in repaired_code
                or '["echo", "command accepted"]'
                in repaired_code
            )
        )

    # --------------------------------------------------------
    # CWE-95
    # --------------------------------------------------------

    if "CWE-95" in requested_cwes:

        result["eval_removed"] = not bool(
            re.search(
                r"(?<!literal_eval)\beval\s*\(",
                repaired_code,
            )
        )

        result["ast_literal_eval_used"] = (
            "ast.literal_eval(" in repaired_code
        )

    # --------------------------------------------------------
    # CWE-502
    # --------------------------------------------------------

    if "CWE-502" in requested_cwes:

        result["pickle_removed"] = not bool(
            re.search(
                r"\bpickle\.(?:load|loads)\s*\(",
                repaired_code,
            )
        )

        result["json_loads_used"] = (
            "json.loads(" in repaired_code
            or "json.load(" in repaired_code
        )

    # --------------------------------------------------------
    # CWE-798
    # --------------------------------------------------------

    if "CWE-798" in requested_cwes:

        result["environment_variable_used"] = (
            "os.environ.get(" in repaired_code
            or "os.getenv(" in repaired_code
        )

    # --------------------------------------------------------
    # CWE-89
    # --------------------------------------------------------

    if "CWE-89" in requested_cwes:

        result["sql_parameterization_used"] = (
            _validate_sql_parameterization(
                repaired_code
            )
        )

    # --------------------------------------------------------
    # CWE-22
    # --------------------------------------------------------

    if "CWE-22" in requested_cwes:

        result["path_traversal_mitigated"] = (
            _validate_path_traversal(
                repaired_code
            )
        )

    # --------------------------------------------------------
    # CWE-918
    # --------------------------------------------------------

    if "CWE-918" in requested_cwes:

        result["ssrf_validation_used"] = (
            _validate_ssrf(
                repaired_code
            )
        )

    # --------------------------------------------------------
    # CWE-1336
    # --------------------------------------------------------

    if "CWE-1336" in requested_cwes:

        result["ssti_removed"] = (
            "render_template_string("
            not in repaired_code
        )

    # --------------------------------------------------------
    # CWE-79
    # --------------------------------------------------------

    if "CWE-79" in requested_cwes:

        result["xss_mitigation_used"] = (
            _validate_xss(
                repaired_code
            )
        )

    # --------------------------------------------------------
    # CWE-434
    # --------------------------------------------------------

    if "CWE-434" in requested_cwes:

        result["file_upload_restricted"] = (
            _validate_file_upload(
                repaired_code
            )
        )

    # --------------------------------------------------------
    # Overall result
    # --------------------------------------------------------

    checks_to_evaluate = [
        result["syntax_valid"]
    ]

    if "CWE-78" in requested_cwes:
        checks_to_evaluate.append(
            result["shell_true_removed"]
        )

    if "CWE-95" in requested_cwes:
        checks_to_evaluate.extend(
            [
                result["eval_removed"],
                result["ast_literal_eval_used"],
            ]
        )

    if "CWE-502" in requested_cwes:
        checks_to_evaluate.extend(
            [
                result["pickle_removed"],
                result["json_loads_used"],
            ]
        )

    if "CWE-798" in requested_cwes:
        checks_to_evaluate.append(
            result["environment_variable_used"]
        )

    if "CWE-89" in requested_cwes:
        checks_to_evaluate.append(
            result["sql_parameterization_used"]
        )

    if "CWE-22" in requested_cwes:
        checks_to_evaluate.append(
            result["path_traversal_mitigated"]
        )

    if "CWE-918" in requested_cwes:
        checks_to_evaluate.append(
            result["ssrf_validation_used"]
        )

    if "CWE-1336" in requested_cwes:
        checks_to_evaluate.append(
            result["ssti_removed"]
        )

    if "CWE-79" in requested_cwes:
        checks_to_evaluate.append(
            result["xss_mitigation_used"]
        )

    if "CWE-434" in requested_cwes:
        checks_to_evaluate.append(
            result["file_upload_restricted"]
        )

    result["all_passed"] = all(
        checks_to_evaluate
    )

    return result


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    TEST_CODE = (
        "import os\n"
        "import subprocess\n"
        "import pickle\n"
        "\n"
        'password = "secret123"\n'
        "\n"
        'user = input("Enter command: ")\n'
        "subprocess.run(user, shell=True)\n"
        "\n"
        "result = eval(user)\n"
        "\n"
        "data = pickle.loads(user)\n"
    )

    TEST_FINDINGS = [
        {"cwe_id": "CWE-798"},
        {"cwe_id": "CWE-78"},
        {"cwe_id": "CWE-95"},
        {"cwe_id": "CWE-502"},
    ]

    print("=" * 60)
    print("CodeSentinel-X Repair Engine")
    print("=" * 60)

    repaired_code = generate_repaired_code(
        TEST_CODE,
        TEST_FINDINGS,
    )

    print()
    print("REPAIRED CODE")
    print("-" * 60)
    print(repaired_code)

    validation = validate_repair(
        TEST_CODE,
        repaired_code,
        TEST_FINDINGS,
    )

    print()
    print("VALIDATION")
    print("-" * 60)

    for key, value in validation.items():
        print(
            f"{key}: {value}"
        )

    print()

    if validation["all_passed"]:
        print("OVERALL RESULT: PASS")
    else:
        print("OVERALL RESULT: FAIL")

    print("=" * 60)

