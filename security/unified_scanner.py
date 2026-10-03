import ast
import subprocess
import tempfile
import os
import json
import re


# ============================================================
# CWE MAPPING
# ============================================================

CWE_MAP = {
    "hardcoded password": "CWE-798", "hardcoded secret": "CWE-798",
    "hardcoded credential": "CWE-798", "hardcoded_password_string": "CWE-798",
    "command injection": "CWE-78", "command execution": "CWE-78", "shell=true": "CWE-78",
    "code injection": "CWE-95", "eval": "CWE-95", "exec": "CWE-95",
    "unsafe deserialization": "CWE-502", "insecure deserialization": "CWE-502", "pickle": "CWE-502",
    "missing authorization": "CWE-862", "incorrect authorization": "CWE-863",
    "improper access control": "CWE-284", "missing authentication for critical function": "CWE-306",
    "missing authentication": "CWE-306", "improper authentication": "CWE-287",
    "authorization bypass through user-controlled key": "CWE-639",
    "server-side request forgery": "CWE-918", "ssrf": "CWE-918",
    "cross-site scripting": "CWE-79", "xss": "CWE-79", "sql injection": "CWE-89",
    "server-side template injection": "CWE-1336", "ssti": "CWE-1336",
    "path traversal": "CWE-22", "directory traversal": "CWE-22", "path_traversal": "CWE-22",
    "unrestricted file upload": "CWE-434", "unrestricted upload": "CWE-434",
    "unsafe file upload": "CWE-434", "file upload": "CWE-434",
    "cross-site request forgery": "CWE-352", "csrf": "CWE-352",
    "open redirect": "CWE-601", "xxe": "CWE-611", "xml external entity": "CWE-611",
    "risky cryptography": "CWE-327", "weak cryptography": "CWE-327",
    "weak password hashing": "CWE-916", "cleartext sensitive data": "CWE-312",
    "cleartext transmission": "CWE-319", "sensitive information in logs": "CWE-532",
    "log injection": "CWE-117", "insufficient logging": "CWE-778",
    "inadequate encryption strength": "CWE-326",
}

CWE_NAMES = {
    "CWE-798": "Use of Hard-coded Credentials", "CWE-78": "OS Command Injection",
    "CWE-95": "Code Injection", "CWE-502": "Deserialization of Untrusted Data",
    "CWE-79": "Cross-Site Scripting", "CWE-89": "SQL Injection",
    "CWE-1336": "Server-Side Template Injection", "CWE-22": "Path Traversal",
    "CWE-434": "Unrestricted File Upload", "CWE-352": "Cross-Site Request Forgery",
    "CWE-601": "Open Redirect", "CWE-611": "XML External Entity (XXE)",
    "CWE-327": "Risky Cryptography", "CWE-916": "Weak Password Hashing",
    "CWE-312": "Cleartext Sensitive Data", "CWE-319": "Cleartext Transmission",
    "CWE-532": "Sensitive Information in Logs", "CWE-117": "Log Injection",
    "CWE-778": "Insufficient Logging", "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication for Critical Function", "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization", "CWE-284": "Improper Access Control",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-918": "Server-Side Request Forgery", "CWE-326": "Inadequate Encryption Strength",
}

BANDIT_IMPORT_ADVISORIES = {"B403", "B404"}
BANDIT_CWE_MAP = {
    "B105": "CWE-798", "B106": "CWE-798", "B107": "CWE-798",
    "B307": "CWE-95", "B301": "CWE-502", "B506": "CWE-502",
    "B602": "CWE-78", "B324": "CWE-327",
}


def _extract_cwe_id(value):
    import re
    if not value:
        return None
    match = re.search(r"\bCWE[-_ ]?(\d+)\b", str(value), re.IGNORECASE)
    return f"CWE-{match.group(1)}" if match else None


def normalize_vulnerability(value, description="", cwe=None, source=None, test_id=None):
    raw = str(value or "").strip()
    text = f"{raw} {description or ''}".lower()
    canonical_cwe = _extract_cwe_id(cwe)

    if canonical_cwe in CWE_NAMES:
        return {
            "CWE-798": "Hardcoded Secret", "CWE-78": "Command Injection", "CWE-95": "Code Injection",
            "CWE-502": "Unsafe Deserialization", "CWE-79": "Cross-Site Scripting", "CWE-89": "SQL Injection",
            "CWE-1336": "Server-Side Template Injection", "CWE-22": "Path Traversal", "CWE-434": "Unrestricted File Upload",
            "CWE-352": "Cross-Site Request Forgery", "CWE-601": "Open Redirect", "CWE-611": "XML External Entity (XXE)",
            "CWE-918": "Server-Side Request Forgery", "CWE-327": "Risky Cryptography", "CWE-916": "Weak Password Hashing",
            "CWE-312": "Cleartext Sensitive Data", "CWE-319": "Cleartext Transmission", "CWE-532": "Sensitive Information in Logs",
            "CWE-117": "Log Injection", "CWE-778": "Insufficient Logging", "CWE-287": "Improper Authentication",
            "CWE-306": "Missing Authentication for Critical Function", "CWE-862": "Missing Authorization",
            "CWE-863": "Incorrect Authorization", "CWE-284": "Improper Access Control",
            "CWE-639": "Authorization Bypass Through User-Controlled Key", "CWE-326": "Inadequate Encryption Strength",
        }[canonical_cwe]

    if source == "bandit" and test_id in BANDIT_CWE_MAP:
        return normalize_vulnerability("", cwe=BANDIT_CWE_MAP[test_id])
    if "hardcoded" in text and any(k in text for k in ("password", "secret", "credential", "api key", "token")): return "Hardcoded Secret"
    if "shell=true" in text or "command injection" in text: return "Command Injection"
    if "eval(" in text or "exec(" in text or "code injection" in text: return "Code Injection"
    if "pickle" in text or "deserialization" in text or "yaml.load" in text: return "Unsafe Deserialization"
    if "cross-site scripting" in text or "xss" in text or "web page generation" in text: return "Cross-Site Scripting"
    if "sql injection" in text or "sql command" in text: return "SQL Injection"
    if "template injection" in text or "ssti" in text or "template engine" in text: return "Server-Side Template Injection"
    if "path traversal" in text or "directory traversal" in text: return "Path Traversal"
    if "file upload" in text or "dangerous type" in text: return "Unrestricted File Upload"
    if "csrf" in text or "cross-site request forgery" in text: return "Cross-Site Request Forgery"
    if "open redirect" in text or "unvalidated redirect" in text: return "Open Redirect"
    if "xml external entity" in text or "xxe" in text or "external entity" in text: return "XML External Entity (XXE)"
    if "server-side request forgery" in text or "ssrf" in text: return "Server-Side Request Forgery"
    if "weak password" in text or "password hashing" in text: return "Weak Password Hashing"
    if "md5" in text or "sha1" in text or "weak cryptographic" in text or "risky cryptography" in text: return "Risky Cryptography"
    if "encryption strength" in text or "tripledes" in text or "3des" in text: return "Inadequate Encryption Strength"
    if "cleartext sensitive" in text: return "Cleartext Sensitive Data"
    if "cleartext transmission" in text or "http://" in text: return "Cleartext Transmission"
    if "sensitive information in logs" in text: return "Sensitive Information in Logs"
    if "log injection" in text: return "Log Injection"
    if "insufficient logging" in text: return "Insufficient Logging"
    if "improper authentication" in text: return "Improper Authentication"
    if "missing authentication" in text: return "Missing Authentication for Critical Function"
    if "missing authorization" in text: return "Missing Authorization"
    if "incorrect authorization" in text: return "Incorrect Authorization"
    if "improper access control" in text: return "Improper Access Control"
    if "authorization bypass" in text: return "Authorization Bypass Through User-Controlled Key"
    return raw.title() if raw else "Unknown Vulnerability"


def infer_cwe(vulnerability, description="", source=None, test_id=None, explicit_cwe=None):
    explicit = _extract_cwe_id(explicit_cwe)

    # Bandit may report manual SQL string construction as CWE-704.
    # CodeSentinel-X classifies this vulnerability under CWE-89 SQL Injection.
    if explicit == "CWE-704":
        explicit = "CWE-89"

    if explicit:
        return explicit
    if source == "bandit" and test_id in BANDIT_CWE_MAP:
        return BANDIT_CWE_MAP[test_id]
    text = f"{vulnerability or ''} {description or ''}".lower()

    # Match identifier-like detector keywords as whole words.
    # Without boundaries, "exec" would match "executable" in
    # unrelated Bandit messages such as B607.
    identifier_keywords = {"eval", "exec", "pickle"}

    for keyword, cwe in CWE_MAP.items():
        if keyword in identifier_keywords:
            if re.search(
                rf"(?<![A-Za-z0-9_]){re.escape(keyword)}(?![A-Za-z0-9_])",
                text,
            ):
                return cwe
        elif keyword in text:
            return cwe

    return None

# ============================================================
# SEVERITY NORMALIZATION
# ============================================================

def normalize_severity(
    severity=None,
    vulnerability="",
    description="",
):
    supplied = str(severity or "").upper()
    text = f"{vulnerability} {description}".lower()
    high_indicators = {
        "hardcoded secret", "command injection", "code injection", "unsafe deserialization",
        "sql injection", "path traversal", "unrestricted file upload", "cross-site request forgery",
        "server-side request forgery", "xml external entity", "open redirect", "missing authentication",
        "missing authorization", "incorrect authorization", "improper authentication", "authorization bypass",
    }
    if any(indicator in text for indicator in high_indicators):
        return "HIGH"
    if supplied in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return supplied
    if "xss" in text or "cross-site scripting" in text or "ssti" in text or "template injection" in text:
        return "MEDIUM"
    return "LOW"


# ============================================================
# USER INPUT DETECTION
# ============================================================

def _contains_user_input(node):

    if node is None:
        return False

    for child in ast.walk(node):

        # Direct input()
        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
            and child.func.id == "input"
        ):
            return True

        # request.files
        if (
            isinstance(child, ast.Attribute)
            and child.attr == "files"
        ):
            return True

        # request.form
        if (
            isinstance(child, ast.Attribute)
            and child.attr == "form"
        ):
            return True

        # request.args
        if (
            isinstance(child, ast.Attribute)
            and child.attr == "args"
        ):
            return True

        # request.data
        if (
            isinstance(child, ast.Attribute)
            and child.attr == "data"
        ):
            return True

        # Common user-controlled variable names
        if isinstance(child, ast.Name):

            if child.id.lower() in {

                "user_input",
                "userinput",
                "input_data",
                # "query" alone is not evidence of user-controlled input.
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

                "upload",
                "uploaded",
                "uploaded_file",
                "file",

                # Template values are commonly user-controlled in SSTI
                "template",
                "template_string",
                "jinja_template",
                "template_data",
            }:
                return True

    return False


# ============================================================
# AST SCANNER
# ============================================================

def scan_ast(
    code,
    filename="<string>",
):

    findings = []

    # Track variables whose values are derived from user-controlled input.
    # This allows simple data-flow detection such as:
    # user_input = input(...)
    # query = "..." + user_input
    # connection.execute(query)
    tainted_variables = set()

    try:

        tree = ast.parse(
            code
        )

    except SyntaxError:

        return findings

    # Pre-pass: collect variables derived from user-controlled input.
    # This is intentionally conservative and performs a few fixed-point
    # passes so simple flows such as request -> username -> query are
    # recognized without treating variable names like `query` as tainted.
    statements = list(ast.walk(tree))
    for _ in range(8):
        changed = False
        for statement in statements:
            value = None
            targets = []

            if isinstance(statement, ast.Assign):
                value = statement.value
                targets = [t for t in statement.targets if isinstance(t, ast.Name)]
            elif isinstance(statement, ast.AnnAssign):
                value = statement.value
                if isinstance(statement.target, ast.Name):
                    targets = [statement.target]

            if value is None or not targets:
                continue

            direct_taint = _contains_user_input(value)
            propagated_taint = any(
                isinstance(child, ast.Name) and child.id in tainted_variables
                for child in ast.walk(value)
            )

            if direct_taint or propagated_taint:
                for target in targets:
                    if target.id not in tainted_variables:
                        tainted_variables.add(target.id)
                        changed = True

        if not changed:
            break

    for node in ast.walk(tree):

        # ====================================================
        # CALL DETECTORS
        # ====================================================

        if isinstance(
            node,
            ast.Call,
        ):

            function_name = None

            if isinstance(
                node.func,
                ast.Name,
            ):

                function_name = (
                    node.func.id
                )

            elif isinstance(
                node.func,
                ast.Attribute,
            ):

                function_name = (
                    node.func.attr
                )

            # =================================================
            # CWE-798 â€” HARDCODED SECRET
            # =================================================

            if (
                isinstance(
                    node.func,
                    ast.Name,
                )
                and node.func.id in {
                    "password",
                    "secret",
                }
            ):

                if node.args:

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
                            "Potential hardcoded credential.",

                        "filename":
                            filename,
                    })

            # =================================================
            # CWE-78 â€” COMMAND INJECTION
            # =================================================

            if function_name in {

                "system",
                "popen",
                "run",
                "call",
                "check_call",
                "check_output",
            }:

                if node.args:

                    argument = node.args[0]

                    shell_false = any(
                        isinstance(keyword, ast.keyword)
                        and keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is False
                        for keyword in node.keywords
                    )

                    # subprocess.run(["echo", user], shell=False)
                    # uses a fixed executable and passes user input as
                    # an argument. Do not classify that as command
                    # injection merely because a later argv element
                    # contains user-controlled data.
                    fixed_executable_argument = (
                        isinstance(argument, (ast.List, ast.Tuple))
                        and len(argument.elts) > 0
                        and isinstance(argument.elts[0], ast.Constant)
                        and isinstance(argument.elts[0].value, str)
                    )

                    if _contains_user_input(argument) and not (
                        shell_false and fixed_executable_argument
                    ):

                        findings.append({

                            "vulnerability":
                                "Command Injection",

                            "cwe":
                                "CWE-78",

                            "line":
                                node.lineno,

                            "severity":
                                "MEDIUM",

                            "description":
                                "User-controlled input reaches "
                                "a command execution function.",

                            "filename":
                                filename,
                        })
            # =================================================
            # CWE-95 â€” CODE INJECTION
            # =================================================

            if (
                isinstance(
                    node.func,
                    ast.Name,
                )
                and node.func.id in {
                    "eval",
                    "exec",
                }
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
                        "Dynamic execution of code may allow "
                        "untrusted input to execute arbitrary code.",

                    "filename":
                        filename,
                })

            # =================================================
            # CWE-502 â€” UNSAFE DESERIALIZATION
            # =================================================

            if (
                isinstance(
                    node.func,
                    ast.Attribute,
                )
                and node.func.attr == "loads"
                and isinstance(
                    node.func.value,
                    ast.Name,
                )
                and node.func.value.id == "pickle"
            ):

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
                        "Deserialization using pickle may "
                        "execute malicious objects from "
                        "untrusted data.",

                    "filename":
                        filename,
                })

            # =================================================
            # CWE-79 â€” CROSS-SITE SCRIPTING
            # =================================================

            if (
                isinstance(
                    node.func,
                    ast.Attribute,
                )
                and node.func.attr in {
                    "write",
                    "render",
                }
            ):

                if node.args:

                    argument = node.args[0]

                    if _contains_user_input(
                        argument
                    ):

                        findings.append({

                            "vulnerability":
                                "Cross-Site Scripting",

                            "cwe":
                                "CWE-79",

                            "line":
                                node.lineno,

                            "severity":
                                "MEDIUM",

                            "description":
                                "User-controlled input may be "
                                "written into generated web "
                                "content without proper "
                                "output encoding.",

                            "filename":
                                filename,
                        })

            # =================================================
            # CWE-89 â€” SQL INJECTION
            # =================================================

            if (
                isinstance(
                    node.func,
                    ast.Attribute,
                )
                and node.func.attr in {
                    "execute",
                    "executemany",
                }
            ):

                if node.args:

                    query_argument = (
                        node.args[0]
                    )

                    query_is_user_controlled = (
                        _contains_user_input(query_argument)
                        or (
                            isinstance(query_argument, ast.Name)
                            and query_argument.id in tainted_variables
                        )
                    )

                    if query_is_user_controlled:

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
                                "User-controlled input may "
                                "reach a SQL execution function "
                                "without proper parameterization.",

                            "filename":
                                filename,
                        })

            # =================================================
            # CWE-1336 — SSTI
            # Detect common Flask/Jinja2 template sinks when the template
            # argument is directly user-controlled or derived from a
            # user-controlled variable.
            ssti_sink = False

            if isinstance(node.func, ast.Name):
                ssti_sink = node.func.id in {
                    "Template",
                    "render_template_string",
                }

            elif isinstance(node.func, ast.Attribute):
                ssti_sink = node.func.attr in {
                    "from_string",
                    "render_template_string",
                }

            if ssti_sink and node.args:

                template_argument = node.args[0]

                if _contains_user_input(template_argument):

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
                            "User-controlled input may be interpreted "
                            "as a server-side template.",
                        "filename":
                            filename,
                    })

            # =================================================
            # CWE-22 â€” PATH TRAVERSAL
            # =================================================

            if (
                isinstance(
                    node.func,
                    ast.Name,
                )
                and node.func.id == "open"
            ):

                if node.args:

                    path_argument = (
                        node.args[0]
                    )

                    user_controlled = (
                        _contains_user_input(
                            path_argument
                        )
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

            # =================================================
            # CWE-434 â€” UNRESTRICTED FILE UPLOAD
            # =================================================

            # Pattern 1:
            #
            # file.save(...)
            #
            # uploaded_file.save(...)
            #

            if (
                isinstance(
                    node.func,
                    ast.Attribute,
                )
                and node.func.attr == "save"
                and isinstance(
                    node.func.value,
                    ast.Name,
                )
            ):

                upload_object = (
                    node.func.value.id
                )

                if upload_object in {

                    "file",
                    "uploaded_file",
                    "upload",
                    "uploaded",
                }:

                    findings.append({

                        "vulnerability":
                            "Unrestricted File Upload",

                        "cwe":
                            "CWE-434",

                        "line":
                            node.lineno,

                        "severity":
                            "HIGH",

                        "description":
                            "Uploaded file is saved without "
                            "visible validation of file type, "
                            "extension, or content.",

                        "filename":
                            filename,
                    })

            # =================================================
            # CWE-434 â€” FILE WRITE FROM UPLOAD
            # =================================================

            # Pattern 2:
            #
            # with open(upload_path, "wb") as file:
            #     file.write(
            #         request.files["file"].read()
            #     )
            #
            # Detect the write() call when its data argument
            # contains a request.files / uploaded-file source.
            #

            if (
                isinstance(
                    node.func,
                    ast.Attribute,
                )
                and node.func.attr == "write"
            ):

                if node.args:

                    write_argument = (
                        node.args[0]
                    )

                    upload_data = False

                    for child in ast.walk(
                        write_argument
                    ):

                        # request.files[...]
                        if (
                            isinstance(
                                child,
                                ast.Subscript,
                            )
                            and isinstance(
                                child.value,
                                ast.Attribute,
                            )
                            and child.value.attr
                            == "files"
                        ):

                            upload_data = True
                            break

                        # request.files[...].read()
                        if (
                            isinstance(
                                child,
                                ast.Call,
                            )
                            and isinstance(
                                child.func,
                                ast.Attribute,
                            )
                            and child.func.attr
                            == "read"
                        ):

                            source = (
                                child.func.value
                            )

                            if (
                                isinstance(
                                    source,
                                    ast.Subscript,
                                )
                                and isinstance(
                                    source.value,
                                    ast.Attribute,
                                )
                                and source.value.attr
                                == "files"
                            ):

                                upload_data = True
                                break

                        # Common uploaded-file variables
                        if (
                            isinstance(
                                child,
                                ast.Name,
                            )
                            and child.id.lower()
                            in {
                                "file",
                                "uploaded_file",
                                "upload",
                                "uploaded",
                                "file_data",
                                "upload_data",
                            }
                        ):

                            upload_data = True
                            break

                    if upload_data:

                        findings.append({

                            "vulnerability":
                                "Unrestricted File Upload",

                            "cwe":
                                "CWE-434",

                            "line":
                                node.lineno,

                            "severity":
                                "HIGH",

                            "description":
                                "Uploaded file content is written "
                                "to storage without visible "
                                "validation of file type, "
                                "extension, or content.",

                            "filename":
                                filename,
                        })

        # ====================================================
        # CWE-352 ? CROSS-SITE REQUEST FORGERY
        # ====================================================

        # Conservative Flask-focused heuristic:
        # Detect state-changing routes that consume request data
        # without visible CSRF/token/origin protection.
        #
        # This is intentionally a static-analysis heuristic and
        # does not claim to prove CSRF in every framework.

        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):

            route_methods = set()
            has_route = False

            for decorator in node.decorator_list:

                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "route"
                ):

                    has_route = True

                    for keyword in decorator.keywords:

                        if keyword.arg == "methods":

                            if isinstance(
                                keyword.value,
                                (ast.List, ast.Tuple, ast.Set),
                            ):

                                for method in keyword.value.elts:

                                    if (
                                        isinstance(
                                            method,
                                            ast.Constant,
                                        )
                                        and isinstance(
                                            method.value,
                                            str,
                                        )
                                    ):

                                        route_methods.add(
                                            method.value.upper()
                                        )

                    if not route_methods:
                        route_methods.add("GET")

            if has_route and route_methods.intersection(
                {"POST", "PUT", "PATCH", "DELETE"}
            ):

                function_text = ""

                for child in ast.walk(node):

                    if isinstance(
                        child,
                        ast.Name,
                    ):

                        function_text += (
                            " " + child.id.lower()
                        )

                    elif isinstance(
                        child,
                        ast.Attribute,
                    ):

                        function_text += (
                            " " + child.attr.lower()
                        )

                    elif isinstance(
                        child,
                        ast.Constant,
                    ):

                        if isinstance(
                            child.value,
                            str,
                        ):

                            function_text += (
                                " " + child.value.lower()
                            )

                uses_request_data = any(
                    marker in function_text
                    for marker in {
                        "request",
                        "request.form",
                        "request.args",
                        "request.data",
                        "request.json",
                        "request.files",
                    }
                )

                has_csrf_protection = any(
                    marker in function_text
                    for marker in {
                        "csrf",
                        "csrf_token",
                        "validate_csrf",
                        "validate_csrf_token",
                        "wtforms.csrf",
                        "origin",
                        "referer",
                        "x-csrf-token",
                        "x-csrftoken",
                    }
                )

                if (
                    uses_request_data
                    and not has_csrf_protection
                ):

                    findings.append({

                        "vulnerability":
                            "Cross-Site Request Forgery",

                        "cwe":
                            "CWE-352",

                        "line":
                            node.lineno,

                        "severity":
                            "HIGH",

                        "description":
                            "A state-changing web route consumes "
                            "request data without visible CSRF, "
                            "token, or origin validation.",

                        "filename":
                            filename,
                    })

        # ====================================================
        # CWE-862 — MISSING AUTHORIZATION
        # ====================================================

        # Conservative Flask-focused heuristic:
        # Detect sensitive state-changing routes that operate
        # on user-controlled resource identifiers without
        # visible authorization checks.
        #
        # This is a static-analysis heuristic and does not
        # claim to prove an authorization vulnerability in
        # every framework or application.

        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):

            route_methods = set()
            has_route = False

            # Detect Flask routes and their HTTP methods.
            for decorator in node.decorator_list:

                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "route"
                ):

                    has_route = True

                    for keyword in decorator.keywords:

                        if keyword.arg == "methods":

                            if isinstance(
                                keyword.value,
                                (ast.List, ast.Tuple, ast.Set),
                            ):

                                for method in keyword.value.elts:

                                    if (
                                        isinstance(
                                            method,
                                            ast.Constant,
                                        )
                                        and isinstance(
                                            method.value,
                                            str,
                                        )
                                    ):

                                        route_methods.add(
                                            method.value.upper()
                                        )

                    # Flask routes default to GET.
                    if not route_methods:
                        route_methods.add("GET")

            if has_route:

                function_text = ""

                # Collect names, attributes and string
                # constants from the complete function.
                for child in ast.walk(node):

                    if isinstance(
                        child,
                        ast.Name,
                    ):

                        function_text += (
                            " " + child.id.lower()
                        )

                    elif isinstance(
                        child,
                        ast.Attribute,
                    ):

                        function_text += (
                            " " + child.attr.lower()
                        )

                    elif isinstance(
                        child,
                        ast.Constant,
                    ):

                        if isinstance(
                            child.value,
                            str,
                        ):

                            function_text += (
                                " " + child.value.lower()
                            )

                # Potentially sensitive operation.
                sensitive_operation = any(
                    marker in function_text
                    for marker in {
                        "delete",
                        "update",
                        "edit",
                        "modify",
                        "transfer",
                        "admin",
                        "account",
                        "profile",
                        "permission",
                        "role",
                    }
                )

                # User-controlled resource identifier.
                has_resource_identifier = any(
                    marker in function_text
                    for marker in {
                        "user_id",
                        "userid",
                        "account_id",
                        "accountid",
                        "record_id",
                        "recordid",
                        "resource_id",
                        "resourceid",
                        "object_id",
                        "objectid",
                    }
                )

                # Visible authorization mechanisms.
                has_authorization = any(
                    marker in function_text
                    for marker in {
                        "login_required",
                        "jwt_required",
                        "current_user",
                        "authorize",
                        "authorization",
                        "permission",
                        "permissions",
                        "has_permission",
                        "check_permission",
                        "role",
                        "roles",
                        "is_admin",
                        "admin_required",
                        "require_admin",
                        "access_control",
                        "access_allowed",
                    }
                )

                # State-changing route.
                state_changing_route = bool(
                    route_methods.intersection(
                        {
                            "POST",
                            "PUT",
                            "PATCH",
                            "DELETE",
                        }
                    )
                )

                if (
                    state_changing_route
                    and sensitive_operation
                    and has_resource_identifier
                    and not has_authorization
                ):

                    findings.append({

                        "vulnerability":
                            "Missing Authorization",

                        "cwe":
                            "CWE-862",

                        "line":
                            node.lineno,

                        "severity":
                            "HIGH",

                        "description":
                            "A sensitive state-changing route "
                            "operates on a user-controlled "
                            "resource identifier without visible "
                            "authorization or permission checks.",

                        "filename":
                            filename,
                    })
        # ====================================================
        # CWE-863 ? INCORRECT AUTHORIZATION
        # ====================================================

        # Conservative Flask-focused heuristic:
        #
        # Detect authenticated state-changing routes that operate
        # on user-controlled resource identifiers but do not show
        # visible resource-level ownership or permission checks.
        #
        # CWE-862 is intentionally excluded here because an
        # authentication mechanism must be visibly present.
        #
        # This is a static-analysis heuristic and does not claim
        # to prove an authorization vulnerability in every
        # framework or application.

        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):

            route_methods = set()
            has_route = False

            # Detect Flask routes and their HTTP methods.
            for decorator in node.decorator_list:

                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "route"
                ):

                    has_route = True

                    for keyword in decorator.keywords:

                        if keyword.arg == "methods":

                            if isinstance(
                                keyword.value,
                                (ast.List, ast.Tuple, ast.Set),
                            ):

                                for method in keyword.value.elts:

                                    if (
                                        isinstance(
                                            method,
                                            ast.Constant,
                                        )
                                        and isinstance(
                                            method.value,
                                            str,
                                        )
                                    ):

                                        route_methods.add(
                                            method.value.upper()
                                        )

                    # Flask routes default to GET.
                    if not route_methods:
                        route_methods.add("GET")

            if has_route:

                function_text = ""

                # Collect names, attributes and string constants
                # from the complete function.
                for child in ast.walk(node):

                    if isinstance(
                        child,
                        ast.Name,
                    ):

                        function_text += (
                            " " + child.id.lower()
                        )

                    elif isinstance(
                        child,
                        ast.Attribute,
                    ):

                        function_text += (
                            " " + child.attr.lower()
                        )

                    elif isinstance(
                        child,
                        ast.Constant,
                    ):

                        if isinstance(
                            child.value,
                            str,
                        ):

                            function_text += (
                                " " + child.value.lower()
                            )

                # Potentially sensitive operation.
                sensitive_operation = any(
                    marker in function_text
                    for marker in {
                        "delete",
                        "update",
                        "edit",
                        "modify",
                        "transfer",
                        "admin",
                        "account",
                        "profile",
                        "permission",
                        "role",
                    }
                )

                # User-controlled resource identifier.
                has_resource_identifier = any(
                    marker in function_text
                    for marker in {
                        "user_id",
                        "userid",
                        "account_id",
                        "accountid",
                        "record_id",
                        "recordid",
                        "resource_id",
                        "resourceid",
                        "object_id",
                        "objectid",
                    }
                )

                # Authentication is present.
                has_authentication = any(
                    marker in function_text
                    for marker in {
                        "login_required",
                        "jwt_required",
                        "authenticated",
                        "is_authenticated",
                        "current_user",
                    }
                )

                # Visible resource-level authorization.
                has_resource_authorization = any(
                    marker in function_text
                    for marker in {
                        "owner_id",
                        "ownerid",
                        "is_owner",
                        "owns_resource",
                        "owns_account",
                        "owns_user",
                        "can_edit",
                        "can_delete",
                        "can_modify",
                        "can_update",
                        "has_permission",
                        "check_permission",
                        "authorize",
                        "access_allowed",
                        "allowed_users",
                        "allowed_roles",
                        "permission_check",
                    }
                )

                # State-changing route.
                state_changing_route = bool(
                    route_methods.intersection(
                        {
                            "POST",
                            "PUT",
                            "PATCH",
                            "DELETE",
                        }
                    )
                )

                if (
                    state_changing_route
                    and sensitive_operation
                    and has_resource_identifier
                    and has_authentication
                    and not has_resource_authorization
                ):

                    findings.append({

                        "vulnerability":
                            "Incorrect Authorization",

                        "cwe":
                            "CWE-863",

                        "line":
                            node.lineno,

                        "severity":
                            "HIGH",

                        "description":
                            "An authenticated state-changing route "
                            "operates on a user-controlled "
                            "resource without visible resource-level "
                            "ownership or authorization enforcement.",

                        "filename":
                            filename,
                    })

        # ====================================================
        # CWE-284 ? IMPROPER ACCESS CONTROL
        # ====================================================

        # Conservative Flask-focused heuristic:
        #
        # Detect state-changing routes that expose sensitive
        # administrative or privileged operations without a
        # visible access-control mechanism.
        #
        # This detector focuses on broad access-control absence.
        # CWE-862 and CWE-863 specifically target missing or
        # incorrect authorization around authenticated resources.
        #
        # This is a static-analysis heuristic and does not claim
        # to prove an access-control vulnerability in every
        # framework or application.

        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):

            route_methods = set()
            has_route = False

            # Detect Flask routes and their HTTP methods.
            for decorator in node.decorator_list:

                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "route"
                ):

                    has_route = True

                    for keyword in decorator.keywords:

                        if keyword.arg == "methods":

                            if isinstance(
                                keyword.value,
                                (ast.List, ast.Tuple, ast.Set),
                            ):

                                for method in keyword.value.elts:

                                    if (
                                        isinstance(
                                            method,
                                            ast.Constant,
                                        )
                                        and isinstance(
                                            method.value,
                                            str,
                                        )
                                    ):

                                        route_methods.add(
                                            method.value.upper()
                                        )

                    # Flask routes default to GET.
                    if not route_methods:
                        route_methods.add("GET")

            if has_route:

                function_text = ""

                # Collect names, attributes and string constants
                # from the complete function.
                for child in ast.walk(node):

                    if isinstance(
                        child,
                        ast.Name,
                    ):

                        function_text += (
                            " " + child.id.lower()
                        )

                    elif isinstance(
                        child,
                        ast.Attribute,
                    ):

                        function_text += (
                            " " + child.attr.lower()
                        )

                    elif isinstance(
                        child,
                        ast.Constant,
                    ):

                        if isinstance(
                            child.value,
                            str,
                        ):

                            function_text += (
                                " " + child.value.lower()
                            )

                # Potentially privileged or sensitive operation.
                privileged_operation = any(
                    marker in function_text
                    for marker in {
                        "admin",
                        "administrator",
                        "manage_users",
                        "manageusers",
                        "delete_user",
                        "deleteuser",
                        "create_user",
                        "createuser",
                        "update_role",
                        "updaterole",
                        "grant",
                        "revoke",
                        "permission",
                        "permissions",
                        "role",
                        "roles",
                        "privilege",
                        "privileges",
                        "settings",
                        "configuration",
                        "config",
                    }
                )

                # Visible access-control mechanism.
                has_access_control = any(
                    marker in function_text
                    for marker in {
                        "admin_required",
                        "is_admin",
                        "is_administrator",
                        "admin_user",
                        "require_admin",
                        "require_role",
                        "role_required",
                        "has_role",
                        "check_role",
                        "check_permission",
                        "has_permission",
                        "permission_check",
                        "authorize",
                        "authorization",
                        "access_allowed",
                        "access_control",
                        "allowed_roles",
                        "allowed_users",
                        "current_user",
                    }
                )

                # State-changing route.
                state_changing_route = bool(
                    route_methods.intersection(
                        {
                            "POST",
                            "PUT",
                            "PATCH",
                            "DELETE",
                        }
                    )
                )

                if (
                    state_changing_route
                    and privileged_operation
                    and not has_access_control
                ):

                    findings.append({

                        "vulnerability":
                            "Improper Access Control",

                        "cwe":
                            "CWE-284",

                        "line":
                            node.lineno,

                        "severity":
                            "HIGH",

                        "description":
                            "A state-changing route performs a "
                            "potentially privileged or sensitive "
                            "operation without visible access-control "
                            "enforcement.",

                        "filename":
                            filename,
                    })

        # ====================================================
        # CWE-639 ? AUTHORIZATION BYPASS THROUGH USER-CONTROLLED KEY
        # ====================================================

        # Conservative Flask-focused heuristic:
        #
        # Detect state-changing routes that use a user-controlled
        # resource identifier/key to access or modify a resource
        # without visible resource-level authorization.
        #
        # This detector complements:
        # CWE-862 - Missing Authorization
        # CWE-863 - Incorrect Authorization
        # CWE-284 - Improper Access Control
        #
        # This is a static-analysis heuristic and does not prove
        # exploitability in every framework or application.

        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):

            route_methods = set()
            has_route = False

            # Detect Flask routes and HTTP methods.
            for decorator in node.decorator_list:

                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "route"
                ):

                    has_route = True

                    for keyword in decorator.keywords:

                        if keyword.arg == "methods":

                            if isinstance(
                                keyword.value,
                                (ast.List, ast.Tuple, ast.Set),
                            ):

                                for method in keyword.value.elts:

                                    if (
                                        isinstance(
                                            method,
                                            ast.Constant,
                                        )
                                        and isinstance(
                                            method.value,
                                            str,
                                        )
                                    ):

                                        route_methods.add(
                                            method.value.upper()
                                        )

                    # Flask routes default to GET.
                    if not route_methods:
                        route_methods.add("GET")

            if has_route:

                state_changing_route = bool(
                    route_methods.intersection(
                        {
                            "POST",
                            "PUT",
                            "PATCH",
                            "DELETE",
                        }
                    )
                )

                if state_changing_route:

                    names = set()
                    attributes = set()
                    strings = set()

                    for child in ast.walk(node):

                        if isinstance(
                            child,
                            ast.Name,
                        ):

                            names.add(
                                child.id.lower()
                            )

                        elif isinstance(
                            child,
                            ast.Attribute,
                        ):

                            attributes.add(
                                child.attr.lower()
                            )

                        elif isinstance(
                            child,
                            ast.Constant,
                        ):

                            if isinstance(
                                child.value,
                                str,
                            ):

                                strings.add(
                                    child.value.lower()
                                )

                    all_identifiers = (
                        names
                        | attributes
                        | strings
                    )

                    # Explicit resource keys that are commonly
                    # supplied or controlled by the requester.
                    user_controlled_keys = {
                        "user_id",
                        "userid",
                        "account_id",
                        "accountid",
                        "record_id",
                        "recordid",
                        "item_id",
                        "itemid",
                        "document_id",
                        "documentid",
                        "project_id",
                        "projectid",
                        "resource_id",
                        "resourceid",
                        "order_id",
                        "orderid",
                        "file_id",
                        "fileid",
                        "customer_id",
                        "customerid",
                        "profile_id",
                        "profileid",
                        "object_id",
                        "objectid",
                    }

                    # Generic keys are handled only when a request
                    # source is visible.
                    generic_keys = {
                        "id",
                        "key",
                    }

                    request_sources = {
                        "request",
                        "args",
                        "form",
                        "json",
                        "values",
                        "query",
                        "path",
                        "params",
                        "get_json",
                    }

                    resource_access_operations = {
                        "get",
                        "find",
                        "find_by_id",
                        "find_by_pk",
                        "query",
                        "filter",
                        "filter_by",
                        "where",
                        "select",
                        "update",
                        "delete",
                        "fetch",
                        "load",
                        "lookup",
                        "retrieve",
                    }

                    authorization_markers = {
                        "owner_id",
                        "ownerid",
                        "created_by",
                        "createdby",
                        "is_owner",
                        "user_is_owner",
                        "owns_resource",
                        "owns_record",
                        "owns_item",
                        "owns_document",
                        "owns_project",
                        "can_edit",
                        "can_delete",
                        "can_update",
                        "can_access",
                        "has_permission",
                        "check_permission",
                        "permission_check",
                        "authorize",
                        "authorization",
                        "access_allowed",
                        "access_control",
                        "allowed_users",
                        "allowed_roles",
                        "admin_required",
                        "require_admin",
                        "role_required",
                        "require_role",
                        "check_role",
                    }

                    has_explicit_user_key = bool(
                        user_controlled_keys.intersection(
                            all_identifiers
                        )
                    )

                    has_generic_user_key = bool(
                        generic_keys.intersection(
                            all_identifiers
                        )
                    )

                    has_request_source = bool(
                        request_sources.intersection(
                            all_identifiers
                        )
                    )

                    has_resource_access = bool(
                        resource_access_operations.intersection(
                            all_identifiers
                        )
                    )

                    has_resource_authorization = bool(
                        authorization_markers.intersection(
                            all_identifiers
                        )
                    )

                    # A specific resource key is strong evidence.
                    # Generic id/key requires visible request input.
                    user_controlled_resource = (
                        has_explicit_user_key
                        or (
                            has_generic_user_key
                            and has_request_source
                        )
                    )

                    if (
                        user_controlled_resource
                        and has_resource_access
                        and not has_resource_authorization
                    ):

                        findings.append({

                            "vulnerability":
                                "Authorization Bypass Through User-Controlled Key",

                            "cwe":
                                "CWE-639",

                            "line":
                                node.lineno,

                            "severity":
                                "HIGH",

                            "description":
                                "A state-changing route uses a "
                                "user-controlled resource key without "
                                "visible ownership or resource-level "
                                "authorization.",

                            "filename":
                                filename,
                        })

        # ====================================================
        # CWE-306 - MISSING AUTHENTICATION FOR CRITICAL FUNCTION
        # ====================================================

        # Conservative Flask-focused heuristic:
        #
        # Detect state-changing routes that perform potentially
        # critical or sensitive operations without visible
        # authentication enforcement.
        #
        # This detector focuses on missing authentication and is
        # intentionally separate from authorization weaknesses such
        # as CWE-862, CWE-863, CWE-284, and CWE-639.
        #
        # This is a static-analysis heuristic and does not prove
        # exploitability in every framework or application.

        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):

            route_methods = set()
            has_route = False

            for decorator in node.decorator_list:

                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "route"
                ):

                    has_route = True

                    for keyword in decorator.keywords:

                        if keyword.arg == "methods":

                            if isinstance(
                                keyword.value,
                                (ast.List, ast.Tuple, ast.Set),
                            ):

                                for method in keyword.value.elts:

                                    if (
                                        isinstance(
                                            method,
                                            ast.Constant,
                                        )
                                        and isinstance(
                                            method.value,
                                            str,
                                        )
                                    ):

                                        route_methods.add(
                                            method.value.upper()
                                        )

                    if not route_methods:
                        route_methods.add("GET")

            if has_route:

                state_changing_route = bool(
                    route_methods.intersection(
                        {
                            "POST",
                            "PUT",
                            "PATCH",
                            "DELETE",
                        }
                    )
                )

                if state_changing_route:

                    names = set()
                    attributes = set()
                    strings = set()

                    # Include the route handler's own function name.
                    # ast.walk(node) does not expose FunctionDef.name
                    # as an ast.Name node.
                    names.add(node.name.lower())

                    for child in ast.walk(node):

                        if isinstance(
                            child,
                            ast.Name,
                        ):

                            names.add(
                                child.id.lower()
                            )

                        elif isinstance(
                            child,
                            ast.Attribute,
                        ):

                            attributes.add(
                                child.attr.lower()
                            )

                        elif isinstance(
                            child,
                            ast.Constant,
                        ):

                            if isinstance(
                                child.value,
                                str,
                            ):

                                strings.add(
                                    child.value.lower()
                                )

                    all_identifiers = (
                        names
                        | attributes
                        | strings
                    )

                    critical_operations = {
                        "admin",
                        "administrator",
                        "manage_users",
                        "manageusers",
                        "delete_user",
                        "deleteuser",
                        "create_user",
                        "createuser",
                        "update_user",
                        "updateuser",
                        "update_role",
                        "updaterole",
                        "grant",
                        "revoke",
                        "permission",
                        "permissions",
                        "role",
                        "roles",
                        "privilege",
                        "privileges",
                        "password",
                        "reset_password",
                        "resetpassword",
                        "change_password",
                        "changepassword",
                        "delete_account",
                        "deleteaccount",
                        "transfer",
                        "payment",
                        "payments",
                        "transaction",
                        "transactions",
                        "settings",
                        "configuration",
                        "config",
                    }

                    authentication_markers = {
                        "login_required",
                        "loginrequired",
                        "jwt_required",
                        "jwtrequired",
                        "auth_required",
                        "authrequired",
                        "authenticated",
                        "is_authenticated",
                        "isauthenticated",
                        "current_user",
                        "currentuser",
                        "verify_token",
                        "verifytoken",
                        "validate_token",
                        "validatetoken",
                        "require_auth",
                        "requireauth",
                        "require_login",
                        "requirelogin",
                        "session_user",
                        "sessionuser",
                        "user_session",
                        "usersession",
                    }

                    has_critical_operation = bool(
                        critical_operations.intersection(
                            all_identifiers
                        )
                    )

                    has_authentication = bool(
                        authentication_markers.intersection(
                            all_identifiers
                        )
                    )

                    if (
                        has_critical_operation
                        and not has_authentication
                    ):

                        findings.append({

                            "vulnerability":
                                "Missing Authentication for Critical Function",

                            "cwe":
                                "CWE-306",

                            "line":
                                node.lineno,

                            "severity":
                                "HIGH",

                            "description":
                                "A state-changing route performs a "
                                "potentially critical function without "
                                "visible authentication enforcement.",

                            "filename":
                                filename,
                        })

        # ====================================================
        # CWE-918 - SERVER-SIDE REQUEST FORGERY
        # ====================================================

        # Conservative Flask-focused heuristic:
        #
        # Detect a Flask route where a URL derived from request
        # input reaches a known outbound HTTP client without
        # visible URL/host validation.
        #
        # This detector intentionally avoids generic .get()
        # calls and hardcoded URLs to reduce false positives.
        #
        # This is a static-analysis heuristic and does not prove
        # exploitability in every framework or application.

        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):

            has_route = False

            for decorator in node.decorator_list:

                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(
                        decorator.func,
                        ast.Attribute,
                    )
                    and decorator.func.attr == "route"
                ):
                    has_route = True

            if has_route:

                url_variables = set()

                for child in ast.walk(node):

                    if isinstance(
                        child,
                        ast.Assign,
                    ):

                        if (
                            isinstance(
                                child.value,
                                ast.Call,
                            )
                            and isinstance(
                                child.value.func,
                                ast.Attribute,
                            )
                            and child.value.func.attr == "get"
                            and isinstance(
                                child.value.func.value,
                                ast.Attribute,
                            )
                            and child.value.func.value.attr in {
                                "args",
                                "form",
                                "values",
                            }
                            and isinstance(
                                child.value.func.value.value,
                                ast.Name,
                            )
                            and child.value.func.value.value.id
                            == "request"
                        ):

                            for target in child.targets:

                                if isinstance(
                                    target,
                                    ast.Name,
                                ):
                                    url_variables.add(
                                        target.id.lower()
                                    )

                    elif isinstance(
                        child,
                        ast.AnnAssign,
                    ):

                        if (
                            isinstance(
                                child.target,
                                ast.Name,
                            )
                            and isinstance(
                                child.value,
                                ast.Call,
                            )
                            and isinstance(
                                child.value.func,
                                ast.Attribute,
                            )
                            and child.value.func.attr == "get"
                            and isinstance(
                                child.value.func.value,
                                ast.Attribute,
                            )
                            and child.value.func.value.attr in {
                                "args",
                                "form",
                                "values",
                            }
                            and isinstance(
                                child.value.func.value.value,
                                ast.Name,
                            )
                            and child.value.func.value.value.id
                            == "request"
                        ):

                            url_variables.add(
                                child.target.id.lower()
                            )

                authentication_and_validation_markers = {
                    "is_safe_url",
                    "safe_url",
                    "validate_url",
                    "valid_url",
                    "validate_host",
                    "allowed_host",
                    "allowed_hosts",
                    "allowlist",
                    "allowlisted",
                    "whitelist",
                    "whitelisted",
                    "trusted_host",
                    "trusted_hosts",
                    "permitted_host",
                    "permitted_hosts",
                    "block_private_ip",
                    "private_ip_check",
                    "ssrf_protection",
                    "ssrf_safe",
                }

                has_url_validation = False

                for child in ast.walk(node):

                    if isinstance(
                        child,
                        ast.Name,
                    ):
                        if (
                            child.id.lower()
                            in authentication_and_validation_markers
                        ):
                            has_url_validation = True

                    elif isinstance(
                        child,
                        ast.Attribute,
                    ):
                        if (
                            child.attr.lower()
                            in authentication_and_validation_markers
                        ):
                            has_url_validation = True

                    elif isinstance(
                        child,
                        ast.Constant,
                    ):
                        if (
                            isinstance(
                                child.value,
                                str,
                            )
                            and child.value.lower()
                            in authentication_and_validation_markers
                        ):
                            has_url_validation = True

                def is_user_controlled_url(argument):

                    if _contains_user_input(argument):
                        return True

                    if (
                        isinstance(
                            argument,
                            ast.Name,
                        )
                        and argument.id.lower()
                        in url_variables
                    ):
                        return True

                    return False

                def is_outbound_http_call(call_node):

                    if not isinstance(
                        call_node,
                        ast.Call,
                    ):
                        return False

                    if not isinstance(
                        call_node.func,
                        ast.Attribute,
                    ):
                        return False

                    method = call_node.func.attr.lower()

                    if method not in {
                        "get",
                        "post",
                        "put",
                        "patch",
                        "delete",
                        "request",
                        "urlopen",
                    }:
                        return False

                    value = call_node.func.value

                    if isinstance(
                        value,
                        ast.Name,
                    ):
                        return value.id.lower() in {
                            "requests",
                            "httpx",
                        }

                    if isinstance(
                        value,
                        ast.Attribute,
                    ):
                        return (
                            method == "urlopen"
                            and value.attr.lower()
                            == "request"
                            and isinstance(
                                value.value,
                                ast.Name,
                            )
                            and value.value.id.lower()
                            == "urllib"
                        )

                    return False

                if not has_url_validation:

                    for child in ast.walk(node):

                        if is_outbound_http_call(child):

                            url_argument = None

                            if child.args:

                                # requests.request("GET", url)
                                # uses the second positional argument
                                # as the URL. Other HTTP helpers such
                                # as requests.get(url) use the first.
                                if (
                                    isinstance(
                                        child.func,
                                        ast.Attribute,
                                    )
                                    and child.func.attr.lower()
                                    == "request"
                                    and len(child.args) >= 2
                                ):
                                    url_argument = child.args[1]
                                else:
                                    url_argument = child.args[0]

                            if url_argument is None:

                                for keyword in child.keywords:

                                    if keyword.arg in {
                                        "url",
                                        "uri",
                                    }:
                                        url_argument = keyword.value
                                        break

                            if (
                                url_argument is not None
                                and is_user_controlled_url(
                                    url_argument
                                )
                            ):

                                findings.append({

                                    "vulnerability":
                                        "Server-Side Request Forgery",

                                    "cwe":
                                        "CWE-918",

                                    "line":
                                        child.lineno,

                                    "severity":
                                        "HIGH",

                                    "description":
                                        "User-controlled URL reaches "
                                        "an outbound HTTP client without "
                                        "visible URL or host validation, "
                                        "which may allow server-side "
                                        "request forgery.",

                                    "filename":
                                        filename,
                                })

                                break

        # ====================================================
        # ASSIGNMENT DETECTORS
        # ====================================================

        if isinstance(
            node,
            ast.Assign,
        ):

            # =================================================
            # HARDCODED SECRET
            # =================================================

            for target in node.targets:

                if isinstance(
                    target,
                    ast.Name,
                ):

                    variable = (
                        target.id.lower()
                    )

                    if any(
                        keyword in variable
                        for keyword in {

                            "password",
                            "passwd",
                            "secret",
                            "api_key",
                            "apikey",
                            "token",
                        }
                    ):

                        if isinstance(
                            node.value,
                            ast.Constant,
                        ):

                            if isinstance(
                                node.value.value,
                                str,
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
                                        "Sensitive credential is "
                                        "hardcoded in source code.",

                                    "filename":
                                        filename,
                                })

    # Add the extended security-pattern detectors while preserving
    # the existing detector implementations above.
    findings.extend(
        scan_extended_patterns(
            tree,
            filename,
            tainted_variables,
        )
    )

    return findings


# ============================================================
# EXTENDED SECURITY PATTERN DETECTORS
# ============================================================

def scan_extended_patterns(tree, filename, tainted_variables=None):
    """
    Additional conservative AST heuristics for the expanded test suite.

    These detectors intentionally report *potential* weaknesses. Static
    analysis cannot prove exploitability for every framework/application.
    The findings are therefore designed to be enriched and reviewed by the
    existing normalization, risk, RAG, repair and closed-loop layers.
    """
    findings = []
    tainted_variables = tainted_variables or set()

    def add(vulnerability, cwe, node, severity, description):
        findings.append({
            "vulnerability": vulnerability,
            "cwe": cwe,
            "line": getattr(node, "lineno", 1),
            "severity": severity,
            "description": description,
            "filename": filename,
        })

    def contains_taint(node):
        if node is None:
            return False
        if _contains_user_input(node):
            return True
        return any(
            isinstance(child, ast.Name) and child.id in tainted_variables
            for child in ast.walk(node)
        )

    def call_name(call):
        if not isinstance(call, ast.Call):
            return ""
        if isinstance(call.func, ast.Name):
            return call.func.id.lower()
        if isinstance(call.func, ast.Attribute):
            return call.func.attr.lower()
        return ""

    def attribute_chain(node):
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr.lower())
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id.lower())
        return list(reversed(parts))

    def is_request_value(node):
        if isinstance(node, ast.Attribute):
            chain = attribute_chain(node)
            return len(chain) >= 2 and chain[0] == "request" and chain[1] in {
                "args", "form", "json", "data", "values", "files"
            }
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            chain = attribute_chain(node.func)
            return len(chain) >= 3 and chain[0] == "request" and chain[1] in {
                "args", "form", "values", "json"
            } and chain[-1] in {"get", "get_json"}
        return False

    def is_flask_route(function):
        methods = set()
        route = False
        for decorator in function.decorator_list:
            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                if decorator.func.attr == "route":
                    route = True
                    for kw in decorator.keywords:
                        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                            for item in kw.value.elts:
                                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                                    methods.add(item.value.upper())
                    if not methods:
                        methods.add("GET")
        return route, methods

    # ------------------------------------------------------------
    # CWE-79 — XSS through Flask return values
    # ------------------------------------------------------------
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route, _ = is_flask_route(function)
        if not route:
            continue
        for node in ast.walk(function):
            if not isinstance(node, ast.Return) or node.value is None:
                continue
            if contains_taint(node.value) and isinstance(
                node.value, (ast.BinOp, ast.JoinedStr, ast.Call)
            ):
                add(
                    "Cross-Site Scripting",
                    "CWE-79",
                    node,
                    "HIGH",
                    "User-controlled input is returned in generated web content without visible output encoding or escaping.",
                )

    # ------------------------------------------------------------
    # CWE-601 — Open Redirect
    # ------------------------------------------------------------
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = call_name(node)
        if name != "redirect":
            continue
        target = node.args[0] if node.args else None
        if target is not None and contains_taint(target):
            add(
                "Open Redirect",
                "CWE-601",
                node,
                "MEDIUM",
                "User-controlled redirect target reaches a redirect operation without visible destination validation.",
            )

    # ------------------------------------------------------------
    # CWE-611 — XXE
    # ------------------------------------------------------------
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "XMLParser", "XMLParserBuilder"
        }:
            dangerous = False
            for kw in node.keywords:
                if kw.arg in {"resolve_entities", "load_dtd", "no_network"}:
                    if kw.arg in {"resolve_entities", "load_dtd"} and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        dangerous = True
            if dangerous:
                add(
                    "XML External Entity (XXE)",
                    "CWE-611",
                    node,
                    "HIGH",
                    "XML parsing is configured to resolve external entities or DTDs, which can enable XXE attacks when parsing untrusted XML.",
                )
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"fromstring", "parse"}:
            if isinstance(node.func.value, ast.Name) and node.func.value.id.lower() in {"etree", "etree_elementtree", "elementtree"}:
                if node.args and contains_taint(node.args[0]):
                    add(
                        "XML External Entity (XXE)",
                        "CWE-611",
                        node,
                        "HIGH",
                        "Untrusted XML reaches an XML parser without visible hardened entity/DTD configuration.",
                    )

    # ------------------------------------------------------------
    # CWE-327 / CWE-916 — weak cryptography and password hashing
    # ------------------------------------------------------------
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        chain = attribute_chain(node.func) if isinstance(node.func, ast.Attribute) else []
        algo = chain[-1] if chain else ""

        if chain[:1] == ["hashlib"] and algo in {"md5", "sha1", "sha", "md4"}:
            password_context = any(
                isinstance(child, ast.Name) and any(k in child.id.lower() for k in {"password", "passwd", "passphrase", "credential"})
                for arg in node.args for child in ast.walk(arg)
            )
            if password_context:
                add(
                    "Weak Password Hashing",
                    "CWE-916",
                    node,
                    "HIGH",
                    "A password-related value is hashed with a fast or cryptographically weak digest instead of a password-hashing function such as Argon2, scrypt, or bcrypt.",
                )
            else:
                add(
                    "Risky Cryptography",
                    "CWE-327",
                    node,
                    "MEDIUM",
                    f"Use of the weak or obsolete {algo.upper()} digest may provide inadequate cryptographic protection.",
                )

        if algo in {"des", "des3", "tripledes", "blowfish"}:
            add(
                "Risky Cryptography",
                "CWE-327",
                node,
                "HIGH",
                f"Use of {algo.upper()} cryptography is potentially obsolete or unsuitable for modern security requirements.",
            )

    # ------------------------------------------------------------
    # CWE-326 — inadequate encryption strength
    # ------------------------------------------------------------
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute):
            chain = attribute_chain(node.func)
            if chain[-1:] == ["new"] and any(part in {"des3", "tripledes", "des"} for part in chain):
                add(
                    "Inadequate Encryption Strength",
                    "CWE-326",
                    node,
                    "HIGH",
                    "A legacy or weak block cipher is used where stronger modern cryptography is expected.",
                )

    # ------------------------------------------------------------
    # CWE-312 / CWE-532 / CWE-117 — sensitive data in logs and log injection
    # ------------------------------------------------------------
    log_methods = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
    sensitive_words = {"password", "passwd", "secret", "token", "api_key", "apikey", "credit_card", "card_number", "ssn", "cvv"}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr.lower() not in log_methods:
            continue

        rendered = []
        for arg in node.args:
            for child in ast.walk(arg):
                if isinstance(child, ast.Name):
                    rendered.append(child.id.lower())
                elif isinstance(child, ast.Constant) and isinstance(child.value, str):
                    rendered.append(child.value.lower())
                elif isinstance(child, ast.Attribute):
                    rendered.append(child.attr.lower())

        text = " ".join(rendered)
        has_sensitive = any(word in text for word in sensitive_words)
        has_user_input = any(
            contains_taint(arg) or is_request_value(arg)
            for arg in node.args
        )

        if has_sensitive:
            cwe = "CWE-532" if any(
                word in text for word in {"password", "passwd", "secret", "token", "api_key", "apikey"}
            ) else "CWE-312"
            add(
                "Sensitive Information in Logs" if cwe == "CWE-532" else "Cleartext Sensitive Data",
                cwe,
                node,
                "HIGH",
                "Sensitive information is written to application logs and may be exposed through log storage or monitoring systems.",
            )
        elif has_user_input:
            add(
                "Log Injection",
                "CWE-117",
                node,
                "MEDIUM",
                "User-controlled input reaches a logging operation without visible sanitization or structured logging controls.",
            )

    # ------------------------------------------------------------
    # CWE-319 — cleartext transmission
    # ------------------------------------------------------------
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        value = node.value.lower()
        if value.startswith("http://") and any(
            marker in value for marker in {"login", "auth", "password", "token", "user", "api", "/"}
        ):
            add(
                "Cleartext Transmission of Sensitive Information",
                "CWE-319",
                node,
                "HIGH",
                "An HTTP URL is used for communication that may carry application or authentication data; HTTPS should be used for protected communication.",
            )

    # Also detect outbound HTTP calls whose URL is an explicit http:// literal.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = call_name(node)
        if name not in {"get", "post", "put", "patch", "delete", "request", "urlopen"}:
            continue
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.lower().startswith("http://"):
                add(
                    "Cleartext Transmission of Sensitive Information",
                    "CWE-319",
                    node,
                    "HIGH",
                    "An outbound request uses cleartext HTTP instead of HTTPS.",
                )
                break

    # ------------------------------------------------------------
    # CWE-287 — improper authentication
    # ------------------------------------------------------------
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        if isinstance(node.test, ast.Compare) and len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.Eq):
            names = [
                child.id.lower()
                for child in ast.walk(node.test)
                if isinstance(child, ast.Name)
            ]
            constants = [
                child.value
                for child in ast.walk(node.test)
                if isinstance(child, ast.Constant) and isinstance(child.value, str)
            ]
            if any(name in {"username", "user", "login", "userid"} for name in names) and any(
                str(value).lower() in {"admin", "administrator", "root", "user"} for value in constants
            ):
                add(
                    "Improper Authentication",
                    "CWE-287",
                    node,
                    "HIGH",
                    "Authentication is implemented using a simple hardcoded identity comparison rather than a robust credential or identity-verification mechanism.",
                )


    return findings


# ============================================================
# BANDIT SCANNER
# ============================================================

def scan_bandit(
    code,
    filename="<string>",
):

    findings = []

    temp_path = None

    try:

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8",
        ) as temp_file:

            temp_file.write(
                code
            )

            temp_path = (
                temp_file.name
            )

        result = subprocess.run(

            [
                "bandit",
                "-q",
                "-f",
                "json",
                temp_path,
            ],

            capture_output=True,
            text=True,

            encoding="utf-8",
            errors="replace",
        )

        if not result.stdout:

            return findings

        try:

            data = json.loads(
                result.stdout
            )

        except json.JSONDecodeError:

            return findings

        supported_bandit_tests = set(BANDIT_CWE_MAP)

        for item in data.get(
            "results",
            [],
        ):
            test_id = item.get("test_id")

            if test_id in BANDIT_IMPORT_ADVISORIES:
                continue

            # Only promote Bandit rules that CodeSentinel-X explicitly
            # maps to a supported CWE. This prevents unrelated Bandit
            # hardening advisories such as B607 from becoming false
            # vulnerability classes in the unified pipeline.
            if test_id not in supported_bandit_tests:
                continue

            findings.append({

                "vulnerability":
                    item.get(
                        "test_name",
                        "Bandit Finding",
                    ),

                "cwe":
                    None,

                "source":
                    "bandit",

                "test_id":
                    test_id,

                "line":
                    item.get(
                        "line_number"
                    ),

                "severity":
                    item.get(
                        "issue_severity",
                        "LOW",
                    ).upper(),

                "description":
                    item.get(
                        "issue_text",
                        "",
                    ),

                "filename":
                    filename,
            })

    except Exception:

        pass

    finally:

        if (
            temp_path
            and os.path.exists(
                temp_path
            )
        ):

            try:

                os.remove(
                    temp_path
                )

            except OSError:

                pass

    return findings


# ============================================================
# SEMGREP SCANNER
# ============================================================

def scan_semgrep(
    code,
    filename="<string>",
):

    findings = []

    temp_path = None

    try:

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8",
        ) as temp_file:

            temp_file.write(
                code
            )

            temp_path = (
                temp_file.name
            )

        result = subprocess.run(

            [
                "semgrep",
                "--config",
                "p/python",
                "--json",
                temp_path,
            ],

            capture_output=True,
            text=True,

            encoding="utf-8",
            errors="replace",
        )

        if not result.stdout:

            return findings

        try:

            data = json.loads(
                result.stdout
            )

        except json.JSONDecodeError:

            return findings

        for item in data.get(
            "results",
            [],
        ):

            extra = item.get(
                "extra",
                {}
            )

            metadata = extra.get(
                "metadata",
                {}
            )

            cwe_value = metadata.get(
                "cwe"
            )

            if isinstance(
                cwe_value,
                list,
            ):

                cwe_value = (
                    cwe_value[0]
                    if cwe_value
                    else None
                )

            findings.append({

                "vulnerability":
                    extra.get(
                        "message",
                        "Semgrep Finding",
                    ),

                "cwe":
                    cwe_value,

                "source":
                    "semgrep",

                "line":
                    item.get(
                        "start",
                        {},
                    ).get(
                        "line"
                    ),

                "severity":
                    extra.get(
                        "severity",
                        "WARNING",
                    ).upper(),

                "description":
                    extra.get(
                        "message",
                        "",
                    ),

                "filename":
                    filename,
            })

    except Exception:

        pass

    finally:

        if (
            temp_path
            and os.path.exists(
                temp_path
            )
        ):

            try:

                os.remove(
                    temp_path
                )

            except OSError:

                pass

    return findings


# ============================================================
# FINDING NORMALIZER
# ============================================================

def normalize_finding(finding):
    source = finding.get("source")
    test_id = finding.get("test_id")
    description = finding.get("description", "") or ""
    cwe = infer_cwe(
        finding.get("vulnerability", ""),
        description,
        source=source,
        test_id=test_id,
        explicit_cwe=finding.get("cwe"),
    )
    vulnerability = normalize_vulnerability(
        finding.get("vulnerability", ""),
        description=description,
        cwe=cwe,
        source=source,
        test_id=test_id,
    )
    severity = normalize_severity(finding.get("severity"), vulnerability, description)
    result = {
        **finding,
        "vulnerability": vulnerability,
        "cwe": cwe,
        "severity": severity,
        "description": description,
    }
    if cwe:
        result["cwe_name"] = CWE_NAMES.get(cwe, "")
    return result


def _finding_priority(finding):
    return {"ast": 3, "semgrep": 2, "bandit": 1}.get(str(finding.get("source", "")).lower(), 0)


def _merge_findings(existing, incoming):
    primary = incoming if _finding_priority(incoming) > _finding_priority(existing) else existing
    secondary = existing if primary is incoming else incoming
    merged = dict(primary)
    sources = []
    for item in (existing, incoming):
        src = item.get("source")
        if src and src not in sources:
            sources.append(src)
    if sources:
        merged["sources"] = sources
    rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    if rank.get(secondary.get("severity", "LOW"), 1) > rank.get(merged.get("severity", "LOW"), 1):
        merged["severity"] = secondary["severity"]
    if not merged.get("description") and secondary.get("description"):
        merged["description"] = secondary["description"]
    return merged


def _deduplicate_findings(findings):
    merged = {}
    for finding in findings:
        cwe = finding.get("cwe")
        line = finding.get("line")
        key = (cwe, line) if cwe else (None, line, finding.get("vulnerability", ""))
        if key in merged:
            merged[key] = _merge_findings(merged[key], finding)
        else:
            merged[key] = finding
    return sorted(
        merged.values(),
        key=lambda item: (
            item.get("line") if isinstance(item.get("line"), int) else 10**9,
            item.get("cwe") or "",
            item.get("vulnerability") or "",
        ),
    )


# ============================================================
# UNIFIED SECURITY ANALYZER
# ============================================================

def analyze_security(code, filename="<string>"):
    raw_findings = (
        scan_ast(code, filename)
        + scan_bandit(code, filename)
        + scan_semgrep(code, filename)
    )
    normalized_findings = [normalize_finding(finding) for finding in raw_findings]
    return _deduplicate_findings(normalized_findings)


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    sample_code = """

import pickle
import subprocess

password = "admin123"

user_input = input(
    "Enter command: "
)

subprocess.run(
    user_input,
    shell=True
)

eval(
    user_input
)

pickle.loads(
    user_input
)

with open(
    user_input,
    "r"
) as file:

    data = file.read()

from flask import request

@app.route(
    "/upload",
    methods=["POST"]
)
def upload():

    file = request.files[
        "file"
    ]

    file.save(
        "/var/www/uploads/"
        + file.filename
    )
"""

    results = analyze_security(
        sample_code,
        "sample.py",
    )

    print(
        json.dumps(
            results,
            indent=4,
        )
    )
