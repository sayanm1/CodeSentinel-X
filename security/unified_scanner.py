import ast
import subprocess
import tempfile
import os
import json


# ============================================================
# CWE MAPPING
# ============================================================

CWE_MAP = {

    # Existing detectors
    "hardcoded password": "CWE-798",
    "hardcoded secret": "CWE-798",
    "hardcoded credential": "CWE-798",

    "command injection": "CWE-78",
    "command execution": "CWE-78",

    "code injection": "CWE-95",
    "eval": "CWE-95",
    "exec": "CWE-95",

    "unsafe deserialization": "CWE-502",
    "insecure deserialization": "CWE-502",

    # Batch 1 â€” Injection
    "cross-site scripting": "CWE-79",
    "xss": "CWE-79",

    "sql injection": "CWE-89",

    "server-side template injection": "CWE-1336",
    "ssti": "CWE-1336",

    # Batch 2 â€” File & Network Security
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "path_traversal": "CWE-22",
    "path_traversal_attack": "CWE-22",

    # CWE-434 â€” Unrestricted File Upload
    "unrestricted file upload": "CWE-434",
    "unrestricted upload": "CWE-434",
    "unsafe file upload": "CWE-434",
    "file upload": "CWE-434",

    # CWE-352 ? Cross-Site Request Forgery
    "cross-site request forgery": "CWE-352",
    "csrf": "CWE-352",
}


CWE_NAMES = {

    "CWE-798":
        "Use of Hard-coded Credentials",

    "CWE-78":
        "Improper Neutralization of Special Elements used in an OS Command",

    "CWE-95":
        "Improper Neutralization of Directives in Dynamically Evaluated Code",

    "CWE-502":
        "Deserialization of Untrusted Data",

    "CWE-79":
        "Improper Neutralization of Input During Web Page Generation",

    "CWE-89":
        "Improper Neutralization of Special Elements used in an SQL Command",

    "CWE-1336":
        "Improper Neutralization of Special Elements Used in a Template Engine",

    "CWE-22":
        "Improper Limitation of a Pathname to a Restricted Directory",

    "CWE-434":
        "Unrestricted Upload of File with Dangerous Type",

    "CWE-352":
        "Cross-Site Request Forgery",
}


# ============================================================
# VULNERABILITY NORMALIZATION
# ============================================================

def normalize_vulnerability(value):

    if not value:
        return "Unknown Vulnerability"

    value = str(value).lower()

    if (
        "hardcoded password" in value
        or "hardcoded secret" in value
        or "hardcoded credential" in value
    ):
        return "Hardcoded Secret"

    if (
        "command injection" in value
        or "command execution" in value
    ):
        return "Command Injection"

    if (
        "code injection" in value
        or value == "eval"
        or value == "exec"
    ):
        return "Code Injection"

    if (
        "unsafe deserialization" in value
        or "insecure deserialization" in value
    ):
        return "Unsafe Deserialization"

    if (
        "cross-site scripting" in value
        or value == "xss"
    ):
        return "Cross-Site Scripting"

    if "sql injection" in value:
        return "SQL Injection"

    if (
        "server-side template injection" in value
        or value == "ssti"
    ):
        return "Server-Side Template Injection"

    if (
        "path traversal" in value
        or "directory traversal" in value
        or "path_traversal" in value
    ):
        return "Path Traversal"

    if (
        "unrestricted file upload" in value
        or "unrestricted upload" in value
        or "unsafe file upload" in value
        or "file upload" in value
    ):
        return "Unrestricted File Upload"

    if (
        "cross-site request forgery" in value
        or value == "csrf"
    ):
        return "Cross-Site Request Forgery"

    return value.title()


# ============================================================
# CWE INFERENCE
# ============================================================

def infer_cwe(
    vulnerability,
    description="",
):

    vulnerability_text = str(
        vulnerability or ""
    ).lower()

    description_text = str(
        description or ""
    ).lower()

    # --------------------------------------------------------
    # CWE-95 — Code Injection
    # Only infer CWE-95 from explicit code-injection indicators.
    # Do NOT infer it from generic subprocess warnings.
    # --------------------------------------------------------

    if (
        vulnerability_text in {"eval", "exec"}
        or "code injection" in vulnerability_text
    ):
        return "CWE-95"

    # --------------------------------------------------------
    # CWE-78 — Command Injection
    # --------------------------------------------------------

    if (
        "command injection" in vulnerability_text
        or "command execution" in vulnerability_text
    ):
        return "CWE-78"

    # --------------------------------------------------------
    # Other CWE mappings
    # --------------------------------------------------------

    text = (
        f"{vulnerability_text} {description_text}"
    )

    for keyword, cwe in CWE_MAP.items():

        # CWE-95 keywords are handled explicitly above.
        if keyword in {
            "code injection",
            "eval",
            "exec",
        }:
            continue

        if keyword in text:
            return cwe

    if (
        "path traversal" in text
        or "directory traversal" in text
        or "pathname" in text
        or "restricted directory" in text
    ):
        return "CWE-22"

    if (
        "unrestricted file upload" in text
        or "unrestricted upload" in text
        or "unsafe file upload" in text
        or "dangerous file type" in text
    ):
        return "CWE-434"

    return None

# ============================================================
# SEVERITY NORMALIZATION
# ============================================================

def normalize_severity(
    severity=None,
    vulnerability="",
    description="",
):

    if severity:

        severity = str(
            severity
        ).upper()

        if severity in {
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
        }:
            return severity

    text = (
        f"{vulnerability} {description}"
    ).lower()

    if (
        "hardcoded" in text
        or "command injection" in text
        or "code injection" in text
        or "unsafe deserialization" in text
        or "sql injection" in text
        or "path traversal" in text
        or "unrestricted file upload" in text
        or "unrestricted upload" in text
        or "unsafe file upload" in text
        or "cross-site request forgery" in text
        or "csrf" in text
    ):
        return "HIGH"

    if (
        "xss" in text
        or "cross-site scripting" in text
        or "ssti" in text
        or "template injection" in text
    ):
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

    # Pre-pass: collect simple variables derived from user input.
    # This intentionally does not mark a variable such as `query` as
    # tainted merely because of its name; its value must actually contain
    # a recognized user-input source.
    for statement in ast.walk(tree):

        if isinstance(statement, ast.Assign):
            if _contains_user_input(statement.value):
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        tainted_variables.add(target.id)

        elif isinstance(statement, ast.AnnAssign):
            if (
                statement.value is not None
                and _contains_user_input(statement.value)
                and isinstance(statement.target, ast.Name)
            ):
                tainted_variables.add(statement.target.id)

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

                    if _contains_user_input(
                        argument
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

            if (
                (
                    isinstance(
                        node.func,
                        ast.Attribute,
                    )
                    and node.func.attr in {
                        "render_template_string",
                        "from_string",
                    }
                )
                or
                (
                    isinstance(
                        node.func,
                        ast.Name,
                    )
                    and node.func.id == "Template"
                )
            ):

                if node.args:

                    template_argument = (
                        node.args[0]
                    )

                    if _contains_user_input(
                        template_argument
                    ):

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
                                "User-controlled input may be "
                                "interpreted as a server-side "
                                "template.",

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

        for item in data.get(
            "results",
            [],
        ):

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

def normalize_finding(
    finding,
):

    vulnerability = (
        normalize_vulnerability(
            finding.get(
                "vulnerability",
                "",
            )
        )
    )

    description = finding.get(
        "description",
        "",
    )

    cwe = finding.get(
        "cwe"
    )

    if cwe is None and finding.get("source") != "bandit":
        cwe = infer_cwe(
        vulnerability,
        description,
    )

    severity = normalize_severity(

        finding.get(
            "severity"
        ),

        vulnerability,

        description,
    )

    return {

        **finding,

        "vulnerability":
            vulnerability,

        "cwe":
            cwe,

        "severity":
            severity,

        "description":
            description,
    }


# ============================================================
# UNIFIED SECURITY ANALYZER
# ============================================================

def analyze_security(
    code,
    filename="<string>",
):

    ast_findings = scan_ast(
        code,
        filename,
    )

    bandit_findings = scan_bandit(
        code,
        filename,
    )

    semgrep_findings = scan_semgrep(
        code,
        filename,
    )

    raw_findings = (
        ast_findings
        + bandit_findings
        + semgrep_findings
    )

    normalized_findings = []

    seen = set()

    for finding in raw_findings:

        normalized = (
            normalize_finding(
                finding
            )
        )

        key = (

            normalized.get(
                "cwe"
            ),

            normalized.get(
                "line"
            ),

            normalized.get(
                "vulnerability"
            ),
        )

        if key not in seen:

            seen.add(
                key
            )

            normalized_findings.append(
                normalized
            )

    return normalized_findings


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
