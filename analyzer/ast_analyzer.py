import ast


class SecurityVisitor(ast.NodeVisitor):

    def __init__(self):
        self.findings = []

    def add_finding(self, node, vulnerability, severity, description):
        self.findings.append({
            "line": getattr(node, "lineno", None),
            "vulnerability": vulnerability,
            "severity": severity,
            "description": description
        })

    # Detect eval()
    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):

            if node.func.id == "eval":
                self.add_finding(
                    node,
                    "Code Injection",
                    "HIGH",
                    "Use of eval() can execute attacker-controlled Python code."
                )

            elif node.func.id == "exec":
                self.add_finding(
                    node,
                    "Code Injection",
                    "HIGH",
                    "Use of exec() can execute dynamically supplied Python code."
                )

        self.generic_visit(node)

    # Detect dangerous imports
    def visit_Import(self, node):
        for alias in node.names:

            if alias.name == "pickle":
                self.add_finding(
                    node,
                    "Unsafe Deserialization",
                    "HIGH",
                    "pickle can execute arbitrary code when loading untrusted data."
                )

            if alias.name == "subprocess":
                self.add_finding(
                    node,
                    "Command Execution",
                    "MEDIUM",
                    "subprocess can execute operating-system commands."
                )

        self.generic_visit(node)

    # Detect hardcoded credentials
    def visit_Assign(self, node):

        for target in node.targets:

            if isinstance(target, ast.Name):

                name = target.id.lower()

                sensitive_names = [
                    "password",
                    "passwd",
                    "secret",
                    "api_key",
                    "apikey",
                    "token"
                ]

                if any(word in name for word in sensitive_names):

                    if isinstance(node.value, ast.Constant):
                        self.add_finding(
                            node,
                            "Hardcoded Secret",
                            "HIGH",
                            f"Possible hardcoded sensitive value stored in '{target.id}'."
                        )

        self.generic_visit(node)


def analyze_code(source_code: str):

    try:
        tree = ast.parse(source_code)
    except SyntaxError as error:
        return {
            "status": "error",
            "error": str(error),
            "findings": []
        }

    visitor = SecurityVisitor()
    visitor.visit(tree)

    return {
        "status": "success",
        "total_findings": len(visitor.findings),
        "findings": visitor.findings
    }


if __name__ == "__main__":

    vulnerable_code = """
import pickle
import subprocess

password = "admin123"

user_input = input("Enter expression: ")
result = eval(user_input)

exec(user_input)

subprocess.call(user_input, shell=True)

data = pickle.loads(user_input)
"""

    result = analyze_code(vulnerable_code)

    for finding in result["findings"]:
        print(finding)