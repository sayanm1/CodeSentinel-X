from security.semgrep_scanner import run_semgrep


code = """import subprocess

user_input = input("Enter command: ")

subprocess.call(user_input, shell=True)
"""


findings = run_semgrep(code)

print("\n=== CodeSentinel-X Semgrep Results ===")

for finding in findings:
    print(finding)

print(f"\nTotal findings: {len(findings)}")