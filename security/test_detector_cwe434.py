from security.unified_scanner import analyze_security


def run_test(name, code, expected_cwe=None, expect_findings=True):
    print(f"\n{name}")
    print("-" * 60)

    findings = analyze_security(code, "test_cwe434.py")

    print(f"Total findings: {len(findings)}")

    for finding in findings:
        print(
            f"CWE: {finding.get('cwe')} | "
            f"Severity: {finding.get('severity')} | "
            f"Vulnerability: {finding.get('vulnerability')}"
        )

    if expect_findings:
        if not findings:
            print("FAIL: Expected a vulnerability but none was detected")
            return False

        if expected_cwe:
            cwes = {finding.get("cwe") for finding in findings}

            if expected_cwe not in cwes:
                print(
                    f"FAIL: Expected {expected_cwe}, "
                    f"but detected {cwes}"
                )
                return False

        print(f"PASS: {expected_cwe} detected")
        return True

    else:
        if findings:
            print("FAIL: False-positive vulnerability detected")
            return False

        print("PASS: No false-positive findings")
        return True


def main():
    passed = 0
    total = 3

    # ============================================================
    # TEST 1 — BASIC UNRESTRICTED FILE UPLOAD
    # ============================================================

    vulnerable_upload = '''
from flask import request

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    file.save("/var/www/uploads/" + file.filename)
'''

    if run_test(
        "TEST 1 — UNRESTRICTED FILE UPLOAD (CWE-434)",
        vulnerable_upload,
        expected_cwe="CWE-434",
        expect_findings=True,
    ):
        passed += 1

    # ============================================================
    # TEST 2 — BENIGN STATIC FILE SAVE
    # ============================================================

    benign_upload = '''
def save_file():
    filename = "report.txt"
    with open("uploads/report.txt", "w") as file:
        file.write("safe content")
'''

    if run_test(
        "TEST 2 — BENIGN STATIC FILE SAVE",
        benign_upload,
        expect_findings=False,
    ):
        passed += 1

    # ============================================================
    # TEST 3 — USER-CONTROLLED FILENAME
    # ============================================================

    user_filename_upload = '''
from flask import request

@app.route("/upload", methods=["POST"])
def upload():
    filename = request.files["file"].filename
    upload_path = "/uploads/" + filename

    with open(upload_path, "wb") as file:
        file.write(request.files["file"].read())
'''

    if run_test(
        "TEST 3 — USER-CONTROLLED UPLOAD FILENAME",
        user_filename_upload,
        expected_cwe="CWE-434",
        expect_findings=True,
    ):
        passed += 1

    # ============================================================
    # SUMMARY
    # ============================================================

    print("\n" + "=" * 60)
    print("CWE-434 DETECTOR TEST SUMMARY")
    print("=" * 60)

    print(f"Tests passed: {passed}/{total}")

    if passed == total:
        print("OVERALL RESULT: PASS")
    else:
        print("OVERALL RESULT: FAIL")


if __name__ == "__main__":
    main()