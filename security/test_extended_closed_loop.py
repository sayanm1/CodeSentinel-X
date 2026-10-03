from security.unified_scanner import analyze_security
from security.repair_engine import generate_repair, validate_repair
from security.test_extended_vulnerabilities import TEST_CODE


EXPECTED_CWES = {
    "CWE-22",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-95",
    "CWE-1336",
    "CWE-352",
    "CWE-434",
    "CWE-502",
    "CWE-639",
    "CWE-798",
    "CWE-862",
    "CWE-863",
    "CWE-284",
    "CWE-306",
    "CWE-918",
}

AUTOMATIC_REPAIR_CWES = {
    "CWE-22",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-95",
    "CWE-1336",
    "CWE-434",
    "CWE-502",
    "CWE-798",
    "CWE-918",
}

CONTEXT_DEPENDENT_CWES = {
    "CWE-284",
    "CWE-306",
    "CWE-352",
    "CWE-639",
    "CWE-862",
    "CWE-863",
}

VALIDATION_FIELDS = [
    "syntax_valid",
    "shell_true_removed",
    "eval_removed",
    "pickle_removed",
    "environment_variable_used",
    "ast_literal_eval_used",
    "json_loads_used",
    "sql_parameterization_used",
    "path_traversal_mitigated",
    "ssrf_validation_used",
    "ssti_removed",
    "xss_mitigation_used",
    "file_upload_restricted",
]


def get_cwe(finding):
    if not isinstance(finding, dict):
        return None

    cwe = finding.get("cwe")

    if isinstance(cwe, dict):
        cwe = (
            cwe.get("id")
            or cwe.get("cwe_id")
            or cwe.get("name")
        )

    if not cwe:
        cwe = (
            finding.get("cwe_id")
            or finding.get("cweId")
            or finding.get("CWE")
        )

    if isinstance(cwe, str):
        cwe = cwe.strip().upper()

        if not cwe.startswith("CWE-"):
            if cwe.isdigit():
                cwe = f"CWE-{cwe}"

        return cwe

    return None


def build_cwe_set(findings):
    return {
        cwe
        for finding in findings
        if (cwe := get_cwe(finding)) is not None
    }


def print_findings(title, findings):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)

    if not findings:
        print("No findings.")
        return

    for index, finding in enumerate(findings, start=1):
        cwe = get_cwe(finding)
        severity = finding.get("severity", "UNKNOWN")
        confidence = finding.get("confidence", "UNKNOWN")
        line = (
            finding.get("line")
            or finding.get("line_number")
            or finding.get("line_no")
            or "?"
        )
        message = (
            finding.get("message")
            or finding.get("description")
            or finding.get("title")
            or "No description"
        )

        print(
            f"{index:02d}. "
            f"{cwe or 'NO-CWE'} | "
            f"Severity: {severity} | "
            f"Confidence: {confidence} | "
            f"Line: {line}"
        )
        print(f"    {message}")


def print_cwe_coverage(findings):
    detected = build_cwe_set(findings)

    missing = EXPECTED_CWES - detected
    extra = detected - EXPECTED_CWES

    print("\n" + "=" * 80)
    print("CWE COVERAGE")
    print("=" * 80)

    print(f"Expected CWE classes : {len(EXPECTED_CWES)}")
    print(f"Detected CWE classes : {len(detected)}")

    print("\nDetected:")
    for cwe in sorted(detected):
        print(f"  ✓ {cwe}")

    print("\nMissing:")
    if missing:
        for cwe in sorted(missing):
            print(f"  ✗ {cwe}")
    else:
        print("  None")

    print("\nExtra:")
    if extra:
        for cwe in sorted(extra):
            print(f"  ! {cwe}")
    else:
        print("  None")

    return not missing and not extra


def analyze_repair_capability(findings):
    automatic_repairs = []
    context_dependent = []
    unavailable = []

    for finding in findings:
        cwe = get_cwe(finding)

        try:
            repair = generate_repair(finding=finding)
        except TypeError:
            repair = generate_repair(finding)

        if not isinstance(repair, dict):
            repair = {
                "repair_status": "REPAIR_UNAVAILABLE",
                "message": "Invalid repair response.",
            }

        repair_status = repair.get(
            "repair_status",
            "REPAIR_UNAVAILABLE",
        )

        if (
            repair_status == "REPAIR_AVAILABLE"
            and cwe in AUTOMATIC_REPAIR_CWES
        ):
            automatic_repairs.append(
                {
                    "finding": finding,
                    "repair": repair,
                }
            )

        elif cwe in CONTEXT_DEPENDENT_CWES:
            context_dependent.append(
                {
                    "finding": finding,
                    "repair": repair,
                }
            )

        else:
            unavailable.append(
                {
                    "finding": finding,
                    "repair": repair,
                }
            )

    return automatic_repairs, context_dependent, unavailable


def print_repair_capability(
    automatic_repairs,
    context_dependent,
    unavailable,
):
    automatic_cwes = sorted(
        {
            get_cwe(item["finding"])
            for item in automatic_repairs
            if get_cwe(item["finding"])
        }
    )

    context_cwes = sorted(
        {
            get_cwe(item["finding"])
            for item in context_dependent
            if get_cwe(item["finding"])
        }
    )

    unavailable_cwes = sorted(
        {
            get_cwe(item["finding"])
            for item in unavailable
            if get_cwe(item["finding"])
        }
    )

    print("\n" + "=" * 80)
    print("REPAIR CAPABILITY ANALYSIS")
    print("=" * 80)

    print(
        f"Automatic repair candidates : "
        f"{len(automatic_repairs)}"
    )
    print(
        f"Context-dependent findings  : "
        f"{len(context_dependent)}"
    )
    print(
        f"Unavailable findings        : "
        f"{len(unavailable)}"
    )

    print("\nAutomatic-repair CWE classes:")
    if automatic_cwes:
        for cwe in automatic_cwes:
            print(f"  ✓ {cwe}")
    else:
        print("  None")

    print("\nContext-dependent CWE classes:")
    if context_cwes:
        for cwe in context_cwes:
            print(f"  • {cwe}")
    else:
        print("  None")

    print("\nUnavailable CWE classes:")
    if unavailable_cwes:
        for cwe in unavailable_cwes:
            print(f"  ✗ {cwe}")
    else:
        print("  None")

    capability_passed = (
        len(unavailable) == 0
        and set(automatic_cwes).issubset(AUTOMATIC_REPAIR_CWES)
        and set(context_cwes).issubset(CONTEXT_DEPENDENT_CWES)
    )

    return capability_passed


def print_validation(validation):
    print("\n" + "=" * 80)
    print("REPAIR VALIDATION")
    print("=" * 80)

    all_passed = True

    for field in VALIDATION_FIELDS:
        value = bool(validation.get(field, False))

        print(
            f"{field}: "
            f"{'True' if value else 'False'}"
        )

        if not value:
            all_passed = False

    validation_all_passed = bool(
        validation.get("all_passed", all_passed)
    )

    print(
        f"all_passed: "
        f"{'True' if validation_all_passed else 'False'}"
    )

    return validation_all_passed


def compare_cwes(before_findings, after_findings):
    before = build_cwe_set(before_findings)
    after = build_cwe_set(after_findings)

    resolved = before - after
    remaining = after & before

    return resolved, remaining


def main():
    print("=" * 80)
    print("CodeSentinel-X Extended Closed-Loop Security Test")
    print("=" * 80)

    print("\nScanning original benchmark code...")

    original_findings = analyze_security(
        TEST_CODE,
        filename="extended_benchmark.py",
    )

    original_cwes = build_cwe_set(original_findings)

    print_findings(
        "ORIGINAL FINDINGS",
        original_findings,
    )

    coverage_passed = print_cwe_coverage(
        original_findings
    )

    print("\n" + "=" * 80)
    print("ORIGINAL SUMMARY")
    print("=" * 80)

    print(
        f"Total findings      : "
        f"{len(original_findings)}"
    )
    print(
        f"Distinct CWE classes: "
        f"{len(original_cwes)}"
    )

    (
        automatic_repairs,
        context_dependent,
        unavailable,
    ) = analyze_repair_capability(
        original_findings
    )

    capability_passed = print_repair_capability(
        automatic_repairs,
        context_dependent,
        unavailable,
    )

    print("\n" + "=" * 80)
    print("GENERATING REPAIRED CODE")
    print("=" * 80)

    repaired_code = TEST_CODE

    generated_repairs = []

    for item in automatic_repairs:
        finding = item["finding"]
        repair = item["repair"]

        repaired = (
            repair.get("repaired_code")
            or repair.get("code")
            or repair.get("generated_code")
        )

        if repaired:
            repaired_code = repaired
            generated_repairs.append(
                {
                    "finding": finding,
                    "repair": repair,
                }
            )

    if not generated_repairs:
        try:
            from security.repair_engine import (
                generate_repaired_code,
            )

            repaired_code = generate_repaired_code(
                TEST_CODE,
                original_findings,
            )
        except Exception:
            repaired_code = TEST_CODE

    print(
        f"\nGenerated repair candidates: "
        f"{len(generated_repairs)}"
    )

    print("\n" + "-" * 80)
    print("REPAIRED CODE")
    print("-" * 80)
    print(repaired_code)

    print("\n" + "=" * 80)
    print("VALIDATING REPAIR")
    print("=" * 80)

    validation = validate_repair(
        TEST_CODE,
        repaired_code,
        findings=original_findings,
    )

    all_validation_passed = print_validation(
        validation
    )

    print("\n" + "=" * 80)
    print("RE-SCANNING REPAIRED CODE")
    print("=" * 80)

    repaired_findings = analyze_security(
        repaired_code,
        filename="extended_benchmark_repaired.py",
    )

    repaired_cwes = build_cwe_set(
        repaired_findings
    )

    print_findings(
        "REPAIRED FINDINGS",
        repaired_findings,
    )

    print("\n" + "=" * 80)
    print("BEFORE / AFTER COMPARISON")
    print("=" * 80)

    resolved_cwes, remaining_cwes = compare_cwes(
        original_findings,
        repaired_findings,
    )

    print(
        f"Original findings : "
        f"{len(original_findings)}"
    )
    print(
        f"Remaining findings: "
        f"{len(repaired_findings)}"
    )

    if original_findings:
        reduction = (
            (
                len(original_findings)
                - len(repaired_findings)
            )
            / len(original_findings)
        ) * 100
    else:
        reduction = 0.0

    print(
        f"Security reduction: "
        f"{reduction:.1f}%"
    )

    print("\nResolved CWE classes:")
    if resolved_cwes:
        for cwe in sorted(resolved_cwes):
            print(f"  ✓ {cwe}")
    else:
        print("  None")

    print("\nRemaining CWE classes:")
    if remaining_cwes:
        for cwe in sorted(remaining_cwes):
            print(f"  • {cwe}")
    else:
        print("  None")

    unresolved_automatic_cwes = (
        repaired_cwes & AUTOMATIC_REPAIR_CWES
    )

    print("\n" + "=" * 80)
    print("AUTOMATIC REPAIR VERIFICATION")
    print("=" * 80)

    if unresolved_automatic_cwes:
        print(
            "Automatically repairable CWE classes "
            "still remain:"
        )

        for cwe in sorted(
            unresolved_automatic_cwes
        ):
            print(f"  • {cwe}")
    else:
        print(
            "All automatically repairable CWE "
            "classes were resolved."
        )

    context_remaining = (
        repaired_cwes & CONTEXT_DEPENDENT_CWES
    )

    print("\nContext-dependent CWE classes remaining:")

    if context_remaining:
        for cwe in sorted(context_remaining):
            print(f"  • {cwe}")
    else:
        print("  None")

    overall_passed = (
        coverage_passed
        and capability_passed
        and all_validation_passed
        and len(unresolved_automatic_cwes) == 0
        and len(unavailable) == 0
    )

    print("\n" + "=" * 80)
    print(
        "OVERALL RESULT: "
        f"{'PASS' if overall_passed else 'FAIL'}"
    )
    print("=" * 80)

    if not coverage_passed:
        print(
            "Coverage verification failed."
        )

    if not capability_passed:
        print(
            "Repair capability classification failed."
        )

    if not all_validation_passed:
        print(
            "Repair validation failed."
        )

    if unavailable:
        print(
            "Unavailable findings remain: "
            f"{len(unavailable)}"
        )

    if unresolved_automatic_cwes:
        print(
            "Automatically repairable CWE classes "
            "still remain:"
        )

        for cwe in sorted(
            unresolved_automatic_cwes
        ):
            print(f"  • {cwe}")


if __name__ == "__main__":
    main()