"""
Tests for CodeSentinel-X OWASP Top 10:2025 mapping.
"""

from security.owasp_mapper import OWASPMapper


def test_mapping(
    mapper: OWASPMapper,
    cwe_id: str,
    expected_category: str,
) -> bool:

    print(f"\nTesting {cwe_id}...")

    result = mapper.map_cwe(cwe_id)

    print(f"Status: {result.get('status')}")

    if result.get("status") != "SUCCESS":
        print("ERROR: No OWASP mapping found.")
        return False

    categories = result.get("categories", [])

    if not categories:
        print("ERROR: Empty OWASP category list.")
        return False

    category_ids = [
        category.get("id")
        for category in categories
    ]

    print(
        "OWASP Categories:",
        ", ".join(category_ids),
    )

    if expected_category not in category_ids:
        print(
            f"ERROR: Expected {expected_category}"
            " not found."
        )
        return False

    print("Mapping: SUCCESS")

    return True


def main():

    print("=" * 70)
    print("CodeSentinel-X — OWASP Top 10:2025 Mapping Test")
    print("=" * 70)

    mapper = OWASPMapper()

    test_cases = [
        ("CWE-78", "A05:2025"),
        ("CWE-79", "A05:2025"),
        ("CWE-89", "A05:2025"),
        ("CWE-22", "A01:2025"),
        ("CWE-352", "A01:2025"),
        ("CWE-862", "A01:2025"),
        ("CWE-287", "A07:2025"),
        ("CWE-798", "A07:2025"),
        ("CWE-327", "A04:2025"),
        ("CWE-502", "A08:2025"),
        ("CWE-532", "A09:2025"),
    ]

    results = []

    for cwe_id, expected_category in test_cases:

        success = test_mapping(
            mapper,
            cwe_id,
            expected_category,
        )

        results.append(success)

    passed = sum(results)
    total = len(results)

    print("\n" + "=" * 70)

    print(
        f"OWASP Mapping Tests: "
        f"{passed}/{total} passed"
    )

    if passed == total:
        print("Overall Result: PASS")
    else:
        print("Overall Result: FAIL")

    print("=" * 70)


if __name__ == "__main__":
    main()
