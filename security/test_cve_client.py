"""
Tests for the CodeSentinel-X NIST NVD CVE API client.
"""

from security.cve_client import CVEClient


def test_cve_lookup(
    client: CVEClient,
    cve_id: str,
) -> bool:

    print(f"\nTesting {cve_id}...")

    result = client.search_cve(
        cve_id=cve_id
    )

    print(f"Status: {result.get('status')}")
    print(f"Source: {result.get('source')}")

    if result.get("status") != "SUCCESS":
        print(f"ERROR: {result.get('error')}")
        return False

    print(
        f"Total Results: "
        f"{result.get('total_results')}"
    )

    results = result.get("results", [])

    if not results:
        print("ERROR: No CVE result returned.")
        return False

    first = results[0]

    print(
        f"CVE ID: "
        f"{first.get('cve_id')}"
    )

    print(
        f"CVSS Score: "
        f"{first.get('cvss_score')}"
    )

    print(
        f"CVSS Severity: "
        f"{first.get('cvss_severity')}"
    )

    print(
        "Description received:",
        bool(first.get("description"))
    )

    print("NVD API: SUCCESS")

    return True


def main():

    print("=" * 70)
    print("CodeSentinel-X — NVD CVE API Test")
    print("=" * 70)

    client = CVEClient(timeout=15)

    test_cases = [
        "CVE-2021-44228",
        "CVE-2014-0160",
        "CVE-2017-0144",
    ]

    results = []

    for cve_id in test_cases:

        success = test_cve_lookup(
            client,
            cve_id,
        )

        results.append(success)

    passed = sum(results)
    total = len(results)

    print("\n" + "=" * 70)

    print(
        f"NVD CVE API Tests: "
        f"{passed}/{total} passed"
    )

    if passed == total:
        print("Overall Result: PASS")
    else:
        print("Overall Result: FAIL")

    print("=" * 70)


if __name__ == "__main__":
    main()