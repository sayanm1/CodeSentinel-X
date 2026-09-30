"""
Tests for the CodeSentinel-X MITRE CWE client.
"""

from security.cwe_client import CWEClient


def test_cwe_lookup(cwe_id: str):
    """Test retrieval of a CWE from MITRE."""

    client = CWEClient()

    print(f"\nTesting {cwe_id}...")

    result = client.get_cwe(cwe_id)

    assert result is not None, "No response returned"

    print(f"CWE ID: {result.get('cwe_id')}")
    print(f"Source: {result.get('source')}")

    if "error" in result:
        print(f"ERROR: {result['error']}")
        return False

    print("MITRE API: SUCCESS")
    print("Data received: YES")

    return True


def main():
    print("=" * 60)
    print("CodeSentinel-X — CWE API Test")
    print("=" * 60)

    test_cases = [
        "CWE-78",
        "CWE-79",
        "CWE-89",
        "CWE-918",
    ]

    results = []

    for cwe_id in test_cases:
        results.append(test_cwe_lookup(cwe_id))

    passed = sum(results)
    total = len(results)

    print("\n" + "=" * 60)
    print(f"CWE API Tests: {passed}/{total} passed")

    if passed == total:
        print("Overall Result: PASS")
    else:
        print("Overall Result: CHECK API RESPONSE")

    print("=" * 60)


if __name__ == "__main__":
    main()