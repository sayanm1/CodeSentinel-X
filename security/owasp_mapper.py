"""
OWASP Top 10:2025 mapping for CodeSentinel-X.

Maps detected CWE weaknesses to relevant OWASP Top 10:2025
categories.

This module does not perform vulnerability scanning.
"""

from __future__ import annotations

from typing import Any, Dict, List


OWASP_2025_CATEGORIES = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}


CWE_TO_OWASP_2025 = {
    # Injection
    "CWE-78": ["A05:2025"],
    "CWE-79": ["A05:2025"],
    "CWE-89": ["A05:2025"],
    "CWE-95": ["A05:2025"],
    "CWE-1336": ["A05:2025"],
    "CWE-611": ["A05:2025"],
    "CWE-918": ["A05:2025"],

    # Access Control
    "CWE-22": ["A01:2025"],
    "CWE-352": ["A01:2025"],
    "CWE-601": ["A01:2025"],
    "CWE-862": ["A01:2025"],
    "CWE-863": ["A01:2025"],
    "CWE-284": ["A01:2025"],

    # Authentication
    "CWE-287": ["A07:2025"],
    "CWE-306": ["A07:2025"],
    "CWE-798": ["A07:2025"],
    "CWE-916": ["A07:2025"],

    # Cryptography
    "CWE-326": ["A04:2025"],
    "CWE-327": ["A04:2025"],
    "CWE-312": ["A04:2025"],
    "CWE-319": ["A04:2025"],

    # Software/Data Integrity
    "CWE-502": ["A08:2025"],
    "CWE-434": ["A08:2025"],

    # Logging / Monitoring
    "CWE-117": ["A09:2025"],
    "CWE-532": ["A09:2025"],
    "CWE-778": ["A09:2025"],
}


class OWASPMapper:
    """Map CWE identifiers to OWASP Top 10:2025 categories."""

    @staticmethod
    def normalize_cwe_id(cwe_id: str) -> str | None:
        if not cwe_id:
            return None

        value = str(cwe_id).strip().upper()

        if value.startswith("CWE-"):
            value = value[4:]

        if not value.isdigit():
            return None

        return f"CWE-{value}"

    def map_cwe(self, cwe_id: str) -> Dict[str, Any]:
        normalized = self.normalize_cwe_id(cwe_id)

        if normalized is None:
            return {
                "status": "INVALID_CWE_ID",
                "cwe_id": cwe_id,
                "source": "OWASP Top 10:2025",
                "categories": [],
            }

        category_ids = CWE_TO_OWASP_2025.get(
            normalized,
            []
        )

        categories: List[Dict[str, str]] = []

        for category_id in category_ids:
            categories.append(
                {
                    "id": category_id,
                    "name": OWASP_2025_CATEGORIES.get(
                        category_id,
                        "Unknown",
                    ),
                }
            )

        if not categories:
            return {
                "status": "NO_MAPPING",
                "cwe_id": normalized,
                "source": "OWASP Top 10:2025",
                "categories": [],
            }

        return {
            "status": "SUCCESS",
            "cwe_id": normalized,
            "source": "OWASP Top 10:2025",
            "categories": categories,
        }

    def map_multiple(
        self,
        cwe_ids: List[str],
    ) -> Dict[str, Any]:

        results = {}

        for cwe_id in cwe_ids:
            normalized = self.normalize_cwe_id(cwe_id)

            key = normalized or str(cwe_id)

            results[key] = self.map_cwe(cwe_id)

        return results


def get_owasp_mapping(
    cwe_id: str,
) -> Dict[str, Any]:
    mapper = OWASPMapper()
    return mapper.map_cwe(cwe_id)


if __name__ == "__main__":

    mapper = OWASPMapper()

    test_cwes = [
        "CWE-78",
        "CWE-79",
        "CWE-89",
        "CWE-798",
        "CWE-502",
    ]

    print("\n" + "=" * 70)
    print("CodeSentinel-X - OWASP Top 10:2025 Mapping")
    print("=" * 70)

    for cwe_id in test_cwes:

        result = mapper.map_cwe(cwe_id)

        print(f"\nCWE: {cwe_id}")
        print(f"Status: {result.get('status')}")

        for category in result.get("categories", []):
            print(
                f"OWASP: {category['id']} — "
                f"{category['name']}"
            )

    print("\n" + "=" * 70)