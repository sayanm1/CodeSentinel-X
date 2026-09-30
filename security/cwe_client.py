"""
MITRE CWE REST API client for CodeSentinel-X.

This module enriches an already-detected CWE with information
from the official MITRE CWE REST API.

It does not perform source-code vulnerability scanning.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import requests


# Official MITRE CWE REST API base URL.
CWE_API_BASE_URL = "https://cwe-api.mitre.org/api/v1"


class CWEClient:
    """Client for the MITRE CWE REST API."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    @staticmethod
    def _normalize_cwe_id(cwe_id: str) -> Optional[str]:
        """
        Normalize CWE identifiers.

        Accepted:
            CWE-78
            cwe-78
            78

        Returns:
            Numeric CWE ID as a string, e.g. "78".
        """

        if not cwe_id:
            return None

        value = str(cwe_id).strip().upper()

        if value.startswith("CWE-"):
            value = value[4:]

        if not value.isdigit():
            return None

        return value

    def get_cwe(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve detailed information about a CWE weakness.

        Example:
            client.get_cwe("CWE-78")
        """

        numeric_id = self._normalize_cwe_id(cwe_id)

        if numeric_id is None:
            return {
                "status": "INVALID_CWE_ID",
                "cwe_id": cwe_id,
                "source": "MITRE CWE",
                "error": "Invalid CWE identifier.",
            }

        endpoint = (
            f"{CWE_API_BASE_URL}/cwe/weakness/{numeric_id}"
        )

        try:
            response = requests.get(
                endpoint,
                timeout=self.timeout,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "CodeSentinel-X/1.0",
                },
            )

            response.raise_for_status()

            data = response.json()

            # MITRE returns:
            #
            # {
            #     "Weaknesses": [...]
            # }
            #
            # Extract the first weakness for convenient use.

            weaknesses = data.get("Weaknesses", [])

            if not weaknesses:
                return {
                    "status": "NOT_FOUND",
                    "cwe_id": f"CWE-{numeric_id}",
                    "source": "MITRE CWE",
                    "api_url": endpoint,
                    "data": data,
                }

            weakness = weaknesses[0]

            return {
                "status": "SUCCESS",
                "cwe_id": f"CWE-{numeric_id}",
                "source": "MITRE CWE",
                "api_url": endpoint,
                "name": weakness.get("Name"),
                "description": weakness.get("Description"),
                "extended_description": weakness.get(
                    "ExtendedDescription"
                ),
                "status_mitre": weakness.get("Status"),
                "abstraction": weakness.get("Abstraction"),
                "likelihood_of_exploit": weakness.get(
                    "LikelihoodOfExploit"
                ),
                "potential_mitigations": weakness.get(
                    "PotentialMitigations"
                ),
                "common_consequences": weakness.get(
                    "CommonConsequences"
                ),
                "detection_methods": weakness.get(
                    "DetectionMethods"
                ),
                "relationships": weakness.get(
                    "Relationships"
                ),
                "references": weakness.get(
                    "References"
                ),
                "data": weakness,
            }

        except requests.HTTPError as exc:
            return {
                "status": "HTTP_ERROR",
                "cwe_id": f"CWE-{numeric_id}",
                "source": "MITRE CWE",
                "api_url": endpoint,
                "error": str(exc),
                "status_code": (
                    exc.response.status_code
                    if exc.response is not None
                    else None
                ),
            }

        except requests.Timeout as exc:
            return {
                "status": "TIMEOUT",
                "cwe_id": f"CWE-{numeric_id}",
                "source": "MITRE CWE",
                "api_url": endpoint,
                "error": str(exc),
            }

        except requests.ConnectionError as exc:
            return {
                "status": "CONNECTION_ERROR",
                "cwe_id": f"CWE-{numeric_id}",
                "source": "MITRE CWE",
                "api_url": endpoint,
                "error": str(exc),
            }

        except requests.RequestException as exc:
            return {
                "status": "REQUEST_ERROR",
                "cwe_id": f"CWE-{numeric_id}",
                "source": "MITRE CWE",
                "api_url": endpoint,
                "error": str(exc),
            }

        except ValueError as exc:
            return {
                "status": "INVALID_JSON",
                "cwe_id": f"CWE-{numeric_id}",
                "source": "MITRE CWE",
                "api_url": endpoint,
                "error": str(exc),
            }

    def get_multiple_cwes(
        self,
        cwe_ids: list[str],
    ) -> Dict[str, Any]:
        """
        Retrieve multiple CWE weaknesses individually.

        Example:
            client.get_multiple_cwes(
                ["CWE-78", "CWE-79", "CWE-89"]
            )
        """

        results: Dict[str, Any] = {}

        for cwe_id in cwe_ids:
            result = self.get_cwe(cwe_id)

            normalized = self._normalize_cwe_id(cwe_id)

            if normalized:
                key = f"CWE-{normalized}"
            else:
                key = str(cwe_id)

            results[key] = result

        return results


def get_cwe_info(
    cwe_id: str,
) -> Optional[Dict[str, Any]]:
    """
    Convenience function for CWE lookup.
    """

    client = CWEClient()

    return client.get_cwe(cwe_id)


if __name__ == "__main__":

    result = get_cwe_info("CWE-78")

    print("\n" + "=" * 70)
    print("CodeSentinel-X - MITRE CWE Intelligence")
    print("=" * 70)

    if result is None:
        print("No response received.")

    else:

        print(f"Status: {result.get('status')}")
        print(f"CWE: {result.get('cwe_id')}")
        print(f"Source: {result.get('source')}")
        print(f"API URL: {result.get('api_url')}")

        if result.get("status") == "SUCCESS":

            print(f"\nName:")
            print(result.get("name"))

            print(f"\nDescription:")
            print(result.get("description"))

            print(f"\nAbstraction:")
            print(result.get("abstraction"))

            print(f"\nMITRE Status:")
            print(result.get("status_mitre"))

            print(f"\nLikelihood of Exploit:")
            print(result.get("likelihood_of_exploit"))

            print("\nMITRE CWE API: SUCCESS")

        else:

            print("\nError:")
            print(result.get("error"))

    print("=" * 70)