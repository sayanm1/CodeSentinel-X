"""
NVD CVE REST API client for CodeSentinel-X.

This module retrieves live CVE intelligence from the
official NIST National Vulnerability Database (NVD) API.

It does not perform source-code vulnerability scanning.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import os
import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVEClient:
    """Client for the official NVD CVE API."""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

        # Optional NVD API key.
        # The client still works without a key.
        self.api_key = os.getenv("NVD_API_KEY")

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "CodeSentinel-X/1.0",
        }

        if self.api_key:
            headers["apiKey"] = self.api_key

        return headers

    def search_cve(
        self,
        keyword: Optional[str] = None,
        cve_id: Optional[str] = None,
        cpe_name: Optional[str] = None,
        results_per_page: int = 5,
    ) -> Dict[str, Any]:
        """
        Search the NVD CVE database.

        Parameters:
            keyword:
                Search keyword such as "openssl" or "log4j".

            cve_id:
                Exact CVE identifier such as "CVE-2021-44228".

            cpe_name:
                CPE name when software/product identification is available.

            results_per_page:
                Maximum number of results requested.
        """

        params: Dict[str, Any] = {
            "resultsPerPage": results_per_page,
        }

        if keyword:
            params["keywordSearch"] = keyword

        if cve_id:
            params["cveId"] = cve_id

        if cpe_name:
            params["cpeName"] = cpe_name

        try:
            response = requests.get(
                NVD_API_URL,
                params=params,
                headers=self._headers(),
                timeout=self.timeout,
            )

            response.raise_for_status()

            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])

            results = []

            for item in vulnerabilities:
                cve = item.get("cve", {})

                cve_identifier = cve.get("id")

                descriptions = cve.get("descriptions", [])

                description = None

                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value")
                        break

                metrics = cve.get("metrics", {})

                cvss_data = None
                cvss_version = None

                if metrics.get("cvssMetricV40"):
                    metric = metrics["cvssMetricV40"][0]
                    cvss_data = metric.get("cvssData")
                    cvss_version = "4.0"

                elif metrics.get("cvssMetricV31"):
                    metric = metrics["cvssMetricV31"][0]
                    cvss_data = metric.get("cvssData")
                    cvss_version = "3.1"

                elif metrics.get("cvssMetricV30"):
                    metric = metrics["cvssMetricV30"][0]
                    cvss_data = metric.get("cvssData")
                    cvss_version = "3.0"

                elif metrics.get("cvssMetricV2"):
                    metric = metrics["cvssMetricV2"][0]
                    cvss_data = metric.get("cvssData")
                    cvss_version = "2.0"

                results.append(
                    {
                        "cve_id": cve_identifier,
                        "description": description,
                        "published": cve.get("published"),
                        "last_modified": cve.get("lastModified"),
                        "vuln_status": cve.get("vulnStatus"),
                        "cvss_version": cvss_version,
                        "cvss_score": (
                            cvss_data.get("baseScore")
                            if cvss_data
                            else None
                        ),
                        "cvss_severity": (
                            cvss_data.get("baseSeverity")
                            if cvss_data
                            else None
                        ),
                        "cvss_vector": (
                            cvss_data.get("vectorString")
                            if cvss_data
                            else None
                        ),
                        "references": [
                            ref.get("url")
                            for ref in cve.get("references", [])
                            if ref.get("url")
                        ],
                    }
                )

            return {
                "status": "SUCCESS",
                "source": "NIST NVD",
                "api_url": NVD_API_URL,
                "total_results": data.get("totalResults", 0),
                "results": results,
            }

        except requests.HTTPError as exc:
            return {
                "status": "HTTP_ERROR",
                "source": "NIST NVD",
                "api_url": NVD_API_URL,
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
                "source": "NIST NVD",
                "api_url": NVD_API_URL,
                "error": str(exc),
            }

        except requests.ConnectionError as exc:
            return {
                "status": "CONNECTION_ERROR",
                "source": "NIST NVD",
                "api_url": NVD_API_URL,
                "error": str(exc),
            }

        except requests.RequestException as exc:
            return {
                "status": "REQUEST_ERROR",
                "source": "NIST NVD",
                "api_url": NVD_API_URL,
                "error": str(exc),
            }

        except ValueError as exc:
            return {
                "status": "INVALID_JSON",
                "source": "NIST NVD",
                "api_url": NVD_API_URL,
                "error": str(exc),
            }


def get_cve_info(
    keyword: Optional[str] = None,
    cve_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Convenience function for CVE lookups."""

    client = CVEClient()

    return client.search_cve(
        keyword=keyword,
        cve_id=cve_id,
    )


if __name__ == "__main__":
    result = get_cve_info(
        cve_id="CVE-2021-44228"
    )

    print("\n" + "=" * 70)
    print("CodeSentinel-X - NIST NVD CVE Intelligence")
    print("=" * 70)

    print(f"Status: {result.get('status')}")
    print(f"Source: {result.get('source')}")
    print(f"Total Results: {result.get('total_results')}")

    if result.get("status") == "SUCCESS":

        for item in result.get("results", []):

            print("\nCVE ID:")
            print(item.get("cve_id"))

            print("\nCVSS:")
            print(
                item.get("cvss_score"),
                item.get("cvss_severity")
            )

            print("\nDescription:")
            print(item.get("description"))

            print("\nPublished:")
            print(item.get("published"))

            print("\nNVD API: SUCCESS")

    else:
        print("\nError:")
        print(result.get("error"))

    print("=" * 70)