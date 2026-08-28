import json
from pathlib import Path
from typing import Optional, List, Dict, Any

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


class SecurityRAG:
    """
    CodeSentinel-X Security RAG Engine

    Features:
    - Loads security knowledge from JSON
    - Handles UTF-8 and UTF-8 BOM files
    - Supports multiple JSON field naming conventions
    - Builds FAISS semantic search index
    - Performs exact CWE matching
    - Performs exact vulnerability matching
    - Supports vulnerability aliases
    - Provides retrieve_knowledge() compatibility
    - Provides retrieve() compatibility
    """

    def __init__(
        self,
        knowledge_file: Optional[str] = None,
        embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2",
    ):

        print("Loading embedding model...")

        self.embedding_model = SentenceTransformer(embedding_model)

        # ---------------------------------------------------------
        # SECURITY KNOWLEDGE FILE
        # ---------------------------------------------------------

        if knowledge_file is None:
            knowledge_file = (
                Path(__file__).resolve().parent
                / "security_knowledge.json"
            )

        self.knowledge_file = Path(knowledge_file)

        self.documents = self._load_documents()

        if not self.documents:
            raise ValueError(
                "Security knowledge file contains no valid documents."
            )

        print(
            f"Loaded {len(self.documents)} security documents."
        )

        # ---------------------------------------------------------
        # BUILD FAISS INDEX
        # ---------------------------------------------------------

        self.index = self._build_index()

        print(
            f"FAISS index created with "
            f"{self.index.ntotal} documents."
        )

    # ============================================================
    # LOAD DOCUMENTS
    # ============================================================

    def _load_documents(self) -> List[Dict[str, Any]]:

        if not self.knowledge_file.exists():
            raise FileNotFoundError(
                f"Security knowledge file not found: "
                f"{self.knowledge_file}"
            )

        # utf-8-sig handles BOTH:
        # UTF-8
        # UTF-8 with BOM
        with open(
            self.knowledge_file,
            "r",
            encoding="utf-8-sig"
        ) as file:

            data = json.load(file)

        # --------------------------------------------------------
        # Support:
        #
        # [
        #   {...}
        # ]
        #
        # OR
        #
        # {
        #   "documents": [...]
        # }
        #
        # OR
        #
        # {
        #   "security_knowledge": [...]
        # }
        # --------------------------------------------------------

        if isinstance(data, dict):

            if "documents" in data:
                data = data["documents"]

            elif "security_knowledge" in data:
                data = data["security_knowledge"]

            elif "knowledge" in data:
                data = data["knowledge"]

            else:
                raise ValueError(
                    "Invalid security knowledge JSON format. "
                    "Expected a list or a dictionary containing "
                    "'documents', 'security_knowledge', or "
                    "'knowledge'."
                )

        if not isinstance(data, list):
            raise ValueError(
                "Security knowledge must be a JSON list."
            )

        normalized_documents = []

        for item in data:

            if not isinstance(item, dict):
                continue

            # ====================================================
            # CWE
            # ====================================================

            cwe = self._get_first_value(
                item,
                [
                    "cwe",
                    "CWE",
                    "cwe_id",
                    "CWE_ID",
                    "CWE-ID",
                    "CWE ID",
                    "cweId",
                    "cweID",
                    "weakness",
                    "weakness_id",
                    "weaknessId",
                ],
            )

            if cwe is not None:

                cwe = str(cwe).strip().upper()

                # Convert:
                # 78 -> CWE-78
                if cwe.isdigit():
                    cwe = f"CWE-{cwe}"

                # Convert:
                # cwe78 -> CWE-78
                elif cwe.startswith("CWE") and not cwe.startswith(
                    "CWE-"
                ):
                    remaining = cwe[3:].strip()

                    if remaining.isdigit():
                        cwe = f"CWE-{remaining}"

            # ====================================================
            # VULNERABILITY
            # ====================================================

            vulnerability = self._get_first_value(
                item,
                [
                    "vulnerability",
                    "Vulnerability",
                    "name",
                    "Name",
                    "type",
                    "Type",
                    "vulnerability_type",
                    "vulnerabilityType",
                    "finding_type",
                    "findingType",
                ],
                default="",
            )

            vulnerability = str(
                vulnerability or ""
            ).strip()

            # ====================================================
            # TITLE
            # ====================================================

            title = self._get_first_value(
                item,
                [
                    "title",
                    "Title",
                    "name_title",
                ],
                default="",
            )

            title = str(
                title or ""
            ).strip()

            # ====================================================
            # DESCRIPTION
            # ====================================================

            description = self._get_first_value(
                item,
                [
                    "description",
                    "Description",
                    "details",
                    "Details",
                    "summary",
                    "Summary",
                ],
                default="",
            )

            description = str(
                description or ""
            ).strip()

            # ====================================================
            # IMPACT
            # ====================================================

            impact = self._get_first_value(
                item,
                [
                    "impact",
                    "Impact",
                    "security_impact",
                    "securityImpact",
                    "consequences",
                    "Consequences",
                ],
                default="",
            )

            impact = str(
                impact or ""
            ).strip()

            # ====================================================
            # COMMON CAUSES
            # ====================================================

            common_causes = self._get_first_value(
                item,
                [
                    "common_causes",
                    "Common Causes",
                    "common causes",
                    "commonCauses",
                    "causes",
                    "Causes",
                    "common_cause",
                ],
                default=[],
            )

            common_causes = self._normalize_list(
                common_causes
            )

            # ====================================================
            # MITIGATION
            # ====================================================

            mitigation = self._get_first_value(
                item,
                [
                    "mitigation",
                    "Mitigation",
                    "mitigations",
                    "Mitigations",
                    "mitigation_steps",
                    "mitigationSteps",
                    "recommendations",
                    "Recommendations",
                    "remediation",
                    "Remediation",
                    "fix",
                    "Fix",
                    "fixes",
                    "Fixes",
                    "prevention",
                    "Prevention",
                ],
                default=[],
            )

            mitigation = self._normalize_list(
                mitigation
            )

            # ====================================================
            # SECURE EXAMPLE
            # ====================================================

            secure_example = self._get_first_value(
                item,
                [
                    "secure_example",
                    "Secure Example",
                    "secureExample",
                    "secure_example_code",
                    "secureExampleCode",
                    "safe_example",
                    "safeExample",
                    "secure_code",
                    "secureCode",
                ],
                default="",
            )

            secure_example = str(
                secure_example or ""
            ).strip()

            # ====================================================
            # NORMALIZED DOCUMENT
            # ====================================================

            normalized = {
                "cwe": cwe,
                "vulnerability": vulnerability,
                "title": title,
                "description": description,
                "impact": impact,
                "common_causes": common_causes,
                "mitigation": mitigation,
                "secure_example": secure_example,
            }

            normalized_documents.append(
                normalized
            )

        return normalized_documents

    # ============================================================
    # HELPER: GET FIRST AVAILABLE VALUE
    # ============================================================

    @staticmethod
    def _get_first_value(
        item: Dict[str, Any],
        keys: List[str],
        default: Any = None,
    ) -> Any:

        for key in keys:

            if key in item:

                value = item[key]

                if value is not None:

                    return value

        return default

    # ============================================================
    # HELPER: NORMALIZE LIST
    # ============================================================

    @staticmethod
    def _normalize_list(
        value: Any
    ) -> List[str]:

        if value is None:
            return []

        # Already a list
        if isinstance(value, list):

            result = []

            for item in value:

                text = str(item).strip()

                if text:
                    result.append(text)

            return result

        # Dictionary
        if isinstance(value, dict):

            result = []

            for key, item in value.items():

                text = f"{key}: {item}".strip()

                if text:
                    result.append(text)

            return result

        # String
        text = str(value).strip()

        if not text:
            return []

        # Handle newline-separated mitigation
        if "\n" in text:

            return [
                line.strip()
                for line in text.splitlines()
                if line.strip()
            ]

        return [text]

    # ============================================================
    # DOCUMENT TO SEARCH TEXT
    # ============================================================

    def _document_to_text(
        self,
        document: Dict[str, Any]
    ) -> str:

        common_causes = document.get(
            "common_causes",
            []
        )

        mitigation = document.get(
            "mitigation",
            []
        )

        if isinstance(common_causes, list):

            common_causes_text = " ".join(
                common_causes
            )

        else:

            common_causes_text = str(
                common_causes
            )

        if isinstance(mitigation, list):

            mitigation_text = " ".join(
                mitigation
            )

        else:

            mitigation_text = str(
                mitigation
            )

        text_parts = [
            str(document.get("cwe") or ""),
            str(document.get("vulnerability") or ""),
            str(document.get("title") or ""),
            str(document.get("description") or ""),
            str(document.get("impact") or ""),
            common_causes_text,
            mitigation_text,
            str(
                document.get(
                    "secure_example"
                ) or ""
            ),
        ]

        return " ".join(
            text_parts
        ).strip()

    # ============================================================
    # BUILD FAISS INDEX
    # ============================================================

    def _build_index(self):

        texts = [
            self._document_to_text(
                document
            )
            for document in self.documents
        ]

        embeddings = self.embedding_model.encode(
            texts,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )

        embeddings = np.asarray(
            embeddings,
            dtype=np.float32,
        )

        dimension = embeddings.shape[1]

        # --------------------------------------------------------
        # IndexFlatIP + normalized vectors
        # = cosine similarity
        # --------------------------------------------------------

        index = faiss.IndexFlatIP(
            dimension
        )

        index.add(
            embeddings
        )

        return index

    # ============================================================
    # NORMALIZE VULNERABILITY
    # ============================================================

    @staticmethod
    def _normalize_vulnerability(
        vulnerability: Optional[str]
    ) -> str:

        if not vulnerability:
            return ""

        value = str(
            vulnerability
        ).strip().lower()

        # Replace separators
        value = value.replace("_", " ")
        value = value.replace("-", " ")

        value = " ".join(
            value.split()
        )

        aliases = {

            # Command injection
            "command execution":
                "command injection",

            "os command injection":
                "command injection",

            "command injection":
                "command injection",

            "subprocess without shell equals true":
                "command injection",

            "subprocess popen with shell equals true":
                "command injection",

            "subprocess call with shell equals true":
                "command injection",

            "subprocess shell injection":
                "command injection",

            # Code injection
            "code injection":
                "code injection",

            # Deserialization
            "unsafe deserialization":
                "unsafe deserialization",

            "deserialization of untrusted data":
                "unsafe deserialization",

            # Hardcoded secrets
            "hardcoded secret":
                "hardcoded secret",

            "hardcoded password":
                "hardcoded secret",

            "hardcoded credential":
                "hardcoded secret",

            "hardcoded password string":
                "hardcoded secret",
        }

        return aliases.get(
            value,
            value
        )

    # ============================================================
    # FIND BY CWE
    # ============================================================

    def _find_by_cwe(
        self,
        cwe_id: Optional[str]
    ) -> List[Dict[str, Any]]:

        if not cwe_id:
            return []

        target_cwe = str(
            cwe_id
        ).strip().upper()

        if target_cwe.isdigit():
            target_cwe = f"CWE-{target_cwe}"

        if (
            target_cwe.startswith("CWE")
            and not target_cwe.startswith("CWE-")
        ):

            remaining = target_cwe[3:].strip()

            if remaining.isdigit():
                target_cwe = f"CWE-{remaining}"

        matches = []

        for document in self.documents:

            document_cwe = document.get(
                "cwe"
            )

            if not document_cwe:
                continue

            document_cwe = str(
                document_cwe
            ).strip().upper()

            if document_cwe.isdigit():
                document_cwe = (
                    f"CWE-{document_cwe}"
                )

            if (
                document_cwe.startswith("CWE")
                and not document_cwe.startswith("CWE-")
            ):

                remaining = (
                    document_cwe[3:]
                    .strip()
                )

                if remaining.isdigit():
                    document_cwe = (
                        f"CWE-{remaining}"
                    )

            if document_cwe == target_cwe:

                matches.append(
                    document
                )

        return matches

    # ============================================================
    # FIND BY VULNERABILITY
    # ============================================================

    def _find_by_vulnerability(
        self,
        vulnerability: Optional[str]
    ) -> List[Dict[str, Any]]:

        if not vulnerability:
            return []

        target = (
            self._normalize_vulnerability(
                vulnerability
            )
        )

        matches = []

        for document in self.documents:

            document_vulnerability = (
                self._normalize_vulnerability(
                    document.get(
                        "vulnerability"
                    )
                )
            )

            if (
                document_vulnerability
                == target
            ):

                matches.append(
                    document
                )

        return matches

    # ============================================================
    # MAIN SEARCH
    # ============================================================

    def search_by_vulnerability(
        self,
        vulnerability: Optional[str] = None,
        cwe_id: Optional[str] = None,
        top_k: int = 1,
    ) -> List[Dict[str, Any]]:
        """
        Search security knowledge.

        Priority:
        1. Exact CWE
        2. Exact vulnerability
        3. Semantic FAISS search
        """

        # --------------------------------------------------------
        # 1. EXACT CWE
        # --------------------------------------------------------

        cwe_matches = self._find_by_cwe(
            cwe_id
        )

        if cwe_matches:

            results = []

            for document in cwe_matches[
                :top_k
            ]:

                result = dict(
                    document
                )

                result["similarity"] = 1.0
                result["distance"] = 0.0

                results.append(
                    result
                )

            return results

        # --------------------------------------------------------
        # 2. EXACT VULNERABILITY
        # --------------------------------------------------------

        vulnerability_matches = (
            self._find_by_vulnerability(
                vulnerability
            )
        )

        if vulnerability_matches:

            results = []

            for document in (
                vulnerability_matches[
                    :top_k
                ]
            ):

                result = dict(
                    document
                )

                result["similarity"] = 1.0
                result["distance"] = 0.0

                results.append(
                    result
                )

            return results

        # --------------------------------------------------------
        # 3. SEMANTIC FAISS SEARCH
        # --------------------------------------------------------

        query_parts = []

        if cwe_id:
            query_parts.append(
                str(cwe_id)
            )

        if vulnerability:
            query_parts.append(
                str(vulnerability)
            )

        query = " ".join(
            query_parts
        ).strip()

        if not query:
            return []

        query_embedding = (
            self.embedding_model.encode(
                [query],
                convert_to_numpy=True,
                normalize_embeddings=True,
                show_progress_bar=False,
            )
        )

        query_embedding = np.asarray(
            query_embedding,
            dtype=np.float32,
        )

        k = min(
            max(1, top_k),
            len(self.documents)
        )

        scores, indices = (
            self.index.search(
                query_embedding,
                k,
            )
        )

        results = []

        for score, index_position in zip(
            scores[0],
            indices[0],
        ):

            if index_position < 0:
                continue

            document = dict(
                self.documents[
                    index_position
                ]
            )

            similarity = float(
                score
            )

            distance = (
                1.0 - similarity
            )

            document["similarity"] = (
                similarity
            )

            document["distance"] = (
                distance
            )

            results.append(
                document
            )

        return results

    # ============================================================
    # SEARCH VULNERABILITY ALIAS
    # ============================================================

    def search_vulnerability(
        self,
        vulnerability: Optional[str] = None,
        cwe_id: Optional[str] = None,
        top_k: int = 1,
    ) -> List[Dict[str, Any]]:

        return self.search_by_vulnerability(
            vulnerability=vulnerability,
            cwe_id=cwe_id,
            top_k=top_k,
        )

    # ============================================================
    # RETRIEVE KNOWLEDGE
    # ============================================================

    def retrieve_knowledge(
        self,
        vulnerability: Optional[str] = None,
        cwe_id: Optional[str] = None,
        top_k: int = 1,
    ) -> Optional[Dict[str, Any]]:
        """
        Compatibility method for explanation_agent.py.

        Returns one security knowledge document.
        """

        results = self.search_by_vulnerability(
            vulnerability=vulnerability,
            cwe_id=cwe_id,
            top_k=top_k,
        )

        if not results:
            return None

        return results[0]

    # ============================================================
    # RETRIEVE ALIAS
    # ============================================================

    def retrieve(
        self,
        vulnerability: Optional[str] = None,
        cwe_id: Optional[str] = None,
        top_k: int = 1,
    ) -> Optional[Dict[str, Any]]:

        return self.retrieve_knowledge(
            vulnerability=vulnerability,
            cwe_id=cwe_id,
            top_k=top_k,
        )