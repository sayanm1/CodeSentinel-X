import json
from pathlib import Path


KNOWLEDGE_FILE = Path(
    "knowledge_base/security_knowledge.json"
)


def load_knowledge_base():

    with open(
        KNOWLEDGE_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


if __name__ == "__main__":

    knowledge = load_knowledge_base()

    print("\n=== CodeSentinel-X Security Knowledge Base ===")

    print(
        "Total security entries:",
        len(knowledge)
    )

    for item in knowledge:

        print(
            f"\n{item['cwe_id']} - "
            f"{item['vulnerability']}"
        )

        print(
            "Title:",
            item["title"]
        )

        print(
            "Impact:",
            item["impact"]
        )

        print(
            "Mitigations:",
            len(item["mitigation"])
        )