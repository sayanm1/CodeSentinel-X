from ai.explanation_agent import create_explanation_agent


def main():

    agent = create_explanation_agent()

    finding = {
        "line": 10,
        "vulnerability": "Command Injection",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": (
            "subprocess call with shell=True identified, "
            "security issue."
        ),
        "source": "Bandit",
        "cwe_id": "CWE-78",
        "cwe_name": (
            "Improper Neutralization of Special Elements "
            "used in an OS Command"
        ),
        "risk_score": 9.0,
        "risk_level": "CRITICAL"
    }

    knowledge = {
        "title": "OS Command Injection",

        "impact": (
            "An attacker may execute unauthorized operating-system "
            "commands, access sensitive information, modify files, "
            "or compromise the host system."
        ),

        "common_causes": [
            "Using subprocess with shell=True",
            "Building operating-system commands using string concatenation",
            "Passing untrusted user input directly to command execution"
        ],

        "mitigation": (
            "Avoid shell=True whenever possible. "
            "Use subprocess with shell=False. "
            "Pass commands and arguments as separate list elements. "
            "Validate and restrict user-controlled input."
        ),

        "secure_example": (
            "subprocess.run(['ping', '-c', '1', hostname], shell=False)"
        )
    }

    result = agent.generate_explanation(
        finding,
        knowledge
    )

    print("\n=== CodeSentinel-X AI Explanation Test ===")

    print("\nVulnerability:")
    print(result["vulnerability"])

    print("\nCWE:")
    print(result["cwe_id"])

    print("\nRisk:")
    print(result["risk_level"])

    print("\nRisk Score:")
    print(result["risk_score"])

    print("\nExplanation:")
    print(result["explanation"])

    print("\nWhy Dangerous:")
    print(result["why_dangerous"])

    print("\nMitigation:")
    print(result["mitigation"])

    print("\nSecure Example:")
    print(result["secure_example"])


if __name__ == "__main__":
    main()