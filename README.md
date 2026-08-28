\# CodeSentinel-X



\## AST-Guided Agentic AI Framework for Explainable Software Vulnerability Detection, Root-Cause Analysis and Automated Code Repair



CodeSentinel-X is an AI-assisted software security framework designed to detect, analyze, explain, and automatically repair common security vulnerabilities in Python source code.



The framework combines static security analysis, CWE-based risk assessment, Retrieval-Augmented Generation (RAG), AI-generated security explanations, and deterministic automated code repair into a closed-loop security pipeline.



\---



\## 🚀 Key Features



\* \*\*Multi-Scanner Security Analysis\*\*



&#x20; \* Bandit integration

&#x20; \* Semgrep integration

&#x20; \* Custom AST-based unified scanner



\* \*\*CWE Mapping\*\*



&#x20; \* CWE-78 — OS Command Injection

&#x20; \* CWE-95 — Code Injection

&#x20; \* CWE-502 — Deserialization of Untrusted Data

&#x20; \* CWE-798 — Use of Hard-coded Credentials



\* \*\*Risk Analysis\*\*



&#x20; \* Vulnerability severity classification

&#x20; \* Risk scoring

&#x20; \* CWE-based risk mapping



\* \*\*Security RAG\*\*



&#x20; \* Security knowledge retrieval

&#x20; \* FAISS vector index

&#x20; \* Embedding-based vulnerability knowledge retrieval



\* \*\*AI Security Explanation\*\*



&#x20; \* Vulnerability explanation

&#x20; \* Root-cause analysis

&#x20; \* Security impact

&#x20; \* Mitigation recommendations

&#x20; \* Secure code examples



\* \*\*Automated Code Repair\*\*



&#x20; \* Hardcoded secret remediation

&#x20; \* Command injection remediation

&#x20; \* Code injection remediation

&#x20; \* Unsafe deserialization remediation



\* \*\*Repair Validation\*\*



&#x20; \* Python syntax validation

&#x20; \* Security pattern validation

&#x20; \* Repair-rule validation



\* \*\*Closed-Loop Verification\*\*



&#x20; \* Scan vulnerable code

&#x20; \* Generate repair

&#x20; \* Validate repaired code

&#x20; \* Re-scan repaired code

&#x20; \* Compare vulnerabilities before and after repair



\---



\## 🏗️ System Architecture



```text

&#x20;                   Source Code

&#x20;                        |

&#x20;                        v

&#x20;             +----------------------+

&#x20;             | Unified Security     |

&#x20;             | Scanner              |

&#x20;             |                      |

&#x20;             | AST + Bandit +       |

&#x20;             | Semgrep              |

&#x20;             +----------+-----------+

&#x20;                        |

&#x20;                        v

&#x20;             +----------------------+

&#x20;             | Finding Normalizer   |

&#x20;             |                      |

&#x20;             | CWE Mapping          |

&#x20;             | Severity             |

&#x20;             | Deduplication        |

&#x20;             +----------+-----------+

&#x20;                        |

&#x20;                        v

&#x20;             +----------------------+

&#x20;             | Risk Engine          |

&#x20;             |                      |

&#x20;             | Risk Score           |

&#x20;             | Risk Level           |

&#x20;             +----------+-----------+

&#x20;                        |

&#x20;                        v

&#x20;             +----------------------+

&#x20;             | Security RAG         |

&#x20;             |                      |

&#x20;             | Embeddings + FAISS   |

&#x20;             +----------+-----------+

&#x20;                        |

&#x20;                        v

&#x20;             +----------------------+

&#x20;             | AI Explanation       |

&#x20;             | Agent                |

&#x20;             |                      |

&#x20;             | Root Cause           |

&#x20;             | Impact               |

&#x20;             | Mitigation           |

&#x20;             +----------+-----------+

&#x20;                        |

&#x20;                        v

&#x20;             +----------------------+

&#x20;             | Automated Repair     |

&#x20;             | Engine               |

&#x20;             +----------+-----------+

&#x20;                        |

&#x20;                        v

&#x20;             +----------------------+

&#x20;             | Repair Validation    |

&#x20;             +----------+-----------+

&#x20;                        |

&#x20;                        v

&#x20;             +----------------------+

&#x20;             | Re-Scan Repaired     |

&#x20;             | Code                 |

&#x20;             +----------+-----------+

&#x20;                        |

&#x20;                        v

&#x20;               Closed-Loop Result

```



\---



\## 🔐 Vulnerabilities Currently Supported



| Vulnerability          | CWE     | Example Detection       | Automated Repair     |

| ---------------------- | ------- | ----------------------- | -------------------- |

| Hardcoded Secret       | CWE-798 | `password = "admin123"` | Environment variable |

| Command Injection      | CWE-78  | `shell=True`            | `shell=False`        |

| Code Injection         | CWE-95  | `eval(user\_input)`      | `ast.literal\_eval()` |

| Unsafe Deserialization | CWE-502 | `pickle.loads()`        | `json.loads()`       |



\---



\## 📂 Project Structure



```text

CodeSentinel-X/

│

├── security/

│   ├── \_\_init\_\_.py

│   ├── bandit\_scanner.py

│   ├── semgrep\_scanner.py

│   ├── unified\_scanner.py

│   ├── finding\_normalizer.py

│   ├── risk\_engine.py

│   ├── repair\_engine.py

│   │

│   ├── test\_bandit\_scanner.py

│   ├── test\_semgrep\_scanner.py

│   ├── test\_risk\_engine.py

│   ├── test\_repair\_engine.py

│   ├── test\_unified\_scanner.py

│   ├── test\_closed\_loop.py

│   └── test\_vulnerable.py

│

├── rag/

│   └── ...

│

├── agents/

│   └── ...

│

├── data/

│   └── ...

│

├── .gitignore

├── requirements.txt

└── README.md

```



\---



\## ⚙️ Installation



\### 1. Clone the repository



```bash

git clone https://github.com/sayanm1/CodeSentinel-X.git

cd CodeSentinel-X

```



\### 2. Create a virtual environment



Windows:



```powershell

python -m venv .venv

```



\### 3. Activate the virtual environment



```powershell

.venv\\Scripts\\activate

```



\### 4. Install dependencies



```powershell

pip install -r requirements.txt

```



If Bandit or Semgrep are not included in `requirements.txt`, install them with:



```powershell

pip install bandit

pip install semgrep

```



\---



\# 🧪 Testing



CodeSentinel-X contains separate validation tests for the security pipeline.



\## Bandit Scanner



```powershell

python -m security.test\_bandit\_scanner

```



Expected result:



```text

Bandit detected 3 finding(s).



PASS: subprocess/shell security issue detected.

PASS: Hardcoded password issue detected.

```



\---



\## Semgrep Scanner



```powershell

python -m security.test\_semgrep\_scanner

```



The scanner should identify the insecure `shell=True` subprocess pattern.



\---



\## Risk Engine



```powershell

python -m security.test\_risk\_engine

```



Expected validation:



```text

CWE Mapping Tests : 4/4



Overall Result: PASS

Risk Engine and CWE mapping are working correctly.

```



\---



\## Automated Repair Engine



```powershell

python -m security.test\_repair\_engine

```



Expected validation:



```text

Repair Rule Tests: 4/4

Validation Tests: 7/7



Overall Result: PASS

```



\---



\# 🔄 Closed-Loop Security Verification



The most important feature of CodeSentinel-X is the closed-loop security workflow.



Run:



```powershell

python -m security.test\_closed\_loop

```



The pipeline performs:



```text

Vulnerable Code

&#x20;     ↓

Initial Security Scan

&#x20;     ↓

CWE Identification

&#x20;     ↓

Risk Analysis

&#x20;     ↓

Automated Repair

&#x20;     ↓

Repair Validation

&#x20;     ↓

Re-Scan Repaired Code

&#x20;     ↓

Before/After Comparison

&#x20;     ↓

Final Security Result

```



Current closed-loop validation demonstrates:



```text

Original vulnerabilities : 4

Remaining vulnerabilities: 0

Security reduction       : 100.0%

Initial CWE detection    : 4/4

Repair validation        : 7/7

CWE resolutions          : 4/4



OVERALL RESULT: PASS

```



This verifies that the framework can detect, repair, validate, and re-scan the tested vulnerabilities successfully.



\---



\# 🤖 AI + RAG Pipeline



The framework uses a Security RAG component to retrieve relevant vulnerability knowledge.



The RAG pipeline:



```text

Security Knowledge

&#x20;      ↓

Embedding Model

&#x20;      ↓

Vector Representation

&#x20;      ↓

FAISS Index

&#x20;      ↓

Similarity Search

&#x20;      ↓

Relevant CWE Knowledge

&#x20;      ↓

AI Security Explanation

```



The retrieved knowledge can provide:



\* CWE information

\* Vulnerability description

\* Security impact

\* Recommended mitigation

\* Secure coding examples



\---



\# 📊 Example Security Report



Example finding:



```text

Vulnerability : Command Injection

CWE           : CWE-78

Severity      : HIGH

Risk Score    : 7.5

Risk Level    : HIGH

```



Explanation:



```text

A Command Injection vulnerability was detected.

The application uses a shell-enabled subprocess call,

which may allow attacker-controlled input to reach the

operating-system command interpreter.

```



Mitigation:



```python

subprocess.run(

&#x20;   \['ping', '-c', '1', hostname],

&#x20;   shell=False,

&#x20;   check=True

)

```



\---



\# 🛠️ Automated Repair Examples



\### Hardcoded Secret



Before:



```python

password = "admin123"

```



After:



```python

import os



password = os.environ.get('APP\_PASSWORD')

```



\---



\### Command Injection



Before:



```python

subprocess.call(user, shell=True)

```



After:



```python

subprocess.call(user, shell=False)

```



\---



\### Code Injection



Before:



```python

eval(user\_input)

```



After:



```python

import ast



ast.literal\_eval(user\_input)

```



\---



\### Unsafe Deserialization



Before:



```python

pickle.loads(user\_data)

```



After:



```python

import json



json.loads(user\_data)

```



\---



\# 📈 Current Validation Results



| Component                  | Result |

| -------------------------- | -----: |

| Bandit Scanner             |   PASS |

| Semgrep Scanner            |   PASS |

| Unified Scanner            |   PASS |

| CWE Mapping                |    4/4 |

| Repair Rules               |    4/4 |

| Repair Validation          |    7/7 |

| Closed-Loop CWE Resolution |    4/4 |

| Security Reduction         |   100% |

| End-to-End Pipeline        |   PASS |



\---



\# 🎯 Research Contribution



CodeSentinel-X focuses on combining multiple stages of software security analysis into a single automated workflow.



The framework integrates:



1\. Static vulnerability detection

2\. AST-guided analysis

3\. Multi-tool security scanning

4\. Finding normalization

5\. CWE classification

6\. Risk scoring

7\. Security knowledge retrieval

8\. AI-generated explanations

9\. Automated code repair

10\. Repair validation

11\. Post-repair security scanning

12\. Closed-loop verification



The closed-loop architecture allows the repaired source code to be independently re-analyzed instead of assuming that a generated repair is secure.



\---



\# ⚠️ Disclaimer



CodeSentinel-X is a research and educational security analysis framework.



Automated repairs should be reviewed and tested before being applied to production software. A successful repair validation result does not guarantee that the entire application is free from security vulnerabilities.



\---



\# 👨‍💻 Author



\*\*Sayan Mukherjee\*\*



M.Tech — Computer Science Engineering



GitHub:

https://github.com/sayanm1



\---



\## ⭐ Project Status



\*\*Active Research / Development\*\*



The framework is currently being expanded toward a complete agentic AI-based software security pipeline with explainable vulnerability detection, root-cause analysis, automated repair, and closed-loop verification.



