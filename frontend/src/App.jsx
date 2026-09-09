import { useRef, useState } from "react";

const API_BASE = "http://127.0.0.1:8000";

const DEFAULT_CODE = `import subprocess
import pickle

password = "admin123"

user = input("Enter command: ")
subprocess.call(user, shell=True)

eval(user)

pickle.loads(user)
`;

function App() {
  const fileInputRef = useRef(null);

  const [code, setCode] = useState(DEFAULT_CODE);
  const [filename, setFilename] = useState("example.py");

  const [scanResult, setScanResult] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [repairResult, setRepairResult] = useState(null);
  const [closedLoopResult, setClosedLoopResult] = useState(null);

  const [loading, setLoading] = useState(false);
  const [activeAction, setActiveAction] = useState("");
  const [error, setError] = useState("");

  // ---------------------------------------------------------
  // Helper
  // ---------------------------------------------------------

  const apiRequest = async (endpoint, body) => {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    let data;

    try {
      data = await response.json();
    } catch {
      throw new Error("Invalid response received from backend.");
    }

    if (!response.ok) {
      throw new Error(
        data.detail ||
          data.message ||
          `Request failed with status ${response.status}`
      );
    }

    return data;
  };

  // ---------------------------------------------------------
  // Scan
  // ---------------------------------------------------------

  const runScan = async () => {
    if (!code.trim()) {
      setError("Please enter Python code first.");
      return;
    }

    setLoading(true);
    setActiveAction("scan");
    setError("");

    try {
      const data = await apiRequest("/api/scan", {
        code,
        filename,
      });

      console.log("Scan API response:", data);

      setScanResult(data);

      // New scan means old downstream results are stale.
      setAnalysisResult(null);
      setRepairResult(null);
      setClosedLoopResult(null);
    } catch (err) {
      console.error("Scan error:", err);
      setError(err.message);
    } finally {
      setLoading(false);
      setActiveAction("");
    }
  };

  // ---------------------------------------------------------
  // Analyze
  // ---------------------------------------------------------

  const runAnalyze = async () => {
    if (!code.trim()) {
      setError("Please enter Python code first.");
      return;
    }

    setLoading(true);
    setActiveAction("analyze");
    setError("");

    try {
      const data = await apiRequest("/api/analyze", {
        code,
        filename,
      });

      console.log("Analyze API response:", data);

      setAnalysisResult(data);
    } catch (err) {
      console.error("Analyze error:", err);
      setError(err.message);
    } finally {
      setLoading(false);
      setActiveAction("");
    }
  };

  // ---------------------------------------------------------
  // Repair
  // ---------------------------------------------------------

  const runRepair = async () => {
    if (!code.trim()) {
      setError("Please enter Python code first.");
      return;
    }

    setLoading(true);
    setActiveAction("repair");
    setError("");

    try {
      const findings =
        scanResult?.findings ||
        scanResult?.final_findings ||
        [];

      const data = await apiRequest("/api/repair", {
        code,
        filename,
        findings,
      });

      console.log("Repair API response:", data);

      setRepairResult(data);
    } catch (err) {
      console.error("Repair error:", err);
      setError(err.message);
    } finally {
      setLoading(false);
      setActiveAction("");
    }
  };

  // ---------------------------------------------------------
  // Closed Loop
  // ---------------------------------------------------------

  const runClosedLoop = async () => {
    if (!code.trim()) {
      setError("Please enter Python code first.");
      return;
    }

    setLoading(true);
    setActiveAction("closed-loop");
    setError("");

    try {
      const data = await apiRequest("/api/closed-loop", {
        code,
        filename,
      });

      console.log("Closed-loop API response:", data);

      // -----------------------------------------------------
      // Normalize initial findings
      // -----------------------------------------------------

      const initialFindings =
        data.initial_findings ??
        data.original_findings ??
        data.initial_scan?.findings ??
        [];

      // -----------------------------------------------------
      // Normalize remaining findings
      // -----------------------------------------------------

      const remainingFindings =
        data.remaining_findings ??
        data.final_findings ??
        data.final_scan?.findings ??
        [];

      // -----------------------------------------------------
      // Initial count
      // -----------------------------------------------------

      const initialCount =
        data.initial_count ??
        data.initial_findings_count ??
        data.original_count ??
        initialFindings.length;

      // -----------------------------------------------------
      // Remaining count
      // -----------------------------------------------------

      const remainingCount =
        data.remaining_count ??
        data.remaining_findings_count ??
        data.final_count ??
        remainingFindings.length;

      // -----------------------------------------------------
      // Security reduction
      // -----------------------------------------------------

      let securityReduction =
        data.security_reduction ??
        data.reduction_percentage ??
        data.security_reduction_percentage;

      if (
        securityReduction === undefined ||
        securityReduction === null
      ) {
        if (initialCount > 0) {
          securityReduction =
            ((initialCount - remainingCount) / initialCount) *
            100;
        } else {
          securityReduction = 100;
        }
      }

      // -----------------------------------------------------
      // Validation
      // -----------------------------------------------------

      const validationPassed =
        data.validation_passed ??
        data.repair_validation?.all_passed ??
        data.validation?.all_passed ??
        data.repair?.validation?.all_passed ??
        (remainingCount === 0);

      // -----------------------------------------------------
      // Final status
      // -----------------------------------------------------

      const finalStatus =
        data.result === "PASS" ||
        data.final_result === "PASS" ||
        data.status === "PASS" ||
        (
          validationPassed === true &&
          remainingCount === 0
        )
          ? "PASS"
          : "FAIL";

      // -----------------------------------------------------
      // CWE resolutions
      // -----------------------------------------------------

      let cweResolutions =
        data.cwe_resolutions ??
        data.cwe_resolution_count ??
        data.resolved_cwes ??
        data.cwe_resolutions_verified;

      if (Array.isArray(cweResolutions)) {
        cweResolutions = cweResolutions.length;
      }

      if (
        cweResolutions === undefined ||
        cweResolutions === null
      ) {
        cweResolutions =
          remainingCount === 0
            ? initialCount
            : Math.max(
                0,
                initialCount - remainingCount
              );
      }

      // -----------------------------------------------------
      // Save normalized result
      // -----------------------------------------------------

      setClosedLoopResult({
        ...data,

        status: finalStatus,

        initial_findings: initialFindings,
        remaining_findings: remainingFindings,

        initial_count: initialCount,
        remaining_count: remainingCount,

        security_reduction: Number(
          Number(securityReduction).toFixed(1)
        ),

        cwe_resolutions: cweResolutions,

        validation_passed: validationPassed,
      });
    } catch (err) {
      console.error("Closed-loop error:", err);
      setError(err.message);
    } finally {
      setLoading(false);
      setActiveAction("");
    }
  };

  // ---------------------------------------------------------
  // File Upload
  // ---------------------------------------------------------

  const handleFileUpload = (event) => {
    const file = event.target.files?.[0];

    if (!file) {
      return;
    }

    if (!file.name.toLowerCase().endsWith(".py")) {
      setError("Please upload a Python (.py) file.");
      return;
    }

    const reader = new FileReader();

    reader.onload = (e) => {
      const content = e.target?.result;

      if (typeof content === "string") {
        setCode(content);
        setFilename(file.name);

        setScanResult(null);
        setAnalysisResult(null);
        setRepairResult(null);
        setClosedLoopResult(null);
        setError("");
      }
    };

    reader.onerror = () => {
      setError("Unable to read the selected file.");
    };

    reader.readAsText(file);
  };

  // ---------------------------------------------------------
  // Clear
  // ---------------------------------------------------------

  const clearAll = () => {
    setCode("");
    setFilename("example.py");

    setScanResult(null);
    setAnalysisResult(null);
    setRepairResult(null);
    setClosedLoopResult(null);

    setError("");

    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  // ---------------------------------------------------------
  // PDF Report
  // ---------------------------------------------------------

  const downloadPDF = () => {
    const findings =
      scanResult?.findings ||
      scanResult?.final_findings ||
      [];

    const repairedCode =
      repairResult?.repaired_code ||
      "";

    const validation =
      repairResult?.validation ||
      {};

    const initialCount =
      closedLoopResult?.initial_count ??
      findings.length;

    const remainingCount =
      closedLoopResult?.remaining_count ??
      0;

    const reduction =
      closedLoopResult?.security_reduction ??
      (
        initialCount > 0
          ? ((initialCount - remainingCount) /
              initialCount) *
            100
          : 100
      );

    const cweResolutions =
      closedLoopResult?.cwe_resolutions ??
      (remainingCount === 0
        ? initialCount
        : Math.max(
            0,
            initialCount - remainingCount
          ));

    const status =
      closedLoopResult?.status ||
      "NOT RUN";

    const escapeHTML = (value) =>
      String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");

    const findingsHTML =
      findings.length > 0
        ? findings
            .map(
              (finding, index) => `
                <div class="finding">
                  <h3>
                    ${index + 1}.
                    ${escapeHTML(
                      finding.vulnerability ||
                        finding.issue ||
                        "Security Finding"
                    )}
                  </h3>

                  <p>
                    <b>CWE:</b>
                    ${escapeHTML(
                      finding.cwe ||
                        finding.cwe_id ||
                        "N/A"
                    )}
                  </p>

                  <p>
                    <b>CWE Name:</b>
                    ${escapeHTML(
                      finding.cwe_name ||
                        "N/A"
                    )}
                  </p>

                  <p>
                    <b>Severity:</b>
                    ${escapeHTML(
                      finding.severity ||
                        "N/A"
                    )}
                  </p>

                  <p>
                    <b>Confidence:</b>
                    ${escapeHTML(
                      finding.confidence ??
                        "N/A"
                    )}
                  </p>

                  <p>
                    <b>Risk Score:</b>
                    ${escapeHTML(
                      finding.risk_score ??
                        "N/A"
                    )}
                  </p>

                  <p>
                    <b>Line:</b>
                    ${escapeHTML(
                      finding.line ??
                        finding.line_number ??
                        "N/A"
                    )}
                  </p>

                  <p>
                    ${escapeHTML(
                      finding.description ||
                        ""
                    )}
                  </p>
                </div>
              `
            )
            .join("")
        : "<p>No security findings detected.</p>";

    const validationHTML =
      Object.keys(validation).length > 0
        ? Object.entries(validation)
            .map(
              ([key, value]) => `
                <tr>
                  <td>${escapeHTML(key)}</td>
                  <td>
                    ${
                      value === true
                        ? "PASS"
                        : value === false
                        ? "FAIL"
                        : escapeHTML(value)
                    }
                  </td>
                </tr>
              `
            )
            .join("")
        : `
            <tr>
              <td>Validation</td>
              <td>Not available</td>
            </tr>
          `;

    const reportHTML = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8" />

        <title>
          CodeSentinel-X Security Report
        </title>

        <style>
          body {
            font-family:
              Arial,
              Helvetica,
              sans-serif;

            margin: 40px;

            color: #111827;

            line-height: 1.6;
          }

          h1 {
            margin-bottom: 5px;
          }

          h2 {
            margin-top: 30px;
            border-bottom: 1px solid #d1d5db;
            padding-bottom: 8px;
          }

          .subtitle {
            color: #6b7280;
          }

          .summary {
            display: grid;
            grid-template-columns:
              repeat(4, 1fr);

            gap: 12px;

            margin: 20px 0;
          }

          .metric {
            border: 1px solid #d1d5db;
            border-radius: 8px;
            padding: 15px;
          }

          .metric span {
            display: block;
            color: #6b7280;
            font-size: 12px;
          }

          .metric strong {
            display: block;
            font-size: 24px;
            margin-top: 5px;
          }

          .finding {
            border: 1px solid #d1d5db;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
          }

          .finding h3 {
            margin-top: 0;
          }

          pre {
            background: #f3f4f6;
            padding: 15px;
            border-radius: 8px;
            white-space: pre-wrap;
            font-family: Consolas, monospace;
            font-size: 12px;
          }

          table {
            width: 100%;
            border-collapse: collapse;
          }

          th,
          td {
            border: 1px solid #d1d5db;
            padding: 8px;
            text-align: left;
          }

          th {
            background: #f3f4f6;
          }

          .footer {
            margin-top: 40px;
            color: #6b7280;
            font-size: 12px;
          }

          @media print {
            body {
              margin: 20px;
            }

            .summary {
              grid-template-columns:
                repeat(4, 1fr);
            }
          }
        </style>
      </head>

      <body>

        <h1>
          CodeSentinel-X
        </h1>

        <div class="subtitle">
          Security Analysis Report
        </div>

        <p>
          <b>File:</b>
          ${escapeHTML(filename)}
        </p>

        <p>
          <b>Generated:</b>
          ${new Date().toLocaleString()}
        </p>

        <h2>
          Executive Summary
        </h2>

        <div class="summary">

          <div class="metric">
            <span>
              Initial Findings
            </span>

            <strong>
              ${initialCount}
            </strong>
          </div>

          <div class="metric">
            <span>
              Remaining Findings
            </span>

            <strong>
              ${remainingCount}
            </strong>
          </div>

          <div class="metric">
            <span>
              Security Reduction
            </span>

            <strong>
              ${Number(reduction).toFixed(1)}%
            </strong>
          </div>

          <div class="metric">
            <span>
              Closed-Loop Status
            </span>

            <strong>
              ${escapeHTML(status)}
            </strong>
          </div>

        </div>

        <h2>
          Security Findings
        </h2>

        ${findingsHTML}

        <h2>
          Original Source Code
        </h2>

        <pre>${escapeHTML(code)}</pre>

        ${
          repairedCode
            ? `
              <h2>
                Repaired Source Code
              </h2>

              <pre>
${escapeHTML(repairedCode)}
              </pre>
            `
            : ""
        }

        <h2>
          Repair Validation
        </h2>

        <table>

          <thead>
            <tr>
              <th>Check</th>
              <th>Result</th>
            </tr>
          </thead>

          <tbody>
            ${validationHTML}
          </tbody>

        </table>

        <h2>
          Closed-Loop Verification
        </h2>

        <p>
          <b>Initial Findings:</b>
          ${initialCount}
        </p>

        <p>
          <b>Remaining Findings:</b>
          ${remainingCount}
        </p>

        <p>
          <b>Security Reduction:</b>
          ${Number(reduction).toFixed(1)}%
        </p>

        <p>
          <b>CWE Resolutions:</b>
          ${cweResolutions}/${initialCount}
        </p>

        <p>
          <b>Final Status:</b>
          ${escapeHTML(status)}
        </p>

        <div class="footer">
          CodeSentinel-X —
          AST-Guided Agentic AI Framework for
          Explainable Software Vulnerability
          Detection, Root-Cause Analysis and
          Automated Code Repair.
        </div>

      </body>
      </html>
    `;

    const reportWindow = window.open(
      "",
      "_blank"
    );

    if (!reportWindow) {
      setError(
        "Please allow pop-ups in your browser to generate the PDF report."
      );
      return;
    }

    reportWindow.document.open();
    reportWindow.document.write(
      reportHTML
    );
    reportWindow.document.close();

    setTimeout(() => {
      reportWindow.focus();
      reportWindow.print();
    }, 500);
  };

  // ---------------------------------------------------------
  // Formatting helpers
  // ---------------------------------------------------------

  const getFindingName = (finding) =>
    finding?.vulnerability ||
    finding?.issue ||
    finding?.title ||
    "Security Finding";

  const getCWE = (finding) =>
    finding?.cwe ||
    finding?.cwe_id ||
    "N/A";

  const getLine = (finding) =>
    finding?.line ??
    finding?.line_number ??
    "N/A";

  const getSeverity = (finding) =>
    finding?.severity ||
    finding?.risk_level ||
    "N/A";

  const getConfidence = (finding) => {
    const value = finding?.confidence;

    if (value === undefined || value === null) {
      return "N/A";
    }

    if (typeof value === "number") {
      return `${Math.round(
        value <= 1 ? value * 100 : value
      )}%`;
    }

    return String(value);
  };

  const findings =
    scanResult?.findings ||
    scanResult?.final_findings ||
    [];

  // ---------------------------------------------------------
  // UI
  // ---------------------------------------------------------

  return (
    <div className="app">

      {/* =====================================================
          HEADER
      ===================================================== */}

      <header className="topbar">

        <div className="brand">

          <div className="brand-mark">
            CS
          </div>

          <div>
            <div className="brand-name">
              CodeSentinel-X
            </div>

            <div className="brand-subtitle">
              AI Security Analysis Framework
            </div>
          </div>

        </div>

        <div className="version">
          v2.0.0
        </div>

      </header>


      <main className="container">

        {/* ===================================================
            HERO
        =================================================== */}

        <section className="hero">

          <div>

            <span className="section-label">
              SECURITY ANALYSIS
            </span>

            <h1>
              Analyze and Secure
              <br />
              Your Python Code
            </h1>

            <p>
              CodeSentinel-X combines AST analysis,
              Bandit, Semgrep, CWE mapping,
              risk analysis, security RAG,
              automated repair and closed-loop
              verification.
            </p>

          </div>

        </section>


        {/* ===================================================
            ERROR
        =================================================== */}

        {error && (

          <div className="error-box">
            <strong>
              Error:
            </strong>{" "}
            {error}
          </div>

        )}


        {/* ===================================================
            CODE INPUT
        =================================================== */}

        <section className="panel">

          <div className="panel-header">

            <div>

              <span className="section-label">
                SOURCE CODE
              </span>

              <h2>
                Python Code
              </h2>

            </div>

            <div className="filename">
              {filename}
            </div>

          </div>


          <textarea
            className="code-editor"
            value={code}
            onChange={(e) =>
              setCode(e.target.value)
            }
            spellCheck="false"
            placeholder="Paste your Python code here..."
          />


          <div className="toolbar">

            <button
              className="secondary-button"
              onClick={() =>
                fileInputRef.current?.click()
              }
            >
              Upload .py
            </button>

            <input
              ref={fileInputRef}
              type="file"
              accept=".py,text/x-python"
              onChange={handleFileUpload}
              style={{
                display: "none",
              }}
            />

            <button
              className="secondary-button"
              onClick={clearAll}
            >
              Clear
            </button>

            <div className="toolbar-spacer" />

            <button
              className="primary-button"
              onClick={runScan}
              disabled={loading}
            >
              {activeAction === "scan"
                ? "Scanning..."
                : "Scan Code"}
            </button>

          </div>

        </section>


        {/* ===================================================
            SCAN RESULTS
        =================================================== */}

        {scanResult && (

          <section className="panel">

            <div className="panel-header">

              <div>

                <span className="section-label">
                  SCAN RESULTS
                </span>

                <h2>
                  Security Findings
                </h2>

              </div>

              <div
                className={
                  scanResult.status === "success"
                    ? "status-badge success"
                    : "status-badge"
                }
              >
                {scanResult.status ||
                  "COMPLETED"}
              </div>

            </div>


            <div className="stats-grid">

              <div className="stat-card">
                <span>
                  Total Findings
                </span>

                <strong>
                  {findings.length}
                </strong>
              </div>


              <div className="stat-card">
                <span>
                  High Risk
                </span>

                <strong>
                  {
                    findings.filter(
                      (f) =>
                        String(
                          f.severity ||
                            f.risk_level ||
                            ""
                        ).toUpperCase() ===
                        "HIGH"
                    ).length
                  }
                </strong>
              </div>


              <div className="stat-card">
                <span>
                  File
                </span>

                <strong className="small-value">
                  {filename}
                </strong>
              </div>


              <div className="stat-card">
                <span>
                  Status
                </span>

                <strong className="small-value">
                  {scanResult.status ||
                    "success"}
                </strong>
              </div>

            </div>


            {findings.length === 0 ? (

              <div className="clean-box">
                ✓ No security vulnerabilities
                detected.
              </div>

            ) : (

              <div className="findings-list">

                {findings.map(
                  (finding, index) => (

                    <div
                      className="finding-card"
                      key={index}
                    >

                      <div className="finding-top">

                        <div>

                          <h3>
                            {getFindingName(
                              finding
                            )}
                          </h3>

                          <span className="line">
                            Line {getLine(
                              finding
                            )}
                          </span>

                        </div>

                        <span className="severity">
                          {getSeverity(
                            finding
                          )}
                        </span>

                      </div>


                      <div className="finding-grid">

                        <div>
                          <span>
                            CWE
                          </span>

                          <strong>
                            {getCWE(
                              finding
                            )}
                          </strong>
                        </div>


                        <div>
                          <span>
                            CWE Name
                          </span>

                          <strong>
                            {finding.cwe_name ||
                              "N/A"}
                          </strong>
                        </div>


                        <div>
                          <span>
                            Confidence
                          </span>

                          <strong>
                            {getConfidence(
                              finding
                            )}
                          </strong>
                        </div>


                        <div>
                          <span>
                            Risk Score
                          </span>

                          <strong>
                            {finding.risk_score ??
                              "N/A"}
                          </strong>
                        </div>

                      </div>


                      {finding.description && (

                        <p className="finding-description">
                          {finding.description}
                        </p>

                      )}

                    </div>

                  )
                )}

              </div>

            )}


            <div className="action-row">

              <button
                className="secondary-button"
                onClick={runAnalyze}
                disabled={loading}
              >
                {activeAction === "analyze"
                  ? "Analyzing..."
                  : "Analyze"}
              </button>


              <button
                className="primary-button"
                onClick={runRepair}
                disabled={loading}
              >
                {activeAction === "repair"
                  ? "Generating..."
                  : "Generate Repair"}
              </button>


              <button
                className="dark-button"
                onClick={runClosedLoop}
                disabled={loading}
              >
                {activeAction ===
                "closed-loop"
                  ? "Verifying..."
                  : "Closed-Loop Verification"}
              </button>

            </div>

          </section>

        )}


        {/* ===================================================
            AI ANALYSIS
        =================================================== */}

        {analysisResult && (

          <section className="panel">

            <div className="panel-header">

              <div>

                <span className="section-label">
                  AI ANALYSIS
                </span>

                <h2>
                  Root-Cause Analysis
                </h2>

              </div>

            </div>


            <div className="analysis-content">

              {analysisResult.explanation && (

                <div className="analysis-block">

                  <h3>
                    Explanation
                  </h3>

                  <p>
                    {analysisResult.explanation}
                  </p>

                </div>

              )}


              {analysisResult.root_cause && (

                <div className="analysis-block">

                  <h3>
                    Root Cause
                  </h3>

                  <p>
                    {analysisResult.root_cause}
                  </p>

                </div>

              )}


              {analysisResult.recommendation && (

                <div className="analysis-block">

                  <h3>
                    Security Recommendation
                  </h3>

                  <p>
                    {analysisResult.recommendation}
                  </p>

                </div>

              )}


              {!analysisResult.explanation &&
                !analysisResult.root_cause &&
                !analysisResult.recommendation && (

                  <pre className="json-output">
                    {JSON.stringify(
                      analysisResult,
                      null,
                      2
                    )}
                  </pre>

                )}

            </div>

          </section>

        )}


        {/* ===================================================
            AUTOMATED REMEDIATION
        =================================================== */}

        {repairResult && (

          <section className="panel">

            <div className="panel-header">

              <div>

                <span className="section-label">
                  AUTOMATED REMEDIATION
                </span>

                <h2>
                  Repair Results
                </h2>

              </div>

              <div className="status-badge success">
                ✓{" "}
                {repairResult.repair_status ||
                  repairResult.status ||
                  "COMPLETED"}
              </div>

            </div>


            {/* Repair recommendations */}

            {Array.isArray(
              repairResult.repairs
            ) &&
              repairResult.repairs.length >
                0 && (

                <div className="repair-list">

                  {repairResult.repairs.map(
                    (repair, index) => (

                      <div
                        className="repair-card"
                        key={index}
                      >

                        <div className="repair-header">

                          <strong>
                            {repair.vulnerability ||
                              "Security Repair"}
                          </strong>

                          <span>
                            {repair.cwe_id ||
                              repair.cwe ||
                              "N/A"}
                          </span>

                        </div>


                        <p>
                          <b>
                            Root Cause:
                          </b>{" "}
                          {repair.root_cause ||
                            "N/A"}
                        </p>


                        <p>
                          <b>
                            Strategy:
                          </b>{" "}
                          {repair.repair_strategy ||
                            repair.strategy ||
                            "N/A"}
                        </p>


                        <p>
                          <b>
                            Confidence:
                          </b>{" "}
                          {repair.repair_confidence ??
                            "N/A"}
                        </p>

                      </div>

                    )
                  )}

                </div>

              )}


            <div className="code-columns">

              <div className="code-card">

                <div className="code-card-header">
                  Original Code
                </div>

                <pre>
                  {repairResult.original_code ||
                    code}
                </pre>

              </div>


              <div className="code-card">

                <div className="code-card-header">
                  Repaired Code
                </div>

                <pre>
                  {repairResult.repaired_code ||
                    "No repaired code returned."}
                </pre>

              </div>

            </div>


            {/* Validation */}

            <div className="validation">

              <div className="validation-header">

                <h3>
                  Repair Validation
                </h3>

                <span
                  className={
                    repairResult.validation
                      ?.all_passed
                      ? "validation-pass"
                      : "validation-status"
                  }
                >
                  {repairResult.validation
                    ?.all_passed
                    ? "7/7 Checks Passed"
                    : "Validation Result"}
                </span>

              </div>


              {repairResult.validation && (

                <div className="validation-grid">

                  {Object.entries(
                    repairResult.validation
                  ).map(
                    ([key, value]) => (

                      <div
                        className="validation-item"
                        key={key}
                      >

                        <span>
                          {key.replace(
                            /_/g,
                            " "
                          )}
                        </span>

                        <strong
                          className={
                            value === true
                              ? "check-pass"
                              : value === false
                              ? "check-fail"
                              : ""
                          }
                        >
                          {value === true
                            ? "✓ PASS"
                            : value === false
                            ? "✗ FAIL"
                            : String(
                                value
                              )}
                        </strong>

                      </div>

                    )
                  )}

                </div>

              )}

            </div>

          </section>

        )}


        {/* ===================================================
            CLOSED LOOP
        =================================================== */}

        {closedLoopResult && (

          <section className="panel closed-loop-panel">

            <div className="panel-header">

              <div>

                <span className="section-label">
                  VERIFICATION PIPELINE
                </span>

                <h2>
                  Closed-Loop Verification
                </h2>

              </div>


              <div
                className={
                  closedLoopResult.status ===
                  "PASS"
                    ? "final-status pass"
                    : "final-status fail"
                }
              >
                {closedLoopResult.status ===
                "PASS"
                  ? "✓ PASS"
                  : "✗ FAIL"}
              </div>

            </div>


            {/* Verification Statistics */}

            <div className="verification-grid">

              <div className="verification-card">

                <span>
                  Initial Findings
                </span>

                <strong>
                  {closedLoopResult.initial_count ??
                    0}
                </strong>

              </div>


              <div className="verification-card">

                <span>
                  Remaining Findings
                </span>

                <strong>
                  {closedLoopResult.remaining_count ??
                    0}
                </strong>

              </div>


              <div className="verification-card">

                <span>
                  Security Reduction
                </span>

                <strong>
                  {closedLoopResult.security_reduction ??
                    0}
                  %
                </strong>

              </div>


              <div className="verification-card">

                <span>
                  CWE Resolutions
                </span>

                <strong>
                  {closedLoopResult.cwe_resolutions ??
                    0}
                  /
                  {closedLoopResult.initial_count ??
                    0}
                </strong>

              </div>

            </div>


            {/* Verification Message */}

            <div
              className={
                closedLoopResult.status ===
                "PASS"
                  ? "verification-message pass-message"
                  : "verification-message fail-message"
              }
            >

              {closedLoopResult.status ===
              "PASS" ? (

                <>
                  <strong>
                    ✓ Security verification
                    successful.
                  </strong>

                  <p>
                    CodeSentinel-X successfully
                    repaired the detected
                    vulnerabilities. The repaired
                    code passed validation and the
                    final security re-scan detected
                    no remaining findings.
                  </p>
                </>

              ) : (

                <>
                  <strong>
                    ✗ Further remediation required.
                  </strong>

                  <p>
                    The closed-loop verification did
                    not fully resolve the detected
                    security findings.
                  </p>
                </>

              )}

            </div>


            {/* Remaining Findings */}

            {closedLoopResult.remaining_count >
              0 &&
              closedLoopResult.remaining_findings
                ?.length > 0 && (

                <div className="remaining-findings">

                  <h3>
                    Remaining Security Findings
                  </h3>

                  {closedLoopResult.remaining_findings.map(
                    (finding, index) => (

                      <div
                        className="finding-card"
                        key={index}
                      >

                        <div className="finding-top">

                          <div>

                            <h3>
                              {getFindingName(
                                finding
                              )}
                            </h3>

                            <span className="line">
                              Line{" "}
                              {getLine(
                                finding
                              )}
                            </span>

                          </div>

                          <span className="severity">
                            {getSeverity(
                              finding
                            )}
                          </span>

                        </div>


                        <div className="finding-grid">

                          <div>

                            <span>
                              CWE
                            </span>

                            <strong>
                              {getCWE(
                                finding
                              )}
                            </strong>

                          </div>

                        </div>

                      </div>

                    )
                  )}

                </div>

              )}

          </section>

        )}


        {/* ===================================================
            PDF REPORT
        =================================================== */}

        <section className="panel report-panel">

          <div className="panel-header">

            <div>

              <span className="section-label">
                SECURITY REPORT
              </span>

              <h2>
                Download Results
              </h2>

            </div>

            <button
              className="primary-button"
              onClick={downloadPDF}
            >
              Download Security Report PDF
            </button>

          </div>


          <p className="report-description">
            Generate a printable PDF report containing
            security findings, CWE mappings, risk
            information, original code, repaired code,
            validation results and closed-loop
            verification status.
          </p>

        </section>


        {/* ===================================================
            FOOTER
        =================================================== */}

        <footer>

          <div>
            CodeSentinel-X
          </div>

          <div>
            AST-Guided Agentic AI Framework
            for Explainable Software
            Vulnerability Detection,
            Root-Cause Analysis and
            Automated Code Repair.
          </div>

        </footer>

      </main>


      {/* =====================================================
          INLINE STYLES
      ===================================================== */}

      <style>{`

        * {
          box-sizing: border-box;
        }

        body {
          margin: 0;
          font-family:
            Inter,
            ui-sans-serif,
            system-ui,
            -apple-system,
            BlinkMacSystemFont,
            "Segoe UI",
            sans-serif;

          background: #f7f8fa;
          color: #111827;
        }

        button,
        textarea {
          font-family: inherit;
        }

        .app {
          min-height: 100vh;
        }

        .topbar {
          height: 72px;
          padding: 0 42px;

          display: flex;
          align-items: center;
          justify-content: space-between;

          background: #ffffff;
          border-bottom: 1px solid #e5e7eb;
        }

        .brand {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .brand-mark {
          width: 40px;
          height: 40px;

          display: flex;
          align-items: center;
          justify-content: center;

          border-radius: 10px;

          background: #111827;
          color: #ffffff;

          font-weight: 800;
          font-size: 13px;
        }

        .brand-name {
          font-weight: 800;
          font-size: 17px;
        }

        .brand-subtitle {
          color: #6b7280;
          font-size: 11px;
          margin-top: 2px;
        }

        .version {
          color: #6b7280;
          font-size: 12px;
        }

        .container {
          width: min(1180px, 94%);
          margin: 0 auto;
          padding: 45px 0 60px;
        }

        .hero {
          padding: 10px 0 38px;
        }

        .section-label {
          font-size: 11px;
          font-weight: 800;
          letter-spacing: 0.14em;
          color: #6b7280;
        }

        .hero h1 {
          margin: 12px 0 14px;

          font-size: clamp(
            36px,
            5vw,
            58px
          );

          line-height: 1.05;
          letter-spacing: -0.04em;
        }

        .hero p {
          max-width: 760px;

          color: #6b7280;
          font-size: 16px;
          line-height: 1.7;
        }

        .panel {
          background: #ffffff;

          border: 1px solid #e5e7eb;
          border-radius: 16px;

          padding: 26px;

          margin-bottom: 24px;

          box-shadow:
            0 8px 30px
            rgba(
              17,
              24,
              39,
              0.04
            );
        }

        .panel-header {
          display: flex;
          align-items: center;
          justify-content: space-between;

          gap: 20px;

          margin-bottom: 20px;
        }

        .panel-header h2 {
          margin: 6px 0 0;

          font-size: 24px;
          letter-spacing: -0.025em;
        }

        .filename {
          padding: 7px 12px;

          border-radius: 999px;

          background: #f3f4f6;
          color: #4b5563;

          font-size: 12px;
          font-family: monospace;
        }

        .code-editor {
          width: 100%;
          min-height: 370px;

          resize: vertical;

          border: 1px solid #d1d5db;
          border-radius: 12px;

          background: #111827;
          color: #e5e7eb;

          padding: 20px;

          font-family:
            Consolas,
            "Courier New",
            monospace;

          font-size: 13px;
          line-height: 1.65;

          outline: none;
        }

        .code-editor:focus {
          border-color: #6b7280;
          box-shadow:
            0 0 0 3px
            rgba(
              107,
              114,
              128,
              0.12
            );
        }

        .toolbar,
        .action-row {
          display: flex;
          align-items: center;
          gap: 10px;

          margin-top: 16px;

          flex-wrap: wrap;
        }

        .toolbar-spacer {
          flex: 1;
        }

        button {
          border: 0;
          cursor: pointer;
        }

        button:disabled {
          cursor: not-allowed;
          opacity: 0.55;
        }

        .primary-button,
        .secondary-button,
        .dark-button {
          padding: 11px 17px;

          border-radius: 9px;

          font-size: 13px;
          font-weight: 700;

          transition:
            transform 0.15s ease,
            opacity 0.15s ease;
        }

        .primary-button:hover:not(:disabled),
        .secondary-button:hover:not(:disabled),
        .dark-button:hover:not(:disabled) {
          transform: translateY(-1px);
        }

        .primary-button {
          background: #111827;
          color: #ffffff;
        }

        .dark-button {
          background: #000000;
          color: #ffffff;
        }

        .secondary-button {
          background: #ffffff;
          color: #111827;
          border: 1px solid #d1d5db;
        }

        .error-box {
          padding: 14px 16px;
          margin-bottom: 20px;

          border-radius: 10px;

          background: #fef2f2;
          border: 1px solid #fecaca;

          color: #991b1b;

          font-size: 13px;
        }

        .stats-grid {
          display: grid;

          grid-template-columns:
            repeat(4, 1fr);

          gap: 12px;

          margin-bottom: 22px;
        }

        .stat-card {
          border: 1px solid #e5e7eb;
          border-radius: 12px;

          padding: 16px;
        }

        .stat-card span,
        .finding-grid span,
        .verification-card span,
        .validation-item span {
          display: block;

          color: #6b7280;

          font-size: 11px;
          text-transform: uppercase;

          letter-spacing: 0.06em;
        }

        .stat-card strong {
          display: block;

          margin-top: 7px;

          font-size: 25px;
        }

        .small-value {
          font-size: 14px !important;
          word-break: break-word;
        }

        .status-badge,
        .severity,
        .final-status {
          display: inline-flex;
          align-items: center;
          justify-content: center;

          border-radius: 999px;

          padding: 7px 12px;

          font-size: 11px;
          font-weight: 800;
          letter-spacing: 0.05em;
        }

        .status-badge.success {
          background: #ecfdf5;
          color: #047857;
        }

        .findings-list {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }

        .finding-card {
          border: 1px solid #e5e7eb;
          border-radius: 12px;

          padding: 18px;
        }

        .finding-top {
          display: flex;
          justify-content: space-between;

          gap: 15px;
        }

        .finding-top h3 {
          margin: 0;

          font-size: 16px;
        }

        .line {
          display: inline-block;

          margin-top: 5px;

          color: #6b7280;

          font-size: 12px;
        }

        .severity {
          background: #fff7ed;
          color: #c2410c;

          height: fit-content;
        }

        .finding-grid {
          display: grid;

          grid-template-columns:
            repeat(4, 1fr);

          gap: 10px;

          margin-top: 16px;
        }

        .finding-grid > div {
          padding: 12px;

          background: #f9fafb;

          border-radius: 9px;
        }

        .finding-grid strong {
          display: block;

          margin-top: 5px;

          font-size: 13px;
        }

        .finding-description {
          margin-bottom: 0;

          color: #4b5563;

          font-size: 13px;
          line-height: 1.6;
        }

        .clean-box {
          padding: 18px;

          border-radius: 10px;

          background: #ecfdf5;
          color: #047857;

          font-weight: 700;
        }

        .analysis-content {
          display: flex;
          flex-direction: column;
          gap: 14px;
        }

        .analysis-block {
          padding: 16px;

          border-radius: 10px;

          background: #f9fafb;
          border: 1px solid #e5e7eb;
        }

        .analysis-block h3 {
          margin-top: 0;
          font-size: 14px;
        }

        .analysis-block p {
          margin-bottom: 0;

          color: #4b5563;
          line-height: 1.65;
        }

        .json-output {
          margin: 0;

          padding: 16px;

          background: #111827;
          color: #e5e7eb;

          border-radius: 10px;

          overflow-x: auto;
        }

        .repair-list {
          display: flex;
          flex-direction: column;
          gap: 10px;

          margin-bottom: 20px;
        }

        .repair-card {
          padding: 15px;

          border: 1px solid #e5e7eb;
          border-radius: 10px;

          background: #fafafa;
        }

        .repair-header {
          display: flex;
          justify-content: space-between;
          gap: 15px;
        }

        .repair-header span {
          color: #6b7280;
          font-family: monospace;
          font-size: 12px;
        }

        .repair-card p {
          color: #4b5563;
          font-size: 13px;
        }

        .code-columns {
          display: grid;

          grid-template-columns:
            repeat(2, 1fr);

          gap: 14px;
        }

        .code-card {
          min-width: 0;

          border: 1px solid #e5e7eb;
          border-radius: 12px;

          overflow: hidden;
        }

        .code-card-header {
          padding: 11px 14px;

          background: #f3f4f6;

          font-size: 12px;
          font-weight: 800;
        }

        .code-card pre {
          margin: 0;

          min-height: 250px;

          padding: 16px;

          background: #111827;
          color: #e5e7eb;

          overflow-x: auto;

          white-space: pre-wrap;

          font-family:
            Consolas,
            "Courier New",
            monospace;

          font-size: 12px;
          line-height: 1.55;
        }

        .validation {
          margin-top: 22px;
        }

        .validation-header {
          display: flex;

          justify-content: space-between;
          align-items: center;

          margin-bottom: 12px;
        }

        .validation-header h3 {
          margin: 0;
        }

        .validation-status,
        .validation-pass {
          font-size: 12px;
          font-weight: 800;
        }

        .validation-pass {
          color: #047857;
        }

        .validation-grid {
          display: grid;

          grid-template-columns:
            repeat(2, 1fr);

          gap: 8px;
        }

        .validation-item {
          display: flex;
          justify-content: space-between;
          gap: 10px;

          padding: 11px 13px;

          background: #f9fafb;

          border-radius: 8px;
        }

        .validation-item span {
          text-transform: capitalize;
        }

        .check-pass {
          color: #047857;
        }

        .check-fail {
          color: #b91c1c;
        }

        .verification-grid {
          display: grid;

          grid-template-columns:
            repeat(4, 1fr);

          gap: 12px;

          margin-bottom: 20px;
        }

        .verification-card {
          padding: 17px;

          border: 1px solid #e5e7eb;
          border-radius: 12px;
        }

        .verification-card strong {
          display: block;

          margin-top: 7px;

          font-size: 25px;
        }

        .final-status.pass {
          background: #ecfdf5;
          color: #047857;
        }

        .final-status.fail {
          background: #fef2f2;
          color: #b91c1c;
        }

        .verification-message {
          padding: 18px;

          border-radius: 11px;

          margin-bottom: 18px;
        }

        .verification-message strong {
          font-size: 14px;
        }

        .verification-message p {
          margin-bottom: 0;

          color: #4b5563;

          font-size: 13px;
          line-height: 1.6;
        }

        .pass-message {
          background: #ecfdf5;
          border: 1px solid #a7f3d0;
        }

        .fail-message {
          background: #fef2f2;
          border: 1px solid #fecaca;
        }

        .remaining-findings h3 {
          margin-bottom: 12px;
        }

        .report-panel {
          margin-top: 10px;
        }

        .report-description {
          color: #6b7280;

          max-width: 760px;

          line-height: 1.6;
        }

        footer {
          padding: 30px 0;

          color: #6b7280;

          font-size: 12px;

          border-top: 1px solid #e5e7eb;

          display: flex;
          justify-content: space-between;
          gap: 20px;
        }

        footer div:first-child {
          color: #111827;
          font-weight: 800;
        }

        @media (max-width: 900px) {

          .stats-grid,
          .verification-grid,
          .finding-grid {
            grid-template-columns:
              repeat(2, 1fr);
          }

          .code-columns {
            grid-template-columns: 1fr;
          }

        }

        @media (max-width: 650px) {

          .topbar {
            padding: 0 18px;
          }

          .container {
            width: 92%;
            padding-top: 25px;
          }

          .panel {
            padding: 18px;
          }

          .stats-grid,
          .verification-grid,
          .finding-grid,
          .validation-grid {
            grid-template-columns: 1fr;
          }

          .panel-header {
            align-items: flex-start;
            flex-direction: column;
          }

          footer {
            flex-direction: column;
          }

        }

      `}</style>

    </div>
  );
}

export default App;