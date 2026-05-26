
import React, { useState, useEffect } from 'react';

// Simulated In-Memory RAG Compliance Knowledge base
const NIST_RAG_DATABASE = {
  "financial_override": "NIST REGULATION 901 MATCHED // CRITICAL DOMAIN // FORCE COMPLIANCE VALUE TO: 'CRITICAL_CREDENTIAL_REVOCATION_REQUIRED'."
};

export default function NexusShieldConsole() {
  const [logs, setLogs] = useState([]);
  const [inputLog, setInputLog] = useState('');
  const [outputJson, setOutputJson] = useState(null);
  const [postureStatus, setPostureStatus] = useState('STANDARD');
  const [isProcessing, setIsProcessing] = useState(false);

  // Ingest background streaming log simulation for raw technical aesthetics
  useEffect(() => {
    const historicalFeeds = [
      "SYSTEM_LOG // CORE_AUTH_DIRECTOR // SSH handshakes dropping packet frequency on port 22.",
      "SYSTEM_LOG // ASSET storage-node-01 // Multi-threading outbound stream initializing connection pools.",
      "SYSTEM_LOG // WORKSTATION desktop-hr-04 // Registry alteration detected on kernel daemon hooks."
    ];
    setLogs(historicalFeeds);
  }, []);

  const executeDualEnginePipeline = () => {
    if (!inputLog.trim()) return;
    setIsProcessing(true);

    setTimeout(() => {
      let vectorClass = "MALICIOUS_ANOMALY_UNKNOWN";
      let targetInfrastructure = "UNIDENTIFIED_NODE_SRV";
      let operationalPosture = "CONTAINMENT_MODE";
      let statusIndicator = "STANDARD";

      const lowInput = inputLog.toLowerCase();

      // FINE-TUNED BEHAVIORAL PATTERN EXTRACTION (Simulated weights matching your 400 rows)
      if (lowInput.includes('payroll') || lowInput.includes('financial') || lowInput.includes('ledger') || lowInput.includes('payroll-desktop-04')) {

        // DYNAMIC RAG RETRIEVAL ENGAGEMENT LAYER
        vectorClass = "ENDPOINT_COMPROMISE";
        targetInfrastructure = "FINANCE_PAYROLL_DESKTOP_04";

        // RAG Rule Block 901 context injection takes priority over standard containment outputs!
        operationalPosture = "CRITICAL_CREDENTIAL_REVOCATION_REQUIRED";
        statusIndicator = "CRITICAL";
      } else if (lowInput.includes('ssh') || lowInput.includes('password') || lowInput.includes('auth')) {
        vectorClass = "BRUTE_FORCE_ATTEMPT";
        targetInfrastructure = "CORE_AUTH_DIRECTOR_SRV";
        operationalPosture = "CONTAINMENT_MODE";
      } else if (lowInput.includes('exfiltrat') || lowInput.includes('outbound') || lowInput.includes('storage')) {
        vectorClass = "DATA_EXFILTRATION";
        targetInfrastructure = "STORAGE_NODE_CLUSTER_01";
        operationalPosture = "ISOLATION_POSTURE";
      } else if (lowInput.includes('keystroke') || lowInput.includes('malware') || lowInput.includes('workstation')) {
        vectorClass = "ENDPOINT_COMPROMISE";
        targetInfrastructure = "DESKTOP_HR_SYSTEM_NODE";
        operationalPosture = "CREDENTIAL_REVOCATION";
      }

      const generatedPayload = {
        "incident_report": {
          "vector_class": vectorClass,
          "target_infrastructure": targetInfrastructure,
          "operational_posture": operationalPosture
        }
      };

      setOutputJson(generatedPayload);
      setPostureStatus(statusIndicator);
      setLogs([inputLog, ...logs]);
      setIsProcessing(false);
    }, 750); // Fluid artificial delay mimicking a fast infrastructure API call
  };

  return (
    <div style={{ backgroundColor: '#050811', color: '#00f0ff', minHeight: '100vh', padding: '30px', fontFamily: '"Courier New", Courier, monospace', boxSizing: 'border-box' }}>
      
      {/* HEADER MATRIX BANNER */}
      <header style={{ borderBottom: '2px solid #00f0ff', paddingBottom: '15px', marginBottom: '30px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '28px', fontWeight: 'bold', tracking: '2px', textShadow: '0 0 12px rgba(0,240,255,0.6)' }}>NEXUS-SHIELD // AUTOMATED THREAT CO-PILOT</h1>
          <p style={{ margin: '5px 0 0 0', color: '#567099', fontSize: '14px', textTransform: 'uppercase' }}>Architecture Framework: Fine-Tuned SLM Adapter Weights + NIST RAG Policy Engine</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ width: '12px', height: '12px', backgroundColor: '#00f0ff', borderRadius: '50%', animation: 'pulse 1.5s infinite' }}></div>
          <span style={{ fontSize: '13px', color: '#00f0ff', letterSpacing: '1px' }}>SYSTEM RECEPTOR ONLINE</span>
        </div>
      </header>

      {/* DASHBOARD TRIPTYCH GRID */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 2fr 1.5fr', gap: '25px' }}>
        
        {/* PANEL 1: INGESTION STREAMS */}
        <div style={{ background: '#0b1220', border: '1px solid #1c2e4a', borderRadius: '6px', padding: '20px' }}>
          <h2 style={{ fontSize: '15px', color: '#ff0055', borderBottom: '1px solid #ff0055', paddingBottom: '6px', marginTop: 0, letterSpacing: '1px' }}>// LIVE RAW INGESTION FEED</h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '15px', maxHeight: '450px', overflowY: 'auto' }}>
            {logs.map((log, index) => (
              <div key={index} style={{ padding: '10px', background: '#050811', borderLeft: '3px solid #ff0055', borderRadius: '4px', fontSize: '11px', color: '#a0b3cf', lineHeight: '1.4' }}>
                {log}
              </div>
            ))}
          </div>
        </div>

        {/* PANEL 2: INTERACTIVE INTERROGATION TERMINAL */}
        <div style={{ background: '#0b1220', border: '1px solid #1c2e4a', borderRadius: '6px', padding: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <h2 style={{ fontSize: '15px', color: '#00f0ff', borderBottom: '1px solid #00f0ff', paddingBottom: '6px', marginTop: 0, letterSpacing: '1px' }}>// COMPLIANCE ANALYSIS OPERATIONAL GATEWAY</h2>
            <p style={{ color: '#748da6', fontSize: '13px', lineHeight: '1.5', marginTop: '12px' }}>
              Drop unstructured raw network telemetry logs, brute-force tracking alerts, or system anomalies below. The fine-tuned behavioral network handles formatting layout, while the integrated RAG engine dynamically checks real-time NIST regulatory parameters.
            </p>
            <textarea
              value={inputLog}
              onChange={(e) => setInputLog(e.target.value)}
              placeholder="Paste telemetry event string input here..."
              style={{ width: '100%', height: '180px', backgroundColor: '#050811', color: '#ffffff', border: '1px solid #1c2e4a', borderRadius: '4px', padding: '15px', fontSize: '14px', fontFamily: 'monospace', boxSizing: 'border-box', marginTop: '15px', resize: 'none' }}
            />
          </div>
          <button
            onClick={executeDualEnginePipeline}
            disabled={isProcessing}
            style={{ width: '100%', backgroundColor: isProcessing ? '#1c2e4a' : '#00f0ff', color: '#050811', border: 'none', borderRadius: '4px', padding: '15px', fontSize: '16px', fontWeight: 'bold', cursor: 'pointer', textTransform: 'uppercase', letterSpacing: '2px', transition: 'all 0.2s ease', marginTop: '20px', boxShadow: isProcessing ? 'none' : '0 0 15px rgba(0,240,255,0.4)' }}
          >
            {isProcessing ? "Analyzing Matrices..." : "Run Hybrid Inference Pipeline"}
          </button>
        </div>

        {/* PANEL 3: REAL-TIME JSON COMPILE STREAM */}
        <div style={{ background: '#0b1220', border: '1px solid #1c2e4a', borderRadius: '6px', padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1c2e4a', paddingBottom: '6px', marginBottom: '15px' }}>
            <h2 style={{ fontSize: '15px', color: '#00f0ff', margin: 0, letterSpacing: '1px' }}>// MATRIX COMPILER VIEW</h2>
            <span style={{ 
              fontSize: '11px', 
              fontWeight: 'bold', 
              padding: '3px 8px', 
              borderRadius: '3px',
              backgroundColor: postureStatus === 'CRITICAL' ? 'rgba(255,0,85,0.2)' : 'rgba(0,240,255,0.2)',
              color: postureStatus === 'CRITICAL' ? '#ff0055' : '#00f0ff',
              border: postureStatus === 'CRITICAL' ? '1px solid #ff0055' : '1px solid #00f0ff'
            }}>
              {postureStatus} RISK POSTURE
            </span>
          </div>

          <pre style={{ backgroundColor: '#050811', border: '1px solid #1c2e4a', borderRadius: '4px', padding: '15px', fontSize: '13px', color: '#ffffff', overflowX: 'auto', minHeight: '220px', lineHeight: '1.5' }}>
            {outputJson ? JSON.stringify(outputJson, null, 2) : '// System idle. Awaiting instruction telemetry execution...'}
          </pre>

          {postureStatus === 'CRITICAL' && (
            <div style={{ marginTop: '20px', padding: '12px', background: 'rgba(255,0,85,0.1)', border: '1px dashed #ff0055', borderRadius: '4px', fontSize: '11px', color: '#ff0055', lineHeight: '1.4' }}>
              <strong>[RAG EVENT WARNING]</strong> {NIST_RAG_DATABASE.financial_override}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
