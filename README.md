# NEXUS-SHIELD // Automated Threat Co-Pilot

A hybrid AI cybersecurity incident-triage console combining a **fine-tuned Small Language Model (SLM)** adapter layer with a **Retrieval-Augmented Generation (RAG)** NIST policy engine. The system ingests raw, unstructured network telemetry and audit logs and emits structured JSON incident reports with classified threat vectors and recommended operational postures.

---

## Architecture Overview

```
┌───────────────────────────────────────────────────────────┐
│                   RAW TELEMETRY INPUT                     │
│    (SSH logs, EDR alerts, DLP events, SIEM correlations)  │
└────────────────────────┬──────────────────────────────────┘
                         │
             ┌───────────▼────────────┐
             │   DUAL-ENGINE PIPELINE │
             └───────────┬────────────┘
                         │
          ┌──────────────┴──────────────────┐
          │                                 │
  ┌───────▼────────┐              ┌─────────▼────────┐
  │   FINE-TUNED   │              │   RAG POLICY     │
  │   SLM ADAPTER  │              │   ENGINE (NIST)  │
  │                │              │                  │
  │ Behavioral     │              │ Rule retrieval   │
  │ pattern        │◄─ AUGMENTS ──│ for domain-      │
  │ extraction     │              │ specific overrides│
  │ (400+ rows)    │              │ (NIST 901, etc.) │
  └───────┬────────┘              └──────────────────┘
          │
  ┌───────▼──────────────────────────────────────────────┐
  │              STRUCTURED INCIDENT REPORT               │
  │  { vector_class, target_infrastructure,              │
  │    operational_posture }                             │
  └──────────────────────────────────────────────────────┘
```

### Engine 1 — Fine-Tuned SLM Adapter Weights

The behavioral classification layer is trained on **401 labeled cybersecurity incidents** (`nexus_data.jsonl`). Each example follows the instruction-tuning format:

```jsonc
{
  "instruction": "Transform unstructured cyber logs into raw, machine-readable Security Incident JSON format.",
  "input": "<raw telemetry string>",
  "output": "{\"incident_report\": {\"vector_class\": \"...\", \"target_infrastructure\": \"...\", \"base_posture\": \"...\"}}"
}
```

The model learns to extract three fields from noisy, heterogeneous log formats:

| Field | Description |
|---|---|
| `vector_class` | Attack category (see table below) |
| `target_infrastructure` | Affected system identifier |
| `base_posture` | Recommended initial response posture |

### Engine 2 — RAG Policy Engine (NIST Compliance)

The NIST RAG database is a structured in-memory retrieval store of compliance rules. On each inference pass, the pipeline checks whether the classified threat falls within any governed domain (e.g., financial systems, payroll infrastructure). If a NIST rule matches, its prescribed response **overrides** the base posture from the fine-tuned layer.

```js
const NIST_RAG_DATABASE = {
  "financial_override": "NIST REGULATION 901 MATCHED // CRITICAL DOMAIN // FORCE COMPLIANCE VALUE TO: 'CRITICAL_CREDENTIAL_REVOCATION_REQUIRED'."
};
```

This models the real-world pattern of **RAG-augmented generation**: the retriever fetches the most relevant policy chunk, which is then injected into the output generation context to enforce compliance-critical behaviour.

---

## Threat Classification Reference

### Vector Classes

| `vector_class` | Description | Example Signal |
|---|---|---|
| `BRUTE_FORCE_ATTEMPT` | Repeated authentication failures, spray patterns | `Failed password for invalid user`, Kerberos pre-auth failures |
| `DATA_EXFILTRATION` | Anomalous outbound data volume or DLP alerts | `412GB outbound`, bulk ledger sync to external repo |
| `ENDPOINT_COMPROMISE` | Local daemon manipulation, registry hooking, LSASS dump | `mimikatz`, `rclone` spawned with root, binary hash mismatch |
| `RANSOMWARE_DEPLOYMENT` | File encryption entropy spikes, VSS deletions | `.locked`/`.crypto` renaming, `README_DECRYPT.txt` generation |
| `INSIDER_THREAT` | Off-hours privileged access, removable media dumps | Credential hijacking, off-shift SIEM correlation |

### Operational Postures

| `base_posture` / `operational_posture` | Severity | Action |
|---|---|---|
| `CONTAINMENT_MODE` | Medium | Isolate affected process; monitor lateral movement |
| `ISOLATION_POSTURE` | High | Network-segment the node; suspend outbound routing |
| `CREDENTIAL_REVOCATION` | High | Invalidate session tokens; force re-authentication |
| `CRITICAL_CREDENTIAL_REVOCATION_REQUIRED` | **CRITICAL** | Immediate full credential revocation; RAG rule enforced |

---

## Training Data

**File:** `nexus_data.jsonl`  
**Format:** JSON Lines (one JSON object per line)  
**Size:** 401 examples  
**Coverage:** 5 balanced threat categories across diverse infrastructure nomenclature

The dataset uses realistic infrastructure names (`finance-payroll-02`, `prod-ledger-primary`, `corp-cluster-replica`) and log formats drawn from:
- Linux `sshd` / PAM authentication logs
- Windows Security Event ID 4625 / 4648
- Kernel network hooks and firewall alerts
- EDR / SIEM correlation events
- VSS and File Integrity Monitor alerts
- DLP agent alerts
- Kerberos pre-authentication failures

To fine-tune a real SLM (e.g., Phi-3 Mini, Mistral 7B, or Llama 3.2 3B) on this dataset, convert to your framework's chat format and use LoRA / QLoRA adapter training.

---

## Tech Stack

| Layer | Technology |
|---|---|
| UI Framework | React 18 |
| Build Tool | Vite 5 |
| Styling | Inline CSS (monochrome cyber aesthetic, `#050811` / `#00f0ff`) |
| Fine-Tuning Data | JSONL instruction-tuning format |
| RAG Store | In-memory JS object (extensible to vector DB) |
| Error Handling | React Error Boundary (`App.jsx`) |

---

## Getting Started

### Prerequisites

- Node.js >= 18
- npm >= 9

### Install

```bash
npm install
```

### Development

```bash
npm run dev
```

Opens at `http://localhost:3000` with hot module replacement.

### Production Build

```bash
npm run build
npm run preview
```

---

## Project Structure

```
nexus-finetuning-rag/
├── index.js               # NexusShieldConsole React component
├── nexus_data.jsonl        # 401-row instruction-tuning dataset
├── index.html              # Vite HTML entry point
├── vite.config.js          # Vite configuration
├── package.json
├── .gitignore
├── src/
│   ├── main.jsx            # React DOM root mount
│   └── App.jsx             # Layout wrapper + ErrorBoundary + global styles
└── README.md
```

---

## Using the Console

1. **Live Ingestion Feed (left panel)** — streams pre-loaded historical log events to simulate a real-time telemetry feed.

2. **Compliance Analysis Gateway (center panel)** — paste any raw log string into the textarea and click **Run Hybrid Inference Pipeline**.

3. **Matrix Compiler View (right panel)** — displays the structured JSON output. The risk posture badge turns **CRITICAL** (red) when the RAG engine fires a compliance override.

### Example Inputs

**Brute Force:**
```
Auth failure: sshd[32258]: Failed password for invalid user admin from 192.168.97.128 port 443 ssh2. Continuous retry count=22.
```

**Data Exfiltration:**
```
Kernel network hook captured unexpected outbound connection from db-cluster-primary to remote IP 10.84.2.144. Outbound volume 412GB exceeds baseline operational metrics.
```

**RAG Override (Financial → CRITICAL):**
```
File Integrity Monitor alert on finance-payroll-02: high-frequency encryption behavior detected in ledger directories.
```

---

## Extending the Architecture

### Replacing the Simulated SLM with a Real Model

The `executeDualEnginePipeline` function in `index.js` contains the simulated behavioral pattern matching. To replace with a real inference call:

```js
// Replace the keyword-matching block with:
const response = await fetch('/api/classify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ log: inputLog }),
});
const { vector_class, target_infrastructure, base_posture } = await response.json();
```

Then deploy your fine-tuned SLM behind `/api/classify` using vLLM, Ollama, or a managed inference endpoint.

### Scaling the RAG Store

Replace `NIST_RAG_DATABASE` with a vector similarity search:

```js
// Embed the input log and retrieve top-k NIST policy chunks
const topChunks = await vectorStore.similaritySearch(inputLog, { k: 3 });
const ragContext = topChunks.map(c => c.pageContent).join('\n');
```

Suitable vector stores: Chroma, Pinecone, Weaviate, pgvector.

---

## License

MIT
