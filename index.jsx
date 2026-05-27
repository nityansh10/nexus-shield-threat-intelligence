import React, { useState, useEffect } from 'react';
import { GoogleGenerativeAI } from '@google/generative-ai';
import { createClient }        from '@supabase/supabase-js';

// ── Data constants ─────────────────────────────────────────────────────────────

const NIST_RAG_DATABASE = {
  financial_override:
    "NIST REGULATION 901 MATCHED // CRITICAL DOMAIN // FORCE COMPLIANCE VALUE TO: 'CRITICAL_CREDENTIAL_REVOCATION_REQUIRED'.",
};

// ── Signal-based threat classification engine ──────────────────────────────
// Each category carries a list of [keyword, weight] pairs and default
// output values when that category wins the scoring round.
// Keywords are matched against lowercased input so case is irrelevant.
// Target infrastructure is extracted from the raw log text separately —
// the default is used only when no known node ID is found in the log.

const SIGNAL_RULES = {
  RANSOMWARE_DEPLOYMENT: {
    signals: [
      ['.locked', 4], ['.crypto', 4], ['.ransom', 4],
      ['readme_decrypt', 5], ['your files are encrypted', 5],
      ['decryption key', 4], ['ransom note', 5],
      ['vssadmin delete', 5], ['delete shadows', 5], ['shadow copy delet', 4],
      ['wbadmin delete', 4], ['bcdedit /set', 3],
      ['file entropy', 3], ['high-frequency encryption', 4],
      ['file encryption detected', 5], ['mass file rename', 3],
      ['ransomware', 5], ['crypto locker', 4],
    ],
    defaultPosture: 'ISOLATION_POSTURE',
    defaultTarget: 'STORAGE_NODE_CLUSTER_01',
  },
  ENDPOINT_COMPROMISE: {
    signals: [
      // LOLBins (native binaries abused for staging / C2)
      ['certutil', 4], ['regsvr32', 4], ['mshta', 4], ['rundll32', 3],
      ['wscript', 3], ['cscript', 3], ['installutil', 3],
      // C2 beacon indicators
      ['encrypted keepalive', 5], ['keepalive', 3], ['c2 beacon', 5],
      ['command and control', 4], ['reverse shell', 4],
      // Parent-child process abuse (svchost spawning arbitrary binaries)
      ['spawned via svchost', 5], ['via svchost', 4], ['via services.exe', 4],
      // Credential theft
      ['mimikatz', 5], ['lsass dump', 5], ['lsass.exe', 4],
      ['credential dump', 4], ['ntds.dit', 5], ['sam database', 4],
      // Code injection / shellcode
      ['process injection', 4], ['dll injection', 4], ['shellcode', 4], ['process hollow', 4],
      // Persistence / hooking
      ['registry hook', 3], ['registry alteration', 3],
      ['kernel hook', 4], ['kernel daemon hook', 4],
      // Privilege escalation
      ['token impersonation', 4], ['uac bypass', 4], ['rootkit', 4],
      // Pre-ransomware staging (shadow copy CREATION ≠ deletion)
      ['shadow copy creation', 3],
      // Protocol abuse for C2 (T1095 — non-application layer protocol)
      ['non-application layer', 4], ['protocol abuse', 4],
      ['covert channel', 3], ['encrypted icmp', 5],
      // Generic
      ['malware', 3], ['keystroke', 3], ['lateral movement', 4],
    ],
    defaultPosture: 'ISOLATION_POSTURE',
    defaultTarget: 'DESKTOP_HR_SYSTEM_NODE',
  },
  DATA_EXFILTRATION: {
    signals: [
      // Volume markers — require unit or qualifier to avoid C2 beacon false-positives
      ['gb outbound', 5], ['mb outbound', 4], ['tb outbound', 5],
      ['outbound volume', 4], ['anomalous outbound', 4], ['high-volume outbound', 4],
      ['exceeds baseline operational', 4], ['exceeds baseline', 3],
      // DLP alerts
      ['dlp alert', 5], ['dlp event', 4], ['data loss prevention', 4],
      // Cloud / repo exfil
      ['upload to external', 4], ['sync to external', 4], ['external repo', 3],
      ['bulk ledger sync', 4], ['large file transfer', 3],
      // DNS / ICMP / protocol tunneling (T1048, T1095)
      // "non-standard encrypted" catches ICMP/HTTP payloads carrying smuggled data
      ['dns tunnel', 5], ['dns exfiltration', 5],
      ['icmp tunnel', 5], ['icmp payload', 4],
      ['non-standard encrypted', 5], ['encrypted text payload', 5],
      ['non-standard payload', 4], ['protocol tunnel', 4],
      // Destination anomaly — traffic to unknown/unmapped external hosts
      ['unmapped external', 4], ['external public node', 4],
      ['unregistered external', 4], ['unknown external', 4],
      // Covert channel / steganography
      ['covert channel', 5], ['steganograph', 4],
      // Direct keyword
      ['exfiltrat', 4],
    ],
    defaultPosture: 'ISOLATION_POSTURE',
    defaultTarget: 'STORAGE_NODE_CLUSTER_01',
  },
  BRUTE_FORCE_ATTEMPT: {
    signals: [
      // Explicit auth failure text (NOT the word "auth" alone — that pollutes server names)
      ['failed password for', 5], ['failed password', 4],
      ['authentication failure', 4], ['login failure', 4],
      ['logon failure', 4], ['invalid user', 4],
      ['invalid credential', 4], ['access denied', 3],
      // Retry / frequency
      ['continuous retry', 5], ['retry count', 4], ['attempt count', 4],
      ['repeated attempt', 4], ['multiple failure', 4],
      // Attack type
      ['brute force', 5], ['brute-force', 5],
      ['password spray', 5], ['dictionary attack', 5], ['credential stuff', 5],
      // Protocol-specific
      ['kerberos pre-auth failure', 5], ['pre-authentication fail', 4],
      ['failed ssh', 4], ['ssh brute', 5],
      // Lockout indicators
      ['account lockout', 4], ['too many attempt', 4], ['account locked', 4],
    ],
    defaultPosture: 'CREDENTIAL_REVOCATION',
    defaultTarget: 'CORE_AUTH_DIRECTOR_SRV',
  },
  INSIDER_THREAT: {
    signals: [
      // Time-based anomalies
      ['off-hours', 4], ['off hours', 4], ['after hours', 4],
      ['outside business hours', 4], ['off-shift', 4],
      ['anomalous access time', 4], ['unusual time', 3],
      // Removable media
      ['usb', 3], ['removable media', 4], ['mass storage device', 4], ['external drive', 4],
      // Data hoarding
      ['bulk download', 4], ['data dump', 4], ['large download', 3],
      ['unusual download volume', 4], ['mass export', 4], ['data export', 3],
      // Personal-cloud uploads
      ['personal email', 4], ['personal cloud', 4], ['gmail', 3],
      // Location / travel anomaly
      ['geo-anomaly', 4], ['impossible travel', 4], ['unusual location', 4],
    ],
    defaultPosture: 'CREDENTIAL_REVOCATION',
    defaultTarget: 'DESKTOP_HR_SYSTEM_NODE',
  },
};

// Tie-break: when two categories have equal score, the more severe one wins.
const SEVERITY_PRIORITY = {
  RANSOMWARE_DEPLOYMENT: 5,
  ENDPOINT_COMPROMISE:   4,
  DATA_EXFILTRATION:     3,
  INSIDER_THREAT:        2,
  BRUTE_FORCE_ATTEMPT:   1,
};

// Scans the raw (pre-lowercase) log for known node IDs so the target field
// reflects what the log actually says rather than a hardcoded default.
const extractTargetInfra = (rawInput) => {
  const upper = rawInput.toUpperCase();
  const known = [
    'FINANCE_PAYROLL_DESKTOP_04',
    'CORE_AUTH_DIRECTOR_SRV',
    'STORAGE_NODE_CLUSTER_01',
    'DESKTOP_HR_SYSTEM_NODE',
  ];
  for (const id of known) {
    if (upper.includes(id)) return id;
  }
  return null;
};

const ADVERSARIAL_PATTERNS = [
  // ── "forget" family ─────────────────────────────────────────────────────────
  // 'forget your instructions' alone misses "forget ALL YOUR previous instructions"
  // because the substring check requires the exact phrase — extra intervening words
  // break the match. Cover the full family with fragment-level anchors instead.
  'forget all',           // forget all (your/previous/my) instructions
  'forget everything',    // forget everything you know
  'forget your',          // forget your instructions / forget your training

  // ── "ignore" family ──────────────────────────────────────────────────────────
  'ignore previous',      // ignore previous instructions / guidelines
  'ignore all previous',
  'ignore safety',        // ignore safety parameters / constraints
  'ignore all instructions',
  'ignore your',          // ignore your guidelines / training

  // ── "disregard" family ───────────────────────────────────────────────────────
  'disregard all',
  'disregard previous',   // disregard previous instructions
  'disregard your',

  // ── "override / reset" family ────────────────────────────────────────────────
  'system override',
  'override all',         // override all instructions / safety
  'override your',
  'reset your',           // reset your instructions / parameters
  'reset all',

  // ── instruction-replacement phrases ──────────────────────────────────────────
  'previous instructions',   // "...your previous instructions" / "forget all previous instructions"
  'previous guidelines',     // ignore previous guidelines
  'all instructions',        // override all instructions / forget all instructions
  'your new instructions',
  'these are your new',
  'new system prompt',
  'your real instructions',

  // ── role / persona hijack ─────────────────────────────────────────────────────
  'act as',
  'you are now a',
  'you are now an',
  'pretend to be',
  'pretend you are',
  'roleplay as',

  // ── direct injection markers ──────────────────────────────────────────────────
  'prompt injection',
  'bypass filter',
  'bypass all',
  'bypass safety',
  'jailbreak',
];

const ERROR_CATALOG = {
  huggingface_gated: {
    label: 'Hugging Face Gated Repo Error',
    stack:
      'OSError: You are trying to access a gated repo.\n' +
      '  File "transformers/utils/hub.py", line 437, in cached_file\n' +
      '    raise EnvironmentError(\n' +
      '      f"You are trying to access a gated repo.\\n"\n' +
      '      f"Make sure to request access at {url}"\n' +
      '    )\n' +
      '  requests.exceptions.HTTPError: 403 Client Error: Forbidden\n' +
      '  for url: https://huggingface.co/meta-llama/Llama-2-7b-hf/resolve/main/config.json',
    explanation:
      'The model weights are locked behind Hugging Face\'s access gate. Your auth token either lacked approval or was not passed correctly during model load. The HF Hub returns HTTP 403 when the token is valid but the gated model page has not been explicitly accepted by the requesting account.',
    resolution:
      'Requested model access via the HF model card portal and pivoted immediately to an ungated base (Phi-3-mini-4k-instruct) to unblock training. Once approved: injected token via huggingface_hub.login(token=HF_TOKEN) before AutoModelForCausalLM.from_pretrained(), and set use_auth_token=True in the from_pretrained() call.',
  },
  cuda_oom: {
    label: 'CUDA Out of Memory',
    stack:
      'torch.cuda.OutOfMemoryError: CUDA out of memory.\n' +
      '  Tried to allocate 2.34 GiB\n' +
      '  (GPU 0; 6.00 GiB total capacity;\n' +
      '   4.89 GiB already allocated;\n' +
      '   512.00 MiB free;\n' +
      '   5.12 GiB reserved in total by PyTorch)\n' +
      '  If reserved memory is >> allocated memory,\n' +
      '  try setting max_split_size_mb to avoid fragmentation.',
    explanation:
      'Full-precision (FP32 / FP16) model weights exceeded available VRAM. A 7B-parameter model requires roughly 14 GB at FP16 — far beyond the available 6 GB. PyTorch reserves contiguous memory blocks; fragmentation from prior allocations caused even smaller allocations to fail with no viable free region.',
    resolution:
      'Applied BitsAndBytes 8-bit quantization (load_in_8bit=True), cutting the in-memory footprint from ~14 GB to ~7 GB. Added LoRA adapters (r=16, alpha=32) targeting q_proj and v_proj layers only — keeping trainable parameters under 1% of total. Enabled gradient_checkpointing=True to trade compute cycles for memory headroom during backward passes.',
  },
  gradient_mismatch: {
    label: 'Gradient Precision Mismatch',
    stack:
      'RuntimeError: Expected all tensors to be on the same device,\n' +
      '  but found at least two devices: cuda:0 and cpu!\n' +
      '\n' +
      '  Traceback during backward pass:\n' +
      '    base_model.model.model.layers.0\n' +
      '      .self_attn.q_proj.lora_A.default\n' +
      '  Mixed dtypes: INT8 (frozen base) vs FP32 (LoRA adapter)\n' +
      '  Gradient accumulation step: 4 / 4',
    explanation:
      'LoRA adapter layers were initialised in FP32 while the frozen base model ran in INT8 after quantisation. During the backward pass, gradient tensors from incompatible dtypes collided on the same layer boundary. PyTorch cannot backpropagate across a dtype boundary without an explicit cast instruction, so training halted immediately on step 0.',
    resolution:
      'Called peft.prepare_model_for_kbit_training(model) before injecting the LoRA config — this casts normalization layers to FP32 and enables gradient checkpointing in a quantisation-safe way. Set fp16=True in TrainingArguments to align all gradient computations to FP16 mixed precision throughout the adapter layers. Verified the fix with model.print_trainable_parameters().',
  },
};

const EXECUTIVE_BRIEFINGS = {
  // ── POLICY_05 ───────────────────────────────────────────────────────────────
  BRUTE_FORCE_ATTEMPT: {
    title: 'Credential Brute-Force Detected',
    impact:
      'An attacker is systematically cycling password combinations against the authentication endpoint. A single successful guess grants direct system access — bypassing every downstream control.',
    mitigation:
      'Rate-limit and block the source IP range immediately. Enforce MFA across all authentication endpoints. Deploy exponential backoff or CAPTCHA on repeated failures.',
  },
  // ── POLICY_03 ───────────────────────────────────────────────────────────────
  DATA_EXFILTRATION: {
    title: 'Unauthorized Data Exfiltration In Progress',
    impact:
      'High-volume sensitive data is moving off-network from main storage arrays right now. Customer records, intellectual property, or financial data may already be in adversary hands.',
    mitigation:
      'Isolate the storage node immediately and cut all outbound connections. Engage your incident response team. Notify legal counsel if regulated data (PII, PCI, PHI) is involved.',
  },
  // ── POLICY_04 — new vector class for ICMP / covert channel tunneling ────────
  DATA_EXFILTRATION_TUNNEL: {
    title: 'ICMP Tunneling / Covert Channel Detected',
    impact:
      'An attacker is smuggling identity data inside harmless-looking ICMP ping packets to bypass perimeter firewalls. This is an active covert exfiltration channel — traffic volume is deliberately deceptive.',
    mitigation:
      'Block all outbound ICMP traffic to unmapped external public nodes immediately. Capture and preserve packet payloads for forensic analysis. Audit the CORE_AUTH_DIRECTOR_SRV process tree for the responsible binary.',
  },
  // ── POLICY_02 ───────────────────────────────────────────────────────────────
  ENDPOINT_COMPROMISE: {
    title: 'Local Host Malware Intercepted',
    impact:
      'A keystroke logging script is actively harvesting user session tokens on an HR endpoint. Every credential entered since the time of compromise is considered stolen.',
    mitigation:
      'Revoke all active session profiles on this node immediately. Run localized endpoint remediation before reconnecting to the network. Audit all accounts that authenticated from this machine.',
  },
  // ── POLICY_01 — NIST 901 RAG override ───────────────────────────────────────
  FINANCIAL_SYSTEM_COMPROMISE: {
    title: 'Critical Financial System Breach — NIST 901 Engaged',
    impact:
      'This breach directly exposes employee compensation records, banking credentials, and tax data. Mandatory regulatory disclosure may be triggered under SOX, PCI-DSS, and GDPR frameworks within 72 hours.',
    mitigation:
      'Invoke NIST 901 credential revocation protocol immediately. Freeze all payroll processing cycles. Notify your CFO and General Counsel before any other action. Isolate the finance network segment from all other infrastructure.',
  },
  RANSOMWARE_DEPLOYMENT: {
    title: 'Active Ransomware Deployment',
    impact:
      'File encryption is underway right now. Every second of delay increases the volume of encrypted and potentially unrecoverable business data. Backup integrity is likely already targeted.',
    mitigation:
      'Kill network access to the affected host immediately. Activate your IR retainer. Assess backup recoverability before any ransom discussion. Do not pay without legal counsel — payment does not guarantee key delivery.',
  },
  INSIDER_THREAT: {
    title: 'Insider Threat — Anomalous Access Pattern',
    impact:
      'A trusted internal account is accessing sensitive systems outside normal operating hours or from an atypical location. This may indicate a compromised credential, a rogue employee, or a supply-chain intrusion.',
    mitigation:
      'Suspend the account pending investigation. Pull the full access log for the past 30 days. Engage HR and legal before any confrontation. Maintain strict evidence chain-of-custody throughout.',
  },
  MALICIOUS_ANOMALY_UNKNOWN: {
    title: 'Unknown Threat Pattern — Analyst Review Required',
    impact:
      'Telemetry does not match any known threat signature in the behavioral model. Manual Tier-2 review is required. Treat the affected asset as hostile until formally cleared.',
    mitigation:
      'Escalate to Tier-2 SOC immediately. Preserve the raw log — do not discard. Feed into your threat intelligence platform for IOC matching (MISP, VirusTotal, Mandiant Advantage).',
  },
};

const NETWORK_NODES = [
  { id: 'CORE_AUTH_DIRECTOR_SRV',     lines: ['CORE AUTH', 'DIRECTOR SRV'],  x: 130, y: 90  },
  { id: 'STORAGE_NODE_CLUSTER_01',    lines: ['STORAGE NODE', 'CLUSTER 01'],  x: 570, y: 90  },
  { id: 'FINANCE_PAYROLL_DESKTOP_04', lines: ['FINANCE', 'PAYROLL 04'],       x: 130, y: 230 },
  { id: 'DESKTOP_HR_SYSTEM_NODE',     lines: ['DESKTOP HR', 'SYSTEM NODE'],   x: 570, y: 230 },
];
const HUB = { x: 350, y: 160 };

// ── Token-RAG Policy Registry ──────────────────────────────────────────────────
// Immutable, ordered policy rules evaluated BEFORE the fuzzy SIGNAL_RULES scorer.
// Each rule uses AND/OR token matching against lowercased input.
// First-match wins; if no policy fires, execution falls through to SIGNAL_RULES.

const THREAT_POLICY_REGISTRY = [
  {
    id: 'POLICY_01',
    description: 'CRITICAL FINANCIAL DOMAIN — NIST 901 Override',
    match: (low) =>
      low.includes('finance_payroll_desktop_04') ||
      low.includes('payroll') ||
      low.includes('ledger') ||
      low.includes('finance-payroll') ||
      low.includes('payroll-desktop'),
    vectorClass:        'FINANCIAL_SYSTEM_COMPROMISE',
    targetInfra:        'FINANCE_PAYROLL_DESKTOP_04',
    operationalPosture: 'CRITICAL_CREDENTIAL_REVOCATION_REQUIRED',
    statusIndicator:    'CRITICAL',
  },
  {
    id: 'POLICY_02',
    description: 'LOCAL HOST MALWARE — HR Endpoint',
    match: (low) =>
      low.includes('desktop_hr_system_node') ||
      low.includes('keystroke software logs') ||
      low.includes('desktop-hr'),
    vectorClass:        'ENDPOINT_COMPROMISE',
    targetInfra:        'DESKTOP_HR_SYSTEM_NODE',
    operationalPosture: 'CREDENTIAL_REVOCATION',
    statusIndicator:    'STANDARD',
  },
  {
    id: 'POLICY_03',
    description: 'BULK STORAGE EXFILTRATION — Storage Cluster',
    match: (low) =>
      low.includes('storage_node_cluster_01') &&
      (low.includes('download') || low.includes('archive') ||
       low.includes('egress')   || low.includes('replication')),
    vectorClass:        'DATA_EXFILTRATION',
    targetInfra:        'STORAGE_NODE_CLUSTER_01',
    operationalPosture: 'ISOLATION_POSTURE',
    statusIndicator:    'STANDARD',
  },
  {
    id: 'POLICY_04',
    description: 'COVERT ICMP TUNNELING — Auth Director',
    match: (low) =>
      low.includes('core_auth_director_srv') &&
      (low.includes('icmp') || low.includes('echo request') || low.includes('packets')),
    vectorClass:        'DATA_EXFILTRATION_TUNNEL',
    targetInfra:        'CORE_AUTH_DIRECTOR_SRV',
    operationalPosture: 'NETWORK_EGRESS_BLOCK',
    statusIndicator:    'STANDARD',
  },
  {
    id: 'POLICY_05',
    description: 'BRUTE FORCE SPRAYING — Auth Director',
    match: (low) =>
      low.includes('core_auth_director_srv') &&
      (low.includes('failed authentication') || low.includes('brute-force') ||
       low.includes('spraying') || low.includes('brute force')),
    vectorClass:        'BRUTE_FORCE_ATTEMPT',
    targetInfra:        'CORE_AUTH_DIRECTOR_SRV',
    operationalPosture: 'CONTAINMENT_MODE',
    statusIndicator:    'STANDARD',
  },
];

// ── Gemini API — system instruction, response schema, model instance ───────────
// The model is initialised once at module load; the component just calls
// geminiModel.generateContent(rawLog). If VITE_GEMINI_API_KEY is absent at
// build time the value is null and the pipeline falls back to local rules.

const GEMINI_SYSTEM_INSTRUCTION = `
You are NEXUS-SHIELD, an enterprise cybersecurity threat intelligence engine.
Analyse the incoming raw security log and classify it using the following 5 immutable
threat policies in strict priority order. The FIRST matching policy wins.

POLICY_01 — FINANCIAL_SYSTEM_COMPROMISE (highest priority — NIST 901 override)
  Triggers when: log mentions payroll systems, ledger records, finance-payroll,
  payroll-desktop, or the node identifier FINANCE_PAYROLL_DESKTOP_04.
  vector_class: "FINANCIAL_SYSTEM_COMPROMISE"
  operational_posture: "CRITICAL_CREDENTIAL_REVOCATION_REQUIRED"
  target_infrastructure: "FINANCE_PAYROLL_DESKTOP_04" (or exact node from log)

POLICY_02 — ENDPOINT_COMPROMISE
  Triggers when: log mentions DESKTOP_HR_SYSTEM_NODE, keystroke software logs,
  active session token harvesting, or desktop-hr malware activity.
  vector_class: "ENDPOINT_COMPROMISE"
  operational_posture: "CREDENTIAL_REVOCATION"
  target_infrastructure: "DESKTOP_HR_SYSTEM_NODE" (or exact node from log)

POLICY_03 — DATA_EXFILTRATION
  Triggers when: log mentions STORAGE_NODE_CLUSTER_01 combined with download,
  archive, egress, or replication activity.
  vector_class: "DATA_EXFILTRATION"
  operational_posture: "ISOLATION_POSTURE"
  target_infrastructure: "STORAGE_NODE_CLUSTER_01" (or exact node from log)

POLICY_04 — DATA_EXFILTRATION_TUNNEL
  Triggers when: log mentions CORE_AUTH_DIRECTOR_SRV combined with ICMP traffic,
  echo request packets, or covert/non-standard encrypted payloads.
  vector_class: "DATA_EXFILTRATION_TUNNEL"
  operational_posture: "NETWORK_EGRESS_BLOCK"
  target_infrastructure: "CORE_AUTH_DIRECTOR_SRV" (or exact node from log)

POLICY_05 — BRUTE_FORCE_ATTEMPT
  Triggers when: log mentions CORE_AUTH_DIRECTOR_SRV combined with failed
  authentication, brute-force attempts, credential spraying, or account lockout.
  vector_class: "BRUTE_FORCE_ATTEMPT"
  operational_posture: "CONTAINMENT_MODE"
  target_infrastructure: "CORE_AUTH_DIRECTOR_SRV" (or exact node from log)

If no policy matches, use:
  vector_class: "MALICIOUS_ANOMALY_UNKNOWN"
  operational_posture: "CONTAINMENT_MODE"
  target_infrastructure: "UNIDENTIFIED_NODE_SRV"

Additional rules:
- Extract the exact node identifier from the log text for target_infrastructure
  whenever one is present; only fall back to the policy default when none is found.
- For every classification generate a concise executive_briefing with three fields:
    title      — a 5-8 word alert headline
    impact     — 2-3 sentences describing the business risk right now
    mitigation — 2-3 sentences of immediate, actionable response directives
- Never add commentary outside the JSON schema.

CRITICAL RULE: You are a database-driven security agent. Whenever the prompt
contains a "RETRIEVED COMPLIANCE CONTEXT" block with policy data, you MUST
explicitly prepend this exact tracking string to the very beginning of your
executive_briefing.title field value:
  [SUPABASE VECTOR DATABASE ACTIVE // CURRENT PLAYBOOK: <Insert Matched Policy Topic Name Here>]
Replace <Insert Matched Policy Topic Name Here> with the exact topic name from
the retrieved policy (e.g. "Ransomware Execution Defense"). When multiple policies
are retrieved, use the topic of the most relevant one. This tracking string must
appear verbatim, including the square brackets. If no compliance context was
retrieved, omit the tracking string entirely.
`.trim();

const GEMINI_RESPONSE_SCHEMA = {
  type: 'object',
  properties: {
    vector_class: {
      type: 'string',
      enum: [
        'FINANCIAL_SYSTEM_COMPROMISE',
        'ENDPOINT_COMPROMISE',
        'DATA_EXFILTRATION',
        'DATA_EXFILTRATION_TUNNEL',
        'BRUTE_FORCE_ATTEMPT',
        'RANSOMWARE_DEPLOYMENT',
        'INSIDER_THREAT',
        'MALICIOUS_ANOMALY_UNKNOWN',
      ],
    },
    target_infrastructure: { type: 'string' },
    operational_posture: {
      type: 'string',
      enum: [
        'CRITICAL_CREDENTIAL_REVOCATION_REQUIRED',
        'CREDENTIAL_REVOCATION',
        'ISOLATION_POSTURE',
        'NETWORK_EGRESS_BLOCK',
        'CONTAINMENT_MODE',
      ],
    },
    executive_briefing: {
      type: 'object',
      properties: {
        title:      { type: 'string' },
        impact:     { type: 'string' },
        mitigation: { type: 'string' },
      },
      required: ['title', 'impact', 'mitigation'],
    },
  },
  required: ['vector_class', 'target_infrastructure', 'operational_posture', 'executive_briefing'],
};

const _apiKey   = import.meta.env.VITE_GEMINI_API_KEY;
const _genAI    = _apiKey ? new GoogleGenerativeAI(_apiKey) : null;
const geminiModel = _genAI
  ? _genAI.getGenerativeModel({
      model: 'gemini-2.5-flash',
      systemInstruction: GEMINI_SYSTEM_INSTRUCTION,
      generationConfig: {
        responseMimeType: 'application/json',
        responseSchema:   GEMINI_RESPONSE_SCHEMA,
      },
    })
  : null;

// ── Supabase pgvector client ───────────────────────────────────────────────────
// text-embedding-004 is not available on this key; gemini-embedding-001 with
// outputDimensionality=768 is used instead to match the vector(768) column.
const supabaseClient =
  import.meta.env.VITE_SUPABASE_URL && import.meta.env.VITE_SUPABASE_ANON_KEY
    ? createClient(
        import.meta.env.VITE_SUPABASE_URL,
        import.meta.env.VITE_SUPABASE_ANON_KEY,
      )
    : null;

async function fetchQueryEmbedding(text) {
  const res = await fetch(
    `https://generativelanguage.googleapis.com/v1/models/gemini-embedding-001:embedContent?key=${_apiKey}`,
    {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        content:              { parts: [{ text }] },
        taskType:             'RETRIEVAL_QUERY',
        outputDimensionality: 768,
      }),
    },
  );
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message ?? `Embedding API HTTP ${res.status}`);
  }
  const data = await res.json();
  return data.embedding.values;
}

// ── Design tokens ──────────────────────────────────────────────────────────────

const C = {
  bg:          '#F8FAFC',
  panel:       '#FFFFFF',
  panelDk:     '#F1F5F9',
  border:      '#E2E8F0',
  borderBright:'#CBD5E1',
  blue:        '#2563EB',
  crimson:     '#DC2626',
  amber:       '#D97706',
  green:       '#16A34A',
  text:        '#0F172A',
  muted:       '#475569',
  dim:         '#94A3B8',
  shadow:      '0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.04)',
  shadowMd:    '0 4px 6px rgba(0,0,0,0.07), 0 2px 4px rgba(0,0,0,0.05)',
};

// Returns the accent color for a network node based on threat severity and node identity.
// FINANCE/CRITICAL → crimson, CORE_AUTH → blue, all others → amber.
const getNodeColor = (nodeId, isCritical) => {
  if (isCritical || nodeId === 'FINANCE_PAYROLL_DESKTOP_04') return C.crimson;
  if (nodeId === 'CORE_AUTH_DIRECTOR_SRV') return C.blue;
  return C.amber;
};

// Returns a low-opacity fill that pairs with each node's accent color.
const getNodeFill = (nodeId, isCritical) => {
  if (isCritical || nodeId === 'FINANCE_PAYROLL_DESKTOP_04') return 'rgba(220,38,38,0.08)';
  if (nodeId === 'CORE_AUTH_DIRECTOR_SRV') return 'rgba(37,99,235,0.08)';
  return 'rgba(217,119,6,0.08)';
};

const panelStyle = (extra = {}) => ({
  background: C.panel,
  border: `1px solid ${C.border}`,
  borderRadius: '8px',
  padding: '24px',
  boxShadow: C.shadow,
  ...extra,
});

const headingStyle = (color = C.blue) => ({
  fontSize: '16px',
  fontWeight: 'bold',
  color,
  borderBottom: `1px solid ${color}40`,
  paddingBottom: '10px',
  marginTop: 0,
  marginBottom: '18px',
  letterSpacing: '1.5px',
});

// ── Component ──────────────────────────────────────────────────────────────────

export default function NexusShieldConsole() {
  const [logs, setLogs]                 = useState([]);
  const [inputLog, setInputLog]         = useState('');
  const [outputJson, setOutputJson]     = useState(null);
  const [postureStatus, setPostureStatus] = useState('STANDARD');
  const [isProcessing, setIsProcessing] = useState(false);
  const [hijackBlocked, setHijackBlocked] = useState(false);
  const [blockedInput, setBlockedInput] = useState('');
  const [activeError, setActiveError]   = useState(null);

  useEffect(() => {
    setLogs([
      'SYSTEM_LOG // CORE_AUTH_DIRECTOR // SSH handshakes dropping packet frequency on port 22.',
      'SYSTEM_LOG // ASSET storage-node-01 // Multi-threading outbound stream initializing connection pools.',
      'SYSTEM_LOG // WORKSTATION desktop-hr-04 // Registry alteration detected on kernel daemon hooks.',
    ]);
  }, []);

  const executeDualEnginePipeline = async () => {
    if (!inputLog.trim()) return;

    const lowInput = inputLog.toLowerCase();

    // ── Phase A: Adversarial guardrail — client-side, BEFORE any network call ──
    if (ADVERSARIAL_PATTERNS.some(p => lowInput.includes(p))) {
      setBlockedInput(inputLog);
      setHijackBlocked(true);
      return;
    }

    setIsProcessing(true);
    setPostureStatus('STANDARD');

    // ── Primary RAG pipeline: Phases B → C → D ────────────────────────────────
    try {
      if (!_apiKey || !supabaseClient || !geminiModel) {
        throw new Error('RAG pipeline not configured — missing env keys');
      }

      // Phase B: Vectorize the log input (768-dim via gemini-embedding-001)
      const queryVector = await fetchQueryEmbedding(inputLog);

      // Phase C: Semantic similarity search against Supabase compliance_policies
      const { data: ragPolicies, error: ragError } = await supabaseClient.rpc('match_policies', {
        query_embedding: queryVector,
        match_threshold: 0.15,
        match_count:     3,
      });
      if (ragError) throw ragError;

      // Phase D: Augment Gemini prompt with retrieved compliance context blocks
      const ragContext = (ragPolicies && ragPolicies.length > 0)
        ? ragPolicies
            .map((p, i) =>
              `[COMPLIANCE POLICY ${i + 1} — ${p.topic.toUpperCase()}]\n${p.policy_text}`,
            )
            .join('\n\n')
        : '';

      const prompt = ragContext
        ? `RETRIEVED COMPLIANCE CONTEXT:\n${ragContext}\n\nSECURITY LOG TO CLASSIFY:\n${inputLog}`
        : inputLog;

      const result = await geminiModel.generateContent(prompt);
      const parsed = JSON.parse(result.response.text());

      setOutputJson({
        incident_report: {
          vector_class:          parsed.vector_class,
          target_infrastructure: parsed.target_infrastructure,
          operational_posture:   parsed.operational_posture,
          executive_briefing:    parsed.executive_briefing,
        },
      });
      setPostureStatus(
        parsed.operational_posture === 'CRITICAL_CREDENTIAL_REVOCATION_REQUIRED'
          ? 'CRITICAL'
          : 'STANDARD',
      );
      setLogs(prev => [inputLog, ...prev]);
      setIsProcessing(false);
      return;

    } catch (err) {
      // ── Layer 3 fallback: local THREAT_POLICY_REGISTRY + SIGNAL_RULES ───────
      console.warn('[NEXUS-SHIELD] RAG pipeline unavailable — activating Layer 3 local engine.', err);
    }

    setTimeout(() => {
      const matchedPolicy = THREAT_POLICY_REGISTRY.find(policy => policy.match(lowInput));
      if (matchedPolicy) {
        setOutputJson({
          incident_report: {
            vector_class:          matchedPolicy.vectorClass,
            target_infrastructure: extractTargetInfra(inputLog) || matchedPolicy.targetInfra,
            operational_posture:   matchedPolicy.operationalPosture,
          },
        });
        setPostureStatus(matchedPolicy.statusIndicator);
        setLogs(prev => [inputLog, ...prev]);
        setIsProcessing(false);
        return;
      }

      // SIGNAL_RULES weighted scorer
      let bestCategory     = null;
      let bestScore        = 0;
      let activeCategories = 0;

      for (const [category, config] of Object.entries(SIGNAL_RULES)) {
        let score = 0;
        for (const [keyword, weight] of config.signals) {
          if (lowInput.includes(keyword)) score += weight;
        }
        if (score > 0) activeCategories++;
        if (
          score > bestScore ||
          (score === bestScore && score > 0 &&
           (SEVERITY_PRIORITY[category] ?? 0) > (SEVERITY_PRIORITY[bestCategory] ?? 0))
        ) {
          bestScore    = score;
          bestCategory = category;
        }
      }

      const vectorClass = bestCategory || 'MALICIOUS_ANOMALY_UNKNOWN';
      const targetInfra = extractTargetInfra(inputLog) ||
                          (bestCategory ? SIGNAL_RULES[bestCategory].defaultTarget : 'UNIDENTIFIED_NODE_SRV');

      let operationalPosture = 'CONTAINMENT_MODE';
      if (bestCategory && bestScore > 0) {
        operationalPosture = SIGNAL_RULES[bestCategory].defaultPosture;
        if (activeCategories >= 2) operationalPosture = 'ISOLATION_POSTURE';
      }

      setOutputJson({
        incident_report: {
          vector_class:          vectorClass,
          target_infrastructure: targetInfra,
          operational_posture:   operationalPosture,
        },
      });
      setPostureStatus('STANDARD');
      setLogs(prev => [inputLog, ...prev]);
      setIsProcessing(false);
    }, 750);
  };

  const activeTarget = outputJson?.incident_report?.target_infrastructure;
  // Prefer the live briefing generated by Gemini; fall back to the static table
  // when running on the local fallback engine (no API key or API failure).
  const briefing     = outputJson
    ? (outputJson.incident_report.executive_briefing ??
       EXECUTIVE_BRIEFINGS[outputJson.incident_report.vector_class] ??
       EXECUTIVE_BRIEFINGS.MALICIOUS_ANOMALY_UNKNOWN)
    : null;
  const isCritical   = postureStatus === 'CRITICAL';

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div style={{ backgroundColor: C.bg, color: C.text, minHeight: '100vh', padding: '32px', fontFamily: '"Courier New", Courier, monospace', boxSizing: 'border-box' }}>

      {/* Keyframe animations */}
      <style>{`
        @keyframes nodePulse {
          0%, 100% { opacity: 0.9; }
          50%       { opacity: 0.15; }
        }
        @keyframes dashFlow {
          from { stroke-dashoffset: 24; }
          to   { stroke-dashoffset: 0; }
        }
        @keyframes shieldGlow {
          0%, 100% { box-shadow: 0 0 0 0 rgba(220, 38, 38, 0.45); }
          50%       { box-shadow: 0 0 0 18px rgba(220, 38, 38, 0); }
        }
        @keyframes fadeUp {
          from { opacity: 0; transform: translateY(10px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes scanPulse {
          0%, 100% { opacity: 1; }
          50%       { opacity: 0.35; }
        }
      `}</style>

      {/* ── ADVERSARIAL HIJACK INTERCEPTOR OVERLAY ───────────────────────── */}
      {hijackBlocked && (
        <div style={{
          position: 'fixed', inset: 0,
          background: 'rgba(15, 23, 42, 0.55)',
          backdropFilter: 'blur(4px)',
          zIndex: 1000,
          display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center',
          animation: 'fadeUp 0.25s ease',
        }}>
          <div style={{
            background: C.panel,
            border: `2px solid ${C.crimson}`,
            borderRadius: '12px',
            padding: '48px 56px',
            maxWidth: '620px',
            width: '90%',
            textAlign: 'center',
            boxShadow: C.shadowMd,
            animation: 'shieldGlow 1.8s ease-in-out infinite',
          }}>
            <div style={{ fontSize: '56px', marginBottom: '20px', lineHeight: 1 }}>🛡</div>
            <h2 style={{ fontSize: '22px', color: C.crimson, letterSpacing: '2px', margin: '0 0 8px 0' }}>
              ALIGNMENT HIJACK BLOCKED
            </h2>
            <p style={{ fontSize: '13px', color: C.muted, letterSpacing: '1px', margin: '0 0 28px 0' }}>
              STATUS: HIJACK_ATTEMPT_BLOCKED // PIPELINE FROZEN
            </p>
            <div style={{
              background: '#FEF2F2',
              border: `1px dashed ${C.crimson}`,
              borderRadius: '6px',
              padding: '14px 18px',
              marginBottom: '28px',
              fontSize: '13px',
              color: C.crimson,
              textAlign: 'left',
              lineHeight: '1.6',
              wordBreak: 'break-word',
            }}>
              <strong style={{ display: 'block', marginBottom: '6px', color: C.text }}>
                INTERCEPTED INPUT:
              </strong>
              {blockedInput.length > 180 ? `${blockedInput.slice(0, 180)}…` : blockedInput}
            </div>
            <p style={{ fontSize: '13px', color: C.muted, lineHeight: '1.6', marginBottom: '32px' }}>
              The guardrail interceptor detected an adversarial prompt pattern in your input.
              Inputs containing alignment-hijacking directives are rejected before reaching the
              classification pipeline to prevent response manipulation.
            </p>
            <button
              onClick={() => { setHijackBlocked(false); setInputLog(''); setBlockedInput(''); }}
              style={{
                background: C.crimson,
                color: '#FFFFFF',
                border: 'none',
                borderRadius: '6px',
                padding: '13px 32px',
                fontSize: '14px',
                fontWeight: 'bold',
                fontFamily: '"Courier New", Courier, monospace',
                cursor: 'pointer',
                letterSpacing: '1.5px',
                textTransform: 'uppercase',
              }}
            >
              CLEAR &amp; RESET PIPELINE
            </button>
          </div>
        </div>
      )}

      {/* ── HEADER ───────────────────────────────────────────────────────────── */}
      <header style={{
        borderBottom: `2px solid ${C.blue}`,
        paddingBottom: '20px',
        marginBottom: '32px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
      }}>
        <div>
          <h1 style={{
            margin: 0,
            fontSize: '30px',
            fontWeight: 'bold',
            color: C.blue,
            letterSpacing: '2px',
          }}>
            NEXUS-SHIELD // AUTOMATED THREAT CO-PILOT
          </h1>
          <p style={{
            margin: '7px 0 0 0',
            color: C.muted,
            fontSize: '14px',
            textTransform: 'uppercase',
            letterSpacing: '1px',
          }}>
            Architecture: Fine-Tuned SLM Adapter Weights + NIST RAG Policy Engine
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            width: '11px', height: '11px',
            backgroundColor: C.green,
            borderRadius: '50%',
            animation: 'scanPulse 1.6s ease-in-out infinite',
            boxShadow: '0 0 6px rgba(22,163,74,0.5)',
          }} />
          <span style={{ fontSize: '13px', color: C.green, letterSpacing: '1px', fontWeight: '600' }}>
            SYSTEM RECEPTOR ONLINE
          </span>
        </div>
      </header>

      {/* ── TOP GRID: 3 columns ───────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 2fr 1.5fr', gap: '24px', marginBottom: '24px' }}>

        {/* PANEL 1 — Live Ingestion Feed */}
        <div style={panelStyle()}>
          <h2 style={headingStyle(C.crimson)}>// LIVE RAW INGESTION FEED</h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '440px', overflowY: 'auto', paddingRight: '4px' }}>
            {logs.map((log, i) => (
              <div key={i} style={{
                padding: '12px 14px',
                background: C.panelDk,
                borderLeft: `3px solid ${C.amber}`,
                borderRadius: '4px',
                fontSize: '13px',
                color: C.text,
                lineHeight: '1.55',
                animation: i === 0 ? 'fadeUp 0.3s ease' : undefined,
              }}>
                {log}
              </div>
            ))}
          </div>
        </div>

        {/* PANEL 2 — Analysis Terminal */}
        <div style={panelStyle({ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' })}>
          <div>
            <h2 style={headingStyle(C.blue)}>// COMPLIANCE ANALYSIS GATEWAY</h2>
            <p style={{ color: C.muted, fontSize: '14px', lineHeight: '1.65', margin: '0 0 16px 0' }}>
              Paste raw network telemetry, brute-force alerts, or system anomaly strings below.
              The fine-tuned behavioral layer classifies the threat vector while the RAG engine
              enforces real-time NIST regulatory overrides for governed domains.
            </p>
            <textarea
              value={inputLog}
              onChange={e => setInputLog(e.target.value)}
              placeholder="Paste telemetry event string here..."
              style={{
                width: '100%',
                height: '200px',
                backgroundColor: C.panelDk,
                color: C.text,
                border: `1px solid ${C.borderBright}`,
                borderRadius: '6px',
                padding: '16px',
                fontSize: '14px',
                fontFamily: '"Courier New", Courier, monospace',
                boxSizing: 'border-box',
                resize: 'none',
                lineHeight: '1.55',
                outline: 'none',
              }}
            />
          </div>
          <button
            onClick={executeDualEnginePipeline}
            disabled={isProcessing}
            style={{
              width: '100%',
              backgroundColor: isProcessing ? C.borderBright : C.blue,
              color: '#FFFFFF',
              border: 'none',
              borderRadius: '6px',
              padding: '16px',
              fontSize: '16px',
              fontWeight: 'bold',
              fontFamily: '"Courier New", Courier, monospace',
              cursor: isProcessing ? 'not-allowed' : 'pointer',
              textTransform: 'uppercase',
              letterSpacing: '2px',
              transition: 'all 0.2s ease',
              marginTop: '20px',
              boxShadow: isProcessing ? 'none' : '0 2px 8px rgba(37,99,235,0.3)',
            }}
          >
            {isProcessing ? 'Analyzing Matrices...' : 'Run Hybrid Inference Pipeline'}
          </button>
        </div>

        {/* PANEL 3 — JSON Output + Executive Briefing */}
        <div style={panelStyle()}>
          {/* Header row with posture badge */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
            <h2 style={{ ...headingStyle(C.blue), borderBottom: 'none', marginBottom: 0, paddingBottom: 0 }}>
              // MATRIX COMPILER VIEW
            </h2>
            <span style={{
              fontSize: '12px',
              fontWeight: 'bold',
              padding: '4px 10px',
              borderRadius: '4px',
              backgroundColor: isCritical ? 'rgba(220,38,38,0.08)' : 'rgba(22,163,74,0.08)',
              color: isCritical ? C.crimson : C.green,
              border: `1px solid ${isCritical ? C.crimson : C.green}`,
              whiteSpace: 'nowrap',
            }}>
              {postureStatus} POSTURE
            </span>
          </div>

          <pre style={{
            background: C.panelDk,
            border: `1px solid ${C.border}`,
            borderRadius: '6px',
            padding: '16px',
            fontSize: '13px',
            color: C.text,
            overflowX: 'auto',
            minHeight: '160px',
            lineHeight: '1.6',
            margin: '0 0 14px 0',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
          }}>
            {outputJson
              ? JSON.stringify(outputJson, null, 2)
              : '// System idle.\n// Awaiting telemetry input...'}
          </pre>

          {isCritical && (
            <div style={{
              padding: '12px 14px',
              background: 'rgba(220,38,38,0.06)',
              border: `1px dashed ${C.crimson}`,
              borderRadius: '6px',
              fontSize: '13px',
              color: C.crimson,
              lineHeight: '1.55',
              marginBottom: '14px',
            }}>
              <strong>[RAG EVENT WARNING]</strong>{' '}
              {NIST_RAG_DATABASE.financial_override}
            </div>
          )}

          {/* Executive Briefing */}
          {briefing && (
            <div style={{
              background: C.panelDk,
              border: `1px solid ${isCritical ? C.crimson : C.borderBright}`,
              borderRadius: '6px',
              padding: '16px',
              animation: 'fadeUp 0.35s ease',
            }}>
              <p style={{ fontSize: '12px', color: isCritical ? C.crimson : C.blue, letterSpacing: '1px', margin: '0 0 8px 0', fontWeight: 'bold' }}>
                // EXECUTIVE BRIEFING
              </p>
              <p style={{ fontSize: '15px', fontWeight: 'bold', color: C.text, margin: '0 0 10px 0', lineHeight: '1.4' }}>
                {briefing.title}
              </p>
              <p style={{ fontSize: '13px', color: C.muted, margin: '0 0 10px 0', lineHeight: '1.65' }}>
                <strong style={{ color: C.text }}>Impact: </strong>{briefing.impact}
              </p>
              <p style={{ fontSize: '13px', color: C.muted, margin: 0, lineHeight: '1.65' }}>
                <strong style={{ color: C.text }}>Mitigation: </strong>{briefing.mitigation}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* ── BOTTOM GRID: Network Map + Error Decoder ──────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '3fr 2fr', gap: '24px' }}>

        {/* PANEL 4 — Network Topology Map */}
        <div style={panelStyle()}>
          <h2 style={headingStyle(C.blue)}>// NETWORK TOPOLOGY MAP</h2>
          <p style={{ fontSize: '14px', color: C.muted, margin: '0 0 18px 0', lineHeight: '1.6' }}>
            Infrastructure node graph. Run an inference to highlight the compromised target node with a live aura signal.
          </p>
          <svg
            viewBox="0 0 700 295"
            width="100%"
            style={{ display: 'block', overflow: 'visible' }}
          >
            {/* Background grid lines (decorative) */}
            {[0,1,2,3,4,5,6].map(i => (
              <line key={`vg${i}`} x1={i*100+50} y1={0} x2={i*100+50} y2={295}
                stroke={C.border} strokeWidth={1} />
            ))}
            {[0,1,2,3,4,5].map(i => (
              <line key={`hg${i}`} x1={0} y1={i*50+22} x2={700} y2={i*50+22}
                stroke={C.border} strokeWidth={1} />
            ))}

            {/* Data lines from hub to each node */}
            {NETWORK_NODES.map(node => {
              const isActive  = activeTarget === node.id;
              const nodeColor = getNodeColor(node.id, isCritical);
              return (
                <line
                  key={`line-${node.id}`}
                  x1={HUB.x} y1={HUB.y}
                  x2={node.x} y2={node.y}
                  stroke={isActive ? nodeColor : C.borderBright}
                  strokeWidth={isActive ? 3 : 1}
                  strokeDasharray={isActive ? '8 4' : '5 7'}
                  style={isActive
                    ? { animation: 'dashFlow 0.35s linear infinite' }
                    : {}}
                />
              );
            })}

            {/* Hub node */}
            <circle cx={HUB.x} cy={HUB.y} r={14} fill={C.panelDk} stroke={C.blue} strokeWidth={2} />
            <text x={HUB.x} y={HUB.y + 5} textAnchor="middle" fontSize="9"
              fill={C.blue} fontFamily='"Courier New", monospace' fontWeight="bold">
              HUB
            </text>

            {/* Infrastructure nodes */}
            {NETWORK_NODES.map(node => {
              const isActive  = activeTarget === node.id;
              const nodeColor = getNodeColor(node.id, isCritical);
              const nodeFill  = getNodeFill(node.id, isCritical);
              return (
                <g key={node.id}>
                  {/* Outer pulse rings (active only) */}
                  {isActive && (
                    <>
                      <circle cx={node.x} cy={node.y} r={36}
                        fill="none" stroke={nodeColor} strokeWidth={2}
                        style={{ animation: 'nodePulse 1.1s ease-in-out infinite' }} />
                      <circle cx={node.x} cy={node.y} r={46}
                        fill="none" stroke={nodeColor} strokeWidth={1}
                        style={{ animation: 'nodePulse 1.1s ease-in-out infinite', animationDelay: '0.35s' }} />
                    </>
                  )}
                  {/* Node circle */}
                  <circle
                    cx={node.x} cy={node.y} r={22}
                    fill={isActive ? nodeFill : '#FFFFFF'}
                    stroke={isActive ? nodeColor : C.borderBright}
                    strokeWidth={isActive ? 2.5 : 1.5}
                  />
                  {/* Node label — 2 lines */}
                  <text textAnchor="middle" fontSize="10"
                    fontFamily='"Courier New", monospace'
                    fill={isActive ? nodeColor : C.muted}
                    fontWeight={isActive ? 'bold' : 'normal'}>
                    <tspan x={node.x} y={node.y + 32}>{node.lines[0]}</tspan>
                    <tspan x={node.x} y={node.y + 46}>{node.lines[1]}</tspan>
                  </text>
                </g>
              );
            })}
          </svg>

          {/* Node legend */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', marginTop: '18px', paddingTop: '16px', borderTop: `1px solid ${C.border}` }}>
            {NETWORK_NODES.map(node => {
              const isActive  = activeTarget === node.id;
              const nodeColor = getNodeColor(node.id, isCritical);
              const nodeFill  = getNodeFill(node.id, isCritical);
              return (
                <div key={node.id} style={{
                  display: 'flex', alignItems: 'center', gap: '7px',
                  padding: '5px 10px',
                  background: isActive ? nodeFill : C.panelDk,
                  border: `1px solid ${isActive ? nodeColor : C.border}`,
                  borderRadius: '4px',
                  fontSize: '12px',
                  color: isActive ? nodeColor : C.muted,
                  fontWeight: isActive ? '600' : 'normal',
                }}>
                  <span style={{
                    width: '8px', height: '8px', borderRadius: '50%',
                    background: isActive ? nodeColor : C.borderBright,
                    flexShrink: 0,
                  }} />
                  {node.id}
                </div>
              );
            })}
          </div>
        </div>

        {/* PANEL 5 — System Diagnostic & Error Decoder */}
        <div style={panelStyle()}>
          <h2 style={headingStyle(C.crimson)}>// SYSTEM DIAGNOSTIC &amp; ERROR TRANSLATOR</h2>
          <p style={{ fontSize: '14px', color: C.muted, margin: '0 0 18px 0', lineHeight: '1.6' }}>
            AI engineering blockers resolved during model fine-tuning. Select an exception to see the
            raw stack, hardware explanation, and PM resolution strategy.
          </p>

          {/* Error selector buttons */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '20px' }}>
            {Object.entries(ERROR_CATALOG).map(([key, err]) => {
              const isActive = activeError === key;
              return (
                <button
                  key={key}
                  onClick={() => setActiveError(prev => prev === key ? null : key)}
                  style={{
                    background: isActive ? 'rgba(220,38,38,0.06)' : C.panelDk,
                    border: `1px solid ${isActive ? C.crimson : C.border}`,
                    borderRadius: '6px',
                    padding: '11px 14px',
                    color: isActive ? C.text : C.muted,
                    fontSize: '13px',
                    fontFamily: '"Courier New", Courier, monospace',
                    cursor: 'pointer',
                    textAlign: 'left',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <span>{err.label}</span>
                  <span style={{ color: isActive ? C.crimson : C.dim, fontSize: '16px', lineHeight: 1 }}>
                    {isActive ? '▲' : '▼'}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Error detail panel */}
          {activeError && (
            <div style={{ animation: 'fadeUp 0.25s ease' }}>
              {/* Raw Exception Stack */}
              <p style={{ fontSize: '12px', color: C.crimson, letterSpacing: '1px', margin: '0 0 8px 0', fontWeight: 'bold' }}>
                RAW EXCEPTION STACK
              </p>
              <pre style={{
                background: C.panelDk,
                border: `1px solid ${C.border}`,
                borderRadius: '6px',
                padding: '14px',
                fontSize: '12px',
                color: C.crimson,
                overflowX: 'auto',
                overflowY: 'auto',
                maxHeight: '160px',
                lineHeight: '1.55',
                margin: '0 0 18px 0',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
              }}>
                {ERROR_CATALOG[activeError].stack}
              </pre>

              {/* Plain English Explanation */}
              <p style={{ fontSize: '12px', color: C.blue, letterSpacing: '1px', margin: '0 0 8px 0', fontWeight: 'bold' }}>
                PLAIN ENGLISH EXPLANATION
              </p>
              <div style={{
                background: C.panelDk,
                border: `1px solid ${C.border}`,
                borderRadius: '6px',
                padding: '14px',
                fontSize: '13px',
                color: C.text,
                lineHeight: '1.65',
                marginBottom: '18px',
              }}>
                {ERROR_CATALOG[activeError].explanation}
              </div>

              {/* PM Resolution Strategy */}
              <p style={{ fontSize: '12px', color: C.green, letterSpacing: '1px', margin: '0 0 8px 0', fontWeight: 'bold' }}>
                PM RESOLUTION STRATEGY
              </p>
              <div style={{
                background: 'rgba(22,163,74,0.06)',
                border: '1px solid rgba(22,163,74,0.25)',
                borderRadius: '6px',
                padding: '14px',
                fontSize: '13px',
                color: C.text,
                lineHeight: '1.65',
              }}>
                {ERROR_CATALOG[activeError].resolution}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
