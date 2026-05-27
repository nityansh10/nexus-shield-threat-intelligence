/**
 * force-seed-db.js — NEXUS-SHIELD compliance_policies bulk seeder
 * Run: node --env-file=.env.local force-seed-db.js
 *
 * This script re-generates all 15 embeddings and attempts bulk insert.
 * RLS bypass options (in priority order):
 *   1. SUPABASE_SERVICE_KEY in .env.local  — bypasses RLS programmatically
 *   2. If blocked: seed-compliance.sql is written → paste into Supabase SQL Editor
 */

import { createClient } from '@supabase/supabase-js';
import { readFileSync, writeFileSync } from 'fs';

// ── Load .env.local ───────────────────────────────────────────────────────────

function loadEnvLocal() {
  try {
    return Object.fromEntries(
      readFileSync('.env.local', 'utf8')
        .split('\n')
        .filter(l => l.includes('=') && !l.startsWith('#'))
        .map(l => {
          const idx = l.indexOf('=');
          return [l.slice(0, idx).trim(), l.slice(idx + 1).trim().replace(/^["']|["']$/g, '')];
        }),
    );
  } catch { return {}; }
}

const env = { ...process.env, ...loadEnvLocal() };

const GEMINI_KEY   = env.VITE_GEMINI_API_KEY;
const SUPABASE_URL = env.VITE_SUPABASE_URL;
const ANON_KEY     = env.VITE_SUPABASE_ANON_KEY;
const SERVICE_KEY  = env.SUPABASE_SERVICE_KEY;   // optional — bypasses RLS

if (!GEMINI_KEY || !SUPABASE_URL || !ANON_KEY) {
  console.error('\nERROR: Missing env vars. Ensure .env.local contains:');
  console.error('  VITE_GEMINI_API_KEY, VITE_SUPABASE_URL, VITE_SUPABASE_ANON_KEY\n');
  process.exit(1);
}

// Service key bypasses RLS; anon key is subject to table policies
const activeKey = SERVICE_KEY ?? ANON_KEY;
const supabase  = createClient(SUPABASE_URL, activeKey, {
  auth: { autoRefreshToken: false, persistSession: false },
  global: SERVICE_KEY
    ? { headers: { Authorization: `Bearer ${SERVICE_KEY}` } }
    : {},
});

// ── Embedding helper (gemini-embedding-001 @ 768 dims) ───────────────────────
// text-embedding-004 is not enabled on this API key; gemini-embedding-001
// with outputDimensionality:768 is the supported equivalent.

async function getEmbedding(text) {
  const res = await fetch(
    `https://generativelanguage.googleapis.com/v1/models/gemini-embedding-001:embedContent?key=${GEMINI_KEY}`,
    {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content:              { parts: [{ text }] },
        taskType:             'RETRIEVAL_DOCUMENT',
        outputDimensionality: 768,
      }),
    },
  );
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message ?? `HTTP ${res.status}`);
  }
  const data = await res.json();
  return data.embedding.values;
}

// ── 15 compliance policies ────────────────────────────────────────────────────

const COMPLIANCE_POLICIES = [
  {
    topic: 'Supply Chain Attack Prevention',
    policy_text: `Supply chain attacks target the software delivery pipeline itself — package registries, build servers, third-party libraries, and vendor update mechanisms — to inject malicious code before it reaches the enterprise perimeter. NIST SP 800-161r1 requires organisations to maintain a Software Bill of Materials (SBOM) for all deployed applications, verified against a known-good hash registry before every production deployment. All third-party packages must pass automated SCA scanning before merge approval. Pinning dependency versions to exact commit SHA hashes in lock files is mandatory; floating version ranges are prohibited in production manifests. Vendor risk assessments must be conducted annually. Artefacts promoted to production must carry a cryptographic signature from a hardware-backed signing key. Monitoring for typosquatting on internal package registry mirrors must run continuously. Any unsigned or hash-mismatched artefact must be quarantined automatically and trigger a P1 incident response.`,
  },
  {
    topic: 'Ransomware Execution Defense',
    policy_text: `Ransomware defence requires layered controls spanning pre-execution, execution, and post-encryption phases. Pre-execution controls include enforcing application allowlisting on all endpoints, disabling macro execution in Office documents by Group Policy, and blocking execution from user-writable directories. During execution, EDR solutions must detect and terminate processes exhibiting high-entropy file write patterns. Volume Shadow Copy deletion commands (vssadmin.exe, wbadmin.exe) and bcdedit /set recovery bypass flags must trigger immediate host isolation via automated SOAR playbook. Backup architecture must follow the 3-2-1-1-0 rule: three copies, two media types, one offsite, one air-gapped immutable copy, zero backup errors verified. Backup integrity must be tested by full restore simulation monthly. Organisations must maintain a minimum of 30 days of immutable backup history. Network segmentation must prevent lateral spread across VLANs.`,
  },
  {
    topic: 'Insider Threat Detection and Response',
    policy_text: `Insider threats — whether malicious, negligent, or compromised — require a programme spanning user behaviour analytics, access governance, and HR coordination. Deploy a UEBA platform configured to baseline each user's normal activity patterns (access times, data volumes, application usage, geolocation). Alert thresholds must fire when deviations exceed 3 standard deviations from the 90-day rolling baseline. Time-of-access anomalies, bulk data staging (downloading more than 500 MB in a 30-minute window), and access to resources outside the user's job function must generate Tier-2 analyst review tickets within 15 minutes. Data egress to personal cloud services must be blocked at the web proxy layer. USB mass storage device attachment events must be logged with device serial number. Departing employees must have all access revoked within 60 minutes of HR notification.`,
  },
  {
    topic: 'API Data Exfiltration Prevention',
    policy_text: `APIs represent a high-bandwidth, often overlooked exfiltration vector. Every externally accessible API endpoint must be catalogued in an API Gateway with rate limiting, authentication, and DLP inspection enforced at the gateway layer. Authentication must require short-lived JWTs with a maximum 15-minute expiry signed with RS256 or ES256; long-lived API keys are prohibited for human-facing APIs. Per-endpoint rate limits must be defined based on business usage baselines. Response payloads must be scanned for PII and PHI patterns using a data classification engine before transmission. Pagination limits must cap all list endpoints at 1000 records per page; bulk-export endpoints must require additional step-up MFA. GraphQL deployments must enforce query depth limits and complexity scoring to prevent recursive traversal exfiltration. All API secrets must be stored in a secrets vault and rotated on a 90-day schedule.`,
  },
  {
    topic: 'Cloud Storage Misconfiguration Prevention',
    policy_text: `Cloud object storage misconfigurations remain the leading cause of large-scale data breaches. An organisation-wide S3 Block Public Access policy must be enforced at the AWS Organization level via Service Control Policy preventing any account from enabling public bucket ACLs. Google Cloud organisation policies must enforce uniform bucket-level access and public access prevention. All buckets storing sensitive data must have server-side encryption enabled with customer-managed KMS keys, and key rotation must be set to 365 days maximum. Access logging must be enabled on every production storage bucket with logs shipped to a centralised SIEM. CSPM tooling must run continuous misconfiguration detection; any open "publicly accessible storage" finding older than 4 hours must auto-page the on-call engineer. Bucket policies must be reviewed in quarterly access reviews and any overly permissive wildcard principals treated as critical findings.`,
  },
  {
    topic: 'Phishing and Social Engineering Defense',
    policy_text: `Phishing remains the initial access vector in over 80% of breaches. Email infrastructure must implement SPF (hard-fail policy), DKIM (2048-bit keys rotated annually), and DMARC (policy: reject with reporting enabled). Inbound email must pass through an advanced email security gateway configured to detonate all URLs in a sandbox and rewrite them to time-of-click protection URLs. Attachments must be detonated in a virtualised sandbox; macros in Office documents must be stripped before delivery. Anti-impersonation controls must flag any sender domain with a Levenshtein edit distance of 2 or less from internal domains. Employees must complete phishing simulation training quarterly; those who click simulated phishing links must receive mandatory micro-training within 24 hours. A documented report-phishing workflow must route suspicious emails to the SOC within 2 minutes.`,
  },
  {
    topic: 'Zero-Day Vulnerability Response',
    policy_text: `Zero-day vulnerabilities require a risk-based defence posture. Organisations must maintain continuous subscription to threat intelligence feeds and triage new advisories within 2 hours of publication for asset impact. Virtual patching must be deployed at the WAF or IPS layer within 4 hours of a credible PoC being published, even before vendor patches are available. All internet-facing systems must be scanned weekly with an authenticated vulnerability scanner; internal systems monthly. CVSS 9.0+ findings on internet-facing assets must be remediated within 24 hours; CVSS 7.0 through 8.9 within 72 hours. A software inventory covering all deployed OS versions, runtimes, and libraries must be maintained and queryable in real time. Exploit telemetry from EDR and network sensors must feed a detection rule pipeline updated within 12 hours of published IoCs.`,
  },
  {
    topic: 'Zero-Trust Network Access Architecture',
    policy_text: `Zero Trust eliminates the concept of an implicit trusted network perimeter and requires continuous, explicit verification for every access request. Network microsegmentation must be implemented so that each application tier resides in a separate microsegment with stateful firewall policies permitting only required traffic flows. User access to applications must be brokered via a ZTNA proxy that evaluates device health posture before granting access; sessions must be re-evaluated every 15 minutes. Privileged access must require hardware FIDO2 tokens for step-up authentication. Service-to-service calls must use short-lived X.509 certificates issued by an internal PKI with a maximum 24-hour validity. DNS resolution for internal services must be provided only over encrypted channels and all queries must be logged. Lateral movement detection must alert on any east-west connection not part of a declared application dependency map.`,
  },
  {
    topic: 'OAuth Token Hijacking and Session Security',
    policy_text: `OAuth 2.0 and OpenID Connect tokens are high-value targets. Access tokens must have a maximum lifetime of 15 minutes; refresh tokens must be rotated on every use and have a maximum absolute lifetime of 7 days for high-sensitivity applications. Refresh token rotation must be enforced at the authorisation server; any attempt to reuse a revoked refresh token must immediately invalidate the entire token family. Tokens must be stored in memory only — never in localStorage or sessionStorage — and transmitted exclusively over TLS 1.2 or higher. The authorisation code flow with PKCE is mandatory for all public clients; the implicit flow is prohibited. Redirect URIs must be exact-match validated. Token introspection endpoints must be protected and rate-limited. Anomalous token use must trigger token revocation and re-authentication prompts.`,
  },
  {
    topic: 'CI/CD Pipeline Security and Poisoning Prevention',
    policy_text: `Compromised CI/CD pipelines can inject malicious code into every downstream deployment. All pipeline definitions must be stored in version control with branch protection and require two approvals for changes. Pipeline execution must run in ephemeral, single-use build environments that are destroyed after each job. All build tools, base images, and CI runner images must be pinned to digest-verified versions; floating tags are prohibited. Secrets must never be embedded in pipeline YAML; all secrets must be injected at runtime from a secrets vault. Automated SCA, SAST, and container image scanning steps are mandatory and must gate the pipeline — a CRITICAL finding blocks promotion. Signed commits must be enforced on the default branch. SLSA Level 2 minimum is required: provenance must be generated and attached to every build artefact. Production deployments must be triggered only by the CI system.`,
  },
  {
    topic: 'Data Loss Prevention Policy Framework',
    policy_text: `A comprehensive DLP programme classifies sensitive data, monitors its movement, and enforces policies to prevent unauthorised disclosure. All data must be classified into four tiers — Public, Internal, Confidential, and Restricted — with automated classification labels applied by the DLP engine based on content inspection. DLP policies must be enforced at four control points: email gateway, web proxy, endpoint agent, and cloud CASB. False-positive thresholds must be reviewed monthly; any policy producing more than 10% false positives must be tuned before deployment. End-users must receive real-time notifications when a DLP policy blocks their action, with a business-justification override workflow that routes to their manager for approval and is logged for 7 years. Data retention policies must be programmatically enforced — Restricted data exceeding its retention period must be automatically purged with certificate-of-destruction logging.`,
  },
  {
    topic: 'Privileged Access Management and Credential Vaulting',
    policy_text: `Privileged accounts represent the highest-risk credential tier and must be governed under a dedicated PAM programme. All privileged credentials must be stored in an enterprise PAM vault with automatic rotation on a schedule not exceeding 30 days for human accounts and 7 days for service accounts. Just-in-time access must be enforced: privileged access must be requested through a ticketed workflow, granted for a time-bounded session of maximum 4 hours, and automatically revoked at session expiry. All privileged sessions must be recorded and the recordings must be stored immutably for a minimum of 12 months. Break-glass accounts must be double-sealed requiring two senior engineers to authorise, and their use must automatically page the CISO. Service account credentials must never be embedded in application code; workload identity federation must be used wherever supported. Quarterly access reviews must attest all privileged accounts.`,
  },
  {
    topic: 'Endpoint Detection and Response Deployment Standards',
    policy_text: `EDR provides the primary telemetry and response capability for endpoint threats. Full EDR agent deployment is mandatory on 100% of managed endpoints and must achieve at least 98% coverage with zero tolerance for gaps on Tier-1 assets including domain controllers, file servers, and jump hosts. EDR must be configured in prevent mode — not just detect mode — and policy exceptions must be documented and reviewed quarterly. Automated response actions must include: network isolation of a host within 60 seconds of a CRITICAL detection (ransomware behaviour, C2 beacon, credential dumping), killing the offending process tree, and preserving a memory dump for forensics. Threat hunting exercises must be conducted monthly using the MITRE ATT&CK framework as a guide. EDR telemetry must be forwarded to the SIEM in real time for correlation. Agent updates must be deployed within 24 hours of a content update release.`,
  },
  {
    topic: 'Network Lateral Movement Prevention',
    policy_text: `Lateral movement — an adversary pivoting from an initial beachhead to higher-value targets — must be detected and blocked through network architecture controls and real-time analytics. All inter-VLAN traffic must traverse a stateful next-generation firewall or microsegmentation policy with default-deny rules and explicit allowlists. Active Directory must enforce tiering: domain controllers, servers, and workstations must be network-isolated so a compromised workstation cannot directly reach a domain controller. Windows authentication protocols: NTLMv1 and NTLMv2 must be disabled in favour of Kerberos; SMB signing must be mandatory on all servers. SIEM detection rules must alert on: port scanning from internal hosts, SMB connections from workstations to more than 5 other workstations within 60 seconds, and authentication with the same credential to more than 10 hosts in 5 minutes. Honeypots and honeytokens must be deployed in each VLAN segment.`,
  },
  {
    topic: 'Incident Response and Business Continuity Planning',
    policy_text: `An effective incident response programme transforms a potentially catastrophic breach into a managed, recoverable event. All organisations must maintain a written IRP aligned to NIST SP 800-61r2 covering Preparation, Detection and Analysis, Containment, Eradication, Recovery, and Post-Incident Activity. The IR retainer must be tested in a full-scale tabletop exercise at least twice per year. Defined SLAs: time-to-detect must be 4 hours or less for CRITICAL incidents; time-to-contain must be 2 hours or less from declaration. Communication trees must be documented for all severity levels including legal counsel, executive leadership, and regulatory notification obligations under GDPR 72-hour window and SEC 4-day material cybersecurity incident rule. Business Continuity Plans must define RTO and RPO for each critical system tested annually; Tier-1 systems must achieve RTO of 4 hours or less and RPO of 1 hour or less.`,
  },
];

// ── Main seeding function ─────────────────────────────────────────────────────

async function forceSeed() {
  console.log('\n╔══════════════════════════════════════════════════════╗');
  console.log('║  NEXUS-SHIELD  •  Force Seed  •  compliance_policies  ║');
  console.log('╚══════════════════════════════════════════════════════╝');
  console.log(`\nTarget : ${SUPABASE_URL}`);
  console.log(`Auth   : ${SERVICE_KEY ? 'service_role key (RLS bypassed ✓)' : 'anon key (RLS applies)'}`);
  console.log(`Model  : gemini-embedding-001 @ 768 dims`);
  console.log(`Rows   : ${COMPLIANCE_POLICIES.length} policies to seed\n`);

  // ── Phase 1: Generate all embeddings ───────────────────────────────────────
  console.log('── Phase 1: Generating embeddings ──');
  const rows = [];

  for (let i = 0; i < COMPLIANCE_POLICIES.length; i++) {
    const { topic, policy_text } = COMPLIANCE_POLICIES[i];
    process.stdout.write(`  [${String(i + 1).padStart(2, '0')}/${COMPLIANCE_POLICIES.length}] ${topic.padEnd(50, '.')} `);
    try {
      const embedding = await getEmbedding(policy_text);
      rows.push({ topic, policy_text, embedding });
      console.log(`${embedding.length}d ✓`);
    } catch (err) {
      console.log(`EMBEDDING ERROR — ${err.message}`);
    }
    if (i < COMPLIANCE_POLICIES.length - 1) {
      await new Promise(r => setTimeout(r, 250));
    }
  }

  console.log(`\n  ${rows.length}/${COMPLIANCE_POLICIES.length} embeddings generated.\n`);

  if (rows.length === 0) {
    console.error('ERROR: No embeddings generated. Check VITE_GEMINI_API_KEY.');
    process.exit(1);
  }

  // ── Phase 2: Bulk insert ────────────────────────────────────────────────────
  console.log('── Phase 2: Bulk inserting into Supabase ──');

  const { data, error } = await supabase
    .from('compliance_policies')
    .insert(rows)
    .select('id, topic');

  if (!error) {
    const count = data?.length ?? rows.length;
    console.log(`\n  ✓ SUCCESS — ${count} vector rows securely sent to ${SUPABASE_URL.replace('https://', '')}`);
    console.log('\n╔══════════════════════════════════════════════════╗');
    console.log(`║  ${count} / ${COMPLIANCE_POLICIES.length} ROWS INSERTED INTO compliance_policies  ║`);
    console.log('╚══════════════════════════════════════════════════╝\n');
    process.exit(0);
  }

  // ── Phase 3: Handle RLS blocker — write SQL fallback ──────────────────────
  const isRls = error.code === '42501' || error.message?.includes('row-level security');
  console.log(`\n  ✗ Insert blocked: ${error.message}`);

  if (isRls) {
    console.log('\n── Phase 3: Writing seed-compliance.sql (RLS bypass fallback) ──');
    const sqlStatements = rows.map(({ topic, policy_text, embedding }) => {
      const t  = topic.replace(/'/g, "''");
      const p  = policy_text.replace(/'/g, "''");
      const v  = `[${embedding.join(',')}]`;
      return `INSERT INTO compliance_policies (topic, policy_text, embedding)\nVALUES ('${t}', '${p}', '${v}');`;
    });

    const sql =
      `-- NEXUS-SHIELD compliance_policies seed  (${new Date().toISOString()})\n` +
      `-- ${rows.length} rows with live gemini-embedding-001 @ 768 dims\n` +
      `-- ─────────────────────────────────────────────────────────────────────\n` +
      `-- RUN THIS FILE IN:  Supabase Dashboard → SQL Editor → New Query → Run\n` +
      `-- OR: add SUPABASE_SERVICE_KEY to .env.local and re-run this script.\n` +
      `-- ─────────────────────────────────────────────────────────────────────\n\n` +
      sqlStatements.join('\n\n') + '\n';

    writeFileSync('seed-compliance.sql', sql, 'utf8');

    console.log(`\n  ${rows.length} INSERT statements written to: seed-compliance.sql`);
    console.log('\n╔═══════════════════════════════════════════════════════════════╗');
    console.log(`║  ${rows.length} ROWS PREPARED — manual step required to load into DB  ║`);
    console.log('╠═══════════════════════════════════════════════════════════════╣');
    console.log('║  OPTION A (30 sec):                                           ║');
    console.log('║    Supabase → SQL Editor → paste seed-compliance.sql → Run    ║');
    console.log('║                                                               ║');
    console.log('║  OPTION B (programmatic):                                     ║');
    console.log('║    Add to .env.local:  SUPABASE_SERVICE_KEY=<secret key>      ║');
    console.log('║    Find it: Supabase → Settings → API → service_role secret   ║');
    console.log('║    Then re-run: node --env-file=.env.local force-seed-db.js   ║');
    console.log('╚═══════════════════════════════════════════════════════════════╝\n');
  } else {
    console.log('\nUnexpected error (not RLS). Check table schema and permissions.');
    console.log('Error detail:', JSON.stringify(error, null, 2));
  }

  process.exit(0);
}

forceSeed().catch(err => {
  console.error('\nFatal error:', err.message);
  process.exit(1);
});
