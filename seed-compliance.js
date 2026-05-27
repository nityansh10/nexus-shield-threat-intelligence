/**
 * seed-compliance.js
 * One-time seeding utility: computes 768-dim Gemini embeddings for 15
 * enterprise cybersecurity compliance policies and upserts them into the
 * Supabase `compliance_policies` table.
 *
 * Prerequisites (run once in Supabase SQL Editor if not already done):
 * ─────────────────────────────────────────────────────────────────────
 * create extension if not exists vector;
 *
 * create table if not exists compliance_policies (
 *   id          bigserial primary key,
 *   topic       text unique not null,
 *   policy_text text        not null,
 *   embedding   vector(768)
 * );
 *
 * create index if not exists compliance_policies_embedding_idx
 *   on compliance_policies using ivfflat (embedding vector_cosine_ops);
 *
 * create or replace function match_policies (
 *   query_embedding  vector(768),
 *   match_threshold  float,
 *   match_count      int
 * )
 * returns table (id bigint, topic text, policy_text text, similarity float)
 * language sql stable as $$
 *   select id, topic, policy_text,
 *          1 - (embedding <=> query_embedding) as similarity
 *   from compliance_policies
 *   where 1 - (embedding <=> query_embedding) > match_threshold
 *   order by similarity desc
 *   limit match_count;
 * $$;
 *
 * Run: node --env-file=.env.local seed-compliance.js
 */

import { readFileSync } from 'fs';
import { createClient } from '@supabase/supabase-js';

// ── Load .env.local ───────────────────────────────────────────────────────────

function loadEnvLocal() {
  try {
    return Object.fromEntries(
      readFileSync('.env.local', 'utf8')
        .split('\n')
        .filter(l => l.includes('=') && !l.startsWith('#'))
        .map(l => {
          const idx = l.indexOf('=');
          const key = l.slice(0, idx).trim();
          const val = l.slice(idx + 1).trim().replace(/^["']|["']$/g, '');
          return [key, val];
        }),
    );
  } catch {
    return {};
  }
}

const env            = { ...process.env, ...loadEnvLocal() };
const GEMINI_KEY     = env.VITE_GEMINI_API_KEY;
const SUPABASE_URL   = env.VITE_SUPABASE_URL;
const SUPABASE_KEY   = env.VITE_SUPABASE_ANON_KEY;

if (!GEMINI_KEY || !SUPABASE_URL || !SUPABASE_KEY) {
  console.error('ERROR: Missing one or more required env vars in .env.local');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// text-embedding-004 is not enabled on this API key.
// gemini-embedding-001 is the supported model; we truncate to 768 dims via
// outputDimensionality to match the Supabase vector(768) column schema.
async function getEmbedding(text) {
  const res = await fetch(
    `https://generativelanguage.googleapis.com/v1/models/gemini-embedding-001:embedContent?key=${GEMINI_KEY}`,
    {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
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
  return data.embedding.values; // 768-element float array
}

// ── 15 Enterprise Compliance Policies ────────────────────────────────────────

const COMPLIANCE_POLICIES = [
  {
    topic: 'Supply Chain Attack Prevention',
    policy_text: `Supply chain attacks target the software delivery pipeline itself — package registries, build servers, third-party libraries, and vendor update mechanisms — to inject malicious code before it reaches the enterprise perimeter. NIST SP 800-161r1 requires organisations to maintain a Software Bill of Materials (SBOM) for all deployed applications, verified against a known-good hash registry before every production deployment. All third-party packages must pass automated SCA (Software Composition Analysis) scanning using tools such as Snyk, OWASP Dependency-Check, or GitHub Dependabot before merge approval. Pinning dependency versions to exact commit SHA hashes in lock files is mandatory; floating version ranges (e.g. "^1.x") are prohibited in production manifests. Vendor risk assessments must be conducted annually and include a review of the vendor's own SBOM attestation. Artefacts promoted to production must carry a cryptographic signature from a hardware-backed signing key, and the build pipeline must verify that signature at deployment time. Monitoring for typosquatting on internal package registry mirrors must run continuously. Any unsigned or hash-mismatched artefact must be quarantined automatically and trigger a P1 incident response. Incident response playbooks must include a "poisoned library" scenario with predefined rollback procedures tested at least once per quarter.`,
  },
  {
    topic: 'Ransomware Execution Defense',
    policy_text: `Ransomware defence requires layered controls spanning pre-execution, execution, and post-encryption phases. Pre-execution controls include enforcing application allowlisting on all endpoints via Windows Defender Application Control (WDAC) or Carbon Black App Control, disabling macro execution in Office documents by Group Policy, and blocking execution from user-writable directories (%TEMP%, %APPDATA%). During execution, EDR solutions must be configured to detect and terminate processes exhibiting high-entropy file write patterns across more than 20 files per second. Volume Shadow Copy deletion commands (vssadmin.exe, wbadmin.exe) and bcdedit /set recovery bypass flags must trigger immediate host isolation via automated SOAR playbook. Backup architecture must follow the 3-2-1-1-0 rule: three copies, two media types, one offsite, one air-gapped immutable copy, zero backup errors verified. Backup integrity must be tested by full restore simulation monthly in an isolated network segment. Organisations must maintain a minimum of 30 days of immutable backup history. Network segmentation must prevent lateral spread: C-level, HR, finance, and engineering VLANs must each require explicit firewall ACL traversal. Ransomware-specific IR retainer contacts must be on speed-dial and tested in a tabletop exercise quarterly. Payment decisions must involve legal counsel, cyber insurance carrier, and law enforcement notification under applicable breach-disclosure deadlines.`,
  },
  {
    topic: 'Insider Threat Detection and Response',
    policy_text: `Insider threats — whether malicious, negligent, or compromised — require a programme spanning user behaviour analytics, access governance, and HR coordination. Deploy a UEBA (User and Entity Behaviour Analytics) platform such as Microsoft Sentinel UEBA, Exabeam, or Securonix configured to baseline each user's normal activity patterns (access times, data volumes, application usage, geolocation). Alert thresholds must fire when deviations exceed 3 standard deviations from the 90-day rolling baseline. Time-of-access anomalies (off-hours logins from standard office locations, impossible travel), bulk data staging (downloading >500 MB in a 30-minute window), and access to resources outside the user's job function must all generate Tier-2 analyst review tickets within 15 minutes. Data egress to personal cloud services (Google Drive personal, Dropbox personal, WeTransfer) must be blocked at the web proxy layer and any attempt must generate a high-priority alert. USB mass storage device attachment events must be logged with device serial number; removable-media encryption policy must be enforced via endpoint DLP. Departing employees must have all access revoked within 60 minutes of HR notification, and an automated "leaver scan" must inspect their recent data access logs for bulk downloads in the preceding 30 days. HR, Legal, and Security must operate a joint case-management workflow with documented evidence chain-of-custody before any personnel action. Insider threat awareness training must be delivered annually with simulated exercises.`,
  },
  {
    topic: 'API Data Exfiltration Prevention',
    policy_text: `APIs represent a high-bandwidth, often overlooked exfiltration vector. Every externally accessible API endpoint must be catalogued in an API Gateway (Kong, Apigee, AWS API GW) with rate limiting, authentication, and DLP inspection enforced at the gateway layer. Authentication must require short-lived JWTs (max 15-minute expiry) signed with RS256 or ES256; long-lived API keys are prohibited for human-facing APIs. Per-endpoint rate limits must be defined based on business usage baselines; any client exceeding 3× the P99 request rate triggers an automatic 429 and a security alert. Response payloads must be scanned for PII (SSN, credit card PANs, passport numbers) and PHI patterns using a data classification engine before transmission; matches generate DLP violations and halt the response. Pagination limits must cap all list endpoints at 1000 records per page; bulk-export endpoints must require additional step-up MFA and log every invocation to an immutable SIEM. API traffic must be inspected by a WAF configured with the OWASP API Security Top 10 ruleset. GraphQL deployments must enforce query depth limits (max 7 levels) and complexity scoring (max 500 points) to prevent recursive traversal exfiltration. All API secrets must be stored in a secrets vault (HashiCorp Vault, AWS Secrets Manager) and rotated on a 90-day schedule.`,
  },
  {
    topic: 'Cloud Storage Misconfiguration Prevention',
    policy_text: `Cloud object storage misconfigurations (public S3 buckets, GCS ACLs, Azure Blob anonymous access) remain the leading cause of large-scale data breaches. An organisation-wide S3 Block Public Access policy must be enforced at the AWS Organization level via Service Control Policy (SCP) preventing any account from enabling public bucket ACLs. Google Cloud organisation policies must enforce "constraints/storage.uniformBucketLevelAccess" and "constraints/storage.publicAccessPrevention". All buckets storing sensitive data (PII, PHI, PCI-DSS in scope) must have server-side encryption enabled with customer-managed KMS keys (SSE-KMS), and key rotation must be set to 365 days maximum. Access logging must be enabled on every production storage bucket, with logs shipped to a centralised SIEM. CSPM (Cloud Security Posture Management) tooling — AWS Security Hub, Prisma Cloud, or Wiz — must run continuous misconfiguration detection and produce a zero-tolerance report for "publicly accessible storage" findings; any open finding older than 4 hours that is not acknowledged must auto-page the on-call engineer. Lifecycle policies must delete incomplete multipart uploads after 24 hours. Cross-account bucket replication must require explicit IAM trust policy approval from the security team. Bucket policies must be reviewed in quarterly access reviews and any overly permissive wildcard principals ("Principal": "*") treated as critical findings.`,
  },
  {
    topic: 'Phishing and Social Engineering Defense',
    policy_text: `Phishing remains the initial access vector in over 80% of breaches. Email infrastructure must implement all three sender authentication standards: SPF (hard-fail policy: "v=spf1 ... -all"), DKIM (2048-bit keys rotated annually), and DMARC (policy: reject; rua and ruf reporting enabled). Inbound email must pass through an advanced email security gateway (Proofpoint, Mimecast, or Microsoft Defender for Office 365) configured to detonate all URLs in a sandbox and rewrite them to time-of-click protection URLs. Attachments must be detonated in a virtualised sandbox; macros in Office documents must be stripped before delivery. Anti-impersonation controls must flag any sender domain with a Levenshtein edit distance of ≤ 2 from internal domains. Employees must complete phishing simulation training quarterly; those who click simulated phishing links must receive mandatory micro-training within 24 hours. Click rates above 5% in simulations must trigger executive escalation and a department-wide refresh. Browser-based credential harvesting must be blocked via MFA enforcement on all SaaS platforms; password managers must be enterprise-provisioned to prevent credential reuse. Vishing (voice phishing) and smishing (SMS phishing) awareness must be included in annual security awareness training. A documented "report phishing" workflow must route suspicious emails to the SOC within 2 minutes; analysts must triage within 15 minutes.`,
  },
  {
    topic: 'Zero-Day Vulnerability Response',
    policy_text: `Zero-day vulnerabilities — flaws exploited before vendor patches exist — require a risk-based defence posture. Organisations must maintain continuous subscription to threat intelligence feeds (CISA KEV, Mandiant Advantage, Recorded Future, or equivalent) and triage new advisories within 2 hours of publication for asset impact. Virtual patching must be deployed at the WAF or IPS layer within 4 hours of a credible PoC being published, even before vendor patches are available. All internet-facing systems must be scanned weekly with an authenticated vulnerability scanner (Qualys, Tenable, Rapid7); internal systems monthly. CVSS 9.0+ findings on internet-facing assets must be remediated within 24 hours; CVSS 7.0–8.9 within 72 hours; CVSS 4.0–6.9 within 30 days. A software inventory covering all deployed OS versions, runtimes, and libraries must be maintained and queryable in real time so impact assessment for new CVEs can be completed within 30 minutes. Exploit telemetry from EDR and network sensors must feed a detection rule pipeline (Sigma, Snort, YARA) that is updated within 12 hours of published IoCs. Organisations must participate in coordinated vulnerability disclosure programmes and have a CVD policy published at security.company.com. Attack surface reduction controls (disabling unneeded services, removing debug interfaces) must be applied to all systems as part of every quarterly hardening review.`,
  },
  {
    topic: 'Zero-Trust Network Access Architecture',
    policy_text: `Zero Trust (NIST SP 800-207) eliminates the concept of an implicit trusted network perimeter and requires continuous, explicit verification for every access request. The foundational tenets are: verify explicitly (authenticate and authorise every request with all available data points), use least-privilege access (just-in-time, just-enough access), and assume breach (design as if adversaries are already in the network). Network microsegmentation must be implemented so that each application tier (web, application, database) resides in a separate microsegment with stateful firewall policies permitting only required traffic flows; east-west traffic must be inspected by a next-generation firewall or service mesh mTLS policy. User access to applications must be brokered via a ZTNA proxy (Zscaler Private Access, Cloudflare Access, or equivalent) that evaluates device health posture (patch level, AV status, disk encryption) before granting access; sessions must be re-evaluated every 15 minutes. Privileged access must require hardware FIDO2 tokens for step-up authentication. Service-to-service calls must use short-lived X.509 certificates issued by an internal PKI with a maximum 24-hour validity. DNS resolution for internal services must be provided only over encrypted channels (DoH/DoT) and all queries must be logged. Lateral movement detection must alert on any east-west connection that was not part of a declared application dependency map. The zero-trust posture must be reviewed in a quarterly architectural review board session.`,
  },
  {
    topic: 'OAuth Token Hijacking and Session Security',
    policy_text: `OAuth 2.0 and OpenID Connect tokens are high-value targets because they grant access without requiring passwords. Access tokens must have a maximum lifetime of 15 minutes; refresh tokens must be rotated on every use (RFC 6749 rolling refresh) and have a maximum absolute lifetime of 7 days for high-sensitivity applications. Refresh token rotation must be enforced at the authorisation server; any attempt to reuse a revoked refresh token must immediately invalidate the entire token family (detect and revoke all descendant tokens). Tokens must be stored in memory only — never in localStorage or sessionStorage — and transmitted exclusively over TLS 1.2+. The authorisation code flow with PKCE (RFC 7636) is mandatory for all public clients; the implicit flow is prohibited. Redirect URIs must be exact-match validated; open redirectors are prohibited. All issued tokens must be bound to a client TLS certificate (mTLS token binding, RFC 8705) for backend services. Token introspection endpoints must be protected and rate-limited. ID tokens must be validated for iss, aud, exp, and iat claims before trust is extended. Anomalous token use (multiple geographic locations for the same session, unexpected client IDs) must trigger token revocation and re-authentication prompts. OAuth application registrations must be reviewed quarterly; dormant applications not used in 90 days must be automatically deregistered.`,
  },
  {
    topic: 'CI/CD Pipeline Security and Poisoning Prevention',
    policy_text: `Compromised CI/CD pipelines can inject malicious code into every downstream deployment — making pipeline security a tier-1 security control. All pipeline definitions (Jenkinsfile, .github/workflows, .gitlab-ci.yml) must be stored in version control with branch protection and require two approvals for changes. Pipeline execution must run in ephemeral, single-use build environments that are destroyed after each job; persistent build agents are prohibited for production pipelines. All build tools, base images, and CI runner images must be pinned to digest-verified versions; floating tags (":latest") are prohibited. Secrets must never be embedded in pipeline YAML; all secrets must be injected at runtime from a secrets vault with short-lived dynamic credentials. Automated SCA, SAST, and container image scanning steps are mandatory and must gate the pipeline — a CRITICAL finding blocks promotion. Signed commits must be enforced on the default branch; the CI system must reject unsigned commits. SLSA (Supply Chain Levels for Software Artefacts) Level 2 minimum is required: provenance must be generated and attached to every build artefact, and the build platform must be non-falsifiable. Production deployments must be triggered only by the CI system — direct "git push to prod" workflows are prohibited. Pipeline activity logs must be shipped to the SIEM within 60 seconds of each event for anomaly detection.`,
  },
  {
    topic: 'Data Loss Prevention Policy Framework',
    policy_text: `A comprehensive DLP programme classifies sensitive data, monitors its movement, and enforces policies to prevent unauthorised disclosure. All data must be classified into four tiers — Public, Internal, Confidential, and Restricted — with automated classification labels applied by the DLP engine based on content inspection (regex patterns for SSN, credit card PANs, IBAN numbers, passport numbers; NLP classifiers for intellectual property and legal privilege). DLP policies must be enforced at four control points: email gateway (block Restricted data from leaving corporate email), web proxy (block upload of Restricted data to non-approved cloud services), endpoint agent (block copy-paste of Restricted data to unapproved applications, encrypt clipboard contents), and cloud CASB (monitor and control sharing of Confidential/Restricted data in sanctioned SaaS platforms). False-positive thresholds must be reviewed monthly; any policy producing more than 10% false positives must be tuned before deployment. End-users must receive real-time notifications when a DLP policy blocks or alerts on their action, with a business-justification override workflow that routes to their manager for approval and is logged for 7 years. DLP coverage metrics (percentage of data stores with active monitoring) must be reported quarterly to the CISO and board. Data retention policies must be programmatically enforced — Restricted data that exceeds its retention period must be automatically purged with certificate-of-destruction logging.`,
  },
  {
    topic: 'Privileged Access Management and Credential Vaulting',
    policy_text: `Privileged accounts — domain administrators, root accounts, service accounts with broad permissions, and cloud IAM power users — represent the highest-risk credential tier and must be governed under a dedicated PAM programme. All privileged credentials must be stored in an enterprise PAM vault (CyberArk, HashiCorp Vault, Delinea) with automatic rotation on a schedule not exceeding 30 days for human accounts and 7 days for service accounts. Just-in-time (JIT) access must be enforced: privileged access must be requested through a ticketed workflow, granted for a time-bounded session (max 4 hours), and automatically revoked at session expiry. All privileged sessions must be recorded (keystroke and screen) and the recordings must be stored immutably for a minimum of 12 months. Shared generic accounts ("administrator", "root") must be eliminated or vaulted with individual checkout logging so every session is attributable to a named individual. Break-glass accounts must be double-sealed (requiring two senior engineers to authorise), and their use must automatically page the CISO and trigger a post-use review within 4 hours. Service account credentials must never be embedded in application code or configuration files; workload identity federation (AWS IRSA, GCP Workload Identity, Azure Managed Identity) must be used wherever supported. Quarterly access reviews must attest all privileged accounts; any account not attested within 14 days of review deadline must be automatically disabled.`,
  },
  {
    topic: 'Endpoint Detection and Response Deployment Standards',
    policy_text: `EDR provides the primary telemetry and response capability for endpoint threats. Full EDR agent deployment is mandatory on 100% of managed endpoints (Windows, macOS, Linux servers) and must achieve ≥98% coverage with zero tolerance for gaps on Tier-1 assets (domain controllers, file servers, jump hosts). EDR must be configured in prevent mode — not just detect mode — and policy exceptions must be documented, approved by the security team, and reviewed quarterly. Detection rules must be tuned to a false-positive rate below 5% on production workloads to prevent alert fatigue. Automated response actions must include: network isolation of a host within 60 seconds of a CRITICAL detection (ransomware behaviour, C2 beacon, credential dumping), killing the offending process tree, and preserving a memory dump for forensics. Threat hunting exercises must be conducted monthly using the MITRE ATT&CK framework as a guide; at minimum two adversary simulation scenarios must be run per quarter (purple team). EDR telemetry must be forwarded to the SIEM in real time for correlation. Agent updates must be deployed within 24 hours of a content update release; outdated agents (>72 hours behind) must auto-notify the endpoint team. Unmanaged devices connecting to the network must be detected by NAC and quarantined to a remediation VLAN until the EDR agent is installed and validated.`,
  },
  {
    topic: 'Network Lateral Movement Prevention',
    policy_text: `Lateral movement — an adversary pivoting from an initial beachhead to higher-value targets — must be detected and blocked through a combination of network architecture controls and real-time analytics. All inter-VLAN traffic must traverse a stateful next-generation firewall or microsegmentation policy; default-deny rules with explicit allowlists are mandatory. Active Directory must enforce tiering: Tier 0 (domain controllers, PKI), Tier 1 (servers), and Tier 2 (workstations) must be network-isolated so that a compromised workstation cannot directly reach a domain controller. Windows authentication protocols: NTLMv1 and NTLMv2 must be disabled in favour of Kerberos; SMB signing must be mandatory on all servers. WMI and PsExec-style remote execution must be blocked between workstations via host-based firewall GPO. Detection rules in the SIEM must alert on: port scanning from internal hosts (>10 ports probed per second), SMB connections from workstations to more than 5 other workstations within 60 seconds, authentication with the same credential to more than 10 hosts in 5 minutes. Honeypots and honeytokens (fake admin credentials, fake file shares) must be deployed in each VLAN segment; any interaction with a honeypot must trigger an immediate P1 incident. Deception technology must be reviewed and updated quarterly to ensure honeypot credibility. Network traffic baselines must be established and anomaly detection must alert on any host communicating with a new internal subnet for the first time outside of a change-management window.`,
  },
  {
    topic: 'Incident Response and Business Continuity Planning',
    policy_text: `An effective incident response programme transforms a potentially catastrophic breach into a managed, recoverable event. All organisations must maintain a written IRP (Incident Response Plan) aligned to NIST SP 800-61r2 covering the phases: Preparation, Detection & Analysis, Containment, Eradication, Recovery, and Post-Incident Activity. The IR retainer must be tested in a full-scale tabletop exercise at least twice per year; one exercise must simulate a ransomware scenario and one must simulate a nation-state APT intrusion. Defined SLAs: time-to-detect (TTD) must be ≤ 4 hours for CRITICAL incidents; time-to-contain (TTC) must be ≤ 2 hours from declaration. Communication trees must be documented for all severity levels, including legal counsel, PR/communications, executive leadership, and regulatory notification obligations (GDPR 72-hour window, SEC 4-day material cybersecurity incident rule). Business Continuity Plans must define RTO (Recovery Time Objective) and RPO (Recovery Point Objective) for each critical system, tested annually; Tier-1 systems must achieve RTO ≤ 4 hours and RPO ≤ 1 hour. Forensic evidence collection procedures must be documented: memory acquisition before shutdown, chain-of-custody forms, write-blockers for disk imaging. All IR activity must be logged in a case management system (ServiceNow, Jira Service Management) with timestamped entries to support legal proceedings. A Post-Incident Review (PIR) must be completed within 5 business days of closure; root-cause findings and corrective actions must be tracked to completion with defined owners and deadlines.`,
  },
];

// ── Seeding loop ──────────────────────────────────────────────────────────────

async function seed() {
  console.log(`\nNEXUS-SHIELD Compliance Policy Seeder`);
  console.log(`Target: ${SUPABASE_URL}`);
  console.log(`Policies: ${COMPLIANCE_POLICIES.length}`);
  console.log(`Embedding model: gemini-embedding-001 (768 dim via outputDimensionality)\n`);

  let inserted    = 0;
  let rlsBlocked  = 0;
  let errors      = 0;
  const sqlRows   = []; // collected when RLS blocks the anon key

  for (let i = 0; i < COMPLIANCE_POLICIES.length; i++) {
    const { topic, policy_text } = COMPLIANCE_POLICIES[i];
    process.stdout.write(`  [${String(i + 1).padStart(2, '0')}/${COMPLIANCE_POLICIES.length}] ${topic} ... `);

    try {
      // Compute 768-dim embedding via Gemini v1 REST
      const embedding = await getEmbedding(policy_text);

      // Attempt direct insert via anon key
      const { error } = await supabase
        .from('compliance_policies')
        .insert({ topic, policy_text, embedding });

      if (!error) {
        console.log('OK');
        inserted++;
      } else if (error.code === '42501' || error.message.includes('row-level security')) {
        // RLS blocks anon inserts — collect for SQL file fallback
        const safeText = policy_text.replace(/'/g, "''");
        const vecLiteral = `[${embedding.join(',')}]`;
        sqlRows.push(
          `INSERT INTO compliance_policies (topic, policy_text, embedding)\n` +
          `VALUES ('${topic}', '${safeText}', '${vecLiteral}');`,
        );
        console.log('RLS (→ SQL file)');
        rlsBlocked++;
      } else {
        console.log(`FAIL — ${error.message}`);
        errors++;
      }
    } catch (err) {
      console.log(`ERROR — ${err.message}`);
      errors++;
    }

    // Brief pause to respect Gemini embedding API rate limits
    if (i < COMPLIANCE_POLICIES.length - 1) {
      await new Promise(r => setTimeout(r, 300));
    }
  }

  console.log(`\n──────────────────────────────────────────`);
  console.log(`Results: ${inserted} inserted, ${rlsBlocked} queued for SQL, ${errors} errors`);

  // Write SQL fallback file when RLS blocked direct inserts
  if (sqlRows.length > 0) {
    const { writeFileSync } = await import('fs');
    const sql =
      `-- NEXUS-SHIELD compliance_policies seed\n` +
      `-- Run this in Supabase SQL Editor (Project → SQL Editor → New Query)\n` +
      `-- It executes as Postgres admin, bypassing Row-Level Security.\n\n` +
      sqlRows.join('\n\n') + '\n';
    writeFileSync('seed-compliance.sql', sql, 'utf8');
    console.log(`\nSQL seed file written: seed-compliance.sql`);
    console.log(`→ Open Supabase Dashboard → SQL Editor → paste & run the file.`);
    console.log(`  (Or: grant INSERT to the anon role and re-run this script.)`);
  }

  if (errors > 0) {
    console.log('\nSome rows encountered unexpected errors. Check output above.');
    process.exit(1);
  } else {
    console.log('\nEmbedding generation complete.');
    process.exit(0);
  }
}

seed();
