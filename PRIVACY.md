# ForgeGuard Privacy Policy & Zero-Data-Retention Commitment

**Last Updated:** October 2026

At **ForgeGuard (SwarmForge)**, we recognize that your source code, architecture diagrams, and security vulnerabilities represent your organization's most sensitive assets. This Privacy Policy details our strict local-first, zero-data-retention architecture.

---

## 1. Core Principles

1. **Local-First Processing by Default**:
   - All Abstract Syntax Tree (AST) lexical parsing, taint-flow analysis, rule evaluations, and code patch synthesis execute **100% locally** within your runtime environment (developer workstation or CI/CD runner).
   - Your source code never leaves your infrastructure during default static analysis.

2. **Zero Code Retention & Zero AI Model Training**:
   - We do not store, index, or retain customer source code.
   - Your proprietary code and vulnerability findings are **never** used to train, fine-tune, or improve public foundation models.

3. **Opt-In Ephemeral LLM Inference**:
   - When external LLM inference bridges (e.g., Featherless.ai, OpenAI-compatible APIs) are explicitly configured via API keys, requests are sent via encrypted HTTPS strictly for real-time contextual analysis and discarded immediately post-response.
   - An offline heuristic synthesizer is built into ForgeGuard for complete air-gapped deployments.

4. **Local Backup & Disaster Recovery Isolation**:
   - Backup snapshots created prior to automated remediation (`.forgeguard_backups/`) reside exclusively on your local filesystem under your direct access control.

---

## 2. Telemetry & Analytics

- ForgeGuard does **not** collect telemetry, user analytics, tracking cookies, or diagnostic identifiers.
- The embedded SOC dashboard (`http://localhost:8899`) operates purely on a local loopback server without third-party tracking scripts.

---

## 3. Compliance Alignment

ForgeGuard is architected to align with major enterprise privacy and cybersecurity frameworks:
- **SOC 2 Type II** (Confidentiality & Privacy Trust Principles)
- **ISO/IEC 27001 / 27701** (Information Security & Privacy Information Management)
- **DPDP Act 2023** (Digital Personal Data Protection Act - Zero unnecessary data collection & local data minimization)
- **GDPR / CCPA** (Data minimization and local data sovereignty)

---

## 4. Contact & Inquiries

For privacy questions or enterprise security reviews, contact:
- **Email:** `privacy@swarmforge.ai`
- **Security Team:** `security@swarmforge.ai`
