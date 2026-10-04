# ForgeGuard Terms & Conditions of Use

**Effective Date:** October 2026

Welcome to **ForgeGuard**, developed by the **SwarmForge Team**. By using ForgeGuard (including its CLI, embedded SOC dashboard, SAST AST engine, STRIDE threat modeler, and autonomous patch synthesizer), you agree to the following Terms & Conditions.

---

## 1. Permitted & Authorized Use
- ForgeGuard is designed strictly for **defensive security auditing, architectural threat modeling, and code remediation**.
- You agree to use ForgeGuard only on source code repositories, systems, and environments for which you have explicit legal authorization to inspect, analyze, and modify.

---

## 2. Automated Code Remediation & Safety Verification
- ForgeGuard incorporates strict **AST Pre-Commit Gates** to verify Python syntax validity before writing modified files to disk, and automatically creates backup snapshots in `.forgeguard_backups/`.
- While ForgeGuard aims for deterministic, zero-regression remediation, all synthesized patches are provided to assist software developers. You are encouraged to review, test, and run your CI/CD verification suites before deploying patched artifacts to production environments.

---

## 3. Disclaimer of Warranties ("AS-IS")
ForgeGuard is provided under the **MIT License** on an `"AS IS"` and `"AS AVAILABLE"` basis, without warranties of any kind, whether express or implied, including but not limited to the implied warranties of merchantability, fitness for a particular purpose, or non-infringement.

---

## 4. Limitation of Liability
In no event shall the authors, contributors, or copyright holders of ForgeGuard be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, loss of data, service interruption, or system downtime) arising out of the use or inability to use this software.

---

## 5. Intellectual Property & Open Source Licensing
- The ForgeGuard core engine and tools are open-sourced under the **MIT License**.
- You are free to inspect, modify, fork, and distribute ForgeGuard in accordance with the MIT License terms outlined in the `LICENSE` file.

---

## 6. Modifications to Terms
We reserve the right to modify or update these Terms & Conditions as ForgeGuard evolves. Continued use of the software constitutes acceptance of any revised terms.

---

## 7. Contact Information
For legal inquiries, licensing questions, or enterprise agreements:
- **Email:** `legal@swarmforge.ai`
- **Security & Vulnerability Reports:** `security@swarmforge.ai`
