## Validation & Attack Scenarios

This rule has been validated against OTRF Mordor Datasets and simulated against two distinct lateral movement techniques to ensure high-fidelity detection. The composite logic differentiates between **Artifact-Based** (Critical) and **Fileless** (High) attacks.

### Scenario 1: Artifact-Based Lateral Movement (PsExec Style)
**Technique:** T1543.003 (Service Creation) + T1021.002 (SMB/Admin Shares)  
**Attack Chain:**
1.  **Network:** Attacker connects via SMB (Port 445).
2.  **Staging:** Attacker drops `PSEXESVC.exe` into the `\ADMIN$` share.
3.  **Execution:** Attacker starts a service pointing to the dropped binary.

**Detection Output (CRITICAL):**
> **Trigger:** All 3 signals matched (Network + Service + File Drop).
>
> **Hunter Directive:**
> `ACTION: CRITICAL suspected SMB/service lateral movement | CONTEXT: High (SMB/RPC + Service + Drop) | Sources=["10.10.10.5"] | ServiceProcs=["PSEXESVC.exe"] | Dropped=["PSEXESVC.exe"]`

---

### Scenario 2: Fileless Lateral Movement (Impacket/SmbExec Style)
**Technique:** T1543.003 (Service Creation) + Living off the Land  
**Attack Chain:**
1.  **Network:** Attacker connects via SMB (Port 445).
2.  **Staging:** No file is dropped to disk (or is deleted instantly).
3.  **Execution:** Attacker starts a service executing a command directly (e.g., `cmd.exe /c ...`).

**Detection Output (HIGH):**
> **Trigger:** 2 signals matched (Network + Service). The lack of a file drop lowers confidence slightly but maintains High Severity due to the anomaly.
>
> **Hunter Directive:**
> `ACTION: HIGH suspected SMB/service lateral movement | CONTEXT: Medium (SMB/RPC + Service) | Sources=["192.168.1.99"] | ServiceProcs=["cmd.exe"] | Dropped=[]`
