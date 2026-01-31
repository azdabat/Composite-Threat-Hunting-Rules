# 02_ScheduledTask_Persistence — Cousin-Based Ecosystem (Composite Hunts)

This folder contains a **Scheduled Task Persistence cousin-pack** inside the broader **LOLBins Composite HuntPack**.

These rules are not duplicates.

They are deliberately engineered as a **cousin-based ecosystem**:

> Each rule anchors on a different *truth surface* of the same attacker objective,  
> so that if an adversary bypasses one telemetry domain, the cousin still catches the persistence.

Scheduled task persistence is one of the highest-value primitives in modern intrusion chains because it enables:

- Silent re-execution after reboot/logon  
- SYSTEM-level persistence  
- LOLBin-based payload staging (rundll32, PowerShell, mshta, etc.)  
- API/COM task creation that avoids `schtasks.exe` entirely  

This pack exists to cover the full persistence surface with **minimum truth + reinforcement + scoring + hunter directives**, aligned with your Composite Detection Framework.

---

## Threat Model — Attacker Intent

Attackers use Scheduled Tasks to achieve:

- **Persistence** (T1053.005)
- **Privilege escalation** (Run as SYSTEM)
- **Defense evasion** (no new services, blends into Windows task noise)
- **Proxy execution** via trusted binaries (rundll32/script engines)
- **Living-off-the-land execution chains**

The key operational reality:

> You cannot detect Scheduled Task persistence reliably with one monolithic rule.  
> You need cousins across different truth domains.

---

# Rule Ecosystem Overview (Cousins)

| Rule | Truth Anchor | What It Detects | Why It Exists |
|------|-------------|----------------|--------------|
| **02A** | `schtasks.exe` execution | Task creation/modification with dangerous `/tr` actions | Catches classic scheduled task abuse via command-line tooling |
| **02B** | TaskCache registry materialization | Silent task persistence via COM/API (no schtasks.exe) | Covers the modern blind spot: API-driven persistence |
| **05A (Legacy/Archive)** | Earlier schtasks composite | Older version of classifier logic | Kept only for reference or migration |

---

# 02A — ScheduledTask Abuse (RUNDLL-Aware Classifier)

**File:** `02A_L2_ScheduledTask_Abuse_RUNDLL_AWARE_Classifier.kql`

### Minimum Truth (Anchor)
A scheduled task is created or modified via:

- `schtasks.exe /create`
- `schtasks.exe /change`

This is the classic persistence entrypoint.

### Reinforcement (Convergence)
The task action (`/tr`) is classified into execution primitives:

- Rundll32 Script/Protocol Handler abuse  
- Rundll32 Remote DLL load (UNC/WebDAV/URL)  
- Rundll32 INF ProxyExec (`LaunchINFSection`)  
- Encoded PowerShell or script engines  
- Writable path execution (`Temp`, `Public`, `ProgramData`)  

### Why This Rule Exists
This is the **high-fidelity task persistence classifier**.

It answers:

- *What task was created?*
- *What does it execute?*
- *Is the `/tr` action an execution primitive?*
- *Is this persistence or normal IT automation?*

### Analyst Outcome
A hunter receives:

- Parsed TaskName (`/tn`)
- Parsed TaskRun (`/tr`)
- Category label (execution model)
- RiskScore + severity
- Explicit pivots into rundll32 execution hunts

---

# 02B — TaskCache Registry Persistence (Silent Task Cousin)

**File:** `02B_L3_TaskCache_SilentTask_Persistence.kql`

### Minimum Truth (Anchor)
A registry write occurs in Scheduled TaskCache surfaces:

- `...\Schedule\TaskCache\Tree`
- `...\Schedule\TaskCache\Tasks`

### Why This Matters (Blind Spot Fix)

Attackers increasingly create tasks via:

- COM APIs  
- PowerShell scheduled task cmdlets  
- WMI interfaces  
- Implant frameworks  

Meaning:

> No `schtasks.exe` execution exists.

But Windows still must materialize the persistence:

- TaskCache registry keys are written
- GUID-backed task definitions appear

### Reinforcement Signals
This cousin adds scoring based on:

- Dangerous primitives in registry value data  
- Base64 payload stashes  
- Network indicators (URL/domain/IP)  
- User-writable execution paths  
- Rare/untrusted writer process  
- Large registry blobs (payload storage)

### Why This Rule Exists
This is the **modern scheduled task persistence truth source**.

It detects persistence even when:

- `schtasks.exe` is never used
- The attacker is “fileless”
- Task creation is done through APIs

---

# 05A — Legacy Scheduled Task Rule (Archive Cousin)

**File:** `05A_L2_ScheduledTask_...`

This file is an older iteration of the scheduled task composite.

### Recommendation
- Keep only if you want historical evolution
- Otherwise rename to:
- 
05A_Legacy_ScheduledTask_Classifier_v1.kql

  Or remove once `02A` is confirmed final.

---

# How These Rules Work Together (Cousin Logic)

Scheduled task persistence has two major attacker paths:

---

## Path 1 — Tool-Based Persistence

Attacker runs:

- `schtasks.exe /create ...`
- `schtasks.exe /change ...`

➡️ **Caught by 02A**

---

## Path 2 — API / Silent Persistence

Attacker uses:

- COM task scheduler APIs  
- PowerShell `Register-ScheduledTask`
- Implant frameworks

No schtasks binary.

➡️ **Caught by 02B**

---

## Operational Truth

> These rules are cousins, not copies.

They cover the same persistence objective through different telemetry truths.

If one fails, the cousin survives.

That is the core of the **cousin-based ecosystem** model.

---

# Recommended Workflow for Hunters

1. **02A fires**
   - Task creation detected
   - Action classified
   - Pivot into execution-phase LOLBin hunts

2. **02B fires**
   - Silent task persistence surfaced
   - Pull Task GUID + XML definition
   - Scope across fleet for same task artifact

3. Correlate both
   - Same host + same timeframe
   - Same writer process
   - Same payload path

---

# MITRE ATT&CK Mapping

- **T1053.005** — Scheduled Task/Job: Scheduled Task  
- **T1218.011** — Rundll32 Proxy Execution  
- **T1027** — Obfuscated/Encoded Payloads  
- **T1105** — Ingress Tool Transfer  
- **T1547** — Persistence Execution Surfaces  

---

# Philosophy Alignment (Composite Framework)

These rules implement:

- **Minimum Truth Anchors**
- **Reinforcement (Convergence, not redefinition)**
- **Noise Suppression**
- **Risk Scoring**
- **Hunter Directives**
- **Cousin-Based Coverage**

This folder is a persistence ecosystem, not a single alert.

---

## Status

**Production-ready composite hunts (tenant tuning expected).**

This is the scheduled task persistence slice of your larger:

**Production-READY Composite Threat Hunting Rules Framework**
