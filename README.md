NOTE: 
My rules are logically production-safe, but final noise tuning requires tenant telemetry and admin workflow context. Without live systems, I validate correctness and attack-truth — operational calibration comes after deployment

# Threat Hunting Philosophy & Detection Design

**Author:** Ala Dabat  
**Focus:** Practical, adversary-informed threat hunting for real SOC environments  
**Audience:** L2 / L2.5 Threat Hunters, Detection Engineers, Security Leads  

---

## Why This Repository Exists

Most SOCs struggle with threat hunting not because they lack tools, but because:

- Detections are **over-engineered**
- Behavioural chains are **forced where they are not required**
- Analysts are overwhelmed by **noise disguised as intelligence**
- Rules are written without regard for **SOC operating reality**

This repository documents a **deliberate, operationally grounded methodology** for threat hunting that:

- Scales to real SOC teams
- Preserves signal fidelity
- Reduces analyst fatigue
- Applies behavioural correlation **only when the attack requires it**

---

## Core Philosophy (TL;DR)

> **Start with the minimum truth required for the attack to exist.**  
> Everything else is reinforcement — not dependency.

If the baseline truth is not met, the attack **is not real**.

---

## Detection Maturity Model Used

### 1. Reductive Baseline (Truth First)

Every attack technique has a **minimum condition that must be true**.

If that condition is not met, the detection should not exist.

**Examples:**
- LSASS credential theft → *LSASS must be accessed*
- Kerberoasting → *Service tickets must be requested using weak encryption*
- OAuth abuse → *A cloud app must request high-risk scopes*

This prevents speculative or assumption-driven hunting.

---

### 2. Composite L2 / L2.5 Hunts (Default)

Most attacks do **not** require full behavioural chains.

Instead, this repository focuses on **Composite Hunts** that:
- Group **related high-signal indicators**
- Prefer **single telemetry sources** where possible
- Use minimal joins only when unavoidable

This is where **most effective threat hunting lives**.

---

### 3. Reinforcement (Confidence, Not Dependency)

Once baseline truth is met, confidence is increased using:
- parent / child execution context
- suspicious paths or arguments
- network proximity
- rarity / prevalence

Reinforcement:
- improves fidelity
- reduces noise
- **never defines the attack**

---

### 4. Behavioural Chains (Used Sparingly)

Behavioural correlation is used **only when the attack cannot exist without it**.

**Example:** DLL sideloading  
A DLL drop alone is benign.  
A DLL load alone is benign.  
The attack is only true when **both occur together**.

---

## Composite Threat Hunt Portfolio

This repository is organised around **Composite Hunts** covering the most critical attack surfaces across endpoint, identity, and cloud environments.

### Implemented & Active Composite Rules

| Attack Surface | Composite Hunt | MITRE | Why It Matters |
|---------------|---------------|-------|----------------|
| **Credential Access** | **LSASS Access / Dump Attempts** | T1003.001 | Core SOC expectation; high signal, low noise |
| **Credential Access** | **NTDS.dit / AD Database Access** | T1003.003 | Domain compromise precursor |
| **Credential Access** | **Kerberoasting (Weak Encryption)** | T1558.003 | Detects RC4 / 0x17 downgrade abuse |
| **Persistence** | **WMI Event Subscription & Consumer** | T1546.003 | Fileless persistence via `scrcons.exe` |
| **Defense Evasion** | **LOLBin Proxy Execution** | T1218 | `rundll32`, `regsvr32`, `mshta` abuse |
| **Defense Evasion** | **DLL Sideloading (Minimal Chain)** | T1574.002 | Correlation only where structurally required |
| **Lateral Movement** | **SMB / Named Pipe Execution** | T1021.002 | PsExec-style behaviour |
| **Privilege Escalation** | **Account Manipulation (User / Group Changes)** | T1098 | Persistence, audit-critical |
| **Exfiltration Prep** | **Archive + Staging (Smash & Grab)** | T1560 | Data staging before exfiltration |
| **Cloud Identity** | **OAuth Illicit App Consent** | T1528 | Cloud persistence & data access |

---

### Planned Composite Additions (Roadmap)

These will follow the same reductive → composite → reinforcement model:

| Attack Surface | Planned Hunt | MITRE | Rationale |
|---------------|-------------|-------|-----------|
| Persistence | Service Creation / Modification Abuse | T1543.003 | High attacker ROI, low noise |
| Impact | Shadow Copy Deletion | T1490 | Ransomware precursor |
| Persistence | Scheduled Task Abuse (User Context) | T1053.005 | Common execution & persistence |
| Credential Access | SAM / Registry Hive Dump Attempts | T1003.002 | Complements LSASS coverage |
| Cloud Activity | OAuth Token Abuse / Graph API Misuse | T1528 | Post-consent cloud exploitation |

---

## Built-In Hunter Directives (Non-Negotiable)

Every composite hunt produces **guidance alongside results**, not after.

Each rule outputs a `HunterDirective` (or equivalent) that answers:

1. **Why** this fired (baseline truth)
2. **What** reinforces confidence
3. **What** to do next

**Example:**
> *HIGH: LSASS accessed by non-AV process using dump-related command line.  
> Action: Validate tool legitimacy, scope for lateral movement, escalate to L3.*

---

## Why Composite Hunts Matter (Example)

DLL sideloading is a technique that **cannot be confirmed from a single event**.

```mermaid
flowchart LR
    subgraph Noise
        A[DLL written to writable path]
        B[Signed binary loads DLL]
        A --> X[Too common alone]
        B --> X
    end

    subgraph Composite_Truth
        C[DLL written to Temp / Public]
        D[Signed binary loads DLL from same path]
        C --> E{Time Window Correlation}
        D --> E
        E --> F[High Confidence Sideload]
        F --> G[Reinforce with Context]
    end
```

## Rarity & Organisational Prevalence (Used Correctly)

Rarity is **not** a detection trigger.  
It is a **prioritisation and confidence amplifier**.

In this methodology, **detection is driven by attack truth**, not by how uncommon an event is.  
Organisational prevalence is applied **only after** the baseline condition of an attack has been met.

> **If the minimum truth of the attack is not satisfied, rarity is irrelevant.**  
> **If the minimum truth *is* satisfied, rarity helps decide urgency and scope.**

### How Rarity Is Applied

Rarity is used in three safe, SOC-real ways:

### 1. Command / Behaviour Prevalence  
**Question:** *How many hosts in this organisation perform this exact behaviour?*

- Low prevalence (1–2 hosts) → likely targeted activity  
- High prevalence (many hosts) → possible tooling, deployment, or admin activity  

This is used to **prioritise triage**, not suppress alerts.

### 2. Parent / Actor Prevalence  
**Question:** *Who normally performs this action in this environment?*

- LOLBins launched by unusual parents (e.g. Office, WMI, script engines)  
- Privileged actions executed by unexpected users or service accounts  

This often surfaces **contextual malice** even when the binary itself is common.

### 3. Burst / Radius Prevalence  
**Question:** *How widely and how fast did this appear?*

- Single host → targeted intrusion  
- Multiple hosts in a short window → automation, lateral movement, or policy abuse  

This is especially effective for persistence, service creation, and credential access.

### What Rarity Is *Not* Used For

- Rarity is **never** a hard filter  
- Rarity does **not** determine whether an alert exists  
- Dangerous actions (e.g. LSASS access, illicit OAuth grants) are **always surfaced**, regardless of prevalence  

### Design Principle

> **Rarity decides how fast we respond — not whether we respond.**

This ensures:
- High-risk behaviour is never suppressed
- Analysts are not flooded with low-value noise
- Targeted attacks stand out without brittle logic

Rarity strengthens detection — it never replaces understanding.
