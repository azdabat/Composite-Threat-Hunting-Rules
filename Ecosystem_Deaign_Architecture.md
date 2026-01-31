---

## Ecosystem Design (Composite Rule Architecture)

A core principle of the **Composite Detection Framework** is that high-fidelity threat hunting is not built from isolated rules.

It is built from **ecosystems**.

Modern intrusion tradecraft does not live inside single binaries, single events, or single detections.  
Attackers move across surfaces, phases, and telemetry domains.

This framework therefore organizes hunts into **ecosystem archetypes** — structured detection families designed for resilience, coverage, and correlation.

---

# 1. Cousin-Based Ecosystems  
### *(Same Objective → Different Truth Surfaces)*

A **Cousin-Based Ecosystem** is the highest-signal structure for persistence and execution primitives.

### Definition

> Multiple hunts detect the **same attacker objective**,  
> but each anchors on a different telemetry truth surface.

These rules are not duplicates.  
They are **cousins**:

- Same attacker goal  
- Different detection anchors  
- Designed for bypass resistance

### Example: Scheduled Task Persistence Cousin Pack

Attackers can register scheduled tasks through multiple methods:

- `schtasks.exe` execution  
- COM / API task registration  
- XML task import  
- Registry TaskCache materialization

A single rule cannot cover all truthfully.

So the ecosystem becomes:

| Cousin Rule | Truth Anchor | What It Catches |
|------------|-------------|----------------|
| Cousin A | `schtasks.exe /create` execution | Classic CLI-based task persistence |
| Cousin B | TaskCache registry materialization | Silent COM/API persistence bypass |
| Cousin C | XML import + writable path | Indirect persistence staging |

### Why This Matters

Attackers bypass one surface — not all.

Cousin ecosystems provide:

- Telemetry redundancy  
- Objective resilience  
- Minimum truth anchoring across domains  

### Best Use Cases

- Scheduled Task persistence  
- Service ImagePath persistence  
- Registry autoruns  
- WMI subscriptions  
- LOLBin proxy execution families

---

---

# 2. Attack-Surface Ecosystems  
### *(Same Domain → Many Behaviours)*

Not all ecosystems are cousins.

Some attacker domains are inherently broad:

- OAuth identity abuse  
- Command-and-Control channels  
- Driver abuse (BYOVD)  
- Cloud persistence surfaces

These are not one objective — they are many.

### Definition

> Multiple hunts cover different attacker behaviours  
> across a single complex attack surface.

These rules are unified because they live in the same operational plane.

### Example: OAuth Abuse Ecosystem

OAuth intrusion is not one technique:

- Consent grant persistence  
- Token replay  
- Refresh token abuse  
- Impossible travel + ASN drift  
- Service principal backdoors  

These are not cousins.

They are **surface variants** inside the identity plane.

### Example: C2 Channel Ecosystem

C2 is not one behaviour:

- Named pipe channels  
- DNS tunneling  
- HTTPS jitter beacons  
- Domain fronting  
- Slack/Telegram abuse  

Different objectives, same surface: **C2 transport layer**.

### Why This Matters

Attack surfaces require completeness, not redundancy.

Attack-Surface ecosystems provide:

- Domain-wide behavioural coverage  
- Modern tradecraft mapping  
- Telemetry plane specialization  

### Best Use Cases

- OAuth / Entra ID threat hunting  
- C2 detection frameworks  
- BYOVD driver ecosystems  
- Cloud control plane persistence

---

---

# 3. Chain-Based Ecosystems  
### *(Same Intrusion Chain → Different Phases)*

This is the highest tier ecosystem type.

Neither cousins nor surface suites.

These rules exist because attacks progress.

### Definition

> Multiple hunts detect different phases  
> of the same intrusion chain, designed to correlate.

This is where Composite Detection becomes **kill-chain aware**.

### Example: Ransomware Progression Ecosystem

A ransomware intrusion is not one event:

- Initial ingress tool transfer  
- Credential access  
- Lateral movement  
- Shadow copy deletion  
- Encryption impact  

These are:

- Not cousins (different objectives)
- Not one surface (multiple planes)

They are linked because:

> They represent attacker progression.

### Why This Matters

Chain ecosystems provide:

- Intrusion convergence detection  
- Escalation confidence  
- Phase correlation for IR readiness  

### Best Use Cases

- Ransomware kill-chain packs  
- Post-exploitation progression suites  
- APT intrusion staging frameworks  
- Multi-phase attack correlation hunts  

---

---

# Ecosystem Taxonomy Summary

| Ecosystem Type | What Links the Rules? | Example | Primary Value |
|--------------|------------------------|---------|--------------|
| **Cousin-Based** | Same objective, different truth anchors | Task persistence cousins | Telemetry resilience |
| **Attack-Surface** | Same domain, many behaviours | OAuth / C2 ecosystems | Surface completeness |
| **Chain-Based** | Same intrusion, different phases | Ransomware progression | Correlation + escalation |

---

# Naming Standard (Repository Structure)

To make ecosystems operational and hiring-manager readable:

### Cousin Packs (Objective Redundancy)
02_ScheduledTask_Persistence_CousinPack 03_Service_Persistence_CousinPack 04_RunKey_Persistence_CousinPack

  
### Attack-Surface Ecosystems (Domain Coverage)
C2_Channel_Ecosystem OAuth_IdentityPlane_Ecosystem BYOVD_DriverAbuse_Ecosystem


### Chain Ecosystems (Kill-Chain Correlation)
Ransomware_KillChain_Ecosystem InitialAccess_to_Impact_Ecosystem PostExploitation_Progression_Ecosystem

---

# Framework Rule Philosophy (Ecosystem-Aligned)

This is why Composite Hunts are not “one query alerts.”

Every ecosystem is engineered as:

- **Minimum Truth Anchor** (non-negotiable)  
- **Reinforcement Signals** (confidence, not dependency)  
- **Noise Suppression** (tenant survivability)  
- **Scoring + Severity** (analyst prioritization)  
- **Hunter Directives** (SOC-ready pivots)  
- **Ecosystem Membership** (rules designed to coexist)

---

**Composite Detection is not about writing more rules.**

It is about building ecosystems that attackers cannot bypass with one trick.

---
