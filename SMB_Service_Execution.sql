// ============================================================================
// COMPOSITE HUNT (L2 / L2.5): SMB + Service Execution (PsExec / Impacket style)
// AUTHOR: Ala Dabat
// MITRE: T1021.002 (SMB/Windows Admin Shares), T1543.003 (Windows Service)
// DATA: DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents (MDE / Sentinel)
// ---------------------------------------------------------------------------
// WHY COMPOSITE (Framework):
//   Baseline Truth  : A new/odd service process is created by services.exe (execution step)
//   Reinforcement   : Correlated inbound SMB/RPC (445/135) and/or admin-share write (.exe/.dll/.sys)
//   Noise Control   : Suppress common service hosts + allow optional dropped-file requirement gating
//
// DESIGN INTENT:
//   - Victim-perspective: detect the target host receiving SMB/RPC then executing via service.
//   - Supports fileless-ish variants (Impacket) by allowing Service+Network even without file drop.
// ============================================================================

let Lookback = 3d;
let CorrWindow = 15m;

// Admin share indicators (writes often show these in FolderPath or UNC-like strings)
// Note: schema varies; we use broad contains on share markers.
let HighRiskShareMarkers = dynamic(["\\ADMIN$\\","\\C$\\","\\IPC$\\","\\admin$\\","\\c$\\","\\ipc$\\"]);

// Common dropped artifact extensions for lateral execution staging
let DropExt = dynamic([".exe",".dll",".sys",".bat",".ps1",".vbs",".js",".hta"]);

// Known common service children (suppress obvious noise; tune per tenant)
let CommonServiceChildren = dynamic([
  "svchost.exe","dllhost.exe","taskhostw.exe","taskhost.exe","conhost.exe",
  "msmpeng.exe","senseir.exe","searchindexer.exe","tiworker.exe"
]);

// Optional: allowlist service installs by known management tools (tune)
let AllowInitiators = dynamic([
  "ccmexec.exe","sccmagent.exe","intuneManagementExtension.exe","taniumclient.exe",
  "qualysagent.exe","nxlog.exe"
]);

// -------------------------
// Signal A: inbound SMB/RPC (victim perspective)
// -------------------------
let InboundSMBRPC =
DeviceNetworkEvents
| where Timestamp >= ago(Lookback)
| where ActionType == "InboundConnectionAccepted"
| where LocalPort in (445, 135)
| where isnotempty(RemoteIP)
| project DeviceId, SMBTime=Timestamp, SourceIP=RemoteIP, LocalPort;

// -------------------------
// Signal B: suspicious admin-share write (optional reinforcement)
// -------------------------
let AdminShareWrites =
DeviceFileEvents
| where Timestamp >= ago(Lookback)
| where tostring(FolderPath) has_any (HighRiskShareMarkers)
| where isnotempty(FileName)
| extend LowerName = tolower(FileName)
| where LowerName has "." and (LowerName endswith_any (DropExt))
| project DeviceId, WriteTime=Timestamp, DroppedFile=FileName, DroppedPath=FolderPath;

// -------------------------
// Baseline Truth: service execution on victim
// - services.exe spawning an uncommon child is a strong "execution" anchor.
// -------------------------
let ServiceSpawn =
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where InitiatingProcessFileName =~ "services.exe"
| where not(tolower(FileName) in~ (CommonServiceChildren))
| where not(tolower(InitiatingProcessFileName) in~ (AllowInitiators))
| extend SvcCmd = tostring(ProcessCommandLine)
| project DeviceId, DeviceName, SvcTime=Timestamp, SvcProc=FileName, SvcCmd, AccountName;

// -------------------------
// Correlate: Service spawn + inbound SMB/RPC + optional admin-share write
// -------------------------
ServiceSpawn
| join kind=inner (InboundSMBRPC) on DeviceId
| where SMBTime between ((SvcTime - CorrWindow) .. SvcTime)
| join kind=leftouter (AdminShareWrites) on DeviceId
| where isempty(WriteTime) or (WriteTime between ((SvcTime - CorrWindow) .. SvcTime))
| summarize
    Time = min(SvcTime),
    TargetHost = any(DeviceName),
    SourceIPs = make_set(SourceIP, 10),
    Ports = make_set(LocalPort, 5),
    ServiceProcesses = make_set(SvcProc, 10),
    ServiceCmds = make_set(SvcCmd, 10),
    DroppedFiles = make_set(DroppedFile, 10),
    DroppedPaths = make_set(DroppedPath, 10),
    Accounts = make_set(AccountName, 10)
  by DeviceId
| extend HasDrop = iif(array_length(DroppedFiles) > 0, 1, 0)
| extend RiskScore =
      0
    + 60                                   // baseline truth: service execution after inbound SMB/RPC
    + iif(HasDrop == 1, 25, 0)             // strong reinforcement: file staged via admin share
    + iif(array_length(SourceIPs) >= 2, 5, 0) // multiple sources (often wormy / operator hopping)
| extend Severity = case(
    RiskScore >= 85, "CRITICAL",
    RiskScore >= 60, "HIGH",
    "MEDIUM"
)
| extend Confidence = iif(HasDrop==1, "High (SMB/RPC + Service + Drop)", "Medium (SMB/RPC + Service)")
| extend HunterDirective = strcat(
    "ACTION: ", Severity, " suspected SMB/service lateral movement | ",
    "CONTEXT: ", Confidence,
    " | Sources=", tostring(SourceIPs),
    " Ports=", tostring(Ports),
    " | ServiceProcs=", tostring(ServiceProcesses),
    " | ",
    "PIVOT: On target host, inspect service install artifacts (System 7045 if available), ",
    "review services.exe lineage, search for dropped payloads in ", tostring(DroppedPaths),
    ". On source IPs, pivot to remote execution tooling (psexec/impacket/winrm)."
)
| project
    Time,
    Severity,
    RiskScore,
    TargetHost,
    SourceIPs,
    Ports,
    Accounts,
    ServiceProcesses,
    ServiceCmds,
    DroppedFiles,
    DroppedPaths,
    HunterDirective
| order by RiskScore desc, Time desc
