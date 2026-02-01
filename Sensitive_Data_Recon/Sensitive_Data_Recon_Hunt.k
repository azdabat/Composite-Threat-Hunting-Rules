// ============================================================================
// L3_Sensitive_Data_Recon_Hunt_V4 (Risk-Based Secrets Recon) — Composite L3
// Author: Ala Dabat
// Data: DeviceProcessEvents (MDE / Sentinel)
// MITRE: T1552 (Unsecured Credentials), T1083 (File & Directory Discovery)
// ============================================================================

let lookback = 24h;

// --- Tooling primitives
let Tools = dynamic([
  "findstr.exe","where.exe","find.exe","dir","ls",
  "grep.exe","locate.exe"
]);

// --- PowerShell recon primitives
let PSTokens = dynamic(["select-string","get-childitem","gci","dir "]);

// --- Keyword intent (targets)
let Keywords = dynamic([
  "password","passwd","secret","secrets","creds","credential",
  "unattend.xml","id_rsa","key.txt","vnc.ini",
  ".env",".git-credentials",".npmrc","config.json",
  "aws_access_key_id","aws_secret_access_key","gcloud","azure",
  "vault","token"
]);

// --- High value targets (strong weighting)
let HighValueTokens = dynamic([
  "unattend.xml","id_rsa",".git-credentials",".env",".npmrc",
  "aws_access_key_id","aws_secret_access_key","gcloud","azure","vault","token"
]);

// --- Path context (noise suppression + reinforcement)
let AdminPaths = dynamic([
  "\\windows\\system32\\",
  "\\program files\\",
  "\\program files (x86)\\",
  "\\windows\\logs\\",
  "\\logfiles\\"
]);

let UserPaths = dynamic([
  "\\users\\",
  "\\appdata\\",
  "\\downloads\\",
  "\\desktop\\",
  "\\documents\\"
]);

// --- Parent context reinforcement
let SuspParents = dynamic([
  "winword.exe","excel.exe","powerpnt.exe","outlook.exe",
  "wscript.exe","cscript.exe","mshta.exe",
  "powershell.exe","pwsh.exe","cmd.exe"
]);

DeviceProcessEvents
| where Timestamp >= ago(lookback)
| extend
    Proc   = tolower(tostring(FileName)),
    Cmd    = tolower(tostring(ProcessCommandLine)),
    Parent = tolower(tostring(InitiatingProcessFileName)),
    User   = tostring(AccountName),
    Host   = tostring(DeviceName)

// ----------------------------
// MINIMUM TRUTH (Baseline Anchor)
// ----------------------------
| where (Proc has_any (Tools) or Cmd has_any (PSTokens))
| where Cmd has_any (Keywords)

// ----------------------------
// REINFORCEMENT SIGNALS
// ----------------------------
| extend
    HasPassTerms      = toint(Cmd has_any ("password","passwd")),
    HasHighValue      = toint(Cmd has_any (HighValueTokens)),
    IsRecursive       = toint(Cmd has_any ("/s","/si","-r","-R","-recurse","--recursive")),
    IsContentSearch   = toint(Proc in~ ("findstr.exe","grep.exe","find.exe") or Cmd has "select-string"),
    TargetsUserPaths  = toint(Cmd has_any (UserPaths)),
    TargetsAdminPaths = toint(Cmd has_any (AdminPaths)),
    SuspParent        = toint(Parent in~ (SuspParents)),
    HasWildcards      = toint(Cmd has_any ("*","?","\\*.","/*.") or Cmd has " -filter ")

// ----------------------------
// SCORING (Explainable Composite)
// ----------------------------
| extend RiskScore =
    0
    + iif(IsContentSearch == 1 and HasPassTerms == 1, 55, 0)
    + iif(HasHighValue == 1, 40, 0)
    + iif(IsRecursive == 1, 20, 0)
    + iif(HasWildcards == 1, 10, 0)
    + iif(TargetsUserPaths == 1, 10, 0)
    + iif(SuspParent == 1, 15, 0)
    - iif(TargetsAdminPaths == 1 and HasHighValue == 0 and HasPassTerms == 0, 30, 0)

// Quiet-by-default gate
| where RiskScore >= 45

// ----------------------------
// SEVERITY TIERS
// ----------------------------
| extend Severity = case(
    RiskScore >= 90, "CRITICAL",
    RiskScore >= 70, "HIGH",
    "MEDIUM"
)

// ----------------------------
// HUNTER DIRECTIVES (SOC-READY)
// ----------------------------
| extend
    DetectionSummary = case(
      HasHighValue == 1 and IsContentSearch == 1, "Targeted content search for high-value secret material",
      HasHighValue == 1,                          "Targeted search for high-value secret files/tokens",
      IsContentSearch == 1 and HasPassTerms == 1, "Content search for password material",
      IsRecursive == 1 and TargetsUserPaths == 1, "Recursive user-profile sweep for secrets",
      "Sensitive keyword search (context required)"
    ),
    HunterDirective = strcat(
      Severity, ": ", DetectionSummary,
      " | Host=", Host,
      " | User=", User,
      " | Proc=", tostring(FileName),
      " | Parent=", tostring(InitiatingProcessFileName),
      " | Score=", tostring(RiskScore),
      " | ACTION: Validate legitimacy. If unapproved: pivot to process tree, recent file access, staging/exfil tooling, and secret rotation if applicable."
    ),
    PivotPack = pack_array(
      "PIVOT-1: Review process ancestry (Office/script parents).",
      "PIVOT-2: Hunt follow-on staging (7z/rar/zip) and outbound network activity.",
      "PIVOT-3: If AWS/Azure/.env/.git-credentials hit: rotate secrets immediately.",
      "PIVOT-4: Check for credential access follow-on (LSASS/NTDS/Kerberos) within ±24h."
    )

// ----------------------------
// OUTPUT
// ----------------------------
| project
    Timestamp,
    DeviceName,
    AccountName,
    Severity,
    RiskScore,
    FileName,
    InitiatingProcessFileName,
    ProcessCommandLine,
    DetectionSummary,
    HunterDirective,
    PivotPack
| order by RiskScore desc, Timestamp desc
