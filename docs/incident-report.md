# Incident Report — Mimikatz Credential Dumping Detection

| Field | Details |
|-------|---------|
| **Report ID** | IR-2026-001 |
| **Date** | 02 July 2026 |
| **Analyst** | Venkateshwaran |
| **Severity** | 🔴 Critical |
| **Status** | Resolved |
| **MITRE ATT&CK** | T1003 — OS Credential Dumping |
| **Host** | DESKTOP-3KO75RC |
| **Agent IP** | 10.0.2.15 |

---

## 1. Executive Summary

On 02 July 2026 at 20:01 UTC, the Wazuh SIEM detected execution of **Mimikatz** — a well-known credential dumping tool — on endpoint `DESKTOP-3KO75RC`. The alert was triggered by custom detection rule 100002 (Level 15 — Critical), which monitors for Mimikatz process creation via Sysmon Event ID 1.

The SOC automation pipeline immediately responded: Shuffle orchestrated automatic IOC enrichment via VirusTotal, an incident case was created in TheHive, and an email alert was sent to the SOC analyst — all within 60 seconds, with zero manual intervention.

---

## 2. Timeline of Events

| Time (UTC) | Event |
|------------|-------|
| **20:01:40** | `mimikatz.exe` executed via PowerShell on DESKTOP-3KO75RC |
| **20:01:40** | Sysmon Event ID 1 (Process Creation) captured on endpoint |
| **20:01:41** | Wazuh agent forwarded event to Wazuh Manager (venky-wazuh) |
| **20:01:42** | Wazuh Rule 100002 fired — Level 15 Critical alert generated |
| **20:02:00** | Shuffle webhook received alert payload from Wazuh |
| **20:02:01** | Shuffle extracted file hash from alert data |
| **20:02:02** | VirusTotal API queried — hash confirmed malicious |
| **20:02:44** | TheHive case auto-created (Alert #100002, SEVERITY: HIGH) |
| **20:02:45** | Email alert sent to SOC analyst — "Mimikatz Detected" |
| **20:35:49** | Analyst confirmed alert — investigation completed |

**Total detection-to-notification time: under 60 seconds**

---

## 3. Initial Alert Details

| Field | Value |
|-------|-------|
| Rule ID | 100002 |
| Rule Level | 15 (Critical) |
| Rule Description | Mimikatz Usage Detected |
| Agent Name | SOC-Windows |
| Agent IP | 10.0.2.15 |
| Manager | venky-wazuh |
| MITRE ID | T1003 |
| Timestamp | 2026-07-02T16:32:42.554+0000 |

---

## 4. Forensic Evidence

### 4.1 — Process Execution Details (Sysmon Event ID 1)

| Field | Value |
|-------|-------|
| Original Filename | `mimikatz.exe` |
| Full Image Path | `C:\Users\venky\Downloads\mimikatz_trunk\x64\mimikatz.exe` |
| Product | Mimikatz for Windows |
| Signature Status | **Unavailable (Unsigned)** |
| Parent Process | `PowerShell.exe` |
| Parent Command Line | `"PowerShell.exe" -noexit -command Set-Location -literalPath 'C:\Users\venky\Downloads\mimikatz_trunk\x64'` |
| Process GUID | d864b018-76b4-6a46-7901-000000000a00 |
| Process ID | 4260 |

### 4.2 — Key Indicators of Compromise (IOCs)

| IOC Type | Value |
|----------|-------|
| Filename | `mimikatz.exe` |
| File Path | `C:\Users\venky\Downloads\mimikatz_trunk\x64\` |
| Parent Process | PowerShell.exe |
| Hash | Extracted and submitted to VirusTotal |
| Host | DESKTOP-3KO75RC |
| Agent IP | 10.0.2.15 |

### 4.3 — TheHive Case Details

| Field | Value |
|-------|-------|
| Alert ID | ~4350144 |
| Reference | internal (#100002) |
| Title | Mimikatz Usage Detected |
| Severity | HIGH |
| TLP | AMBER |
| PAP | AMBER |
| Source | WAZUH Alert |
| Created By | SOAR (Shuffle) — Automated |
| Status | New |

---

## 5. Attack Analysis

### What is Mimikatz?

Mimikatz is an open-source credential dumping tool widely used by attackers and red teams. It can extract plaintext passwords, NTLM hashes, Kerberos tickets, and other credentials directly from Windows memory (LSASS process).

### MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique |
|--------|-----------|--------------|
| Credential Access | T1003 — OS Credential Dumping | T1003.001 — LSASS Memory |

### Attack Chain Observed

```
Attacker Access
      ↓
PowerShell launched (parent process)
      ↓
Navigated to Downloads\mimikatz_trunk\x64\
      ↓
.\mimikatz.exe executed (unsigned binary)
      ↓
Sysmon Event ID 1 captured process creation
      ↓
Wazuh Rule 100002 triggered (Level 15)
      ↓
SOAR pipeline activated
```

### Why This Is Critical

- Mimikatz execution indicates an attacker may already have **local admin or SYSTEM privileges**
- Credential dumping could lead to **lateral movement** across the network
- Harvested credentials could enable **domain compromise** if Active Directory is present
- The executable was **unsigned** and launched from the **Downloads folder** — both major red flags

---

## 6. Automated Response Actions Taken

| Action | Tool | Result |
|--------|------|--------|
| Alert detection | Wazuh (Rule 100002) | ✅ Critical alert fired |
| IOC enrichment | VirusTotal via Shuffle | ✅ Hash queried automatically |
| Case creation | TheHive via Shuffle | ✅ SEVERITY:HIGH case created |
| Analyst notification | Gmail via Shuffle | ✅ Email sent within 60 seconds |

---

## 7. Containment Recommendations

### Immediate Actions
- [ ] **Isolate** endpoint DESKTOP-3KO75RC from the network immediately
- [ ] **Reset** credentials for user `venky` — assume passwords are compromised
- [ ] **Revoke** any active sessions or tokens associated with the host
- [ ] **Preserve** memory dump and disk image for forensic analysis

### Short-Term Actions
- [ ] **Scan** all other endpoints for mimikatz.exe or similar artifacts
- [ ] **Review** authentication logs for lateral movement attempts
- [ ] **Check** for any new user accounts or privilege escalation events
- [ ] **Search** SIEM for Event ID 4624 (successful logon) from the compromised host

### Long-Term Recommendations
- [ ] **Block** PowerShell execution from Downloads, Temp, and AppData folders via GPO
- [ ] **Enable** Credential Guard on all Windows endpoints to protect LSASS
- [ ] **Deploy** attack surface reduction (ASR) rules via Windows Defender
- [ ] **Implement** application whitelisting to block unsigned executables
- [ ] **Enable** PowerShell ScriptBlock logging (Event ID 4104) for deeper visibility

---

## 8. Detection Rule Used

```xml
<!-- Wazuh Custom Rule — local_rules.xml -->
<rule id="100002" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" 
         type="pcre2">(?i)mimikatz\.exe</field>
  <description>Mimikatz Usage Detected</description>
  <mitre>
    <id>T1003</id>
  </mitre>
</rule>
```

**Rule logic:** Monitors Sysmon process creation events (Event Group 1). If the original filename matches `mimikatz.exe` (case-insensitive), fires a Level 15 Critical alert with MITRE T1003 tag.

---

## 9. Lessons Learned

| Finding | Recommendation |
|---------|---------------|
| Mimikatz ran from Downloads folder | Block execution from user-writable directories via GPO |
| PowerShell was the parent process | Enable PowerShell constrained language mode |
| Binary was unsigned | Enforce application whitelisting (unsigned binaries blocked) |
| Detection was automated | SOAR pipeline worked correctly — no tuning needed |
| Alert-to-email under 60 seconds | Automation pipeline performing as expected |

---

## 10. References

| Resource | Link |
|----------|------|
| MITRE ATT&CK T1003 | https://attack.mitre.org/techniques/T1003/ |
| Mimikatz GitHub | https://github.com/gentilkiwi/mimikatz |
| Wazuh Documentation | https://documentation.wazuh.com |
| Sysmon Event ID 1 | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon |
| Credential Guard | https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/ |

---
