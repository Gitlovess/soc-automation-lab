# Lab Setup Notes

## Infrastructure — Vultr Cloud

| VM | OS | RAM | Purpose |
|----|-----|-----|---------|
| Wazuh Server | Ubuntu 22.04 | 4GB | SIEM |
| TheHive | Ubuntu 22.04 | 4GB | Case Management |
| Windows 10 | Windows 10 | 2GB | Endpoint (Wazuh Agent + Sysmon) |

## Wazuh Setup
- Installed via official Wazuh installer script
- Windows 10 endpoint enrolled as agent (Agent ID: 001)
- Sysmon deployed on Windows 10 with SwiftOnSecurity config
- Custom rule added to `/var/ossec/etc/rules/local_rules.xml`

## Shuffle Setup
- Account created at shuffler.io
- Webhook trigger configured to receive Wazuh alerts
- Workflow: Webhook → Shuffle Tools (parse) → VirusTotal → TheHive → Email

## TheHive Setup
- Installed on separate Vultr Ubuntu VM
- Connected to Shuffle via API key
- Organisation: SOC-LAB

## Wazuh → Shuffle Integration
Added to `/var/ossec/etc/ossec.conf`:
```xml
<integration>
  <name>shuffle</name>
  <hook_url>https://shuffler.io/api/v1/hooks/YOUR_WEBHOOK_ID</hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

## Attack Simulation
- Downloaded Mimikatz from GitHub releases
- Ran `.\mimikatz.exe` via PowerShell on Windows 10
- Wazuh Rule 100002 fired within seconds
- Full pipeline completed in under 60 seconds
