[MITRE ATT&CK](https://attack.mitre.org/techniques/T1003/001/#uses-DS0017)

```SPL
`search_range`
(index=win_sysmon EventCode=1 Image="*powershell.exe" CommandLine IN ("*Invoke-Mimikatz*", "*procdump.exe -ma lsass*", "*rundll32.exe*comsvcs.dll*MiniDump*", "*taskmgr.exe* /dump*")) OR 
(index=win_powershell EventCode=4104 Message IN ("*Invoke-Mimikatz*", "*procdump.exe -ma lsass*", "*rundll32.exe*comsvcs.dll*MiniDump*", "*taskmgr.exe* /dump*"))
| eval hunting_trigger="mitre-detection-strategy",
mitre_category="Credential Access",
mitre_technique="OS Credential Dumping",
mitre_technique_id="T0003",
mitre_subtechnique="LSASS Memory", 
mitre_subtechnique_id="001",
mitre_link="https://attack.mitre.org/techniques/T1003/001/#uses-DS0017",
mitre_version="v17",
creator="Cpl Dougherty",
upload_date="2025-10-18",
last_modify_date="2025-10-18",
last_tested="yyyy-mm-dd",
priority="Critical"
`enrich`
`give_time`
| collect index=alerts sourcetype=WinEventLog
```
