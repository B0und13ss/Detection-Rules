[MITRE ATT&CK](https://attack.mitre.org/techniques/T1003/001/#uses-DS0022)

```SPL
`search_range`
(index=win_sysmon EventCode="11" TargetFileName="*.dmp*" Image IN ("*procdump.exe*", "*rundll32.exe*", "*taskmgr.exe*", "*powershell.exe*", "*wmic.exe*", "*schtasks.exe*", "*cmd.exe*", "*comsvcs.dll*")) OR
(index=win_security EventCode="4663" Object_Name="*.dmp*" Process_Name IN ("*procdump.exe*", "*rundll32.exe*", "*taskmgr.exe*", "*powershell.exe*", "*wmic.exe*", "*schtasks.exe*", "*cmd.exe*", "*comsvcs.dll*"))
| eval hunting_trigger="Unexpected creation of LSASS dump files",
       mitre_category="Credential Access",
       mitre_technique="OS Credential Dumping",
       mitre_technique_id="T0003",
       mitre_subtechnique="LSASS Memory", 
       mitre_subtechnique_id="001",
       mitre_link="https://attack.mitre.org/techniques/T1003/001/#uses-DS0022",
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
