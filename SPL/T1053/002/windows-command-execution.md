[MITRE ATT&CK](https://attack.mitre.org/techniques/T1053/002/#uses-DS0017)

```SPL
`search_range`
index=win_system EventCode=4698 TaskName="*at*" NOT (User="*SYSTEM*" AND TaskName="*\\Microsoft\\Windows\\Defrag\\ScheduledDefrag*")
| eval hunting_trigger="Windows Command Execution",
       mitre_category="Persistence",
       mitre_technique="Scheduled Task/Job",
       mitre_technique_id="T1053",
       mitre_subtechnique="At", 
       mitre_subtechnique_id="002",
       mitre_link="https://attack.mitre.org/techniques/T1053/002/#uses-DS0017",
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
