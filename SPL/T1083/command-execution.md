[MITRE ATT&CK](https://attack.mitre.org/techniques/T1083/#uses-DS0017)

```SPL
`indextime`
index=win_security EventCode=4688 Process_Command_Line IN ("*ls*", "*dir*", "*tree*", "*locate*", "*forfiles*") Creator_Process_Name IN ("*powershell.exe*", "*cmd.exe*", "*bash*") NOT Process_Command_Line IN ("*csc.exe*", "*reg*", "*appcmd.exe*", "*mcafee*", "*.jar*", "*$sidString*", "*Win32_Service*", "*repadmin*", "*VMwareToolboxCmd.exe*", "*ping*", "*worldwinddata*", "*chrome.exe*", "*Windows Defender Advanced Threat Protection*", "*sysconfdir*", "*CCM_SoftwareUpdatesClientConfig*", "*keytool.exe*")
| eval hunting_trigger="Executed commands and arguments that may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.",
       mitre_category="Discovery",
       mitre_technique="File and Directory Discovery",
       mitre_technique_id="T1083",
       mitre_subtechnique="", 
       mitre_subtechnique_id="",
       mitre_link="https://attack.mitre.org/techniques/T1083/#uses-DS0017",
       mitre_version="v17",
       creator="Cpl Dougherty",
       upload_date="2025-10-18",
       last_modify_date="2025-10-18",
       last_tested="yyyy-mm-dd",
       priority="Medium"
`enrich`
`give_time`
| collect index=alerts sourcetype=WinEventLog
```
