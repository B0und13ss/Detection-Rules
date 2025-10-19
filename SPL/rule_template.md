```SPL
`search_range`
<<<<<<<PUT SEACH HERE>>>>>>>>
| eval hunting_trigger="mitre-detection-strategy",
mitre_category="category",
mitre_technique="technique",
mitre_technique_id="Txxxx",
mitre_subtechnique="subtechnique", 
mitre_subtechnique_id="xxx",
mitre_link="link-to-mitre-tcode",
mitre_version="v17",
creator="your-name-here",
upload_date="yyyy-mm-dd",
last_modify_date="yyyy-mm-dd",
last_tested="yyyy-mm-dd",
priority="criticality"
`enrich`
`give_time`
| collect index="collection_index" source="source" sourcetype="sourcetype"
```

FOR NEW APP ON OWN TIME
```SPL
index=win_security
| head 1
| eval hunting_trigger="THIS IS ANOTHER TEST",
       search_name="TEST PART 2",
       mitre_category="Credential_Access",
       mitre_technique="OS Credential Dumping",
       mitre_technique_id="T1003",
       mitre_subtechnique="LSASS Memory", 
       mitre_subtechnique_id="001",
       mitre_link="https://attack.mitre.org/techniques/T1003/001/#uses-DS0017",
       mitre_version="v17",
       creator="Cpl Dougherty",
       upload_date="2025-10-18",
       last_modify_date="2025-10-18",
       last_tested="yyyy-mm-dd",
       priority="Critical",
       orig_index=index,
       orig_host=host
| eval enrichment = mvjoin(mvappend("Trigger=".hunting_trigger,
                                    "MITRE Category=".mitre_category, 
                                    "MITRE Technique=".mitre_technique . ":" . mitre_subtechnique, 
                                    "MITRE Code=".mitre_technique_id . "." . mitre_subtechnique_id, 
                                    "Ref=".mitre_link, 
                                    "Ver=".mitre_version, 
                                    "Author=".creator, 
                                    "Upload=".upload_date, 
                                    "Modify=".last_modify_date, 
                                    "Tested=".last_tested, 
                                    "Priority=".priority), "
"), _raw = mvjoin(mvappend(enrichment, "___________________________________________________", "", _raw), "
"), indextime = _indextime 
| convert ctime(indextime) 
| collect index=jarvis output_format=hec
```
