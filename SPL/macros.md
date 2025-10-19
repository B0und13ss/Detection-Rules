```SPL
`search_range`

_index_earliest=-15m AND _index_latest=now
```

```SPL
`enrich`

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
"), eval _raw = mvjoin(mvappend(enrichment, "___________________________________________________", "", _raw), "
")
| eval indextime = _indextime
| convert ctime(indextime)
```

```SPL
`get_rule(1)`

| append [| rest /servicesNS/-/-/saved/searches splunk_server=local | where title="$rule_name$" | eval _raw = mvjoin(mvappend("TITLE:", title, "", "DESCRIPTION:" ,if(description="", "NO DESCRIPTION FOUND", description), "", "RULE:", search), " ") ]

rule_name
```
