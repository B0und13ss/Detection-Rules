```SPL
`indextime`
#

SPL SEARCH HERE

#
| eval hunting_trigger="", ```why does this alert fire```
       search_name="", ```copy the title here```
       mitre_category="none",
       mitre_technique="none",
       mitre_subtechnique="none",
       mitre_technique_id="Txxxx",
       mitre_subtechnique_id="xxx",
       mitre_link="none", ```link to the web page / detection strategy```
       mitre_version="v17",
       apt=mvappend("", ""), ```apts, keep extra "" if a single value```
       creator=mvappend("", ""), ```keep extra "" if a single value```
       upload_date="", ```yyyy-mm-dd```
       last_modify_date="",
       last_tested="",
       priority="Low", ```Low/Medium/High/Critical```
       orig_index=index,
       orig_host=host
`rule_enrich`
`populate_jarvis`
```

---

# FOR NEW APP ON OWN TIME

## Search
```SPL
`search_range`
#

SPL SEARCH HERE

#
| eval search_name="", ```copy the title here```
       hunting_trigger="", ```why does this alert fire```
       mitre_category="",
       mitre_technique="",
       mitre_subtechnique="",
       mitre_technique_id="Txxxx",
       mitre_subtechnique_id="xxx",
       mitre_link="", ```link to the web page / detection strategy```
       mitre_version="",
       apt=mvappend("", ""), ```apts, keep extra "" if a single value```
       creator=mvappend("", ""), ```keep extra "" if a single value```
       upload_date="", ```yyyy-mm-dd```
       last_modify_date="",
       last_tested="",
       priority="", ```Low/Medium/High/Critical```
       orig_index=index,
       orig_host=host
`format`
`alert`
```

## Macros

### search_range
```SPL
_index_earliest=-10m@m AND _index_latest=now
```

### format
```SPL
| eval enrichment = mvjoin(mvappend("Trigger=".hunting_trigger,
                                    "Category: ".mitre_category, 
                                    "Technique: ".mitre_technique . ":" . mitre_subtechnique, 
                                    "Code: ".mitre_technique_id . "." . mitre_subtechnique_id, 
                                    "Ref: ".mitre_link, 
                                    "Ver: ".mitre_version,
                                    "APT(s): ".mvjoin(apt, ", "),
                                    "Author: ".mvjoin(creator, ", "), 
                                    "Upload: ".upload_date, 
                                    "Modify: ".last_modify_date, 
                                    "Tested: ".last_tested, 
                                    "Priority: ".priority), "
"), _raw = mvjoin(mvappend("___________________________________________________",
                           "|                   ALERT DATA                    |",
                           "|_________________________________________________|",
                           "",
                           enrichment,
                           "",
                           "___________________________________________________",
                           "|                      EVENT                      |",
                           "|_________________________________________________|",
                           "",
                           _raw),
                           "
")
```

### alert
```SPL
| collect index=alerts output_format=hec
```
