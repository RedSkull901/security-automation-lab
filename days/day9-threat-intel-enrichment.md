# Day 9 - Threat Intelligence Enrichment



## Objective

Enhance SSH brute-force detection by enriching suspicious IP

addresses with external threat intelligence data.



---



## Threat Intelligence Source

- AbuseIPDB

- REST API based IP reputation service



---



## Enrichment Data Added

- Abuse confidence score

- Country code

- Whitelist status



---



## Security Engineering Notes

- Contextual enrichment improves alert prioritization

- API failures must not break detections

- External data should be treated as advisory



---



## Next Steps

- Add VirusTotal enrichment

- Apply risk-based severity scoring

- Trigger automated response actions


