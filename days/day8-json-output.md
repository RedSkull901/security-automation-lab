# Day 8 - Structured JSON Output for Security Automation



## Objective

Enhance Python-based SSH brute-force detection by producing

structured JSON output suitable for automation pipelines.



---



## Why JSON Output

- Enables integration with SIEM and SOAR platforms

- Allows machine-to-machine communication

- Makes alerts easier to parse and act upon



---



## Output Structure

The script outputs a JSON object containing:

- Detection name

- Severity level

- Time window

- Generation timestamp

- Alert count

- List of affected IPs



---



## Example Use Cases

- Forward output to a SIEM

- Send alerts via webhook

- Feed results into a SOAR workflow

- Store detections in a database



---



## Security Engineering Notes

- Structured output is mandatory for scalable automation

- JSON enables clean separation between detection and response

- This design supports future API integrations



---



## Next Steps

- Add threat intelligence enrichment

- Push alerts to external services

- Build multi-step automation workflows
