# Day 11 - Automated Response Actions (SOAR Basics)



## Objective

Extend SSH brute-force detection to include automated

response actions based on risk and severity.



---



## Response Strategy

- Low severity: ignore

- Medium severity: alert only

- High severity: simulate blocking action



---



## Why Simulation First

- Prevents accidental service disruption

- Allows safe testing of automation logic

- Mirrors enterprise SOAR testing practices



---



## Security Engineering Notes

- Automated response must be controlled and reversible

- Decision logic should always precede response

- Simulation mode is critical before production rollout



---



## Next Steps

- Implement real blocking actions

- Add rollback mechanisms

- Integrate notifications


