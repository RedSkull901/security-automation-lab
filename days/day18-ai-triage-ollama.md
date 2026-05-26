# Day 18 — AI-Powered Alert Triage with Ollama

## What this day adds

A local LLM analyses every high and medium severity alert and produces a
structured incident report — what happened, why it's risky, what the system
did, and what the analyst should do next.

Everything runs on the VM. No API keys. No subscriptions. No internet
dependency for inference.

---

## Why local LLM instead of a cloud API

The honest tradeoff:

| | Cloud API (Claude, GPT-4) | Ollama (local) |
|---|---|---|
| Quality | Best available | Good enough for structured triage |
| Cost | Per-token pricing | Free forever |
| Privacy | Data leaves your server | Data never leaves the VM |
| Availability | Depends on internet | Works offline |
| Rate limits | Yes | None |

For a security tool, data privacy is a real concern. Alert data contains
IP addresses, timestamps, and system state — sending that to a third-party
API on every detection is a policy decision, not just a technical one.
Running inference locally sidesteps it entirely.

---

## Model selection — why llama3.2:3b

Tested two models against a real alert:

```
qwen2.5:3b   — 45 seconds, weak output (one vague sentence)
               with structured prompt: 2m13s, excellent output
               verdict: prompt-dependent, inconsistent

llama3.2:3b  — 81 seconds, good structured output consistently
               verdict: reliable, predictable, good enough
```

For automation, consistency beats best-case performance. `llama3.2:3b`
produces useful output with a straightforward prompt every time.

Speed: ~80 seconds per alert on CPU. Acceptable for background automation
where nobody is waiting interactively for the result.

---

## New concept: prompt engineering for structured output

The quality of LLM output is almost entirely determined by the prompt.
For automation, you want *structured* output — not a paragraph of prose,
but a predictable format your code can parse and display.

Two patterns that work:

**1. Explicit format template**
```
Respond in exactly this format:
INCIDENT: [one sentence]
RISK: [severity and reason]
ACTIONS TAKEN: [what happened]
RECOMMENDED NEXT STEPS:
1. [action]
2. [action]
3. [action]
```

**2. Role + context + constraints**
```
You are a SOC analyst writing a concise incident report.
[structured data]
Be concise, max 100 words.
```

Pattern 1 wins for automation because it forces the model into a shape
your code expects. Pattern 2 works for conversational use where flexibility
matters more.

**Temperature** — set to 0.2 (low). Temperature controls randomness:
- `0.0` = deterministic, same output every time
- `0.5` = balanced
- `1.0` = creative, unpredictable

For security triage you want consistency, not creativity. 0.2 gives
slightly varied wording while keeping the structure reliable.

---

## Architecture

```
Detection alert (from event store)
        │
        ▼
TriageEngine.analyze(alert)
        │
        ├── build_prompt(alert)      ← structured prompt with alert data
        │
        ├── POST /api/generate       ← Ollama local API
        │       model: llama3.2:3b
        │       temperature: 0.2
        │       stream: false
        │
        └── TriageResult
                ├── summary          ← the incident report text
                ├── duration_sec     ← how long inference took
                └── success          ← bool, False if Ollama unavailable
        │
        ▼
Playbook picks up triage_summary
        │
        ▼
Discord embed includes "🤖 AI Triage" field
        │
        ▼
Analyst sees full context in one Discord card
```

---

## Graceful degradation

The triage engine never blocks the pipeline. If Ollama is down, the
model isn't loaded, or inference times out — the playbook logs the error
and continues. The Discord alert still goes out, just without the AI field.

```python
if triage_engine.is_available():
    triage_result = triage_engine.analyze(event)
    if triage_result.success:
        triage_summary = triage_result.summary
    # if it fails, triage_summary stays None — alert still sends
```

This is a core principle for automation tooling: **degrade gracefully**.
A tool that crashes when a dependency is down is worse than a tool that
continues without that feature.

---

## Running it

```bash
# Verify Ollama is running
ollama list

# Test triage directly
python -m security_core.automations.triage

# Run the full playbook with triage enabled
SAL_DRY_RUN=true python -m security_core.automations.playbook --dry-run

# Watch mode — polls every 60s, triages new alerts
python -m security_core.automations.playbook --watch

# Override model
TRIAGE_MODEL=qwen2.5:3b python -m security_core.automations.triage
```

---

## What a Discord alert looks like now

```
🔴 SSH Brute-Force Detected
Suspicious activity from 1.2.3.4 exceeded detection threshold.

IP Address          1.2.3.4
Severity            🔴 HIGH
Action taken        🔒 Blocked (auto)
Failed attempts     12
Risk score          207
Abuse confidence    87%
Country             🇨🇳 CN
AbuseIPDB reports   42

🤖 AI Triage
INCIDENT: IP 1.2.3.4 conducted 12 failed SSH login attempts in 10
minutes with a high AbuseIPDB confidence score of 87%.
RISK: High — the IP has 42 prior abuse reports and originates from
a high-risk region, suggesting automated credential stuffing.
ACTIONS TAKEN: The system automatically blocked the IP for 30 minutes
via iptables.
RECOMMENDED NEXT STEPS:
1. Review auth.log for any successful logins from this IP before the block.
2. Check if this IP appears in other detection windows or on other ports.
3. Consider adding to permanent blocklist if activity resumes post-unblock.
```

The analyst gets full context — raw data + AI interpretation + specific
next steps — in a single Discord card. No log grepping, no context switching.

---

## Tests

```bash
python -m pytest security_core/tests/test_triage.py -v
# 16 tests — all Ollama calls mocked, no real LLM needed in CI
```

The test suite covers: prompt content validation, availability checks,
success path, empty response handling, timeout handling, connection errors,
result shape, and batch analysis.

---

## Lessons

**Prompt engineering is engineering.** The difference between a useful
triage report and a vague one-liner is almost entirely in the prompt
structure. Explicit format templates, clear role definition, and tight
constraints (max tokens, temperature) produce reliable output from small
models.

**Small models are underrated for structured tasks.** `llama3.2:3b` is
3 billion parameters — tiny by modern standards. For a well-defined task
with a structured prompt, it performs well enough to be genuinely useful.
The use case has to match the model: open-ended creative writing, no.
Fill in a structured security incident report from JSON data, yes.

**Local inference is slower but owns its data.** 80 seconds per alert
on CPU sounds slow. For a background automation task that runs async
and doesn't block anything else, it's completely acceptable. And the
tradeoff — zero cost, zero data exposure, zero rate limits, zero internet
dependency — is worth it for a security tool.
