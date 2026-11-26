# AI Security Analyst

Detects suspicious SSH login activity in OpenSSH logs and explains each alert in plain language using an LLM, with MITRE ATT&CK mapping.

## Features
- Parses OpenSSH auth logs into 5-minute windows per source IP
- Rule-based detection: brute force, user enumeration, success after failures
- Optional ML detection with Isolation Forest
- LLM analyst (Gemini or offline mock) returns severity, likely attack, MITRE technique and recommended actions
- Evaluation against injected synthetic attacks (precision / recall / F1)
- Streamlit dashboard

## Setup
```bash
pip install -r requirements.txt
```
For Gemini, add your key to a `.env` file (`GEMINI_API_KEY=...`). The `mock` provider works without a key.

## Run
```bash
streamlit run app.py
```
Upload an OpenSSH `.log` file, or place the [Loghub OpenSSH sample](https://github.com/logpai/loghub) at `data/raw/OpenSSH_2k.log`.

## Structure
```
app.py          Streamlit UI
src/            parsers, features, detectors, llm_analyst, evaluate, inject_attacks
knowledge/      MITRE ATT&CK notes per detector
data/           ground truth and processed alerts
notebook/       exploration
```
