# AI Security Analyst

Detects suspicious SSH login activity in OpenSSH logs, explains each alert in plain language with an LLM (MITRE ATT&CK mapping), and tunes its own detection thresholds with hill-climbing search.

## Problem
SSH servers are attacked continuously. Fixed-threshold tools raise thousands of terse alerts, and choosing the thresholds by hand is guesswork. The system detects attacks, explains each alert, and searches for better thresholds automatically.

## Features
- Parses OpenSSH auth logs into 5-minute windows per source IP
- Rule-based detection: brute force, user enumeration, success after failures
- Optional ML detection with Isolation Forest
- LLM analyst (Gemini or offline mock): severity, likely attack, MITRE technique, recommended actions
- Evaluation against injected synthetic attacks and benign users (precision / recall / F1)
- Hill-climbing threshold tuning, tuned on 5 randomised scenarios and tested on 5 unseen ones
- Streamlit dashboard

## Setup
Requires Python 3.11+.
```bash
pip install -r requirements.txt
```
For Gemini, create a `.env` file in the project root:
```
GEMINI_API_KEY=your_key_here
```
The `mock` provider works without a key.

## Data
`data/raw/` is not committed. Download the Loghub OpenSSH logs:
- 2,000-line sample: https://github.com/logpai/loghub/tree/master/OpenSSH (save as `data/raw/OpenSSH_2k.log`)
- Full log (about 70 MB): https://zenodo.org/record/3227177 (extract the OpenSSH file, e.g. as `data/raw/SSH.log`)

## Run
```bash
streamlit run app.py                       
python run_tuning.py                       
python run_tuning.py data/raw/SSH.log      
```

## Structure
```
app.py             Streamlit dashboard
run_tuning.py      runs the four hill-climbing variants and the grid-search baseline
src/
  parsers.py       regex parser (OpenSSH log -> events)
  features.py      per-IP, per-5-minute-window features
  detectors.py     rule-based detectors and Isolation Forest
  inject_attacks.py  synthetic attacks and benign users with ground truth
  evaluate.py      precision / recall / F1
  llm_analyst.py   Gemini analyst with offline mock mode
  tuner.py         hill-climbing algorithms (AI Theory)
knowledge/         MITRE ATT&CK notes per detector
data/              ground truth and processed sample output
results/           tuning results and convergence chart
notebook/          exploration
```

## References
- MITRE ATT&CK, https://attack.mitre.org
- He et al., "Loghub: A Large Collection of System Log Datasets towards Automated Log Analytics", arXiv:2008.06448, 2020
- Liu, Ting and Zhou, "Isolation Forest", IEEE ICDM, 2008
- Russell and Norvig, *Artificial Intelligence: A Modern Approach*, 4th ed.
- Microsoft & omdia, via CSA(2026)
- Prophet Security survey (2025)
- Verizon DBIR 2025
