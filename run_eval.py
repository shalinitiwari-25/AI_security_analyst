import sys; sys.path.insert(0, "src")
from parsers import parse_file
from inject_attacks import inject
from features import build_features
from detectors import detect_rules
from evaluate import evaluate

df = parse_file("data/raw/OpenSSH_2k.log")
df2, truth = inject(df)
truth.to_csv("data/ground_truth.csv", index=False)
print("Events before/after injection:", len(df), "->", len(df2))
print(truth[["source_ip", "attack_type", "label", "start"]].to_string(index=False))

alerts = detect_rules(build_features(df2))
metrics, rows = evaluate(alerts, truth)
print("\nPer-case result:")
for ip, kind, res in rows:
    print(f"  {ip:<14} {kind:<24} {res}")
print("\nMetrics:", metrics)


import pandas as pd
from detectors import detect_iforest
feats = build_features(df2)
ml = detect_iforest(feats)
m_ml, rows_ml = evaluate(ml, truth, any_detector=True)
combined = pd.concat([alerts, ml], ignore_index=True)
m_c, rows_c = evaluate(combined, truth, any_detector=True)
print("\nRules only        :", metrics)
print("Isolation Forest  :", m_ml)
print("Combined          :", m_c)
print("Isolation Forest flagged", len(ml), "of", len(feats), "windows")
for ip, kind, res in rows_ml:
    print(f"  IF  {ip:<14} {kind:<24} {res}")