import pandas as pd


EXPECTED = {
    "brute_force": {"brute_force"},
    "slow_brute_force": {"brute_force"},
    "user_enumeration": {"user_enumeration"},
    "success_after_failures": {"success_after_failures"},
}

def evaluate(alerts, truth, any_detector=False):
    alerted = alerts.groupby("source_ip")["detector"].apply(set).to_dict() if len(alerts) else {}
    rows, tp, fn, fp = [], 0, 0, 0
    for r in truth.itertuples():
        got = alerted.get(r.source_ip, set())
        if r.label == "attack":
            hit = bool(got) if any_detector else bool(got & EXPECTED[r.attack_type])
            tp += hit; fn += (not hit)
            rows.append((r.source_ip, r.attack_type, "detected" if hit else "MISSED"))
        else:
            fp += bool(got)
            rows.append((r.source_ip, r.attack_type, "false alarm" if got else "ok (no alert)"))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"TP": tp, "FP": fp, "FN": fn, "precision": round(precision, 2),
            "recall": round(recall, 2), "f1": round(f1, 2)}, rows