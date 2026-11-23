import pandas as pd

def detect_rules(feats, brute_thr=10, enum_thr=5, compromise_fail=5):
    alerts = []
    for r in feats.itertuples():
        base = {"source_ip": r.source_ip, "window_start": str(r.window),
                "failed_logins": int(r.failed), "unique_usernames": int(r.unique_users),
                "successful_logins": int(r.accepted)}
        if r.accepted > 0 and r.failed >= compromise_fail:
            alerts.append({**base, "detector": "success_after_failures"})
        if r.failed >= brute_thr:
            alerts.append({**base, "detector": "brute_force"})
        if r.unique_users >= enum_thr:
            alerts.append({**base, "detector": "user_enumeration"})
    out = pd.DataFrame(alerts)
    if not out.empty:
        out.insert(0, "alert_id", [f"A-{i+1:03d}" for i in range(len(out))])
    return out


def detect_iforest(feats, contamination=0.05, seed=42):
    """Unsupervised anomaly detection on the window features (Isolation Forest)."""
    from sklearn.ensemble import IsolationForest
    cols = ["failed", "invalid", "accepted", "unique_users", "events"]
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed)
    model.fit(feats[cols])
    out = feats.copy()
    out["anomaly_score"] = -model.score_samples(feats[cols])   
    flagged = out[model.predict(feats[cols]) == -1].copy()
    flagged["detector"] = "isolation_forest"
    return flagged.rename(columns={"failed": "failed_logins", "unique_users": "unique_usernames"})