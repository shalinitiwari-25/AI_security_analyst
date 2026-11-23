import pandas as pd

def build_features(df, window="5min"):
    d = df[df["source_ip"].notna()].copy()
    d["window"] = d["timestamp"].dt.floor(window)
    d["is_failed"] = d["event_type"].isin(["failed_password", "failed_invalid_user"])
    d["is_invalid"] = d["event_type"] == "invalid_user"
    d["is_accepted"] = d["event_type"] == "accepted_password"

    feats = (d.groupby(["source_ip", "window"])
               .agg(failed=("is_failed", "sum"),
                    invalid=("is_invalid", "sum"),
                    accepted=("is_accepted", "sum"),
                    unique_users=("user", "nunique"),
                    events=("event_type", "size"))
               .reset_index())
    return feats