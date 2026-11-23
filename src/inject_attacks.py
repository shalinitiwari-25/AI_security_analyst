import numpy as np
import pandas as pd

ATTACK_NET = "203.0.113."
BENIGN_NET = "198.51.100."

def _events(ip, start, offsets, event_type, users):
    return pd.DataFrame({
        "timestamp": [start + pd.Timedelta(seconds=float(s)) for s in offsets],
        "source_ip": ip, "user": users, "event_type": event_type})

def inject(df, seed=42):
    """Add synthetic attacks and benign users to parsed events.
    Returns (new_df, ground_truth)."""
    rng = np.random.default_rng(seed)
    first = df["timestamp"].min().ceil("5min")
    n_windows = int((df["timestamp"].max() - first) / pd.Timedelta("5min")) - 1
    picks = rng.choice(n_windows, size=9, replace=False)
    starts = [first + pd.Timedelta(minutes=5 * int(k)) + pd.Timedelta(seconds=int(rng.integers(0, 60)))
              for k in picks]
    parts, truth = [], []

    def add(i, ip, kind, label, ev):
        parts.append(ev)
        truth.append({"source_ip": ip, "attack_type": kind, "label": label,
                      "start": ev.timestamp.min(), "end": ev.timestamp.max()})


    ip = ATTACK_NET + "10"            
    add(0, ip, "brute_force", "attack",
        _events(ip, starts[0], np.sort(rng.uniform(0, 150, 45)), "failed_password", "root"))
    ip = ATTACK_NET + "11"            
    add(1, ip, "slow_brute_force", "attack",
        _events(ip, starts[1], np.sort(rng.uniform(0, 240, 6)), "failed_password", "root"))
    ip = ATTACK_NET + "12"            
    names = ["admin", "test", "oracle", "ubuntu", "guest", "postgres", "git", "ftp",
             "user", "pi", "jenkins", "mysql", "support", "dev", "backup"]
    add(2, ip, "user_enumeration", "attack",
        _events(ip, starts[2], np.sort(rng.uniform(0, 120, 15)), "invalid_user", names))
    ip = ATTACK_NET + "13"            
    ev = pd.concat([
        _events(ip, starts[3], np.sort(rng.uniform(0, 150, 12)), "failed_password", "admin"),
        _events(ip, starts[3] + pd.Timedelta(seconds=170), [0], "accepted_password", "admin")])
    add(3, ip, "success_after_failures", "attack", ev)

    
    ip = BENIGN_NET + "20"            
    ev = pd.concat([
        _events(ip, starts[4], [0, 20], "failed_password", "alice"),
        _events(ip, starts[4] + pd.Timedelta(seconds=45), [0], "accepted_password", "alice")])
    add(4, ip, "typo_then_login", "benign", ev)
    ip = BENIGN_NET + "21"            
    add(5, ip, "single_failure", "benign",
        _events(ip, starts[5], [0], "failed_password", "bob"))
    ip = BENIGN_NET + "22"            
    add(6, ip, "normal_login", "benign",
        _events(ip, starts[6], [0], "accepted_password", "carol"))
    ip = BENIGN_NET + "23"            
    ev = pd.concat([
        _events(ip, starts[7], [0, 15, 30, 50], "failed_password", "dave"),
        _events(ip, starts[7] + pd.Timedelta(seconds=80), [0], "accepted_password", "dave")])
    add(7, ip, "forgot_password", "benign", ev)

    out = pd.concat([df] + parts, ignore_index=True).sort_values("timestamp").reset_index(drop=True)
    return out, pd.DataFrame(truth)