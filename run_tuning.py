import os, sys, time
sys.path.insert(0, "src")
import pandas as pd
from parsers import parse_file
from tuner import *
 
LOG = sys.argv[1] if len(sys.argv) > 1 else "data/raw/OpenSSH_2k.log"
LAM = float(sys.argv[2]) if len(sys.argv) > 2 else 0.3    
TAG = os.path.splitext(os.path.basename(LOG))[0] + f"_lam{LAM}"
df = parse_file(LOG)
print("Log:", LOG, "| events:", len(df), "| penalty weight:", LAM)
print("Building scenarios (training seeds 1-5, test seeds 101-105)...")
train, test = Scenario(df, range(1, 6)), Scenario(df, range(101, 106))
 
runs = {}
def run(name, fn):
    obj = Objective(train, LAM)
    t = time.time()
    state, val, path = fn(obj)
    runs[name] = (state, val, path, obj.evals, time.time() - t)
 
run("Simple hill climbing",     lambda o: simple_hill_climbing(o, DEFAULT))
run("Stochastic hill climbing", lambda o: stochastic_hill_climbing(o, DEFAULT))
run("Steepest-ascent",          lambda o: steepest_ascent(o, DEFAULT))
run("Random-restart (30)",      lambda o: random_restart(o, 30))
run("Grid search (baseline)",   lambda o: grid_search(o))
 
rows = []
for name, (state, evals, steps) in [("Default thresholds", (DEFAULT, 0, 0))] + \
        [(n, (r[0], r[3], len(r[2]) - 1)) for n, r in runs.items()]:
    tr, te = train.score(*state, lam=LAM), test.score(*state, lam=LAM)
    rows.append({"method": name, "thresholds": state, "evals": evals, "steps": steps,
                 "train_objective": round(tr["objective"], 3), "test_f1": round(te["f1"], 2),
                 "test_recall": round(te["recall"], 2),
                 "test_false_alarms": round(te["false_alarms"], 1),
                 "test_alerts": round(te["alerts"], 1)})
table = pd.DataFrame(rows)
print(table.to_string(index=False))
 
os.makedirs("results", exist_ok=True)
table.to_csv(f"results/tuning_{TAG}.csv", index=False)
try:
    import plotly.graph_objects as go
    fig = go.Figure()
    for name, (state, val, path, evals, secs) in runs.items():
        if "Grid" not in name:
            fig.add_trace(go.Scatter(x=list(range(len(path))), y=[v for _, v in path],
                                     mode="lines+markers", name=name))
    fig.update_layout(title="Objective after each hill-climbing step",
                      xaxis_title="Step", yaxis_title="Objective")
    fig.write_html(f"results/convergence_{TAG}.html")
    print(f"Saved results/tuning_{TAG}.csv and results/convergence_{TAG}.html")
except ImportError:
    print(f"Saved results/tuning_{TAG}.csv (install plotly for the chart)")
 
from inject_attacks import inject
from features import build_features
from detectors import detect_rules
from evaluate import evaluate
ok = True
for thr in [(10, 5, 5), (5, 5, 5), (17, 8, 6)]:
    d2, tr_ = inject(df, seed=1, vary=True)
    al = detect_rules(build_features(d2), *thr)
    m, _ = evaluate(al, tr_)
    real = int((~al.source_ip.isin(tr_.source_ip)).sum()) if len(al) else 0
    sc = Scenario(df, [1])
    f1, p_, r_, fp, ra, _ = sc._case(sc.cases[0], *thr)
    ok &= (m["precision"], m["recall"], m["FP"], real) == (round(p_, 2), round(r_, 2), fp, ra)
print("Fast scorer matches the real pipeline:", ok)
