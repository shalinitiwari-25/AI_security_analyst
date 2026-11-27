import random
import numpy as np
from inject_attacks import inject
from features import build_features
from evaluate import EXPECTED

SPACE = {"brute_thr": (3, 60), "enum_thr": (2, 25), "compromise_fail": (2, 30)}
DEFAULT = (10, 5, 5)          


class Scenario:

    def __init__(self, df, seeds):
        self.cases = []
        for sd in seeds:
            df2, truth = inject(df, seed=sd, vary=True)
            f = build_features(df2)
            injected = set(truth.source_ip)
            real = f[~f.source_ip.isin(injected)]
            inj = []
            for r in truth.itertuples():
                g = f[f.source_ip == r.source_ip]
                inj.append((r.attack_type, r.label, g.failed.to_numpy(),
                            g.unique_users.to_numpy(), g.accepted.to_numpy()))
            self.cases.append({"n": len(f), "inj": inj,
                               "real": (real.failed.to_numpy(), real.unique_users.to_numpy(),
                                        real.accepted.to_numpy())})

    def _case(self, case, b, e, c):
        rf, ru, ra = case["real"]
        real_alerts = int((rf >= b).sum() + (ru >= e).sum() + ((ra > 0) & (rf >= c)).sum())
        tp = fp = fn = 0
        for kind, label, f, u, a in case["inj"]:
            got = set()
            if ((a > 0) & (f >= c)).any():
                got.add("success_after_failures")
            if (f >= b).any():
                got.add("brute_force")
            if (u >= e).any():
                got.add("user_enumeration")
            if label == "attack":
                if got & EXPECTED[kind]:
                    tp += 1
                else:
                    fn += 1
            elif got:
                fp += 1
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        return f1, p, r, fp, real_alerts, real_alerts / case["n"]

    def score(self, b, e, c, lam=0.3):
        m = np.mean([self._case(cs, b, e, c) for cs in self.cases], axis=0)
        return {"objective": m[0] - lam * m[5], "f1": m[0], "precision": m[1], "recall": m[2],
                "false_alarms": m[3], "alerts": m[4], "alert_rate": m[5]}


class Objective:

    def __init__(self, scenario, lam=0.3):
        self.sc, self.lam, self.cache, self.evals = scenario, lam, {}, 0

    def __call__(self, s):
        if s not in self.cache:
            self.cache[s] = self.sc.score(*s, lam=self.lam)["objective"]
            self.evals += 1
        return self.cache[s]


STEPS = (1, 2, 5)


def neighbours(s):
    for i, (lo, hi) in enumerate(SPACE.values()):
        for step in STEPS:
            for d in (-step, step):
                v = s[i] + d
                if lo <= v <= hi:
                    t = list(s)
                    t[i] = v
                    yield tuple(t)


def simple_hill_climbing(obj, start, seed=0):
    rnd = random.Random(seed)
    cur, val = start, obj(start)
    path = [(cur, val)]
    improved = True
    while improved:
        improved = False
        nb = list(neighbours(cur))
        rnd.shuffle(nb)
        for n in nb:
            v = obj(n)
            if v > val + 1e-9:
                cur, val, improved = n, v, True
                path.append((cur, val))
                break
    return cur, val, path


def stochastic_hill_climbing(obj, start, seed=0):
    rnd = random.Random(seed)
    cur, val = start, obj(start)
    path = [(cur, val)]
    while True:
        uphill = [(n, obj(n)) for n in neighbours(cur)]
        uphill = [(n, v) for n, v in uphill if v > val + 1e-9]
        if not uphill:
            return cur, val, path
        cur, val = rnd.choice(uphill)
        path.append((cur, val))


def steepest_ascent(obj, start):
    cur, val = start, obj(start)
    path = [(cur, val)]
    while True:
        best, best_v = None, val
        for n in neighbours(cur):
            v = obj(n)
            if v > best_v + 1e-9:
                best, best_v = n, v
        if best is None:
            return cur, val, path
        cur, val = best, best_v
        path.append((cur, val))


def random_restart(obj, restarts=10, seed=0):
    rnd = random.Random(seed)
    best = None
    for _ in range(restarts):
        start = tuple(rnd.randint(lo, hi) for lo, hi in SPACE.values())
        res = steepest_ascent(obj, start)
        if best is None or res[1] > best[1]:
            best = res
    return best


def grid_search(obj, steps=(3, 2, 2)):
    ranges = [range(lo, hi + 1, st) for (lo, hi), st in zip(SPACE.values(), steps)]
    best, best_v = None, -1e9
    for b in ranges[0]:
        for e in ranges[1]:
            for c in ranges[2]:
                v = obj((b, e, c))
                if v > best_v:
                    best, best_v = (b, e, c), v
    return best, best_v, [(best, best_v)]
