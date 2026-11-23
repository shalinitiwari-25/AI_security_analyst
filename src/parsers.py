import re
import pandas as pd

HEADER = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$"
)

# order matters: the more specific pattern first
EVENTS = [
    ("failed_invalid_user", re.compile(r"Failed password for invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")),
    ("failed_password",     re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>[\d.]+)")),
    ("accepted_password",   re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)")),
    ("invalid_user",        re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[\d.]+)")),
    ("connection_closed",   re.compile(r"Connection closed by (?P<ip>[\d.]+)")),
]

def parse_line(line, year=2015):
    h = HEADER.match(line)
    if not h:
        return None
    for name, pat in EVENTS:
        m = pat.search(h["msg"])
        if m:
            d = m.groupdict()
            ts = pd.to_datetime(f"{year} {h['month']} {h['day']} {h['time']}",
                                format="%Y %b %d %H:%M:%S")
            return {"timestamp": ts, "source_ip": d.get("ip"),
                    "user": d.get("user"), "event_type": name}
    return None

def parse_file(path, start_year=2015):
    rows = []
    with open(path, errors="ignore") as f:
        for line in f:
            r = parse_line(line.rstrip("\n"), start_year)
            if r:
                rows.append(r)
    df = pd.DataFrame(rows)
    # year rollover: if the month number drops (Dec -> Jan), add a year
    offset = (df["timestamp"].dt.month.diff() < 0).cumsum()
    mask = offset > 0
    df.loc[mask, "timestamp"] = [
        t + pd.DateOffset(years=int(o)) for t, o in zip(df.loc[mask, "timestamp"], offset[mask])
    ]
    return df