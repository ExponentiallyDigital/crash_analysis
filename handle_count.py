#!/usr/bin/env python3
#
# display the total number of handles open at a given interval. eg:
# 2026-01-16T21:29:53.4081804+11:00       146274
# 2026-01-16T21:30:04.9163369+11:00       146295
# 2026-01-16T21:30:16.8221244+11:00       146298
# 2026-01-16T21:30:28.6221430+11:00       146435
# 2026-01-16T21:30:40.4067889+11:00       146359
# 2026-01-16T21:30:52.1842899+11:00       146358
# 2026-01-16T21:31:03.8340475+11:00       146354
# 2026-01-16T21:31:15.5963347+11:00       146419
# 2026-01-16T21:31:27.0139448+11:00       146371
# Wrote handle_totals_unique.csv
#
from pathlib import Path
import json
import sys
import csv
import re

# !!!!!!!!!!!!! 
# !!!!!!!!!!!!! edit below lines:
# !!!!!!!!!!!!! 
INPUT = Path(r"C:\perflogs\2026-01-16_21-29-52_perfdata_log.json")
OUT_CSV = Path("handle_totals_unique.csv")

EXCLUDE_SUBSTR = "process__total__handle_count"

# regex patterns to extract instance name from common key forms
PATTERNS = [
    re.compile(r"__arcspeed_process_(.+?)__handle_count$"),  # __arcspeed_process_<inst>__handle_count
    re.compile(r"(.+?)__handle_count$"),                    # <inst>__handle_count
    re.compile(r"(.+?)_handle_count$"),                     # <inst>_handle_count
]

def load_json_objects(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"{path} not found")
    objs = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        # detect array vs NDJSON
        first_nonblank = None
        for line in f:
            if line.strip():
                first_nonblank = line.lstrip()
                break
        f.seek(0)
        if first_nonblank and first_nonblank.startswith("["):
            objs = json.load(f)
        else:
            for i, raw in enumerate(f, 1):
                s = raw.strip()
                if not s:
                    continue
                if s.startswith("\ufeff"):
                    s = s.lstrip("\ufeff")
                try:
                    objs.append(json.loads(s))
                except json.JSONDecodeError:
                    print(f"Warning: skipping invalid JSON on line {i}", file=sys.stderr)
    return objs

def canonical_instance_from_key(key: str):
    # return canonical instance name or None if key is not a handle counter
    if EXCLUDE_SUBSTR in key:
        return None
    for pat in PATTERNS:
        m = pat.search(key)
        if m:
            inst = m.group(1)
            # normalize whitespace and lower-case for canonicalization
            return inst.strip()
    return None

def total_handles_for_sample(sample: dict) -> int:
    counters = sample.get("counters", {}) or {}
    instance_map = {}  # instance -> value (keep first seen)
    for k, v in counters.items():
        inst = canonical_instance_from_key(k)
        if not inst:
            continue
        # convert value to int if possible
        try:
            val = int(v)
        except Exception:
            # skip non-numeric
            continue
        # keep the first value seen for this instance to avoid double counting
        if inst not in instance_map:
            instance_map[inst] = val
    # sum unique instances
    return sum(instance_map.values())

def main():
    objs = load_json_objects(INPUT)
    if not objs:
        print("No objects loaded", file=sys.stderr)
        return
    rows = []
    for s in objs:
        ts = s.get("timestamp") or s.get("time") or s.get("ts")
        total = total_handles_for_sample(s)
        rows.append({"Timestamp": ts, "TotalHandles": total})
    # print to console
    for r in rows:
        print(f"{r['Timestamp']}\t{r['TotalHandles']}")
    # save CSV
    with OUT_CSV.open("w", newline="", encoding="utf-8") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=["Timestamp", "TotalHandles"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {OUT_CSV}")

if __name__ == "__main__":
    main()
