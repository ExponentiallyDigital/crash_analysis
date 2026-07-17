#!/usr/bin/env python3
"""
handle_visualisation.py
Reads NDJSON or JSON-array perf log, extracts per-process handle counts,
plots trends, writes CSV, and prints simple trend slopes for top processes.

This variant explicitly excludes aggregate/total counters (e.g. process__total__handle_count)
so totals and top-process selection are not inflated.
"""

import json
from pathlib import Path
import re
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

# === Configuration ===
# Input file
# !!!!!!!!!!!!! 
# !!!!!!!!!!!!! edit below lines:
# !!!!!!!!!!!!! 
INPUT_PATH = Path(r"C:\perflogs\2026-01-16_21-29-52_perfdata_log.json")
TOP_N = 20 # top 20 processes to chart
PLOT_STYLE = "seaborn-v0_8-darkgrid"
# Exclude any counter key that contains this substring (adjust if your key differs)
EXCLUDE_SUBSTR = "process__total__handle_count"
# ===

# derive base name: eg "2026-01-16_21-29-52_perfdata" from the input stem
_input_stem = INPUT_PATH.stem  # e.g., "2026-01-16_21-29-52_perfdata_log"
if _input_stem.endswith("_log"):
    BASE_NAME = _input_stem[:-4]  # remove trailing "_log"
else:
    BASE_NAME = _input_stem
# output files placed in same folder as input
OUT_DIR = INPUT_PATH.parent
OUT_TRENDS = OUT_DIR / f"{BASE_NAME}_handle_trend.png"
OUT_TOTAL = OUT_DIR / f"{BASE_NAME}_handle_pressure.png"
OUT_CSV = OUT_DIR / f"{BASE_NAME}_handle_counts.csv"

# === Loader (NDJSON or JSON array) ===
def load_json_objects(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    objs = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        first_nonblank = None
        for line in f:
            if line.strip():
                first_nonblank = line.lstrip()
                break
        f.seek(0)
        if first_nonblank and first_nonblank.startswith("["):
            try:
                objs = json.load(f)
            except json.JSONDecodeError as e:
                raise RuntimeError(f"Failed to parse JSON array: {e}")
        else:
            for i, raw in enumerate(f, 1):
                s = raw.strip()
                if not s:
                    continue
                if s.startswith("\ufeff"):
                    s = s.lstrip("\ufeff")
                try:
                    objs.append(json.loads(s))
                except json.JSONDecodeError as e:
                    print(f"Warning: JSON decode error on line {i}: {e}; preview: {s[:200]!r}", file=sys.stderr)
                    continue
    return objs

# === Extract rows ===
def extract_handle_rows(objs):
    rows = []
    for sample in objs:
        ts_raw = sample.get("timestamp") or sample.get("time") or sample.get("ts")
        try:
            ts = pd.to_datetime(ts_raw)
        except Exception:
            continue
        counters = sample.get("counters") or {}
        # collect keys that look like handle counters but exclude aggregate/total keys
        handle_keys = [
            k for k in counters.keys()
            if (k.endswith("__handle_count") or k.endswith("_handle_count"))
            and (EXCLUDE_SUBSTR not in k)
            and not re.search(r"\b(total|_total_)\b", k, flags=re.IGNORECASE)
        ]

        for k in handle_keys:
            instance = k.replace("__arcspeed_process_", "").replace("__handle_count", "").replace("_handle_count", "")
            handles = counters.get(k, None)
            if handles is None:
                continue
            display_name = instance
            if "svchost" in instance.lower():
                cmd_key = f"__arcspeed_process_{instance}__command_line"
                cmd = counters.get(cmd_key, "") or ""
                match = re.search(r"-k\s+([^\s\"']+)", cmd)
                if match:
                    display_name = f"svchost ({match.group(1)})"
                else:
                    if cmd:
                        short = cmd.strip()[:60].replace("\n", " ")
                        display_name = f"svchost ({short}...)"
            try:
                rows.append({"Timestamp": ts, "Process": display_name, "Handles": int(handles)})
            except Exception:
                # skip non-integer handle values
                continue
    return rows

# === Compute simple linear slope (handles per second) for a series ===
def compute_slope(series_index, series_values):
    """
    Compute linear slope (handles per second) for a time series.
    series_index: pandas Index of timestamps or arraylike of datetimes
    series_values: arraylike of numeric values (handles)
    """
    # Convert index to numpy datetime64[ns] then to seconds since epoch
    idx = pd.to_datetime(series_index)
    # convert to int64 nanoseconds then to seconds (float)
    x = idx.view("int64").astype(float) / 1e9
    y = np.asarray(series_values, dtype=float)

    # mask out NaNs in y or x
    mask = ~np.isnan(y) & ~np.isnan(x)
    if mask.sum() < 2:
        return 0.0

    x = x[mask]
    y = y[mask]

    # linear least squares: y = m*x + b
    A = np.vstack([x, np.ones_like(x)]).T
    m, _ = np.linalg.lstsq(A, y, rcond=None)[0]
    return float(m)


# === Main ===
def main():
    print("Loading JSON objects...")
    objs = load_json_objects(INPUT_PATH)
    print(f"Loaded {len(objs)} JSON objects")
    rows = extract_handle_rows(objs)
    if not rows:
        print("No handle rows parsed. Exiting.", file=sys.stderr)
        return
    df = pd.DataFrame(rows)
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    df = df.sort_values("Timestamp")

    # Determine top processes by peak handle count, exclude _total pseudo-process
    grouped_max = df.groupby("Process")["Handles"].max().sort_values(ascending=False)
    top_processes = [p for p in grouped_max.head(TOP_N + 5).index.tolist() if p != "_total"][:TOP_N]
    print("Top processes:", top_processes)

    # Pivot safely
    df_top = df[df["Process"].isin(top_processes)].copy()
    df_wide = df_top.pivot_table(index="Timestamp", columns="Process", values="Handles", aggfunc="max")
    df_wide = df_wide.sort_index()
    df_wide_ffill = df_wide.ffill()

    # Try to set style (fallback to built-in if not available)
    try:
        plt.style.use(PLOT_STYLE)
    except OSError:
        plt.style.use("dark_background")

    # Combined line chart
    fig, ax = plt.subplots(figsize=(14, 7))
    for proc in top_processes:
        if proc in df_wide_ffill.columns:
            ax.plot(df_wide_ffill.index, df_wide_ffill[proc], marker="o", markersize=3, label=proc)
    ax.set_title("Top Handle Consumers Over Time")
    ax.set_xlabel("Time")
    ax.set_ylabel("Handle Count")
    ax.legend(bbox_to_anchor=(1.02, 1), loc="upper left", fontsize="small")
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d %H:%M:%S"))
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(OUT_TRENDS, dpi=150)
    plt.close(fig)
    print(f"Wrote {OUT_TRENDS}")

    # Total system handle pressure (exclude any _total pseudo-process if present)
    df_total = df[df["Process"] != "_total"].groupby("Timestamp")["Handles"].sum().reset_index().sort_values("Timestamp")
    fig2, ax2 = plt.subplots(figsize=(14, 4))
    ax2.fill_between(df_total["Timestamp"], df_total["Handles"], color="skyblue", alpha=0.4)
    ax2.plot(df_total["Timestamp"], df_total["Handles"], color="Slateblue", alpha=0.8)
    ax2.set_title("Total System Handle Pressure")
    ax2.set_xlabel("Time")
    ax2.set_ylabel("Total Handles")
    ax2.grid(True, alpha=0.3)
    ax2.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d %H:%M:%S"))
    fig2.autofmt_xdate()
    fig2.tight_layout()
    fig2.savefig(OUT_TOTAL, dpi=150)
    plt.close(fig2)
    print(f"Wrote {OUT_TOTAL}")

    # Save wide CSV
    if not df_wide.empty:
        df_wide.to_csv(OUT_CSV, index=True)
        print(f"Wrote {OUT_CSV}")
    else:
        print("Wide DataFrame empty; CSV not written.", file=sys.stderr)

    # Compute and print simple slopes (handles per day) for top processes
    print("\nSimple linear trend (handles per day) for top processes:")
    for proc in top_processes:
        if proc in df_wide.columns:
            series = df_wide_ffill[proc]
            slope_per_sec = compute_slope(series.index.to_numpy(), series.to_numpy())
            slope_per_day = slope_per_sec * 86400.0
            print(f"  {proc:40s} {slope_per_day:8.2f} handles")

    print("Done.")

if __name__ == "__main__":
    main()
