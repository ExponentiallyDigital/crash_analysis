#!/usr/bin/env python3
r"""
Memory Corruption Investigation Report Generator
------------------------------------------------
Usage:
    python C:\Users\andrew\Documents\crash_analysis\ddr5_analyser-report.py -i <input_directory> -o <output.html>

Arguments:
    -i, --input-dir   Directory containing forensic JSON files
                      (produced by ddr5_analyser-extract.ps1)
    -o, --output      Path for the final HTML report

Example:
    python ddr5_analyzer.py -i C:\json -o report.html

Description:
    Reads JSON files produced by the ddr5_analyser-extract.ps1 PowerShell extractor and renders the
    extracted fields: bug check, uptime, SMBIOS/DIMM, WHEA, MCA, PFN, stack/fault context, and
    chain-of-custody metadata.

"""
import argparse
import glob
import html as html_module
import json
import os
import re
import statistics
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone


def parse_args():
    p = argparse.ArgumentParser(description="Render WinDbg-extracted crash data, no commentary")
    p.add_argument("-i", "--input-dir", required=True)
    p.add_argument("-o", "--output", required=True)
    return p.parse_args()


def load_jsons(dir_path):
    crashes, errors = [], []
    paths = sorted(glob.glob(os.path.join(dir_path, "*.json")))
    for f in paths:
        try:
            with open(f, encoding="utf-8") as fh:
                crashes.append((os.path.basename(f), json.load(fh)))
        except Exception as e:
            errors.append((os.path.basename(f), str(e)))
    return crashes, errors, paths


def parse_uptime(extra_raw):
    m = re.search(r"(?:System Uptime|Uptime):\s*(\d+)\s+days?\s*(\d+):(\d+):(\d+)", extra_raw)
    if m:
        days, h, mi, s = map(int, m.groups())
        return timedelta(days=days, hours=h, minutes=mi, seconds=s).total_seconds()
    m = re.search(r"Uptime:\s*(\d+) sec", extra_raw)
    if m:
        return int(m.group(1))
    return None


def extract_smbios_dimms(extra_raw):
    dimms = []
    blocks = re.split(r"(?=Memory Device)", extra_raw)
    for blk in blocks:
        loc = re.search(r"Locator:\s*(.+)", blk)
        bank = re.search(r"Bank Locator:\s*(.+)", blk)
        mfr = re.search(r"Manufacturer:\s*(.+)", blk)
        serial = re.search(r"Serial Number:\s*(.+)", blk)
        part = re.search(r"Part Number:\s*(.+)", blk)
        if loc:
            dimms.append({
                "Slot": loc.group(1).strip(),
                "Bank": bank.group(1).strip() if bank else "?",
                "Manufacturer": mfr.group(1).strip() if mfr else "?",
                "Serial": serial.group(1).strip() if serial else "?",
                "PartNumber": part.group(1).strip() if part else "?",
            })
    return dimms


def parse_pfn_anomalies(pfn_list):
    # Matches real WinDbg !pfn output: bare trailing state word, "reference
    # count N" lowercase with a space (no "PageLocation:"/"ReferenceCount:"
    # labels exist in real output).
    anomalies = []
    state_words = ("Free", "Zeroed", "Standby", "Modified", "ModifiedNoWrite",
                    "Active", "Transition", "Bad")
    for entry in pfn_list:
        raw = entry.get("RawOutput", "") or ""
        pfn = entry.get("PFN", "?")
        ref_match = re.search(r"reference count\s+([0-9a-fA-F]+)", raw, re.I)
        state_match = re.search(r"\b(" + "|".join(state_words) + r")\b", raw)
        if not state_match:
            continue
        location = state_match.group(1)
        ref_count = int(ref_match.group(1), 16) if ref_match else 0
        if location == "Free" and ref_count > 0:
            anomalies.append(f"PFN {pfn}: marked Free but reference count is {ref_count}")
        if location == "Active" and ref_count == 0:
            anomalies.append(f"PFN {pfn}: Active but reference count is 0")
    return anomalies


def parse_bios_version(extra_raw):
    m = re.search(r"BIOS\s+Version\s*:?\s*(.+)", extra_raw, re.I)
    if m:
        return m.group(1).strip()
    m = re.search(r"SMBIOS\s+Version\s*:?\s*(.+)", extra_raw, re.I)
    if m:
        return m.group(1).strip()
    return None


def parse_agesa(extra_raw):
    m = re.search(r"AGESA\s*:?\s*(.+)", extra_raw, re.I)
    if m:
        return m.group(1).strip()
    m = re.search(r"(ComboAM5\s*PI\s*[\d.]+[a-z]?)", extra_raw, re.I)
    if m:
        return m.group(1).strip()
    return None


def esc(t):
    return html_module.escape(str(t)) if t is not None else ""


def main():
    args = parse_args()
    crashes, load_errors, found_paths = load_jsons(args.input_dir)

    print(f"Input dir: {args.input_dir}", file=sys.stderr)
    print(f"JSON files found: {len(found_paths)}", file=sys.stderr)
    for fname, err in load_errors:
        print(f"  FAILED TO PARSE: {fname}: {err}", file=sys.stderr)
    print(f"JSON files loaded OK: {len(crashes)}", file=sys.stderr)

    if not crashes:
        print("No usable JSON files. Nothing to report.", file=sys.stderr)
        print("If you expected data here: check the PowerShell extractor's own", file=sys.stderr)
        print("console output for 'No BugCheck line in <file>' warnings. That", file=sys.stderr)
        print("extractor SKIPS a dump entirely (writes no JSON at all) if !analyze -v", file=sys.stderr)
        print("output didn't match its expected BugCheck line patterns. That is the", file=sys.stderr)
        print("most common reason for zero, or fewer, JSON files than .dmp files.", file=sys.stderr)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(
                "<!DOCTYPE html><html><body><h1>No data</h1>"
                f"<p>0 usable JSON files loaded from {esc(args.input_dir)}. "
                f"{len(found_paths)} .json file(s) were found on disk. "
                f"{len(load_errors)} failed to parse as JSON.</p>"
                "<p>Check the PowerShell extractor's console output for "
                "&quot;No BugCheck line&quot; warnings: it writes no JSON file "
                "for a dump if !analyze -v output did not match the expected "
                "patterns.</p></body></html>"
            )
        print(f"Wrote {args.output}", file=sys.stderr)
        return

    per_dump = []
    counts = Counter()
    for fname, data in crashes:
        try:
            ana = data.get("Analysis", {}) or {}
            bc = ana.get("BugCheck", {}) or {}
            fore = data.get("Forensics", {}) or {}
            extra = fore.get("ExtraRaw", "") or ""
            ext_meta = data.get("ExtractionMetadata", {}) or {}

            uptime = parse_uptime(extra)
            dimms = extract_smbios_dimms(extra)
            bios = parse_bios_version(extra)
            agesa = parse_agesa(extra)
            whea = fore.get("WHEA_Errors", []) or []
            mca = fore.get("MCA_Entries", []) or []
            pfn_details = fore.get("PFNDetails", []) or []
            pfn_anoms = parse_pfn_anomalies(pfn_details)
            params = bc.get("Parameters", []) or []
            arg1 = params[0].get("value") if params else None

            counts["files"] += 1
            counts["has_bugcheck"] += 1 if bc.get("Code") else 0
            counts["has_uptime"] += 1 if uptime is not None else 0
            counts["has_dimms"] += 1 if dimms else 0
            counts["has_bios"] += 1 if bios else 0
            counts["has_agesa"] += 1 if agesa else 0
            counts["has_whea"] += 1 if whea else 0
            counts["has_mca"] += 1 if mca else 0
            counts["has_pfn_details"] += 1 if pfn_details else 0
            counts["has_pfn_anomaly"] += 1 if pfn_anoms else 0
            counts["has_bucketid"] += 1 if ana.get("BucketId") else 0
            counts["has_faultingip"] += 1 if ana.get("FaultingIP") else 0
            counts["has_stack"] += 1 if ana.get("StackText") else 0

            per_dump.append({
                "file": fname,
                "sha256": data.get("SHA256"),
                "os_version": data.get("OSVersion"),
                "bugcheck_code": bc.get("Code"),
                "bugcheck_name": bc.get("Name"),
                "params": params,
                "arg1": arg1,
                "uptime_sec": uptime,
                "bios": bios,
                "agesa": agesa,
                "dimms": dimms,
                "whea": whea,
                "mca": mca,
                "pfn_details": pfn_details,
                "pfn_anoms": pfn_anoms,
                "faulting_ip": ana.get("FaultingIP"),
                "process_name": ana.get("ProcessName"),
                "image_name": ana.get("ImageName"),
                "bucket_id": ana.get("BucketId"),
                "stack": ana.get("StackText") or [],
                "registers": ana.get("Registers") or {},
                "extractor_ver": ext_meta.get("ExtractorVersion"),
                "extraction_time": ext_meta.get("ExtractionUTC"),
                "file_size": ext_meta.get("OriginalFileSize"),
            })
        except Exception as e:
            print(f"  WARNING: failed to process {fname}: {e}", file=sys.stderr)
            continue

    uptimes = [d["uptime_sec"] for d in per_dump if d["uptime_sec"] is not None]
    bugcheck_counts = Counter(
        f"{d['bugcheck_code'] or ''} {d['bugcheck_name'] or ''}".strip()
        for d in per_dump if d["bugcheck_code"]
    )
    bucket_counts = Counter(d["bucket_id"] for d in per_dump if d["bucket_id"])
    arg1_counts = Counter(d["arg1"] for d in per_dump if d["arg1"])
    serial_counts = Counter(dm["Serial"] for d in per_dump for dm in d["dimms"])

    out = []
    out.append("<!DOCTYPE html><html><head><meta charset='UTF-8'>")
    out.append("<title>WinDbg Crash Data Report</title><style>")
    out.append("body{font-family:Consolas,Menlo,monospace;margin:20px;font-size:14px}")
    out.append("table{border-collapse:collapse;width:100%;margin:8px 0}")
    out.append("th,td{border:1px solid #999;padding:4px 8px;text-align:left;vertical-align:top}")
    out.append("th{background:#eee}")
    out.append("h1,h2,h3{margin-top:24px}")
    out.append(".mono{font-family:Consolas,Menlo,monospace;font-size:0.85em}")
    out.append(".small{font-size:0.85em;color:#555}")
    out.append("pre{white-space:pre-wrap;font-size:0.8em;background:#f7f7f7;padding:8px}")
    out.append("</style></head><body>")

    out.append("<h1>WinDbg Crash Data Report</h1>")
    out.append(
        f"<p class='small'>Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC "
        f"from {esc(args.input_dir)} | {len(crashes)} JSON file(s) loaded</p>"
    )

    out.append("<h2>Extraction diagnostics</h2><table>")
    out.append("<tr><th>Field</th><th>Present</th><th>/ Total</th></tr>")
    n = counts["files"]
    for label, key in [
        ("BugCheck code parsed", "has_bugcheck"),
        ("Uptime parsed", "has_uptime"),
        ("SMBIOS DIMM data parsed", "has_dimms"),
        ("BIOS version parsed", "has_bios"),
        ("AGESA parsed", "has_agesa"),
        ("WHEA records present", "has_whea"),
        ("MCA records present", "has_mca"),
        ("PFN details present", "has_pfn_details"),
        ("PFN anomaly flagged", "has_pfn_anomaly"),
        ("Bucket ID present", "has_bucketid"),
        ("Faulting IP present", "has_faultingip"),
        ("Stack text present", "has_stack"),
    ]:
        out.append(f"<tr><td>{label}</td><td>{counts[key]}</td><td>{n}</td></tr>")
    out.append("</table>")
    if load_errors:
        out.append(
            "<p class='small'>" + f"{len(load_errors)} file(s) found but failed to parse as JSON: "
            + ", ".join(esc(f) for f, _ in load_errors) + "</p>"
        )

    out.append("<h2>Bug check code frequency</h2><table><tr><th>Bug check</th><th>Count</th></tr>")
    if bugcheck_counts:
        for k, v in bugcheck_counts.most_common():
            out.append(f"<tr><td>{esc(k)}</td><td>{v}</td></tr>")
    else:
        out.append("<tr><td colspan='2'>none extracted</td></tr>")
    out.append("</table>")

    out.append("<h2>DEFAULT_BUCKET_ID frequency</h2><table><tr><th>Bucket ID</th><th>Count</th></tr>")
    if bucket_counts:
        for k, v in bucket_counts.most_common():
            out.append(f"<tr><td class='mono'>{esc(k)}</td><td>{v}</td></tr>")
    else:
        out.append("<tr><td colspan='2'>none extracted</td></tr>")
    out.append("</table>")

    out.append("<h2>Uptime</h2><table><tr><th>Metric</th><th>Value</th></tr>")
    out.append(f"<tr><td>Count parsed</td><td>{len(uptimes)} / {n}</td></tr>")
    if uptimes:
        out.append(f"<tr><td>Mean</td><td>{timedelta(seconds=int(statistics.mean(uptimes)))}</td></tr>")
        out.append(f"<tr><td>Median</td><td>{timedelta(seconds=int(statistics.median(uptimes)))}</td></tr>")
        if len(uptimes) > 1:
            out.append(f"<tr><td>Std dev</td><td>{timedelta(seconds=int(statistics.stdev(uptimes)))}</td></tr>")
        out.append(
            f"<tr><td>Range</td><td>{timedelta(seconds=int(min(uptimes)))} "
            f"to {timedelta(seconds=int(max(uptimes)))}</td></tr>"
        )
    out.append("</table>")

    out.append("<h2>Arg1 / faulting virtual address frequency</h2><table><tr><th>Address</th><th>Count</th></tr>")
    if arg1_counts:
        for k, v in arg1_counts.most_common():
            out.append(f"<tr><td class='mono'>{esc(k)}</td><td>{v}</td></tr>")
    else:
        out.append("<tr><td colspan='2'>none extracted</td></tr>")
    out.append("</table>")

    out.append("<h2>SMBIOS DIMM serial frequency</h2><table><tr><th>Serial</th><th>Count</th></tr>")
    if serial_counts:
        for k, v in serial_counts.most_common():
            out.append(f"<tr><td class='mono'>{esc(k)}</td><td>{v}</td></tr>")
    else:
        out.append("<tr><td colspan='2'>none extracted</td></tr>")
    out.append("</table>")

    out.append("<h2>Per-dump summary</h2><table>")
    out.append(
        "<tr><th>#</th><th>File</th><th>BugCheck</th><th>Arg1</th><th>Uptime</th>"
        "<th>OS</th><th>BIOS</th><th>AGESA</th><th>Bucket ID</th><th>SHA256</th>"
        "<th>Size</th><th>Extracted (UTC)</th></tr>"
    )
    for i, d in enumerate(per_dump, 1):
        uptime_disp = str(timedelta(seconds=int(d["uptime_sec"]))) if d["uptime_sec"] is not None else ""
        out.append(
            f"<tr><td>{i}</td><td>{esc(d['file'])}</td>"
            f"<td>{esc(d['bugcheck_code'])} {esc(d['bugcheck_name'])}</td>"
            f"<td class='mono'>{esc(d['arg1'])}</td><td>{uptime_disp}</td>"
            f"<td>{esc(d['os_version'])}</td><td>{esc(d['bios'])}</td><td>{esc(d['agesa'])}</td>"
            f"<td class='mono'>{esc(d['bucket_id'])}</td>"
            f"<td class='mono' style='font-size:0.7em'>{esc(d['sha256'])}</td>"
            f"<td>{esc(d['file_size'])}</td><td>{esc(d['extraction_time'])}</td></tr>"
        )
    out.append("</table>")

    for i, d in enumerate(per_dump, 1):
        out.append(f"<h2>{esc(d['file'])}</h2>")

        out.append("<h3>Fault context</h3><table>")
        for label, val in [
            ("Process", d["process_name"]), ("Image", d["image_name"]),
            ("Faulting IP", d["faulting_ip"]), ("Bucket ID", d["bucket_id"]),
        ]:
            out.append(f"<tr><td>{label}</td><td class='mono'>{esc(val)}</td></tr>")
        out.append("</table>")

        if d["stack"]:
            out.append("<h3>Stack text</h3><pre>" + esc("\n".join(d["stack"])) + "</pre>")

        if d["registers"]:
            out.append("<h3>Registers</h3><table>")
            for k, v in d["registers"].items():
                out.append(f"<tr><td>{esc(k)}</td><td class='mono'>{esc(v)}</td></tr>")
            out.append("</table>")

        if d["dimms"]:
            out.append(
                "<h3>SMBIOS DIMMs</h3><table><tr><th>Slot</th><th>Bank</th>"
                "<th>Manufacturer</th><th>Serial</th><th>Part number</th></tr>"
            )
            for dm in d["dimms"]:
                out.append(
                    f"<tr><td>{esc(dm['Slot'])}</td><td>{esc(dm['Bank'])}</td>"
                    f"<td>{esc(dm['Manufacturer'])}</td><td class='mono'>{esc(dm['Serial'])}</td>"
                    f"<td>{esc(dm['PartNumber'])}</td></tr>"
                )
            out.append("</table>")

        if d["whea"]:
            out.append(
                "<h3>WHEA errors</h3><table><tr><th>Bank</th><th>Rank</th><th>Row</th>"
                "<th>Column</th><th>Bit</th><th>Physical addr</th></tr>"
            )
            for e in d["whea"]:
                out.append(
                    f"<tr><td>{esc(e.get('Bank'))}</td><td>{esc(e.get('Rank'))}</td>"
                    f"<td>{esc(e.get('Row'))}</td><td>{esc(e.get('Column'))}</td>"
                    f"<td>{esc(e.get('BitPosition'))}</td><td class='mono'>{esc(e.get('PhysicalAddress'))}</td></tr>"
                )
            out.append("</table>")

        if d["mca"]:
            out.append("<h3>MCA entries</h3><table><tr><th>Bank</th><th>Status</th><th>Address</th></tr>")
            for e in d["mca"]:
                out.append(
                    f"<tr><td>{esc(e.get('Bank'))}</td><td class='mono'>{esc(e.get('Status'))}</td>"
                    f"<td class='mono'>{esc(e.get('Address'))}</td></tr>"
                )
            out.append("</table>")

        if d["pfn_anoms"]:
            out.append("<h3>PFN anomalies (flagged)</h3><ul>")
            for a in d["pfn_anoms"]:
                out.append(f"<li>{esc(a)}</li>")
            out.append("</ul>")

        if d["pfn_details"]:
            out.append("<h3>PFN raw details</h3><pre>" + esc(
                "\n\n".join(f"PFN {p.get('PFN')}:\n{p.get('RawOutput')}" for p in d["pfn_details"])
            ) + "</pre>")

    out.append("<h2>Raw JSON</h2>")
    for fname, data in crashes:
        out.append(f"<h3>{esc(fname)}</h3><pre>{esc(json.dumps(data, indent=2))}</pre>")

    out.append("</body></html>")

    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(out))

    print(f"Wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
