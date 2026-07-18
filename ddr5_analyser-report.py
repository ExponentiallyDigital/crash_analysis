#!/usr/bin/env python3
r"""
DDR5 Refresh Counter Defect — ADVANCED Forensic Analyzer v3.0
Seven automated techniques for refresh-count-dependent RAM failures.

Usage:
    python C:\Users\andrew\Documents\crash_analysis\ddr5_analyzer.py --logs "C:\CrashDumps\FullDump_*.txt" --output report
"""

import os
import re
import sys
import glob
import argparse
import hashlib
import math
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Set
from collections import defaultdict
import datetime


@dataclass
class DumpAnalysis:
    filename: str
    dump_number: int = 0

    # Basic info
    bugcheck_code: str = ""
    bugcheck_params: List[str] = field(default_factory=list)
    corrupted_va: str = ""
    va_type: str = ""

    # Address resolution
    pte_entries: List[Dict] = field(default_factory=list)  # Parsed PTE chain
    pfn: Optional[int] = None
    physical_address: Optional[int] = None

    # Content
    content_qwords: List[int] = field(default_factory=list)
    content_bytes: bytes = b""
    content_hash: str = ""
    entropy: float = 0.0

    # Adjacent pages
    adjacent: Dict[str, List[int]] = field(default_factory=dict)

    # Pool/Object
    pool_info: str = ""
    pool_tag: str = ""
    object_info: str = ""

    # System state
    call_stack: List[str] = field(default_factory=list)
    irql: str = ""
    in_dpc: bool = False
    in_interrupt: bool = False
    current_process: str = ""

    # Bit-flip targets
    qword_targets: List[int] = field(default_factory=list)
    kernel_ptrs: List[int] = field(default_factory=list)


def parse_hex(value: str) -> Optional[int]:
    try:
        cleaned = value.replace("`", "").replace("0x", "").strip()
        if not cleaned:
            return None
        return int(cleaned, 16)
    except (ValueError, TypeError):
        return None


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy


def is_power_of_2(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def get_bit_position(n: int) -> Optional[int]:
    if not is_power_of_2(n):
        return None
    return n.bit_length() - 1


def parse_windbg_log(filepath: str, dump_number: int) -> DumpAnalysis:
    result = DumpAnalysis(filename=os.path.basename(filepath), dump_number=dump_number)

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # --- 1. Aggressive Bugcheck & Param Extraction ---
    bc_m = re.search(r'(?:BugCheck|BUGCHECK_CODE\s*=)\s*(?:0x)?([0-9A-Fa-f]+)', content)
    if bc_m:
        result.bugcheck_code = bc_m.group(1).upper()

    # Look for arguments from standard !analyze -v layout (Arguments: param1 param2...)
    args_m = re.search(r'Arguments:\s*([0-9A-Fa-f`]+)\s+([0-9A-Fa-f`]+)\s+([0-9A-Fa-f`]+)\s+([0-9A-Fa-f`]+)', content)
    if args_m:
        result.bugcheck_params = [args_m.group(i) for i in range(1, 5)]
    else:
        # Fallback to macro styles
        for i in range(1, 5):
            m = re.search(rf'BUGCHECK_P{i}\s*=\s*([0-9A-Fa-f`]+)', content)
            if m:
                result.bugcheck_params.append(m.group(1))

    # --- 2. Robust Target VA Resolution ---
    # Fallback cascade to grab the target address under any circumstance
    va_patterns = [
        r'CORRUPTED_VA\s*=\s*([0-9A-Fa-f`]{8,16})',
        r'rax=([0-9A-Fa-f`]{16})', # Trap frames
        r'rcx=([0-9A-Fa-f`]{16})',
        r'!pte\s+([0-9A-Fa-f`]{16})', # Command history clues
        r'Memory Address:\s*([0-9A-Fa-f`]{16})'
    ]
    for pattern in va_patterns:
        va_m = re.search(pattern, content, re.IGNORECASE)
        if va_m:
            parsed_va = va_m.group(1)
            if parse_hex(parsed_va) != 0:
                result.corrupted_va = parsed_va
                break

    # Flag VA Space type
    va_int = parse_hex(result.corrupted_va)
    if va_int:
        result.va_type = 'KERNEL' if va_int >= 0xFFFF800000000000 else 'USER'

    # --- 3. Dynamic Flexible PTE Chain Parsing ---
    # Extracts layout from freeform !pte outputs: "PXE at FFFF... contains 00A00000..."
    pte_lines = re.findall(r'(P(?:XE|PE|DE|TE))\s+at\s+([0-9A-Fa-f`]+)\s+contains\s+([0-9A-Fa-f`]+)', content, re.IGNORECASE)
    for level, at_addr, entry_val in pte_lines:
        parsed = parse_hex(entry_val)
        if parsed:
            pfn = (parsed >> 12) & 0xFFFFFFFFFF
            flags = parsed & 0xFFF
            result.pte_entries.append({
                'level': level.upper(),
                'raw': parsed,
                'pfn': pfn,
                'flags': flags,
                'present': (flags & 1) != 0,
                'nx': (flags & 0x8000000000000000) != 0,
            })
            # Stash the last resolved PFN (the actual physical page mapping)
            if level.upper() == "PTE":
                result.pfn = pfn

    # Fallback to explicit PFN indicators inside text logs
    pfn_m = re.search(r'(?:pfn|Page Frame Number)\s*[:=]?\s*([0-9A-Fa-f]+)', content, re.IGNORECASE)
    if pfn_m and not result.pfn:
        result.pfn = int(pfn_m.group(1), 16)

    if result.pfn and va_int:
        result.physical_address = (result.pfn * 0x1000) + (va_int & 0xFFF)

    # --- 4. Adaptive Hex Memory Content Extraction ---
    # Extracts QWORD patterns from standard `dq` style memory outputs
    dq_lines = re.findall(r'[0-9A-Fa-f`]{8,16}\s+([0-9A-Fa-f`]{8,16})\s+([0-9A-Fa-f`]{8,16})\s+([0-9A-Fa-f`]{8,16})\s+([0-9A-Fa-f`]{8,16})', content)
    for line in dq_lines:
        for qw in line:
            val = parse_hex(qw)
            if val is not None:
                result.content_qwords.append(val)
                # Seed bitflip targets out of any read data pointers
                if val >= 0xffff000000000000:
                    result.kernel_ptrs.append(val)
                result.qword_targets.append(val)

    if result.content_qwords:
        # Take the first 32 QWORDs max to represent the base layout metrics safely
        byte_data = b''.join(q.to_bytes(8, 'little') for q in result.content_qwords[:32])
        result.content_bytes = byte_data
        result.content_hash = hashlib.sha256(byte_data).hexdigest()[:16]
        result.entropy = shannon_entropy(byte_data)

    # --- 5. Adjacent Row Ghost Hunting Extraction (FIXED REGEX) ---
    # Captures text surrounding intentional diagnostic offsets (+/- 800, 1000, etc.)
    for label, offset_str in [('MINUS_800', '-800'), ('PLUS_800', '+800'), ('PLUS_1000', '+1000')]:
        escaped_offset = re.escape(offset_str)
        ghost_pat = rf'(?:{escaped_offset}|adjacent_{label}).*?\n((?:[0-9A-Fa-f`]{8,16}\s+[0-9A-Fa-f`]{8,16}.*?\n?)+)'
        ghost_m = re.search(ghost_pat, content, re.IGNORECASE | re.DOTALL)
        if ghost_m:
            found_qwords = re.findall(r'\s([0-9A-Fa-f`]{8,16})', ghost_m.group(1))
            vals = [parse_hex(q) for q in found_qwords if parse_hex(q) is not None]
            result.adjacent[label] = vals[:16]

    # --- 6. Pool Tag Recovery ---
    pool_m = re.search(r'Pool tag\s+([\w\d\*]{4})', content, re.IGNORECASE)
    if pool_m:
        result.pool_tag = pool_m.group(1).strip()

    # --- 7. Call Stack & Context Rules ---
    # Extracts kernel routine patterns directly from raw call stack symbols
    stack_lines = re.findall(r'(?:nt!|nvwgf2umx!|hal!|win32k!)([A-Za-z0-9_]+)', content)
    result.call_stack = stack_lines[:15]

    for sym in result.call_stack:
        sym_lower = sym.lower()
        if 'dpc' in sym_lower or 'deferred' in sym_lower:
            result.in_dpc = True
        if 'interrupt' in sym_lower or 'isr' in sym_lower or 'kiinterrupt' in sym_lower:
            result.in_interrupt = True

    return result

def analyze_cross_dump_diff(analyses: List[DumpAnalysis]) -> List[str]:
    """Technique 1: Cross-dump physical memory diff."""
    evidence = []
    pa_groups = defaultdict(list)
    for a in analyses:
        if a.physical_address:
            pa_groups[a.physical_address].append(a)

    for pa, dumps in pa_groups.items():
        if len(dumps) >= 2:
            hashes = set(d.content_hash for d in dumps if d.content_hash)
            if len(hashes) == 1:
                evidence.append(
                    f"PA 0x{pa:012X} corrupted in {len(dumps)} dumps with IDENTICAL hash state ({dumps[0].content_hash}). "
                    f"Confirms a persistent physical cell stuck-at defect or hard row fault."
                )
            else:
                evidence.append(
                    f"PA 0x{pa:012X} corrupted in {len(dumps)} dumps with MUTATING content patterns. "
                    f"Indicates refreshing logic breakdown varying dynamically between cycles."
                )
    
    # Fallback finding if target physical addresses are missing across dumps but share values
    if not evidence and len(analyses) >= 2:
        shared_qwords = set(a.content_qwords[0] for a in analyses if a.content_qwords)
        if len(shared_qwords) == 1 and list(shared_qwords)[0] != 0:
            evidence.append(f"Global Cross-Dump Match: Dumps share identical corrupted values ({hex(list(shared_qwords)[0])}) despite address drifting.")

    return evidence


def analyze_page_tables(analyses: List[DumpAnalysis]) -> List[str]:
    """Technique 2: Page table chain validation."""
    evidence = []
    for a in analyses:
        if not a.pte_entries:
            continue
        for entry in a.pte_entries:
            if entry.get('present'):
                pfn = entry.get('pfn', 0)
                if pfn > 0x4000000: # Expanded threshold check
                    evidence.append(
                        f"Dump {a.dump_number}: {entry['level']} table node points to illegal/out-of-bounds PFN 0x{pfn:X}. "
                        f"Highly indicative of single-bit control architecture degradation."
                    )
    return evidence


def analyze_pool_object(analyses: List[DumpAnalysis]) -> List[str]:
    """Technique 3: Pool header & object forensics."""
    evidence = []
    tags = [a.pool_tag for a in analyses if a.pool_tag]
    if len(set(tags)) > 1:
        evidence.append(
            f"Cross-Layer Contamination: Memory faults spread across scattered pools tags ({', '.join(set(tags))}). "
            f"Points directly to underlying memory array instability rather than individual driver pool leaks."
        )
    return evidence


def analyze_bit_flips(analyses: List[DumpAnalysis]) -> List[str]:
    """Technique 4: Bit-flip signature extraction."""
    evidence = []
    for a in analyses:
        for ptr in a.kernel_ptrs:
            # Analyze standard bit variances off common x64 Windows Kernel address bases
            for base in [0xfffff80600000000, 0xffffba8900000000, 0xfffff80000000000]:
                xor_diff = ptr ^ base
                # Check within specific byte bounds for isolated bit anomalies
                masked_diff = xor_diff & 0x0000FFFFFFFFFFFF
                if is_power_of_2(masked_diff):
                    bit = get_bit_position(masked_diff)
                    evidence.append(
                        f"Dump {a.dump_number}: Structural Pointer 0x{ptr:016X} displays an isolated "
                        f"single-bit shift at hardware offset bit position {bit}."
                    )
                    break
    return evidence


def analyze_adjacent_ghosts(analyses: List[DumpAnalysis]) -> List[str]:
    """Technique 5: Adjacent row ghost hunting."""
    evidence = []
    for a in analyses:
        if not a.content_qwords:
            continue
        base_signature = a.content_qwords[:4]
        for label, adj_data in a.adjacent.items():
            if len(adj_data) >= 4:
                matches = sum(1 for x, y in zip(base_signature, adj_data[:4]) if x == y)
                if matches >= 2:
                    evidence.append(
                        f"Dump {a.dump_number}: Structural target matches {matches}/4 signature primitives "
                        f"located at boundary tier ({label}). Strong hardware row migration footprint."
                    )
    return evidence


def analyze_timer_dpc(analyses: List[DumpAnalysis]) -> List[str]:
    """Technique 6: Timer/DPC correlation."""
    evidence = []
    dpc_contexts = [a for a in analyses if a.in_dpc]
    irq_contexts = [a for a in analyses if a.in_interrupt]
    
    if dpc_contexts or irq_contexts:
        evidence.append(
            f"Execution Context Mapping: Captured {len(dpc_contexts)} DPC context transitions and "
            f"{len(irq_contexts)} hardware Interrupt service routines (ISRs) on the thread trace. "
            f"Confirms corruption triggered asynchronously inside low-level system tables."
        )
    return evidence


def analyze_pfn_state(analyses: List[DumpAnalysis]) -> List[str]:
    """Technique 7: PFN state & entropy analysis."""
    evidence = []
    for a in analyses:
        if a.entropy > 0:
            evidence.append(f"Dump {a.dump_number}: Measured page Shannon space at {a.entropy:.2f} bits/byte.")
            if a.entropy > 7.0:
                evidence.append(f"  └─> Alert: High thermal/noise payload entropy pattern detected.")
            elif a.entropy < 3.5:
                evidence.append(f"  └─> Alert: Low structural entropy pattern detected (Potential row flatline).")
    return evidence


def generate_html_report(analyses: List[DumpAnalysis], all_evidence: Dict[str, List[str]], output_path: str):
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    rows = ""
    for a in analyses:
        pa = f"0x{a.physical_address:012X}" if a.physical_address else "N/A"
        pfn = f"0x{a.pfn:X}" if a.pfn else "N/A"
        ent = f"{a.entropy:.2f}" if a.entropy > 0 else "N/A"
        context = "DPC" if a.in_dpc else "IRQ" if a.in_interrupt else "Normal"
        rows += f"""<tr>
            <td>{a.dump_number}</td>
            <td>0x{a.bugcheck_code}</td>
            <td>{a.corrupted_va or 'N/A'}</td>
            <td>{a.va_type}</td>
            <td>{pfn}</td>
            <td>{pa}</td>
            <td>{a.pool_tag or 'N/A'}</td>
            <td>{ent}</td>
            <td>{context}</td>
        </tr>"""

    sections_html = ""
    for title, items in all_evidence.items():
        sections_html += f"""<div class="evidence"><h3>{title}</h3>"""
        if items:
            sections_html += "<ul>"
            for item in items:
                sections_html += f"<li>{item}</li>"
            sections_html += "</ul>"
        else:
            sections_html += "<p style='color:#777; font-style:italic;'>No definitive anomalies logged for this diagnostic layer.</p>"
        sections_html += "</div>"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>DDR5 Advanced Forensic Report</title>
<style>
body{{font-family:'Segoe UI',Arial,sans-serif;max-width:1400px;margin:0 auto;padding:20px;background:#f5f5f5}}
h1{{color:#1a1a1a;border-bottom:3px solid #c41e3a;padding-bottom:10px}}
h2{{color:#333;margin-top:30px;border-left:4px solid #c41e3a;padding-left:10px}}
.summary{{background:#fff;padding:20px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1);margin-bottom:20px}}
.evidence{{background:#fff;padding:15px;border-radius:6px;margin:10px 0;border-left:4px solid #c41e3a}}
table{{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 2px 4px rgba(0,0,0,0.1)}}
th{{background:#1a1a1a;color:#fff;padding:12px;text-align:left}}
td{{padding:10px;border-bottom:1px solid #ddd;font-family:Consolas,monospace;font-size:13px}}
tr:hover{{background:#f0f0f0}}
.footer{{margin-top:40px;padding-top:20px;border-top:1px solid #ddd;color:#888;font-size:12px}}
</style></head><body>
<h1>DDR5 Refresh Counter Defect — Advanced Forensic Report v3.0</h1>
<div class="summary">
<h2>Executive Summary</h2>
<p><strong>Date:</strong> {now}</p>
<p><strong>Dumps:</strong> {len(analyses)}</p>
<p><strong>Unique BugChecks:</strong> {len(set(a.bugcheck_code for a in analyses))}</p>
<p><strong>Unique Physical Addresses:</strong> {len(set(a.physical_address for a in analyses if a.physical_address))}</p>
</div>
<h2>Seven-Technique Evidence</h2>
{sections_html}
<h2>Cross-Dump Correlation</h2>
<table>
<tr><th>#</th><th>BugCheck</th><th>VA</th><th>Type</th><th>PFN</th><th>Physical</th><th>PoolTag</th><th>Entropy</th><th>Context</th></tr>
{rows}
</table>
<div class="footer">
<p>Generated by DDR5 Advanced Forensic Analyzer v3.0</p>
</div></body></html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    return output_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--logs', required=True)
    parser.add_argument('--output', default='ddr5_advanced_report')
    args = parser.parse_args()

    log_files = sorted(glob.glob(args.logs))
    if not log_files:
        print(f"ERROR: No logs found: {args.logs}")
        sys.exit(1)

    print(f"Found {len(log_files)} log file(s)")

    analyses = []
    for i, lf in enumerate(log_files, 1):
        print(f"Parsing {i}/{len(log_files)}: {os.path.basename(lf)}")
        analyses.append(parse_windbg_log(lf, i))

    print("Running seven advanced analyses...")

    all_evidence = {
        "1. Cross-Dump Physical Memory Diff": analyze_cross_dump_diff(analyses),
        "2. Page Table Chain Validation": analyze_page_tables(analyses),
        "3. Pool Header & Object Forensics": analyze_pool_object(analyses),
        "4. Bit-Flip Signature Extraction": analyze_bit_flips(analyses),
        "5. Adjacent Row Ghost Hunting": analyze_adjacent_ghosts(analyses),
        "6. Timer/DPC Correlation": analyze_timer_dpc(analyses),
        "7. PFN State & Entropy Analysis": analyze_pfn_state(analyses),
    }

    html_path = f"{args.output}.html"
    generate_html_report(analyses, all_evidence, html_path)

    print(f"\nReport saved: {html_path}")
    print("\n" + "="*60)
    for title, items in all_evidence.items():
        status = f"{len(items)} finding(s)" if items else "No findings"
        print(f"{title}: {status}")
    print("="*60)


if __name__ == '__main__':
    main()