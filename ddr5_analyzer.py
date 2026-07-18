#!/usr/bin/env python3
"""
DDR5 Refresh Counter Defect — ADVANCED Forensic Analyzer v2.0
Seven automated techniques for refresh-count-dependent RAM failures.

Usage:
    python ddr5_analyzer.py --logs "C:\CrashDumps\ddr5_analyser_*.txt" --output report
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

    # --- Bugcheck ---
    bc = re.search(r'BUGCHECK_CODE\s*=\s*0x([0-9A-Fa-f]+)', content)
    if bc:
        result.bugcheck_code = bc.group(1).upper()

    for i in range(1, 5):
        m = re.search(rf'BUGCHECK_P{i}\s*=\s*([0-9A-Fa-f`]+)', content)
        if m:
            result.bugcheck_params.append(m.group(1))

    # --- VA ---
    va_m = re.search(r'CORRUPTED_VA\s*=\s*([0-9A-Fa-f`]+)', content)
    if va_m:
        result.corrupted_va = va_m.group(1)

    vt = re.search(r'VA_TYPE\s*=\s*(\w+)', content)
    if vt:
        result.va_type = vt.group(1)

    # --- PTE Chain Parsing ---
    pte_section = re.search(r'###SECTION:CORRUPTION###(.*?)###SECTION:PFN###', content, re.DOTALL)
    if pte_section:
        pte_text = pte_section.group(1)
        # Extract each PTE level: "PTE at FFFF... contains 00000000`00000000"
        levels = re.findall(r'(P[DMLE][EP]?\s+at\s+[0-9A-Fa-f`]+)\s+contains\s+([0-9A-Fa-f`]+)', pte_text)
        for level_name, entry_val in levels:
            parsed = parse_hex(entry_val)
            if parsed:
                pfn = (parsed >> 12) & 0xFFFFFFFFFF
                flags = parsed & 0xFFF
                result.pte_entries.append({
                    'level': level_name.strip(),
                    'raw': parsed,
                    'pfn': pfn,
                    'flags': flags,
                    'present': (flags & 1) != 0,
                    'nx': (flags & 0x8000000000000000) != 0,
                })
        # Also try !vtop output
        vtop_match = re.search(r'pfn\s+([0-9A-Fa-f]+)', pte_text, re.IGNORECASE)
        if vtop_match and not result.pfn:
            result.pfn = int(vtop_match.group(1), 16)

    # --- PFN ---
    pfn_section = re.search(r'###SECTION:PFN###(.*?)###SECTION:CONTENT###', content, re.DOTALL)
    if pfn_section:
        pfn_m = re.search(r'pfn\s+([0-9A-Fa-f]+)', pfn_section.group(1), re.IGNORECASE)
        if pfn_m:
            result.pfn = int(pfn_m.group(1), 16)

    if result.pfn and result.corrupted_va:
        va_val = parse_hex(result.corrupted_va)
        if va_val:
            result.physical_address = (result.pfn * 0x1000) + (va_val & 0xFFF)

    # --- Content ---
    content_section = re.search(r'DUMP_START_VA\s*=\s*([0-9A-Fa-f`]+)(.*?)(?=###SECTION:ADJACENT###)', content, re.DOTALL)
    if content_section:
        qwords = re.findall(r'[0-9A-Fa-f`]+\s+([0-9A-Fa-f`]+)\s+([0-9A-Fa-f`]+)\s+([0-9A-Fa-f`]+)\s+([0-9A-Fa-f`]+)', content_section.group(2))
        for line in qwords:
            for qw in line:
                val = parse_hex(qw)
                if val is not None:
                    result.content_qwords.append(val)

    if result.content_qwords:
        byte_data = b''.join(q.to_bytes(8, 'little') for q in result.content_qwords)
        result.content_bytes = byte_data
        result.content_hash = hashlib.sha256(byte_data).hexdigest()[:16]
        result.entropy = shannon_entropy(byte_data[:256])

    # --- Adjacent pages ---
    adj_section = re.search(r'###SECTION:ADJACENT###(.*?)###SECTION:POOL###', content, re.DOTALL)
    if adj_section:
        adj_text = adj_section.group(1)
        for label in ['MINUS_800', 'MINUS_400', 'PLUS_400', 'PLUS_800', 'PLUS_1000', 'PLUS_2000', 'PLUS_4000']:
            pat = rf'ADJACENT_{label}(.*?)(?=ADJACENT_|###SECTION:)'
            m = re.search(pat, adj_text, re.DOTALL)
            if m:
                qwords = re.findall(r'[0-9A-Fa-f`]+\s+([0-9A-Fa-f`]+)', m.group(1))
                vals = [parse_hex(q) for q in qwords if parse_hex(q) is not None]
                result.adjacent[label] = vals[:16]

    # --- Pool ---
    pool_section = re.search(r'###SECTION:POOL###(.*?)###SECTION:OBJECT###', content, re.DOTALL)
    if pool_section:
        pool_text = pool_section.group(1)
        tag_m = re.search(r'Pool page\s+[^\s]+\s+region is\s+([^\n]+)', pool_text)
        if tag_m:
            result.pool_info = tag_m.group(1).strip()
        # Extract pool tag from pool header if visible
        tag_m2 = re.search(r'([A-Z0-9]{4,8})\s*\n', pool_text)
        if tag_m2:
            result.pool_tag = tag_m2.group(1).strip()

    # --- Object ---
    obj_m = re.search(r'OBJECT_INFO\s*=\s*(.+)', content)
    if obj_m:
        result.object_info = obj_m.group(1).strip()

    # --- Stack ---
    stack_section = re.search(r'###SECTION:STACK###(.*?)###SECTION:REGISTERS###', content, re.DOTALL)
    if stack_section:
        lines = re.findall(r'^\s*[0-9a-f]+\s+[0-9a-f]+\s+(.+)$', stack_section.group(1), re.MULTILINE)
        result.call_stack = [l.strip() for l in lines[:8]]

    # --- IRQL ---
    irql_m = re.search(r'###SECTION:IRQL###(.*?)###SECTION:BITFLIP###', content, re.DOTALL)
    if irql_m:
        irql_val = re.search(r'([0-9A-Fa-f]+)\s*\n', irql_m.group(1))
        if irql_val:
            result.irql = irql_val.group(1).strip()

    # Check if in DPC/interrupt from stack
    for line in result.call_stack:
        if 'dpc' in line.lower() or 'DPC' in line:
            result.in_dpc = True
        if 'interrupt' in line.lower() or 'ISR' in line or 'KiInterrupt' in line:
            result.in_interrupt = True

    # --- Bit-flip targets ---
    bf_section = re.search(r'###SECTION:BITFLIP###(.*)', content, re.DOTALL)
    if bf_section:
        for i in range(4):
            m = re.search(rf'QWORD_{i}\s*=\s*([0-9A-Fa-f`]+)', bf_section.group(1))
            if m:
                val = parse_hex(m.group(1))
                if val is not None:
                    result.qword_targets.append(val)
                    ptr_m = re.search(rf'QWORD_{i}_IS_KERNEL_PTR\s*=\s*YES', bf_section.group(1))
                    if ptr_m or (val >= 0xffff000000000000):
                        result.kernel_ptrs.append(val)

    return result


def analyze_cross_dump_diff(analyses: List[DumpAnalysis]) -> List[str]:
    """Technique 1: Cross-dump physical memory diff."""
    evidence = []

    # Group by physical address
    pa_groups = defaultdict(list)
    for a in analyses:
        if a.physical_address:
            pa_groups[a.physical_address].append(a)

    for pa, dumps in pa_groups.items():
        if len(dumps) >= 2:
            hashes = set(d.content_hash for d in dumps if d.content_hash)
            if len(hashes) == 1:
                evidence.append(
                    f"PA 0x{pa:012X} corrupted in {len(dumps)} dumps with IDENTICAL content. "
                    f"This is a stuck-at data bit or persistent row corruption."
                )
            else:
                evidence.append(
                    f"PA 0x{pa:012X} corrupted in {len(dumps)} dumps with DIFFERENT content each time "
                    f"({len(hashes)} unique hashes). The refresh counter hits a fixed row that "
                    f"contains different data on each boot. Classic stuck counter."
                )

    return evidence


def analyze_page_tables(analyses: List[DumpAnalysis]) -> List[str]:
    """Technique 2: Page table chain validation."""
    evidence = []

    for a in analyses:
        for entry in a.pte_entries:
            if entry.get('present'):
                pfn = entry.get('pfn', 0)
                # Impossible PFN check (assuming max 128GB = 0x2000000 PFNs)
                if pfn > 0x2000000:
                    evidence.append(
                        f"Dump {a.dump_number}: {entry['level']} points to impossible PFN 0x{pfn:X} "
                        f"(exceeds 128GB). This is a bit-flip in the page table itself."
                    )

                # NX bit corruption in kernel space
                flags = entry.get('flags', 0)
                if a.va_type == 'KERNEL' and not (flags & 0x8000000000000000):
                    evidence.append(
                        f"Dump {a.dump_number}: Kernel VA {a.corrupted_va} has NX bit cleared in PTE. "
                        f"Possible refresh corruption of PTE flags."
                    )

    return evidence


def analyze_pool_object(analyses: List[DumpAnalysis]) -> List[str]:
    """Technique 3: Pool header & object forensics."""
    evidence = []

    tags = defaultdict(list)
    for a in analyses:
        if a.pool_tag:
            tags[a.pool_tag].append(a)

    if len(tags) > 2:
        evidence.append(
            f"Corruption spans {len(tags)} different pool tags: {', '.join(tags.keys())}. "
            f"A software bug would typically corrupt one allocation type."
        )

    for a in analyses:
        if a.object_info and 'bad' in a.object_info.lower():
            evidence.append(
                f"Dump {a.dump_number}: Object validation failed — {a.object_info}"
            )

    return evidence


def analyze_bit_flips(analyses: List[DumpAnalysis]) -> List[str]:
    """Technique 4: Bit-flip signature extraction."""
    evidence = []

    # Compare kernel pointers to expected canonical range
    for a in analyses:
        for ptr in a.kernel_ptrs:
            # A valid kernel pointer should be in canonical form
            # If it's "almost" valid, compute XOR with nearest valid boundary
            if ptr < 0xffff800000000000 or ptr > 0xfffff87fffffffff:
                # Find nearest valid kernel pointer boundary
                expected = 0xfffff80000000000
                xor = ptr ^ expected
                if is_power_of_2(xor):
                    bit = get_bit_position(xor)
                    evidence.append(
                        f"Dump {a.dump_number}: Kernel pointer 0x{ptr:016X} differs from canonical "
                        f"by exactly bit {bit} (XOR=0x{xor:X}). Single-bit data path fault."
                    )

    return evidence


def analyze_adjacent_ghosts(analyses: List[DumpAnalysis]) -> List[str]:
    """Technique 5: Adjacent row ghost hunting."""
    evidence = []

    for a in analyses:
        if not a.content_qwords:
            continue

        first_8 = tuple(a.content_qwords[:8])

        for label, adj_data in a.adjacent.items():
            if len(adj_data) >= 8:
                adj_8 = tuple(adj_data[:8])
                matches = sum(1 for x, y in zip(first_8, adj_8) if x == y)
                if matches >= 6:
                    evidence.append(
                        f"Dump {a.dump_number}: Corrupted page shares {matches}/8 qwords with "
                        f"adjacent page ({label}). Strong evidence of row copy at hardware row granularity."
                    )

    return evidence


def analyze_timer_dpc(analyses: List[DumpAnalysis]) -> List[str]:
    """Technique 6: Timer/DPC correlation."""
    evidence = []

    dpc_count = sum(1 for a in analyses if a.in_dpc)
    irq_count = sum(1 for a in analyses if a.in_interrupt)

    if dpc_count >= 2:
        evidence.append(
            f"{dpc_count}/{len(analyses)} crashes occurred in DPC context. "
            f"This suggests the corrupted memory was touched by a background task, "
            f"not the active user thread. Consistent with refresh corruption sitting "
            f"idle until a deferred procedure accesses it."
        )

    if irq_count >= 2:
        evidence.append(
            f"{irq_count}/{len(analyses)} crashes occurred in interrupt context. "
            f"Hardware corruption often manifests first in interrupt handlers "
            f"that touch shared kernel structures."
        )

    return evidence


def analyze_pfn_state(analyses: List[DumpAnalysis]) -> List[str]:
    """Technique 7: PFN state & entropy analysis."""
    evidence = []

    entropies = [a.entropy for a in analyses if a.entropy > 0]
    if entropies:
        avg_entropy = sum(entropies) / len(entropies)
        evidence.append(
            f"Average Shannon entropy of corrupted pages: {avg_entropy:.2f} bits/byte "
            f"(max 8.0). Normal kernel data ≈ 3–5. Random corruption ≈ 7–8. "
            f"Row copy ≈ same as source (3–5)."
        )

        if avg_entropy > 6.5:
            evidence.append(
                f"High entropy ({avg_entropy:.2f}) suggests random bit flips or address decoder "
                f"fault producing garbage data, not a clean row copy."
            )
        elif avg_entropy < 4.0:
            evidence.append(
                f"Low entropy ({avg_entropy:.2f}) suggests structured data corruption — "
                f"possibly a row copy from another valid kernel structure."
            )

    return evidence


def generate_html_report(analyses: List[DumpAnalysis], all_evidence: Dict[str, List[str]], output_path: str):
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Build correlation table
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

    # Build evidence sections
    sections_html = ""
    for title, items in all_evidence.items():
        if items:
            sections_html += f"""<div class="evidence"><h3>{title}</h3><ul>"""
            for item in items:
                sections_html += f"<li>{item}</li>"
            sections_html += "</ul></div>"

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
<h1>DDR5 Refresh Counter Defect — Advanced Forensic Report v2.0</h1>
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
<p>Generated by DDR5 Advanced Forensic Analyzer v2.0</p>
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
