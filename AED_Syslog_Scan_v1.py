import os
import glob
import gzip
import re
from datetime import datetime
from collections import defaultdict
import argparse

def normalize_message(msg):
    """Try to make similar messages look identical for grouping purposes"""
    # 1. Remove common syslog trailer: hostname process[pid]:
    msg = re.sub(r'^[^ ]+\s+[^[]+\[\d+\]:\s*', '', msg, flags=re.IGNORECASE)

    # 2. Remove inner PIDs like [2956] or (12345)
    msg = re.sub(r'\[\d+\]|\(\d+\)', '', msg)

    # 3. Collapse multiple spaces / normalize whitespace
    msg = re.sub(r'\s+', ' ', msg.strip())

    # 4. (Optional) Remove varying times after certain prefixes
    # Example: remove ISO-like times after WARNING: or similar
    msg = re.sub(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ [A-Z]{3}', '', msg)

    # 5. For rmmitigations-like: remove the actual seconds number
    msg = re.sub(r'deleted 0 offramps rows, \d+\.\d+ s', 'deleted 0 offramps rows, X.XX s', msg)

    # You can add more rules here later, e.g.:
    # if "spTMSPrefix" in msg: msg = re.sub(r'spTMSPrefix s [^ ]+', 'spTMSPrefix s <IP/PREFIX>', msg)

    return msg.strip()

def main():
    parser = argparse.ArgumentParser(description="Syslog Health Check Scanner")
    parser.add_argument('--diag-path', required=True, help="Path to diagnostic package directory")
    parser.add_argument('--output-dir', default=os.path.dirname(os.path.abspath(__file__)),
                        help="Directory to save report")
    parser.add_argument('--exclude-categories', default='', help="Comma-separated categories to exclude")
    parser.add_argument('--extra-keywords', default='', help="Comma-separated extra keywords")
    args = parser.parse_args()

    # ────────────────────────────────────────────────
    # Keyword patterns (same as before)
    keyword_patterns = [
        ('software_component_crashing', re.compile(r"Software Component .* is 'Crashing", re.IGNORECASE)),
        ('sync_failed_due_to_error',    re.compile(r"sync failed due to error", re.IGNORECASE)),
        ('crash',      'crash'),
        ('fail',       'fail'),
        ('error',      'error'),
        ('warning',    'warning'),
        ('reboot',     'reboot'),
        ('invalid',    'invalid'),
        ('interrupt',  'interrupt'),
        ('leak',       'leak'),
        ('timeout',    'timeout'),
        ('blinky',     'blinky'),
        ('ipmi',       'ipmi'),
        ('file_system','file_system'),
        ('database',   'database'),
        ('mce',        'mce'),
    ]

    excludes = {kw.strip().lower() for kw in args.exclude_categories.split(',') if kw.strip()}

    active_keywords = [(name, matcher) for name, matcher in keyword_patterns if name.lower() not in excludes]

    extra_raw = [kw.strip() for kw in args.extra_keywords.split(',') if kw.strip()]
    extra_keywords = []
    seen = set()
    for kw in extra_raw:
        if kw not in seen:
            extra_keywords.append((kw, kw))
            seen.add(kw)

    all_keywords = active_keywords + extra_keywords

    categories = {name: defaultdict(lambda: {'count': 0, 'first': None, 'last': None, 'timestamps': []})
                  for name, _ in all_keywords}

    total_files = 0
    total_matches = 0

    log_files = sorted(set(
        glob.glob(os.path.join(args.diag_path, '**', 'syslog*'), recursive=True) +
        glob.glob(os.path.join(args.diag_path, '**', '*.txt'), recursive=True) +
        glob.glob(os.path.join(args.diag_path, '**', '*.gz'), recursive=True)
    ))

    SKIP_LOWER = {'login-ui-fail', 'auth-local-failed'}

    for file_path in log_files:
        if not file_path.lower().endswith(('.txt', '.gz')):
            continue
        opener = open if file_path.lower().endswith('.txt') else gzip.open
        try:
            with opener(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    lower_line = line.lower()
                    if any(s in lower_line for s in SKIP_LOWER): continue

                    try:
                        ts_str, rest = line.split(' ', 1)
                        ts = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S%z')
                        original_message = rest.strip()
                    except:
                        continue

                    norm_msg = normalize_message(original_message)

                    assigned = False
                    for display_name, matcher in all_keywords:
                        if isinstance(matcher, str):
                            match = matcher.lower() in lower_line
                        else:
                            match = bool(matcher.search(line))

                        if match:
                            data = categories[display_name][norm_msg]
                            data['count'] += 1
                            data['timestamps'].append(ts)
                            if data['first'] is None or ts < data['first']:
                                data['first'] = ts
                            if data['last'] is None or ts > data['last']:
                                data['last'] = ts
                            total_matches += 1
                            assigned = True
                            break

            total_files += 1
        except Exception as e:
            print(f"Error reading {os.path.basename(file_path)}: {e}")

    # Debug
    print("\nDEBUG - Matches per keyword:")
    for name, _ in all_keywords:
        cnt = sum(d['count'] for d in categories[name].values())
        print(f"  {name:28} : {cnt:6,d} occurrences")

    # Output
    diag_name = os.path.basename(os.path.normpath(args.diag_path)) or "diag"
    output_file = os.path.join(args.output_dir, f"health_check_report_{diag_name}.txt")

    with open(output_file, 'w', encoding='utf-8') as out:
        out.write("Syslog Health Check Report\n")
        out.write(f"Diagnostic package: {diag_name}\n")
        out.write(f"Generated: {datetime.now().isoformat()}\n\n")
        out.write(f"Total files scanned: {total_files}\n")
        out.write(f"Total matching entries: {total_matches:,}\n\n")
        out.write("Matches by category:\n")

        for name, _ in all_keywords:
            total = sum(d['count'] for d in categories[name].values())
            out.write(f"  - {name}: {total:,}\n")

        for name, _ in all_keywords:
            msgs = categories[name]
            if not msgs: continue

            total_occ = sum(d['count'] for d in msgs.values())
            unique_norm = len(msgs)

            out.write(f"\n{'='*70}\n")
            out.write(f"Category: {name}\n")
            out.write(f"Unique normalized messages: {unique_norm}\n")
            out.write(f"Total occurrences: {total_occ:,}\n")

            sorted_msgs = sorted(msgs.items(), key=lambda x: x[1]['count'], reverse=True)

            for norm_msg, data in sorted_msgs[:15]:
                example_ts = data['first'].strftime('%Y-%m-%d %H:%M:%S%z')
                out.write(f"\n{example_ts}  {norm_msg}\n")
                out.write(f"    Occurrences: {data['count']:,}\n")
                out.write(f"    First seen:  {data['first'].isoformat()}\n")
                out.write(f"    Last seen:   {data['last'].isoformat()}\n")

            if len(msgs) > 15:
                out.write(f"\n... {len(msgs)-15} more unique normalized messages ...\n")

    print(f"Report saved to: {output_file}")

if __name__ == "__main__":
    main()