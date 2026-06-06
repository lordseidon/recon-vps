#!/usr/bin/env python3
"""TCP DNS resolver — drop-in replacement for dnsx when UDP is blocked.
Usage: python3 dnsx_tcp.py -l subs.txt -o resolved.txt [-t threads]
Output format matches: sub.domain.com [A] [1.2.3.4]
"""
import sys, os, time, signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    import dns.resolver
    import dns.message
    import dns.query
except ImportError:
    print("Install dnspython: pip install dnspython", file=sys.stderr)
    sys.exit(1)

def resolve_tcp(domain):
    try:
        answer = dns.resolver.resolve(domain, 'A', tcp=True, lifetime=5)
        ips = sorted(str(r) for r in answer)
        return domain, ips
    except Exception:
        return domain, []

def main():
    input_file = None
    output_file = None
    threads = 50
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ('-l', '-list') and i + 1 < len(args):
            input_file = args[i + 1]; i += 1
        elif args[i] in ('-o',) and i + 1 < len(args):
            output_file = args[i + 1]; i += 1
        elif args[i] in ('-t', '-threads') and i + 1 < len(args):
            threads = int(args[i + 1]); i += 1
        elif args[i].startswith('-'):
            i += 1
        else:
            i += 1

    if not input_file:
        print("Usage: dnsx_tcp.py -l subs.txt -o resolved.txt", file=sys.stderr)
        sys.exit(1)

    # Handle stdin
    if input_file == '-':
        lines = [l.strip() for l in sys.stdin if l.strip()]
    else:
        with open(input_file) as f:
            lines = [l.strip() for l in f if l.strip()]

    total = len(lines)
    if total == 0:
        sys.exit(0)

    out = open(output_file, 'w') if output_file else sys.stdout
    count = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(resolve_tcp, d): d for d in lines}
        for f in as_completed(futures):
            domain, ips = f.result()
            for ip in ips:
                line = f"{domain} [A] [{ip}]\n"
                out.write(line)
                out.flush()
            count += 1
            if count % 100 == 0:
                print(f"\r  Resolved {count}/{total}...", file=sys.stderr, end='')

    print(f"\r  Resolved {count}/{total}", file=sys.stderr)
    if output_file:
        out.close()

if __name__ == '__main__':
    main()
