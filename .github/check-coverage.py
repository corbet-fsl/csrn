#!/usr/bin/env python3
"""Fail closed unless production line and branch coverage are both complete."""
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
if report.get('type') != 'llvm.coverage.json.export' or not report.get('data'):
    raise SystemExit('Missing LLVM coverage data')
failed = False
for data in report['data']:
    for metric in ('lines', 'branches'):
        total = data['totals'][metric]
        count, covered = total['count'], total['covered']
        print(f'{metric}: {covered}/{count}')
        branchless = (
            metric == 'branches' and count == 0 and covered == 0
            and '--branchless-facade' in sys.argv[2:]
            and data.get('files')
            and all(f.get('branches') == [] for f in data['files'])
        )
        if (count <= 0 and not branchless) or covered != count:
            failed = True
if failed:
    raise SystemExit('Require 100% measured production line and branch coverage')
