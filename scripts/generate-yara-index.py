#!/usr/bin/env python3
"""Generate neo23x0-index.yar from YARA rule files in /usr/share/yara-rules/neo23x0."""

import os

lines = ['// Auto-generated Neo23x0 YARA rules index', '']
neo_dir = '/usr/share/yara-rules/neo23x0'
for f in sorted(os.listdir(neo_dir)):
    if f.endswith('.yar'):
        lines.append(f'include "neo23x0/{f}"')
lines.append('')
with open('/usr/share/yara-rules/neo23x0-index.yar', 'w') as f:
    f.write('\n'.join(lines))
print(f'Generated neo23x0-index.yar with {len(lines)} lines')
