# AGENTS.md

This file contains agent-focused guidance for maintaining OhMyPCAP.

## Updating Vendored Dependencies

OhMyPCAP bundles D3 and d3-sankey in `static/` so the application works offline and builds remain deterministic.

### D3

To update to the latest version:

```bash
curl -sL "https://unpkg.com/d3@7/dist/d3.min.js" -o static/d3.min.js
curl -sL "https://unpkg.com/d3-sankey@0.12/dist/d3-sankey.min.js" -o static/d3-sankey.min.js
```

After updating, verify the files load correctly and run the test suite:

```bash
python3 -m unittest discover -v
```

If the copyright year changed, update `static/LICENSE` accordingly.

Check for D3 releases at https://github.com/d3/d3/releases.
Recommended cadence: every 6–12 months, or immediately if a security CVE is announced.

## README Maintenance

When adding, removing, or renaming sections in `README.md`, always update the **Table of Contents** at the top of the file. GitHub auto-generates anchor IDs from heading text (lowercased, spaces→hyphens, special chars stripped). Duplicate heading names get `-1`, `-2`, etc. suffixes.
