# Third-Party Notices

This package **bundles no third-party code.** This file records how that was
established, so the statement is checkable rather than asserted.

## Runtime dependencies

`package.json` declares none:

```json
"dependencies": {},
"devDependencies": {},
"peerDependencies": {}
```

## What the shipped files import

Every import across the shipped source resolves to one of three places, none of
which is a bundled third-party library:

| Import | Kind | Notes |
|---|---|---|
| `node:fs` | Node.js built-in | ships with the runtime; not redistributed here |
| `./classifier.js` | local | part of this package |
| `openclaw/plugin-sdk/plugin-entry` | host-provided | supplied by the OpenClaw runtime, not vendored into this package |

Verification command:

```bash
grep -hoE 'from "[^"]+"' index.js classifier.js | sort -u
```

Output:

```
from "./classifier.js"
from "node:fs"
from "openclaw/plugin-sdk/plugin-entry"
```

## Why there is no `license-checker` output

The usual method is:

```bash
npx license-checker --production --out licenses.txt
```

That was **not** used here, for two reasons — and neither is "it was skipped":

1. **It would have nothing to report.** The tool enumerates licenses of installed
   production dependencies. This package has none, so the output would be empty
   or absent. The enumeration above is the stronger evidence.
2. **This host has no outbound network access** to the npm registry, so `npx`
   cannot fetch the tool. The direct inspection above does not require the network.

If a future version adds a dependency, regenerate this file with the standard
tooling at that time.

## Test files

`test-classifier.mjs`, `test-hook.mjs`, and `test-session-trust.mjs` run on
Node.js built-ins only (`node:test` / `node:assert`). They are development
artifacts and are not part of the runtime enforcement path.

---

*Effective for version 0.1.0.*
