# Repo Conventions

Small, repo-wide style conventions — not a control/SOP, just what keeps drift
from creeping back in. Filed from #175 (structural health review, 2026-07-08).

## Bash shebang
Every `.sh` file starts with `#!/usr/bin/env bash` (not `#!/bin/bash`) —
portable across systems where bash isn't at a fixed path (Google Shell Style
Guide).

## Python module docstrings
Every `.py` file's module-level documentation is a PEP 257 triple-quote
docstring (`"""..."""`, immediately after the shebang if the file has one),
not a `#`-comment header block — so `__doc__` is populated consistently and
tools that introspect it (help(), doc generators) see the same thing
everywhere.

## Date-stamped filenames (`findings/`, `plans/`)
New files use dashed `YYYY-MM-DD` (e.g. `2026-07-11-issue-171-audit.md`), not
compact `YYYYMMDD`. Existing files aren't being renamed retroactively — this
is a going-forward convention only.
