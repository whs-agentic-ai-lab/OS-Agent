#!/usr/bin/env python3
from __future__ import annotations

import sys
import urllib.request


try:
    with urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=2) as response:
        raise SystemExit(0 if response.status == 200 else 1)
except Exception as exc:
    print(exc, file=sys.stderr)
    raise SystemExit(1) from exc
