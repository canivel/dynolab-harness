"""Validate the public claims ledger (theory of change, year-one output 1).

Every claim must be quoted word for word from an archived source, and graded
with a verdict from ledger/verdicts.yaml or marked not assessable from outside.
"""
from __future__ import annotations

import datetime as dt
import re

import yaml

from .config import LEDGER_DIR

CATEGORIES = {"monitoring", "containment", "incident_reporting"}
REQUIRED = ["id", "developer", "category", "quote", "source_url", "archive_url",
            "retrieved", "verdict"]


def validate(ledger_dir=LEDGER_DIR) -> list[str]:
    with open(ledger_dir / "verdicts.yaml") as f:
        verdicts = {v["id"] for v in yaml.safe_load(f)["verdicts"]}
    with open(ledger_dir / "claims.yaml") as f:
        claims = yaml.safe_load(f).get("claims") or []

    problems, seen = [], set()
    for i, c in enumerate(claims):
        where = f"claim {c.get('id', f'#{i}')}"
        for k in REQUIRED:
            if not c.get(k):
                problems.append(f"{where}: missing {k}")
        if c.get("id") in seen:
            problems.append(f"{where}: duplicate id")
        seen.add(c.get("id"))
        if c.get("category") and c["category"] not in CATEGORIES:
            problems.append(f"{where}: category must be one of {sorted(CATEGORIES)}")
        if c.get("verdict") and c["verdict"] not in verdicts:
            problems.append(f"{where}: unknown verdict {c['verdict']!r}")
        for k in ("source_url", "archive_url"):
            if c.get(k) and not re.match(r"https?://", c[k]):
                problems.append(f"{where}: {k} is not a URL")
        if c.get("retrieved") and not isinstance(c["retrieved"], dt.date):
            problems.append(f"{where}: retrieved must be a YYYY-MM-DD date")
        if c.get("verdict") not in (None, "pending", "not_assessable_from_outside") \
                and not c.get("evidence"):
            problems.append(f"{where}: a graded verdict must link at least one evidence bundle")
    return problems
