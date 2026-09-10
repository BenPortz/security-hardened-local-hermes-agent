#!/usr/bin/env python3
"""Regression test: a burst of new mail must not suppress older un-fetched messages.

Gmail lists newest first. An earlier version passed --max straight through as the API's
maxResults, so the listing itself was capped: once more messages matched the query window
than the cap, the oldest un-fetched ones fell below the cut, were never listed again, and
aged out of the window without being ingested. Anyone able to send mail could exploit that
to keep one specific message from ever reaching triage.

The fetcher now pages the full window, skips what is already on disk, and takes the OLDEST
pending messages first, so --max delays a backlog instead of dropping it.

Runs offline: the Gmail API is stubbed, no token and no network.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import gmail_fetch as gf  # noqa: E402

TOTAL = 40          # messages matching the window
CAP = 25            # --max for each run
PAGE = 25           # smaller than TOTAL, so pagination is exercised too

ALL_IDS = ["m%02d" % i for i in range(TOTAL, 0, -1)]      # newest first, as Gmail returns


def _stub_api(path: str, token: str, params: dict | None = None) -> dict:
    if path == "/messages":
        start = int((params or {}).get("pageToken", 0))
        chunk = ALL_IDS[start:start + PAGE]
        out: dict = {"messages": [{"id": m} for m in chunk]}
        if start + PAGE < len(ALL_IDS):
            out["nextPageToken"] = str(start + PAGE)
        return out
    mid = path.split("/")[-1]
    return {"id": mid, "threadId": "T", "snippet": "s", "labelIds": ["INBOX"],
            "payload": {"mimeType": "text/plain",
                        "headers": [{"name": "From", "value": "sender@example.com"},
                                    {"name": "Subject", "value": mid},
                                    {"name": "Date", "value": "Wed, 26 Aug 2026 09:15:00 -0500"}],
                        "body": {"data": ""}}}


def _on_disk(inbox: Path) -> list[str]:
    return sorted(p.stem.replace("gmail-", "") for p in inbox.glob("*.json"))


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="fetch-backlog-"))
    gf.INBOX = tmp
    gf._api_get = _stub_api
    gf.load_token = lambda: {"access_token": "stub", "scope": gf.SCOPE_READONLY}
    gf.assert_readonly = lambda tok: None
    gf.ensure_fresh = lambda tok: tok
    gf.audit_logger.log_event = lambda *a, **k: None

    try:
        n1 = gf.fetch(query="newer_than:1d", maxn=CAP)
        assert n1 == CAP, "first run should ingest the cap, got %r" % n1
        oldest = sorted("m%02d" % i for i in range(1, CAP + 1))
        assert _on_disk(tmp) == oldest, "first run must take the OLDEST pending, got %r" % _on_disk(tmp)

        n2 = gf.fetch(query="newer_than:1d", maxn=CAP)
        assert n2 == TOTAL - CAP, "second run should drain the rest, got %r" % n2
        assert _on_disk(tmp) == sorted(ALL_IDS), "backlog did not fully drain"

        n3 = gf.fetch(query="newer_than:1d", maxn=CAP)
        assert n3 == 0, "third run should be idempotent, got %r" % n3
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("PASS: %d messages ingested across runs; a flood cannot suppress an older one" % TOTAL)
    return 0


if __name__ == "__main__":
    sys.exit(main())
