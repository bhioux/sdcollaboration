#!/usr/bin/env python3
"""
SDC Threat Feed Refresher
-------------------------
Fetches The Hacker News and Bleeping Computer Security RSS feeds
and writes them as static JSON to feeds/thn.json and feeds/cisa.json.

Usage:
  python fetch-feeds.py

Run this manually, via cron, or wire it into any CI pipeline.
Requires: Python 3.8+ (stdlib only — no pip installs needed)

To auto-run via GitHub Actions, the repo PAT needs the `workflow` scope.
Add that scope at: https://github.com/settings/tokens
Then push .github/workflows/fetch-feeds.yml from the .github/ directory.
"""

import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

FEEDS_DIR = Path(__file__).parent / "feeds"
FEEDS_DIR.mkdir(exist_ok=True)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SDC-ThreatFeed/1.0)",
    "Accept": "application/rss+xml, application/xml, text/xml, */*",
}

SEC_KEYWORDS = [
    "security", "ransomware", "malware", "vulnerability", "exploit",
    "phish", "breach", "attack", "hack", "zero-day", "backdoor",
    "cve", "worm", "trojan", "spyware", "credential", "data leak",
]

def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read()

def strip_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text or "")
    return re.sub(r"\s+", " ", text).strip()

def parse_rss(xml_bytes: bytes, source: str, sec_filter: bool = False) -> list[dict]:
    root = ET.fromstring(xml_bytes)
    channel = root.find("channel")
    raw_items = (channel.findall("item") if channel is not None else [])[:20]
    items = []

    for item in raw_items:
        def t(tag):
            el = item.find(tag)
            return (el.text or "").strip() if el is not None else ""

        title = t("title")
        link  = t("link") or t("guid")
        desc  = strip_html(t("description"))[:300]
        pub   = t("pubDate")
        cats  = [el.text or "" for el in item.findall("category")]

        if sec_filter:
            combined = (title + " " + " ".join(cats)).lower()
            if not any(kw in combined for kw in SEC_KEYWORDS):
                continue

        items.append({
            "title":       title,
            "link":        link,
            "description": desc,
            "pubDate":     pub,
            "source":      source,
        })

        if len(items) >= 8:
            break

    return items

def write_feed(path: Path, items: list[dict]):
    payload = {
        "status":  "ok",
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "items":   items,
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Wrote {len(items)} items → {path.name}")

def main():
    print("Fetching The Hacker News…")
    try:
        thn_xml = fetch("https://feeds.feedburner.com/TheHackersNews")
        thn_items = parse_rss(thn_xml, "thehackernews.com", sec_filter=False)
        write_feed(FEEDS_DIR / "thn.json", thn_items)
    except Exception as e:
        print(f"  ERROR: {e}", file=sys.stderr)

    print("Fetching Bleeping Computer Security…")
    try:
        bc_xml = fetch("https://www.bleepingcomputer.com/feed/")
        bc_items = parse_rss(bc_xml, "bleepingcomputer.com", sec_filter=True)
        write_feed(FEEDS_DIR / "cisa.json", bc_items)
    except Exception as e:
        print(f"  ERROR: {e}", file=sys.stderr)

    print("Done.")

if __name__ == "__main__":
    main()
