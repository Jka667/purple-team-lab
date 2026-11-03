"""Run each detection's SPL in Splunk over its purple-team test window and write a detected/missed report.

  export SPLUNK_TOKEN=<token>   (Settings > Tokens in Splunk)
  python scripts/check_detections.py results/run-20261103-101500.csv \
      --detections ../splunk-detection-as-code/detections --splunk https://splunk-vm:8089 --insecure
"""
import argparse
import csv
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import yaml


def epoch(ts):
    return int(datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def count_results(base_url, token, spl, earliest, latest, insecure=False):
    spl = spl.strip()
    if not spl.startswith("|"):
        spl = "search " + spl
    body = urllib.parse.urlencode({"search": spl, "earliest_time": earliest, "latest_time": latest,
                                   "output_mode": "json"}).encode()
    req = urllib.request.Request(f"{base_url.rstrip('/')}/services/search/v2/jobs/export", data=body,
                                 headers={"Authorization": f"Bearer {token}"})
    ctx = ssl._create_unverified_context() if insecure else None  # lab Splunk uses a self-signed cert
    with urllib.request.urlopen(req, context=ctx, timeout=300) as r:
        return sum(1 for line in r if line.strip() and "result" in json.loads(line))


def report(rows, results):
    lines = ["| Detection | Technique | Test | Host | Result | Hits |", "|---|---|---|---|---|---|"]
    for row, hits in zip(rows, results):
        status = "DETECTED" if hits else "**MISSED**"
        lines.append(f"| {row['detection_id']} | {row['technique']} | {row['test_name']} | {row['host']} | {status} | {hits} |")
    detected = sum(1 for h in results if h)
    return f"# Purple team run\n\nDetected {detected}/{len(results)} emulated techniques.\n\n" + "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("run_csv")
    p.add_argument("--detections", default="../splunk-detection-as-code/detections")
    p.add_argument("--splunk", default="https://localhost:8089")
    p.add_argument("--lag", type=int, default=600, help="seconds after the test to include (indexing delay)")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed lab cert)")
    args = p.parse_args(argv)

    token = os.environ.get("SPLUNK_TOKEN") or p.error("set SPLUNK_TOKEN")
    detections = {d["id"]: d for d in (yaml.safe_load(f.read_text(encoding="utf-8"))
                                       for f in Path(args.detections).glob("*.yml"))}
    with open(args.run_csv, encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))

    results = []
    for row in rows:
        det = detections.get(row["detection_id"])
        if not det:
            print(f"{row['detection_id']}: not found in {args.detections}")
            results.append(0)
            continue
        hits = count_results(args.splunk, token, det["search"], epoch(row["start_utc"]) - 60,
                             epoch(row["end_utc"]) + args.lag, args.insecure)
        print(f"{row['detection_id']}: {hits} hit(s)")
        results.append(hits)

    out = Path(args.run_csv).with_suffix(".md")
    out.write_text(report(rows, results), encoding="utf-8")
    print(f"report: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
