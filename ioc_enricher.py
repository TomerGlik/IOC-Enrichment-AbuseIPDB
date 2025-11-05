#!/usr/bin/env python3
# Simple AbuseIPDB enricher (no cache, inline API key, up to 1000 IPs)

import requests
import time
import csv
import ipaddress

API_KEY = "YOUR_API"  # <-- put your AbuseIPDB key here
API_URL = "https://api.abuseipdb.com/api/v2/check"

INPUT_FILE = "ips.txt"
OUTPUT_FILE = "enriched_ips.csv"

MAX_RECORDS = 1000           # hard cap due to AbuseIPDB policy
SLEEP_BETWEEN = 1.0          # be polite to the API
TIMEOUT = 10                 # seconds for HTTP requests
MAXAGE_DAYS = "30"           # recent window

HEADERS = {
    "Accept": "application/json",
    "Key": API_KEY,
}

CSV_HEADERS = [
    "IP",
    "AbuseScore",
    "Severity",
    "TotalReports",
    "LastReportedAt",
    "Country",
    "UsageType",
    "ISP",
    "Domain",
]


def classify_score(score):
    try:
        s = int(score)
    except Exception:
        return "unknown"
    if s >= 85:
        return "high"
    if s >= 50:
        return "medium"
    return "low"


def load_ips(path):
    """Read IPs from file, one per line; validate IPv4/IPv6; deduplicate while keeping order."""
    ips = []
    seen = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            try:
                ip = ipaddress.ip_address(raw).compressed
            except ValueError:
                print(f"Skipping invalid IP: {raw}")
                continue
            if ip in seen:
                continue
            seen.add(ip)
            ips.append(ip)
    return ips


def get_ip_info(ip):
    """Call AbuseIPDB and return the 'data' dict or None."""
    params = {"ipAddress": ip, "maxAgeInDays": MAXAGE_DAYS}
    try:
        r = requests.get(API_URL, headers=HEADERS, params=params, timeout=TIMEOUT)
        if r.status_code == 200:
            j = r.json()
            return j.get("data")
        elif r.status_code == 429:
            # Simple rate limit handling: read Retry-After if present, otherwise wait a bit
            wait = int(r.headers.get("Retry-After", "2"))
            print(f"[{ip}] Rate limited (429). Waiting {wait}s...")
            time.sleep(wait)
            return get_ip_info(ip)  # retry once after wait
        else:
            print(f"[{ip}] HTTP {r.status_code}: {r.text[:200]}")
            return None
    except requests.RequestException as e:
        print(f"[{ip}] Request error: {e}")
        return None


def enrich_ip_list(input_file=INPUT_FILE, output_file=OUTPUT_FILE):
    ips = load_ips(input_file)

    # Enforce the 1000-record limit
    if len(ips) > MAX_RECORDS:
        print(f"Input contains {len(ips)} IPs; limiting to first {MAX_RECORDS}.")
        ips = ips[:MAX_RECORDS]

    results = []

    for idx, ip in enumerate(ips, start=1):
        print(f"[{idx}/{len(ips)}] Querying: {ip}")
        data = get_ip_info(ip)

        if data is None:
            # still write a row indicating failure for traceability
            results.append({
                "IP": ip,
                "AbuseScore": "",
                "Severity": "failed",
                "TotalReports": "",
                "LastReportedAt": "",
                "Country": "",
                "UsageType": "",
                "ISP": "",
                "Domain": "",
            })
        else:
            score = data.get("abuseConfidenceScore")
            row = {
                "IP": ip,
                "AbuseScore": score,
                "Severity": classify_score(score),
                "TotalReports": data.get("totalReports", ""),
                "LastReportedAt": data.get("lastReportedAt", ""),
                "Country": data.get("countryCode", ""),
                "UsageType": data.get("usageType", ""),
                "ISP": data.get("isp", ""),
                "Domain": data.get("domain", ""),
            }
            results.append(row)
            print(f"  -> Score: {row['AbuseScore']} ({row['Severity']})")

        time.sleep(SLEEP_BETWEEN)

    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADERS)
        writer.writeheader()
        writer.writerows(results)

    print(f"\n✅ Done. Saved to {output_file}")


if __name__ == "__main__":
    enrich_ip_list()
