# 🛡️ AbuseIPDB IOC Enricher

A small and practical Python script I wrote to help enrich IP addresses using [AbuseIPDB](https://www.abuseipdb.com/) and classify their threat level.

It's mainly intended for security analysts, threat hunters, or anyone working with IOC feeds — to quickly identify risky IPs based on community-reported abuse data.

---

## 📥 Input: `ips.txt`

Just create a simple text file with one IP address per line, for example:

8.8.8.8
185.220.100.255
1.1.1.1

## 📤 Output: `enriched_ips.csv`

After running the script, you'll get a CSV file with each IP’s:

- Abuse Confidence Score (0–100)
- Severity (`low`, `medium`, `high`) based on score thresholds

Sample output:

185.220.100.255,99,high
8.8.8.8,0,low

## ⚙️ How to Use

1. Install the required library:

In bash
pip install -r requirements.txt

2.Replace the line in ioc_enricher.py with your own API key API_KEY = "INSERT_YOUR_API_KEY_HERE" L.5

3.Run the script, your results will be saved to enriched_ips.csv

 ## 📤 Quick Note:
AbuseIPDB has a free tier with limited API quota (1,000 requests/day)

📌 Why I Built This
I often work with large IOC lists and wanted a lightweight, scriptable way to get a quick snapshot of which IPs are actually worth blocking or investigating further.

This project helped me practice:

Working with APIs

Parsing & classifying data

Building simple enrichment workflows for our Feed server.

Feel free to fork, use, or improve.
Created with ☕ and requests by Tomer Glik

