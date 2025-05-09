import requests
import time
import csv

API_KEY = "INSERT_YOUR_API_KEY_HERE"  # AbuseIPDB key for enrichemnt, Your account API Key
API_URL = "https://api.abuseipdb.com/api/v2/check"

headers = {
    "Accept": "application/json",
    "Key": API_KEY
}

def get_ip_info(ip):
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "30"
    }
    try:
        response = requests.get(API_URL, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()["data"]
            score = data["abuseConfidenceScore"]
            return score
        else:
            return None
    except Exception:
        return None

def classify_score(score):
    if score >= 85:
        return "high"
    elif score >= 50:
        return "medium"
    else:
        return "low"

def enrich_ip_list(input_file="ips.txt", output_file="enriched_ips.csv"):
    results = []

    with open(input_file, "r") as f:
        ips = [line.strip() for line in f if line.strip()]

    for ip in ips:
        score = get_ip_info(ip)
        if score is not None:
            level = classify_score(score)
            results.append([ip, score, level])
            print(f"{ip} → Score: {score} ({level})")
        else:
            print(f"{ip} → Failed to retrieve info")
        time.sleep(1.2)  # Rate

    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP", "Abuse Score", "Severity"])
        writer.writerows(results)

    print(f"\n✅ Finished. Saved to {output_file}")

if __name__ == "__main__":
    enrich_ip_list()
