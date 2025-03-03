import requests
import pandas as pd
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

# Load API keys from .env file
load_dotenv()
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")

# Use a session to optimize API requests
session = requests.Session()

# Define file paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))  # Directory of the script
IPS_FILE = os.path.join(SCRIPT_DIR, "ips.txt")  # File containing IP addresses

# Function to check IP using IPinfo
def check_ipinfo(ip):
    url = f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}"
    try:
        response = session.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'Country': data.get('country', 'N/A'),
                'Hostname': data.get('hostname', 'N/A'),
                'Org': data.get('org', 'N/A')
            }
    except requests.exceptions.RequestException:
        return {'Country': 'N/A', 'Hostname': 'N/A', 'Org': 'N/A'}

# Function to check IP using AbuseIPDB
def check_abuseipdb(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    try:
        response = session.get(url, headers=headers, params=params, timeout=5)
        return response.json() if response.status_code == 200 else {}
    except requests.exceptions.RequestException:
        return {}

# Function to check IP using VirusTotal
def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = session.get(url, headers=headers, timeout=5)
        return response.json() if response.status_code == 200 else {}
    except requests.exceptions.RequestException:
        return {}

# Function to determine if an IP is malicious
def is_malicious(abuse_score, malicious_votes):
    return 'Malicious' if (malicious_votes > 0 or abuse_score > 1) else 'Not Malicious'

# Function to perform parallel IP checks
def run_checks():
    # Ensure ips.txt exists
    if not os.path.exists(IPS_FILE):
        print(f"❌ Error: File {IPS_FILE} not found.")
        return

    # Read IPs from file
    with open(IPS_FILE, 'r') as file:
        ips = [line.strip() for line in file]

    print(f"📌 Scanning {len(ips)} IP addresses...")

    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:  # Run 5 parallel tasks
        future_to_ip = {executor.submit(check_ip, ip): ip for ip in ips}
        for future in as_completed(future_to_ip):
            ip_result = future.result()
            if ip_result:
                results.append(ip_result)

    # Ask the user for the preferred file format
    save_results(results)

# Function to check a single IP (used in parallel execution)
def check_ip(ip):
    print(f"🔍 Checking IP: {ip}")

    ipinfo_data = check_ipinfo(ip)
    country = ipinfo_data['Country']
    hostname = ipinfo_data['Hostname']
    org = ipinfo_data['Org']

    abuse_data = check_abuseipdb(ip)
    abuse_score = abuse_data.get('data', {}).get('abuseConfidenceScore', 0)

    vt_data = check_virustotal(ip)
    malicious_votes = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)

    abuse_score = int(abuse_score)
    malicious_votes = int(malicious_votes)
    malicious_status = is_malicious(abuse_score, malicious_votes)

    return {
        'IP': ip,
        'Country': country,
        'Hostname': hostname,
        'Org': org,
        'AbuseIPDB Score': abuse_score,
        'VirusTotal Malicious Votes': malicious_votes,
        'Malicious Status': malicious_status
    }

# Function to save results in user-selected format
def save_results(results):
    output_path_base = os.path.expanduser("~/Desktop/ip_report")

    print("\n📁 Choose the output file format:")
    print("1️⃣ Excel (.xlsx)")
    print("2️⃣ CSV (.csv)")
    print("3️⃣ JSON (.json)")

    while True:
        choice = input("\nEnter your choice (1/2/3): ").strip()

        if choice == "1":
            output_path = output_path_base + ".xlsx"
            df = pd.DataFrame(results)
            df.to_excel(output_path, index=False)
            print(f"✅ Report saved as Excel file: {output_path}")
            break

        elif choice == "2":
            output_path = output_path_base + ".csv"
            df = pd.DataFrame(results)
            df.to_csv(output_path, index=False)
            print(f"✅ Report saved as CSV file: {output_path}")
            break

        elif choice == "3":
            output_path = output_path_base + ".json"
            with open(output_path, "w") as json_file:
                json_file.write(pd.DataFrame(results).to_json(orient="records", indent=4))
            print(f"✅ Report saved as JSON file: {output_path}")
            break

        else:
            print("❌ Invalid choice! Please enter 1, 2, or 3.")

# Run the scan automatically when the script is executed
if __name__ == "__main__":
    run_checks()
