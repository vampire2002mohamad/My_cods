# 🚀 IP Scanner Tool

**IP Scanner Tool** is a powerful and simple tool for scanning IP addresses using three well-known security services:

- **IPinfo**: Provides geolocation, ISP, and hostname information.
- **AbuseIPDB**: Checks whether the IP has been reported for malicious activity.
- **VirusTotal**: Scans the IP address against multiple security engines.

The tool reads a list of IPs from `ips.txt`, performs security checks, and generates a detailed **Excel report (`ip_report.xlsx`)** on the **Desktop**.

---

## 🔹 Features

✅ **Reads IPs from `ips.txt` automatically**  
✅ **Runs security checks in parallel for better performance**  
✅ **Saves results in an Excel report (`ip_report.xlsx`) on the Desktop**  
✅ **Supports both Linux and Windows**  
✅ **Uses `.env` file for API keys security**  
✅ **Multithreaded execution for faster processing**  

---

## 🛠 Installation

First, install the required dependencies:

```sh
pip install requests pandas openpyxl python-dotenv
```

### 🔑 Setting Up API Keys
This tool requires API keys from:

- IPinfo.io  
- AbuseIPDB  
- VirusTotal  

#### Step 1: Create a `.env` file
Inside the project folder, create a `.env` file:

```sh
nano .env
```

Add your API keys:

```ini
IPINFO_TOKEN=your_ipinfo_api_key_here
ABUSEIPDB_KEY=your_abuseipdb_api_key_here
VT_API_KEY=your_virustotal_api_key_here
```

Save the file (CTRL + X, then Y, then Enter).

---

## 📂 Project Structure

```
ip-scanner/
│── ip_scan.py          # Main script
│── .env.example        # Example .env file for API keys
│── ips.txt             # Sample IP list
│── README.md           # Documentation
│── .gitignore          # Ignore sensitive files
```

---

## 📌 How to Use

### 1️⃣ Create `ips.txt`
Create a file named `ips.txt` in the same directory as `ip_scan.py` and add IPs (one per line):

```
8.8.8.8
1.1.1.1
192.168.1.1
```

### 2️⃣ Run the Script

#### 📌 On Linux
```sh
python ip_scan.py
```

#### 📌 On Windows
```sh
python ip_scan.py
```

### 3️⃣ Choose the Output Format
When prompted, enter `1` for Excel, `2` for CSV, or `3` for JSON.  
The report will be saved on the Desktop.

### 4️⃣ View the Report
After execution, the tool generates a detailed Excel, CSV, or JSON report and saves it on the Desktop.

---

## 🎯 Example Output

| IP         | Country | Hostname         | Org              | AbuseIPDB Score | VirusTotal Malicious Votes | Malicious Status |
|------------|---------|-----------------|------------------|-----------------|-----------------------------|------------------|
| 8.8.8.8    | US      | google.com      | Google LLC       | 0               | 0                           | Not Malicious    |
| 1.1.1.1    | US      | cloudflare.com  | Cloudflare       | 1               | 0                           | Not Malicious    |
| 192.168.1.1| N/A     | N/A             | Private Network  | 0               | 0                           | Not Malicious    |

---

## 🔧 Future Improvements

🚀 Support for IPv6 Scanning  
🚀 Additional export formats (CSV, JSON)  
🚀 Web-based GUI using Flask or Streamlit  

---

## 📢 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Clone your fork:

```sh
git clone https://github.com/YOUR_USERNAME/ip-scanner.git
cd ip-scanner
```

3. Create a new branch:

```sh
git checkout -b feature-new-update
```

4. Make changes and push:

```sh
git add .
git commit -m "Added new feature"
git push origin feature-new-update
```

5. Open a Pull Request on GitHub.

---

## 📞 Contact

For issues or suggestions, open an issue on GitHub or email `your-email@example.com`.

---

## 🔗 GitHub Repository

📌 **GitHub Repository**

🚀 **Ready to scan? Run `python ip_scan.py` now!** 🚀
