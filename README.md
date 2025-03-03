IP Scanner Tool
IP Scanner Tool is a powerful and simple tool to analyze IP addresses using three well-known security services:

IPinfo: Provides geolocation, ISP, and hostname information.
AbuseIPDB: Checks whether the IP has been reported for malicious activity.
VirusTotal: Scans the IP address against multiple security engines.
This tool reads a list of IPs from a file (ips.txt), performs security checks, and generates a detailed Excel report (ip_report.xlsx) on the Desktop.

🚀 Features
✅ Reads IPs from ips.txt automatically
✅ Runs security checks in parallel for better performance
✅ Saves results in an Excel report (ip_report.xlsx) on the Desktop
✅ Supports both Linux and Windows
✅ Uses .env file for API keys security
✅ Multithreaded execution for faster processing

🛠️ Installation
Before using the tool, install the required dependencies:

sh
Copy
Edit
pip install requests pandas openpyxl python-dotenv
🔑 Setting Up API Keys
This tool requires API keys from the following services:

IPinfo.io
AbuseIPDB
VirusTotal
In the tool’s directory, create a .env file:
sh
Copy
Edit
nano .env
Add your API keys inside .env:
ini
Copy
Edit
IPINFO_TOKEN=YOUR_IPINFO_TOKEN
ABUSEIPDB_KEY=YOUR_ABUSEIPDB_KEY
VT_API_KEY=YOUR_VIRUSTOTAL_KEY
Save the file (CTRL + X, then Y, then Enter).
📂 Project Structure
bash
Copy
Edit
ip-scanner/
│── ip_scan.py          # Main script
│── .env                # API keys (user-provided)
│── ips.txt             # List of IPs to scan
│── README.md           # Documentation
📌 How to Use
1️⃣ Create ips.txt
Create a file named ips.txt in the same directory as ip_scan.py and add IPs (one per line):

Copy
Edit
8.8.8.8
1.1.1.1
192.168.1.1
2️⃣ Run the Script
📌 On Linux
Open the terminal, navigate to the project folder, and run:

sh
Copy
Edit
python ip_scan.py
📌 On Windows
Open PowerShell, navigate to the project directory, and run:

sh
Copy
Edit
python ip_scan.py
3️⃣ View the Report
After execution, the tool generates a detailed Excel report (ip_report.xlsx) and saves it on the Desktop.

📜 Example Output
IP	Country	Hostname	Org	AbuseIPDB Score	VirusTotal Malicious Votes	Malicious Status
8.8.8.8	US	google.com	Google LLC	0	0	Not Malicious
1.1.1.1	US	cloudflare.com	Cloudflare	1	0	Not Malicious
192.168.1.1	N/A	N/A	Private Network	0	0	Not Malicious
🔧 Future Improvements
🚀 Support for IPv6 Scanning
🚀 Additional export formats (CSV, JSON)
🚀 Web-based GUI using Flask or Streamlit

📢 Contributing
Contributions are welcome! To contribute:

Fork the repository
Clone your fork:
sh
Copy
Edit
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd ip-scanner
Create a new branch:
sh
Copy
Edit
git checkout -b feature-new-update
Make changes and push:
sh
Copy
Edit
git add .
git commit -m "Added new feature"
git push origin feature-new-update
Open a Pull Request on GitHub.
📞 Contact
For issues or suggestions, open an issue on GitHub or email your-email@example.com.

🔗 GitHub Repository
📌 GitHub Repository

🚀 Ready to scan? Run python ip_scan.py now! 🚀
📌 Final Notes
This README.md is designed to be copy-pasted directly into your GitHub repository.
Replace YOUR_USERNAME/YOUR_REPO with your actual GitHub repository name.
Update your-email@example.com if you want to provide support contact.
🎯 Your tool is now ready for GitHub! Let me know if you need further improvements. 🚀🔥
