# 🔍 Deep Scan Multitool

A powerful and user-friendly **pentesting tool** for deep scanning an IP address. This script performs multiple security checks and saves results in a structured report.

## 🚀 Features
- **Port Scanning**: Identifies open ports.
- **Banner Grabbing**: Retrieves service banners.
- **WHOIS Lookup**: Fetches domain information.
- **Reverse DNS Lookup**: Resolves IP to domain name.
- **Traceroute Analysis**: Maps network path.
- **Vulnerability Detection**: Checks for known security issues.
- **Automatic Report Generation**: Saves results in `result_[ip].txt`.

## 🛠️ Installation
### Prerequisites
- Python 3.x
- Required dependencies:
  ```sh
  pip install scapy termcolor tqdm python-whois requests
  ```

## 🎯 Usage
1. **Run the script**:
   ```sh
   python main.py
   ```
2. **Enter the target IP address** when prompted.
3. **View results on the console** and in `result_[ip].txt`.

## 📸 Example Output
```sh
Enter target IP: 192.168.1.1

Scanning IP: 192.168.1.1
Initializing scan...
Scanning ports: ██████████ 100%
Open ports: [22, 80, 443]
Banner on 22: OpenSSH 7.9
WHOIS Information: ...
Reverse DNS: example.com
Traceroute: ...
Results saved to result_192.168.1.1.txt
```

## ⚠️ Disclaimer
This tool is for **educational purposes** only. Unauthorized scanning may be **illegal**. Use it only on networks you own or have explicit permission to test.

Happy hacking! 🕵️‍♂️
