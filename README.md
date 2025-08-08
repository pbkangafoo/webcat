# WEBCAT 🐱‍💻

**WEBCAT** is a powerful multithreaded web directory and file scanner designed to help security professionals and enthusiasts discover interesting resources on web servers. It combines traditional fuzzing techniques with OWASP Web Security Testing Guide (WSTG)-inspired checks to deliver comprehensive reconnaissance capabilities in a lightweight, easy-to-use tool.

Version: 0.8

---

## 🚀 Features

- 🔍 **Multithreaded scanning** of directories and files with customizable wordlists  
- 🎯 **HTTP status code filtering** and verbose output for precise result control  
- 🛠️ **HTTP method enumeration** via OPTIONS requests to identify allowed HTTP verbs (WSTG-CONF-06)  
- 🛡️ **Security header analysis** detecting missing headers like Content-Security-Policy, HSTS, and X-Frame-Options (WSTG-HTT-02)  
- 🕵️‍♂️ **Sensitive file and directory detection** based on a top 20 list of common secrets and configuration files (WSTG-INFO-05)  
- 🔐 **TLS certificate inspection** for HTTPS targets, revealing issuer and expiry details (WSTG-CRYP-01)  
- 📝 Flexible **output options** with detailed tab-separated result files including HTTP status, methods, missing headers, sensitive file flags, and TLS info  
- ⚙️ Easy to **enable or disable advanced OWASP-inspired checks** with a simple command-line flag (`-x`)

---
## 🔍 Screenshot

![Screenshot](https://github.com/pbkangafoo/webcat/blob/main/webcat_screenshot.jpg "webcat screenshot")

---

## 🗂️ Wordlists

The tool ships with a simple example wordlist for demonstration purposes only. For comprehensive scanning, we recommend using extensive wordlists from the well-known [SecLists](https://github.com/danielmiessler/SecLists) project, which offers a rich collection of directory and file names, sensitive files, and payloads commonly used in web security testing.

Download SecLists or any other custom wordlist and pass it to the tool using the `-f` parameter for more effective and thorough scans.

---

## 🛠️ Installation

This tool requires Python 3 and the [requests](https://pypi.org/project/requests/) library. To install `requests`, run:

```bash
pip install requests
```

After cloning or downloading this repository, you can run the tool directly using Python.

---

## 💡 Usage Examples

```bash
# Basic scan with default settings, scanning URLs from 'wordlist.txt' against https://example.com
python webcat_extended.py -u https://example.com -f wordlist.txt

# Verbose mode: show all responses regardless of status code
python webcat_extended.py -u https://example.com -f wordlist.txt -v

# Filter output only for status codes 200, 301, and 403
python webcat_extended.py -u https://example.com -f wordlist.txt -d 200 301 403

# Enable OWASP WSTG extra checks (HTTP methods, security headers, sensitive files, TLS info)
python webcat_extended.py -u https://example.com -f wordlist.txt -x

# Save scan results to a file (tab-separated)
python webcat_extended.py -u https://example.com -f wordlist.txt -o results.tsv

# Use 20 concurrent threads for faster scanning
python webcat_extended.py -u https://example.com -f wordlist.txt -t 20

# Combine multiple options: verbose + extra checks + output file + threads
python webcat_extended.py -u https://example.com -f wordlist.txt -v -x -o results.tsv -t 15
```

---

If you find this tool helpful or have ideas for improvement, feel free to contribute or open an issue!  
Happy scanning! 🐾✨
