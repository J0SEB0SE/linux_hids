# Python HIDS (Host Intrusion Detection System)

A lightweight Host Intrusion Detection System (HIDS) built in Python for monitoring file integrity, detecting suspicious process activity, and integrating with VirusTotal for malware reputation checks.

## Features

* File Integrity Monitoring (FIM) using SHA-256 hashing
* Baseline creation and comparison
* Detection of created, modified, and deleted files
* Recursive directory monitoring
* Suspicious process detection using psutil
* VirusTotal hash reputation checks
* Configurable monitoring directories and file extensions
* Alert logging with timestamps
* Continuous monitoring mode
* One-time scan mode

## Technologies Used

* Python 3
* hashlib
* psutil
* requests
* VirusTotal API

## Usage

Build a baseline:

```bash
chomd +x setup.sh
./setup.sh
```

Run a one-time scan:

```bash
python3 main.py --once
```

Start continuous monitoring:

```bash
python3 main.py
```

## Project Structure

```text
main.py          # Program entry point
config.py        # Configuration management
scanner.py       # File and process monitoring
virustotal.py    # VirusTotal API integration
```

## Learning Objectives

This project demonstrates practical cybersecurity concepts including:

* Host Intrusion Detection Systems (HIDS)
* File Integrity Monitoring (FIM)
* Cryptographic Hashing
* Malware Reputation Analysis
* Process Monitoring
* Security Logging
* Python Security Automation

## Disclaimer

This project is intended for educational and research purposes only.
