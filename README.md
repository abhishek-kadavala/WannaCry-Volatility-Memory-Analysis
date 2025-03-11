# WannaCry-Volatility-Memory-Analysis
This repository contains a detailed forensic analysis of the WannaCry ransomware using the Volatility Framework. The analysis includes memory forensics techniques to extract artifacts, detect persistence mechanisms, analyze registry keys, find encryption traces, and identify indicators of compromise (IOCs) from an infected system's memory dump.

Features & Analysis Covered
✅ Extracting process lists and suspicious executables
✅ Identifying WannaCry mutexes and registry keys
✅ Finding network activity, including IPs and .onion domains
✅ Dumping and analyzing malware-related files
✅ Searching for Bitcoin wallet addresses and ransom notes
✅ Detecting persistence mechanisms and execution flow
✅ Memory artifact extraction for further investigation

Tools Used
Volatility 2.6.1 (for memory forensics)
Python 2.7 (required for Volatility 2.x)
grep, strings, awk (for log and data filtering)

