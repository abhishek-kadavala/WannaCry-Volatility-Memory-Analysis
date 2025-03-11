# Memory Analysis using Volatility

## Introduction  

This repository provides an in-depth forensic analysis of memory dumps using the **Volatility Framework**. The focus is on investigating the **WannaCry ransomware** attack through memory forensic techniques. By leveraging **Volatility 2.6.1**, we extract artifacts, detect persistence mechanisms, analyze registry keys, track network activity, and identify **Indicators of Compromise (IOCs)** from an infected system’s memory dump.  

Memory forensics is a crucial technique in **cybersecurity and incident response**, allowing investigators to recover **process lists, network connections, loaded DLLs, encryption traces, and malware artifacts** from volatile memory. This project documents the step-by-step analysis used to uncover **malicious activities** and **persistence mechanisms** related to the WannaCry ransomware.  

### Identifying the Operating System  

To begin the analysis, use the `imageinfo` plugin in Volatility to determine the operating system of the memory dump. Run the following command:  

```bash
python2.7 vol.py -f wannacry.vmem imageinfo
```

![imageinfo](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/imageinfo.png)

## Process Analysis  

This is the **Win7SP1x64** OS. Let's proceed with the `pslist` plugin to list the running processes:  

```bash
python2.7 vol.py -f sample/wanncry.vmem --profile=Win7SP1x64 pslist
```

`--profile` specifies the OS profile, and `pslist` lists the running processes along with their PID and virtual address.  

![pslist](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/pslist.png)

As we can see, `wannacry.exe` and `@wannacrydecruptor` are present, indicating possible malware.  

### Parent-Child Process Relationship  

To visualize parent-child relationships, use the `pstree` plugin:  

```bash
python2.7 vol.py -f sample/wanncry.vmem --profile=Win7SP1x64 pstree
```

![pstree](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/pstree.png)

`explorer.exe` directly opened `WannaCry.EXE`, which then launched `@WanaDecryptor.exe`, which subsequently started `taskhsvc.exe`. Since `taskhsvc.exe` is not a legitimate Windows process, it is suspicious.  

### Hidden Processes Detection  

Using `psscan`, we can detect hidden processes:

```bash
python2.7 vol.py -f sample/wanncry.vmem --profile=Win7SP1x64 psscan | sort -k 6
```

![psscan](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/psscan.png)

`taskdl.exe` (PID 2084) is hidden but was initiated by `WannaCry.EXE`, further confirming malicious activity.  

### Network Connections  

Checking network connections with `netscan`:

```bash
python2.7 vol.py -f sample/wanncry.vmem --profile=Win7SP1x64 netscan
```

![netscan](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/netscan.png)

`taskhsvc.exe` and `@WanaDecryptor.exe` are making connections, indicating potential C2 communication or communication to darkweb because it's ransomeware.  

### Identified Suspicious Processes  

- `2464` - WannaCry.EXE  
- `2340` - @WanaDecryptor.exe  
- `2752` - @WanaDecryptor.exe  
- `2092` - taskhsvc.exe  
- `2084` - taskdl.exe (Hidden)  

## Handles Analysis  

### Mutant Objects  

Mutants are often used by malware for synchronization. Let's scan for them in WannaCry.EXE:

```bash
python2.7 vol.py -f sample/wanncry.vmem --profile=Win7SP1x64 handles -t mutant -p 2464
```

![mutant](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/mutant.png)

Two mutant objects are present: `MsWinZonesCacheCounterMutexA` and `MsWinZonesCacheCounterMutexA0`, which are unique IOCs.  

### File Handles  

There is a chance that ransomware is accessing the file for encryption or using its own encryption key.
Checking files accessed by WannaCry.EXE:

```bash
python2.7 vol.py -f sample/wanncry.vmem --profile=Win7SP1x64 handles -t file -p 2464
```

![files](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/files.png)

It accesses `00000000.eky` (possibly an encryption key) and `hibsys.WNCRYT`, indicating encryption activity. However, in Windows, there is a file called `hibsys.sys` that exists. Maybe this file was encrypted by the malware. 

Checking `taskhsvc.exe` file access:

```bash
python2.7 vol.py -f sample/wanncry.vmem --profile=Win7SP1x64 handles -t file -p 2092
```

![2092_files](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/2092_files.png)

This process is accessing **Tor**, reinforcing its malicious nature.  

## DLL Analysis  

Legitimate executables follow a standard DLL order: `Executable -> ntdll.dll -> Kernel32.dll -> Other DLLs`.  

```bash
python2.7 vol.py -f sample/wanncry.vmem --profile=Win7SP1x64 dlllist -p 2464
```

![dlllist](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/dlllist.png)

If we notice first, four processes have a timestamp from 1970, while other processes have timestamps from 2021. This indicates the use of anti-forensic techniques.

Additionally, WannaCry.EXE and ntdll.dll are both repeating, which is quite unusual. As I mentioned, in a legitimate process, the DLL loading order should be: `executable -> ntdll.dll -> Kernel32.dll -> other DLLs`. However, in this case, there is no proper order.

But from line number 6, in the second occurrence of WannaCry.EXE, the DLL order is maintained.
This basically indicates DLL injection, as we see `ntdll.dll`, `wow64.dll`, `wow64win.dll`, and `wow64cpu.dll` being injected.

## Persistence Mechanism  

Most malware uses the registry for persistence. We check the **HKLM\Run** key:

```bash
python2.7 vol.py -f sample/wanncry.vmem --profile=Win7SP1x64 hivelist
```

![hivelist](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/hivelist.png)

```bash
python2.7 vol.py -f sample/wanncry.vmem --profile=Win7SP1x64 printkey -o 0xfffff8a0012f1010 -K "Microsoft\Windows\Currentversion\Run"
```

![software_run_key](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/software_run_key.png)

We didn't find anything.

Manually checking each registry is a time-consuming task, so let's search for `Software\Microsoft\Windows\CurrentVersion\Run` in every registry.

```bash
python2.7 vol.py -f sample/wanncry.vmem --profile=Win7SP1x64 printkey -K "Software\Microsoft\Windows\Currentversion\Run"
```

![persistant](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/persistant.png)

We got the `tasksche.exe` is suspicious and the random string `gvwcegcjpglxe848` is also suspicious, and if we check this exe on Google, it shows the WannaCry.

## Memory Dump  

We will dump the memory of all suspicious processes and analyze them. Using `memdump`, we can extract the entire process memory, unlike `procdump`, which only dumps the executable file.

Dumping WannaCry.EXE's memory:

```bash
python2.7 vol.py -f sample/wanncry.vmem --profile=Win7SP1x64 memdump -p 2464 -D ./dump
```

![2464_dump](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/2464_dump.png)

### Extracting Onion Links
Since the ransomware might communicate via Tor, let's analyze the dumped strings and grep for `.onion` links:

```bash
strings ./dump/2464.dmp | grep -i ".onion"
```
![Onion Links](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/2464_onion.png)

### Checking for Bitcoin Addresses
Bitcoin addresses might be embedded within the memory dump. Let's search for occurrences of "bitcoin":

```bash
strings ./dump/2464.dmp | grep -i "bitcoin"
```
![Bitcoin Search](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/2464_bitcoin.png)

We didn't get any address, but we are sure that it's available in this as the URL parameter `address` shows.

### Extracting Valid Bitcoin Addresses
Bitcoin addresses start with `1` or `3`, are 34 characters long, and legacy addresses begin with `bc1`. We use regex to extract them:

```bash
strings ./dump/2464.dmp | grep -E "^[13][A-Za-z0-9]{33}$"
```
![Bitcoin Address Regex](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/2464_regex_address.png)

Finally, we got the address of Bitcoin.

### Checking the Decryptor for Additional Information
To confirm, let's analyze the `@WanaDecryptor` file:

```bash
strings ./dump/2340.dmp | grep -i ".onion"
```
![Decryptor Onion Links](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/2340_onion.png)

### Extracting All Bitcoin Addresses from Memory
To find all Bitcoin addresses within the memory file, we apply regex directly to `wannacry.vmem`:

```bash
strings sample/wanncry.vmem | grep -E "^[13][A-Za-z0-9]{33}$"
```
![Bitcoin Addresses in Memory](https://github.com/abhishek-kadavala/WannaCry-Volatility-Memory-Analysis/blob/main/images/wannacry_regex_address.png)

---

This analysis confirms WannaCry’s behavior, revealing its **process execution, persistence mechanisms, network activity, and encryption techniques** through Volatility memory forensics.
