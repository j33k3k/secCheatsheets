# Windows DFIR Artifacts — Complete Reference

**Source:** Windows DFIR Artifacts MindMap (by @netbiosX)
**Toolset:** DFIRWS Win11 Forensics VM (352 tools)

---

## Category Legend

| Color | Category |
|-------|----------|
| 🟡 Yellow | Registry |
| 🟢 Light Green | Relevant Files and Log Files |
| 🔵 Blue | Files — NTFS |
| 🟣 Purple/Pink | Files — Databases |
| 🟩 Dark Green | Windows Event Logs |
| 🟠 Orange | Memory |

<img width="1995" height="1401" alt="image" src="https://github.com/user-attachments/assets/d240b485-7199-4ef1-b954-cda99fa6f01f" /> 
| Icon | Evidential Value |
|------|-----------------|
| 🔵 Cyan circle | Persistence Evidence |
| 🟢 Lime circle | File Presence Evidence |
| 🟡 Yellow circle | User Activity |
| 🔴 Red circle | Evidence of Execution |
| 🟣 Purple circle | Lateral Movement |
| 🩷 Pink circle | Data Exfiltration |


---

## 1. WINDOWS EVENT LOGS (🟩)

### 1.1 EVT / EVTX
**What:** Primary Windows event log format (.evtx). Contains Security, System, Application, and hundreds of operational logs.
**Use:** Timeline of system activity, logon events, process creation, service installs, privilege escalation, audit failures.
**Location:** `C:\Windows\System32\winevt\Logs\`
**Retrieval:**
```powershell
# Collect with KAPE
.\kape.exe --tsource C: --tdest C:\Evidence\EventLogs --target EventLogs

# Parse with EvtxECmd (all logs, full maps)
.\EvtxECmd.exe -d "C:\Evidence\EventLogs" --csv C:\Output\evtx --csvf evtx_all.csv

# View results
.\TimelineExplorer.exe C:\Output\evtx\evtx_all.csv

# Quick filter for Security log only
.\EvtxECmd.exe -f "C:\Evidence\Security.evtx" --csv C:\Output\evtx --csvf security.csv
```

### 1.2 BITS Logs & Files
**What:** Background Intelligent Transfer Service logs. BITS is used by Windows Update but also abused for stealthy downloads by malware.
**Use:** Detect malicious file transfers, C2 downloads, lateral movement file staging. Persistence via BITS jobs.
**Location:** `C:\ProgramData\Microsoft\Network\Downloader\qmgr.db` and BITS-Client operational log.
**Retrieval:**
```powershell
# Parse BITS EVTX
.\EvtxECmd.exe -f "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Bits-Client%4Operational.evtx" --csv C:\Output --csvf bits.csv

# Extract BITS database (ESE format)
.\ESEDatabaseView.exe "C:\ProgramData\Microsoft\Network\Downloader\qmgr.db"

# PowerShell live: list active BITS jobs
Get-BitsTransfer -AllUsers | Format-List *
```

### 1.3 Authentication Logs
**What:** Security.evtx events covering logon (4624), logoff (4634), failed logon (4625), explicit credential use (4648), Kerberos TGT/TGS requests (4768/4769).
**Use:** Identify brute force, pass-the-hash, lateral movement, privilege escalation, service account abuse.
**Retrieval:**
```powershell
# Parse Security log with EvtxECmd
.\EvtxECmd.exe -f "C:\Evidence\Security.evtx" --csv C:\Output --csvf auth.csv

# Filter for logon events in TimelineExplorer: EventID 4624,4625,4648,4768,4769,4771
# PowerShell live query
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624,4625,4648} | Select TimeCreated,Id,Message | Export-Csv auth_events.csv
```

### 1.4 Account Created
**What:** Security Event ID 4720 (user account created), 4722 (enabled), 4732 (added to local group), 4728 (added to global group).
**Use:** Detect attacker-created backdoor accounts, privilege escalation via group membership changes.
**Retrieval:**
```powershell
.\EvtxECmd.exe -f "C:\Evidence\Security.evtx" --csv C:\Output --csvf acct.csv
# Filter EventID: 4720, 4722, 4726, 4728, 4732, 4733, 4756
```

### 1.5 Process Creations
**What:** Security Event ID 4688 (process creation with command line), Sysmon Event ID 1. Records parent-child process relationships and full command lines.
**Use:** Detect malicious execution chains, LOLBins, encoded PowerShell, lateral movement tooling.
**Retrieval:**
```powershell
# Security log process creation
.\EvtxECmd.exe -f "C:\Evidence\Security.evtx" --csv C:\Output --csvf proccreate.csv
# Filter EventID 4688

# Sysmon process creation (if Sysmon installed)
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-Sysmon%4Operational.evtx" --csv C:\Output --csvf sysmon.csv
# Filter EventID 1
```

### 1.6 RDP Logs
**What:** TerminalServices-RemoteConnectionManager (Event 1149 — successful RDP auth), TerminalServices-LocalSessionManager (21/22/23/24/25 — session lifecycle), Security 4624 Type 10.
**Use:** Track lateral movement via RDP, session duration, source IPs.
**Retrieval:**
```powershell
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx" --csv C:\Output --csvf rdp_conn.csv
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx" --csv C:\Output --csvf rdp_session.csv
```

### 1.7 WMI Consumer Created
**What:** Microsoft-Windows-WMI-Activity/Operational log. Event IDs 5857–5861 track WMI provider loads, filter-to-consumer bindings, and permanent event subscriptions.
**Use:** Detect WMI-based persistence (event subscriptions), lateral movement via WMI, fileless execution.
**Retrieval:**
```powershell
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-WMI-Activity%4Operational.evtx" --csv C:\Output --csvf wmi.csv
# Filter EventID 5857,5858,5859,5860,5861
```

### 1.8 PowerShell Events & Logs
**What:** Microsoft-Windows-PowerShell/Operational (Event 4104 — ScriptBlock logging, 4103 — module logging), Windows PowerShell (classic, Event 400/403/600).
**Use:** Reconstruct attacker PowerShell commands, detect encoded commands, download cradles, AMSI bypass attempts.
**Retrieval:**
```powershell
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-PowerShell%4Operational.evtx" --csv C:\Output --csvf ps_operational.csv
.\EvtxECmd.exe -f "C:\Evidence\Windows PowerShell.evtx" --csv C:\Output --csvf ps_classic.csv
# Focus on EventID 4104 for ScriptBlock content
```

### 1.9 Sysmon Logs
**What:** Microsoft-Windows-Sysmon/Operational. If Sysmon is deployed, provides granular process, network, file, registry, DNS, WMI, pipe, and image load events (IDs 1–29).
**Use:** Gold standard for endpoint telemetry — process trees, network connections, file creation timestamps, DLL loads.
**Retrieval:**
```powershell
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-Sysmon%4Operational.evtx" --csv C:\Output --csvf sysmon_all.csv
```

### 1.10 Service Installation & Execution Logs
**What:** System Event ID 7045 (new service installed), 7036 (service started/stopped), 7040 (start type changed). Security Event 4697 (service installed).
**Use:** Detect malicious service persistence (PsExec, Cobalt Strike service EXE, ransomware deployment).
**Retrieval:**
```powershell
.\EvtxECmd.exe -f "C:\Evidence\System.evtx" --csv C:\Output --csvf services.csv
# Filter EventID 7045, 7036, 7040
```

### 1.11 AppLocker Events
**What:** Microsoft-Windows-AppLocker/* logs. Events 8003/8004 (blocked), 8005/8006 (allowed), 8007 (audit).
**Use:** Determine if application whitelisting blocked or allowed attacker tools.
**Retrieval:**
```powershell
.\EvtxECmd.exe -d "C:\Evidence\Microsoft-Windows-AppLocker*.evtx" --csv C:\Output --csvf applocker.csv
```

### 1.12 AV Log Files
**What:** Microsoft-Windows-Windows Defender/Operational (Event 1116/1117 — detection/action), third-party AV logs.
**Use:** Identify what was detected and when, quarantined files, disabled protection timestamps.
**Retrieval:**
```powershell
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-Windows Defender%4Operational.evtx" --csv C:\Output --csvf defender.csv
# Also check: C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log
```

### 1.13 ETW Traces Files (.etl)
**What:** Event Tracing for Windows binary trace files. Providers include DNS, TCP/IP, Firewall, Defender, .NET runtime.
**Use:** Low-level kernel and provider events not captured in EVTX. Network connection details, DNS resolution traces.
**Location:** `C:\Windows\System32\LogFiles\WMI\`, various `.etl` files.
**Retrieval:**
```powershell
# Parse ETL files
.\etwdump.exe "C:\Evidence\trace.etl" --csv C:\Output --csvf etw_trace.csv

# Or convert with PowerShell
Get-WinEvent -Path "C:\Evidence\trace.etl" -Oldest | Export-Csv etw_output.csv
```

---

## 2. RELEVANT FILES AND LOG FILES (Light Green)

### 2.1 NTLM Logs
**What:** NTLM authentication events in Security log (4776 — credential validation) and NTLM operational log.
**Use:** Detect pass-the-hash attacks, NTLM relay, downgrade attacks from Kerberos to NTLM.
**Retrieval:**
```powershell
.\EvtxECmd.exe -f "C:\Evidence\Security.evtx" --csv C:\Output --csvf ntlm.csv
# Filter EventID 4776
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-NTLM%4Operational.evtx" --csv C:\Output --csvf ntlm_op.csv
```

### 2.2 SMB Logs
**What:** SMB client/server events. Security log 5140/5145 (share access), SMB operational logs.
**Use:** Lateral movement tracking, file share access, PsExec/WMI remote share usage, data exfiltration staging.
**Retrieval:**
```powershell
.\EvtxECmd.exe -f "C:\Evidence\Security.evtx" --csv C:\Output --csvf smb_access.csv
# Filter EventID 5140, 5145
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-SMBServer%4Security.evtx" --csv C:\Output --csvf smb_server.csv
```

### 2.3 WINRM Logs
**What:** Windows Remote Management logs. Microsoft-Windows-WinRM/Operational. Used for PowerShell Remoting and WS-Management.
**Use:** Detect remote command execution via Enter-PSSession / Invoke-Command, lateral movement.
**Retrieval:**
```powershell
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-WinRM%4Operational.evtx" --csv C:\Output --csvf winrm.csv
```

### 2.4 Named Pipes Events
**What:** Sysmon Event IDs 17/18 (pipe created/connected). Named pipes are IPC mechanisms often used by C2 frameworks.
**Use:** Detect Cobalt Strike SMB beacons (default pipe names like `\MSSE-*`, `\msagent_*`), PsExec pipes, lateral movement.
**Retrieval:**
```powershell
# Requires Sysmon
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-Sysmon%4Operational.evtx" --csv C:\Output --csvf pipes.csv
# Filter EventID 17, 18
```

### 2.5 Windows Firewall Logs
**What:** `C:\Windows\System32\LogFiles\Firewall\pfirewall.log` and Microsoft-Windows-Windows Firewall With Advanced Security events.
**Use:** Identify blocked/allowed connections, firewall rule changes (attacker disabling FW), port scans.
**Retrieval:**
```powershell
# Copy firewall log
copy "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" C:\Evidence\

# Parse firewall EVTX
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx" --csv C:\Output --csvf fw.csv

# System log firewall events
# Filter EventID 2004 (rule added), 2006 (rule deleted), 2033 (rule modified)
```

### 2.6 Group Policy Files & Logs
**What:** `C:\Windows\System32\GroupPolicy\`, `C:\Windows\debug\UserMode\gpsvc.log`, Group Policy operational EVTX.
**Use:** Detect GPO-based attacks (pushing malicious scripts/tasks via GPO), policy tampering.
**Retrieval:**
```powershell
# Collect GPO files
robocopy "C:\Windows\System32\GroupPolicy" "C:\Evidence\GPO" /E /COPYALL
# Parse GP operational log
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-GroupPolicy%4Operational.evtx" --csv C:\Output --csvf gpo.csv
```

### 2.7 AMSI Logs
**What:** Anti-Malware Scan Interface logs. AMSI captures content from PowerShell, VBScript, JScript, .NET, WMI, and Office macros before execution.
**Use:** See exact malicious script content that was submitted to AMSI for scanning, even if obfuscated at the PS layer.
**Retrieval:**
```powershell
# AMSI events appear in Windows Defender operational log (Event 1116) and
# Microsoft-Windows-AMSI/Debug (if enabled)
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-Windows Defender%4Operational.evtx" --csv C:\Output --csvf amsi.csv
```

### 2.8 Web Application & Proxy Logs
**What:** IIS logs (`C:\inetpub\logs\LogFiles\`), Apache/Nginx logs, proxy logs (Squid, Blue Coat, etc.).
**Use:** Web shell access patterns, SQL injection attempts, exploitation timelines, C2 over HTTP.
**Retrieval:**
```powershell
# Collect IIS logs
robocopy "C:\inetpub\logs\LogFiles" "C:\Evidence\IIS" /E
# Geolocate IPs in IIS logs
.\iisGeolocate.exe -f "C:\Evidence\IIS\u_ex*.log" --csv C:\Output\iis_geo.csv
```

### 2.9 Executables in Specific Directories
**What:** Suspicious EXE/DLL/script files in unusual locations: `C:\Windows\Temp\`, `C:\Users\Public\`, `C:\PerfLogs\`, user temp/AppData dirs, System32 (misplaced binaries).
**Use:** Dropped malware, tools, webshells, attacker utilities staged for execution.
**Retrieval:**
```powershell
# Scan suspicious directories
.\clamscan.exe -r C:\Windows\Temp\ --log=C:\Output\temp_scan.log
.\clamscan.exe -r C:\Users\Public\ --log=C:\Output\public_scan.log

# String analysis on suspicious files
.\bstrings.exe -f "C:\Evidence\suspicious.exe" -o C:\Output\strings.txt --ls 8

# PE analysis
.\4N4LDetector.exe  # Open GUI, load suspicious binary
```

### 2.10 OneDrive / GoogleDrive / Dropbox Log Files
**What:** Cloud sync client logs. OneDrive: `%LocalAppData%\Microsoft\OneDrive\logs\`, Google Drive: `%LocalAppData%\Google\DriveFS\Logs\`, Dropbox: `%AppData%\Dropbox\`.
**Use:** Data exfiltration via cloud sync, timestamped file sync events, what was uploaded.
**Retrieval:**
```powershell
# Collect cloud sync logs
robocopy "%LocalAppData%\Microsoft\OneDrive\logs" "C:\Evidence\OneDrive" /E
robocopy "%LocalAppData%\Google\DriveFS\Logs" "C:\Evidence\GDrive" /E
robocopy "%AppData%\Dropbox" "C:\Evidence\Dropbox" *.log /S
```

### 2.11 SSH Authorized Keys Files
**What:** `C:\Users\<user>\.ssh\authorized_keys` and `C:\ProgramData\ssh\administrators_authorized_keys`. OpenSSH server configuration.
**Use:** Detect backdoor SSH keys planted for persistent remote access.
**Retrieval:**
```powershell
# Enumerate all authorized_keys files
Get-ChildItem -Path C:\Users -Recurse -Filter "authorized_keys" -ErrorAction SilentlyContinue
Get-Content "C:\ProgramData\ssh\administrators_authorized_keys" -ErrorAction SilentlyContinue
# Also check sshd_config for custom paths
type "C:\ProgramData\ssh\sshd_config"
```

### 2.12 WMI MOF Files
**What:** Managed Object Format files used to define WMI classes and event subscriptions. Located at `C:\Windows\System32\wbem\AutoRecover\`.
**Use:** Persistence via WMI event subscriptions compiled from MOF files. Attackers drop malicious MOF files.
**Retrieval:**
```powershell
# Collect MOF files
robocopy "C:\Windows\System32\wbem" "C:\Evidence\WMI" *.mof /S
# List auto-recover MOFs
dir "C:\Windows\System32\wbem\AutoRecover\*.mof"
```

### 2.13 VPN Agent Log Files
**What:** VPN client logs — Cisco AnyConnect, GlobalProtect, WireGuard, OpenVPN logs.
**Use:** Identify VPN sessions, source IPs, connection durations, unauthorized VPN usage.
**Retrieval:**
```powershell
# Common VPN log locations
robocopy "C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client" "C:\Evidence\VPN" *.log /S
robocopy "%LocalAppData%\Palo Alto Networks\GlobalProtect" "C:\Evidence\VPN_GP" *.log /S
```

### 2.14 Sysvol Folder
**What:** `\\<DC>\SYSVOL\<domain>\` — contains GPO scripts, logon scripts, group policy templates. Replicated across DCs.
**Use:** Detect GPO-delivered malware, malicious logon scripts, modified policy objects.
**Retrieval:**
```powershell
# On domain controller
robocopy "C:\Windows\SYSVOL" "C:\Evidence\SYSVOL" /E /COPYALL
# Check scripts folder specifically
dir "C:\Windows\SYSVOL\sysvol\<domain>\scripts\" /s
```

### 2.15 Startup Folder Files
**What:** `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` and `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\`.
**Use:** Persistence — shortcuts or scripts placed here run at user logon.
**Retrieval:**
```powershell
# All user startup folders
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -Recurse
# All-users startup
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Recurse
```

### 2.16 StartupInfo XML Files
**What:** `C:\Windows\System32\WDI\LogFiles\StartupInfo\*.xml` — records first 5 process starts after logon with command lines and timing.
**Use:** See what executed immediately at boot/logon — catches persistence and early-stage malware.
**Retrieval:**
```powershell
robocopy "C:\Windows\System32\WDI\LogFiles\StartupInfo" "C:\Evidence\StartupInfo" *.xml
# Parse with PowerShell
Get-ChildItem "C:\Evidence\StartupInfo\*.xml" | ForEach-Object { [xml](Get-Content $_) | Select-Xml "//Process" | Select -Expand Node }
```

### 2.17 NetLogon Log File
**What:** `C:\Windows\debug\netlogon.log` — DC authentication traffic debug log. Records domain logon attempts and their results.
**Use:** Detect pass-the-hash/pass-the-ticket across the domain, account lockout sources, trust authentication issues.
**Retrieval:**
```powershell
copy "C:\Windows\debug\netlogon.log" "C:\Evidence\"
# Enable detailed logging if not already
nltest /dbflag:0x2080ffff
```

### 2.18 Browser Files
**What:** Chrome/Edge/Firefox history, downloads, cache, cookies, bookmarks, autofill, saved passwords (encrypted).
**Use:** User activity, phishing link clicks, malware download URLs, web-based C2 comms, attacker research on victim network.
**Location:** `%LocalAppData%\Google\Chrome\User Data\Default\`, `%LocalAppData%\Microsoft\Edge\User Data\Default\`, `%AppData%\Mozilla\Firefox\Profiles\`
**Retrieval:**
```powershell
# Parse browser SQLite databases
.\SQLECmd.exe -d "C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default" --csv C:\Output --csvf chrome.csv

# Parse Edge
.\SQLECmd.exe -d "C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default" --csv C:\Output --csvf edge.csv
```

### 2.19 Web Access Log Files (Apache)
**What:** Apache/IIS access logs recording HTTP requests, source IPs, URIs, user agents, response codes.
**Use:** Webshell access, exploitation attempts, reconnaissance, data exfiltration via HTTP.
**Retrieval:**
```powershell
.\iisGeolocate.exe -f "C:\inetpub\logs\LogFiles\W3SVC1\*.log" --csv C:\Output\iis.csv
```

### 2.20 DNS Client & Server Logs
**What:** DNS Client events (Microsoft-Windows-DNS-Client/Operational), DNS Server logs (on DCs). DNS debug logging and analytical logs.
**Use:** DNS tunneling detection, C2 domain lookups, DGA domain patterns, DNS exfiltration.
**Retrieval:**
```powershell
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-DNSServer%4Analytical.evtx" --csv C:\Output --csvf dns_server.csv
# DNS client cache (live)
Get-DnsClientCache | Export-Csv C:\Evidence\dns_cache.csv
```

### 2.21 USB Devices Logs / Keys / Events
**What:** `SYSTEM\CurrentControlSet\Enum\USBSTOR`, `SYSTEM\CurrentControlSet\Enum\USB`, setupapi.dev.log, Security 6416 (new external device).
**Use:** Track USB device connections, timestamps, serial numbers — insider threat/data exfiltration investigations.
**Retrieval:**
```powershell
# Registry parse for USB history
.\RECmd.exe -d "C:\Evidence\Registry" --bn RECmd\BatchExamples\USB.reb --csv C:\Output --csvf usb.csv

# Or via RegistryExplorer
.\RegistryExplorer.exe  # Navigate to SYSTEM\CurrentControlSet\Enum\USBSTOR

# setupapi log
copy "C:\Windows\INF\setupapi.dev.log" "C:\Evidence\"
```

### 2.22 Email Client Files & Logs
**What:** Outlook PST/OST files (`%LocalAppData%\Microsoft\Outlook\`), Thunderbird profiles, web mail download logs.
**Use:** Phishing email analysis, attachment extraction, email exfiltration, BEC investigation.
**Retrieval:**
```powershell
# Collect Outlook data files
robocopy "%LocalAppData%\Microsoft\Outlook" "C:\Evidence\Outlook" *.pst *.ost
# PST can be opened in Autopsy or with pst-parser tools
```

### 2.23 Defender Files & Logs
**What:** Windows Defender quarantine (`C:\ProgramData\Microsoft\Windows Defender\Quarantine\`), scan history, MPLog files, detection history.
**Use:** Recover quarantined malware for analysis, correlate detection times, check if Defender was disabled.
**Retrieval:**
```powershell
# Collect Defender artifacts
robocopy "C:\ProgramData\Microsoft\Windows Defender" "C:\Evidence\Defender" /E
# Parse Defender operational log
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-Windows Defender%4Operational.evtx" --csv C:\Output --csvf defender_events.csv
# Live: check Defender status
Get-MpComputerStatus
Get-MpThreatDetection | Format-List *
```

### 2.24 Scheduled Tasks Logs & Job Files
**What:** Task XML files at `C:\Windows\System32\Tasks\`, Task Scheduler operational log (Event 106/140/141/200/201), legacy .job files at `C:\Windows\Tasks\`.
**Use:** Persistence via scheduled tasks, detect attacker-created tasks (running payloads, reverse shells).
**Retrieval:**
```powershell
# Collect all task definitions
robocopy "C:\Windows\System32\Tasks" "C:\Evidence\Tasks" /E
robocopy "C:\Windows\Tasks" "C:\Evidence\Jobs" *.job

# Parse Task Scheduler log
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-TaskScheduler%4Operational.evtx" --csv C:\Output --csvf tasks.csv
# Filter EventID 106 (created), 140 (updated), 141 (deleted), 200 (action started), 201 (action completed)
```

### 2.25 Data Transfer Tools Logs
**What:** Logs from tools like Robocopy, xcopy, BITS, rclone, WinSCP, FileZilla, FTP client logs.
**Use:** Evidence of data staging and exfiltration, what was copied and when, destination paths/hosts.
**Retrieval:**
```powershell
# Check for rclone/WinSCP/FileZilla configs and logs
Get-ChildItem "C:\Users" -Recurse -Include "rclone.conf","WinSCP.ini","sitemanager.xml","filezilla.log" -ErrorAction SilentlyContinue
```

### 2.26 WSL System Files & Logs
**What:** Windows Subsystem for Linux root filesystem at `%LocalAppData%\Packages\CanonicalGroupLimited.*\LocalState\rootfs\`, bash history, WSL distro configs.
**Use:** Attackers may use WSL to bypass EDR, run Linux-native tools, proxy network traffic.
**Retrieval:**
```powershell
# Find WSL installations
Get-ChildItem "%LocalAppData%\Packages\*Ubuntu*\LocalState\rootfs" -ErrorAction SilentlyContinue
# Copy bash history
copy "%LocalAppData%\Packages\*Ubuntu*\LocalState\rootfs\home\*\.bash_history" "C:\Evidence\"
```

### 2.27 RDPCache / RDP Jumplist
**What:** RDP bitmap cache at `%LocalAppData%\Microsoft\Terminal Server Client\Cache\bcache*.bmc` and `Cache0000.bin`. Also RDP MRU at `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\`.
**Use:** Reconstruct screenshots of what the attacker saw via RDP. Identify RDP target hosts.
**Retrieval:**
```powershell
# Collect RDP cache files
robocopy "%LocalAppData%\Microsoft\Terminal Server Client\Cache" "C:\Evidence\RDPCache" /E
# For reconstruction: download bmc-tools (github.com/ANSSI-FR/bmc-tools)
# python bmc-tools.py -s C:\Evidence\RDPCache -d C:\Output\RDPScreenshots

# RDP MRU from registry
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Microsoft\Terminal Server Client\Servers" --csv C:\Output --csvf rdp_mru.csv
```

### 2.28 IIS Log Files
**What:** IIS web server logs recording all HTTP/HTTPS requests with timestamps, source IPs, URIs, query strings, HTTP methods, user agents, and response codes.
**Location:** `C:\inetpub\logs\LogFiles\W3SVC<n>\`
**Use:** Webshell access detection, exploitation timeline, reconnaissance patterns, data exfiltration via web requests.
**Retrieval:**
```powershell
robocopy "C:\inetpub\logs\LogFiles" "C:\Evidence\IIS" /E
.\iisGeolocate.exe -f "C:\Evidence\IIS\W3SVC1\*.log" --csv C:\Output\iis_geo.csv
```

### 2.29 Windows Drivers Files
**What:** `C:\Windows\System32\drivers\` — kernel-mode driver files (.sys). Also driver signing info and catalog files.
**Use:** Detect unsigned/malicious kernel drivers (rootkits), BYOVD (Bring Your Own Vulnerable Driver) attacks.
**Retrieval:**
```powershell
# List unsigned drivers (live)
Get-WmiObject Win32_SystemDriver | Where {$_.Started -eq $true} | Select Name,PathName,State | Export-Csv C:\Evidence\drivers.csv
# Scan drivers directory with ClamAV
.\clamscan.exe -r "C:\Windows\System32\drivers" --log=C:\Output\driver_scan.log
```

### 2.30 RMM/RAT Log Files
**What:** Logs from Remote Monitoring/Management tools (TeamViewer, AnyDesk, ConnectWise, etc.) and RATs.
**Use:** Detect unauthorized remote access, attacker-installed RMM tools for persistence.
**Location:** TeamViewer: `%AppData%\TeamViewer\`, AnyDesk: `%ProgramData%\AnyDesk\`, ConnectWise: `C:\Windows\Temp\ScreenConnect\`
**Retrieval:**
```powershell
# TeamViewer connections log
copy "%AppData%\TeamViewer\Connections_incoming.txt" "C:\Evidence\"
copy "%AppData%\TeamViewer\TeamViewer*_Logfile.log" "C:\Evidence\"
# AnyDesk
copy "%ProgramData%\AnyDesk\connection_trace.txt" "C:\Evidence\"
copy "%ProgramData%\AnyDesk\ad_svc.trace" "C:\Evidence\"
```

### 2.31 Windows RPC Firewall Logs
**What:** RPC firewall filtering events when RPC Firewall is deployed. Tracks RPC interface calls.
**Use:** Detect DCSync (DRSR interface), remote service creation, remote scheduled task creation, PetitPotam.
**Retrieval:**
```powershell
# If RPC Firewall is deployed (github.com/zeronetworks/rpcfirewall)
.\EvtxECmd.exe -f "C:\Evidence\RPCFW%4Operational.evtx" --csv C:\Output --csvf rpcfw.csv
```

### 2.32 Microsoft-Windows-Shell-Core/Operational
**What:** Shell-Core operational log. Records application launches from Explorer shell, start menu interactions.
**Use:** Evidence of execution — what the user launched via the GUI shell.
**Retrieval:**
```powershell
.\EvtxECmd.exe -f "C:\Evidence\Microsoft-Windows-Shell-Core%4Operational.evtx" --csv C:\Output --csvf shellcore.csv
```

### 2.33 SCCM Agent Files & Logs
**What:** SCCM/MECM client logs at `C:\Windows\CCM\Logs\`. Tracks software deployments, policy updates, application installs.
**Use:** Detect SCCM-based lateral movement, malicious package deployment, compromised SCCM infrastructure.
**Retrieval:**
```powershell
robocopy "C:\Windows\CCM\Logs" "C:\Evidence\SCCM" *.log
```

### 2.34 Scripts Files (vbs, ps1, bat, cmd, py…)
**What:** Attacker scripts found anywhere on disk — PowerShell (.ps1), batch (.bat/.cmd), VBScript (.vbs), Python (.py), JavaScript (.js).
**Use:** Malware payloads, persistence scripts, reconnaissance scripts, credential harvesters, exfiltration scripts.
**Retrieval:**
```powershell
# Search for scripts in suspicious locations
Get-ChildItem C:\Windows\Temp,C:\Users\Public,"C:\PerfLogs" -Include *.ps1,*.bat,*.cmd,*.vbs,*.js,*.py -Recurse -ErrorAction SilentlyContinue

# String/static analysis
.\bstrings.exe -f "C:\Evidence\malicious.ps1" -o C:\Output\script_strings.txt

# Deobfuscate JavaScript
# Use synchrony.ps1 for JS deobfuscation
```

### 2.35 Office Cache / Servercache & Saved Documents
**What:** Office file cache at `%LocalAppData%\Microsoft\Office\<version>\OfficeFileCache\`, recent documents cache, auto-save files.
**Use:** Recover documents opened (including from network/cloud), phishing document artifacts, data exfiltration via Office files.
**Retrieval:**
```powershell
robocopy "%LocalAppData%\Microsoft\Office" "C:\Evidence\OfficeCache" /E /S
# Check recent docs
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Microsoft\Office" --csv C:\Output --csvf office_mru.csv
```

### 2.36 AppX Packages Folders
**What:** UWP/Store app packages at `C:\Program Files\WindowsApps\` and `%LocalAppData%\Packages\`.
**Use:** Sideloaded malicious AppX packages, unusual store apps, app data containing artifacts.
**Retrieval:**
```powershell
# List installed AppX packages
Get-AppxPackage -AllUsers | Select Name,InstallLocation,Version | Export-Csv C:\Evidence\appx.csv
```

### 2.37 NTDS.dit / EDB Logs
**What:** Active Directory database (`C:\Windows\NTDS\ntds.dit`) and transaction logs. Contains all AD objects, password hashes, Kerberos keys.
**Use:** Detect if ntds.dit was exfiltrated (DCSync or volume shadow copy), extract compromised hashes.
**Retrieval:**
```powershell
# Check for ntds.dit copies/exfiltration evidence
# On a DC — check VSS for ntds.dit extraction
vssadmin list shadows
# Check for ntdsutil/secretsdump artifacts
.\EvtxECmd.exe -f "C:\Evidence\Security.evtx" --csv C:\Output --csvf dcsync.csv
# Filter EventID 4662 with GUID {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes-All)
```

### 2.38 Winget Activity
**What:** Windows Package Manager (winget) logs at `%LocalAppData%\Packages\Microsoft.DesktopAppInstaller_*\LocalState\DiagOutputDir\`.
**Use:** Track software installations via winget — attacker-installed tools.
**Retrieval:**
```powershell
robocopy "%LocalAppData%\Packages\Microsoft.DesktopAppInstaller_*\LocalState\DiagOutputDir" "C:\Evidence\Winget" /E
```

### 2.39 INetCache / CryptoNetUrlCache
**What:** IE/Edge legacy cache at `%LocalAppData%\Microsoft\Windows\INetCache\`, CryptnetUrlCache for CRL/OCSP responses.
**Use:** Cached web content, downloaded files, certificate validation events (malware code signing investigation).
**Retrieval:**
```powershell
robocopy "%LocalAppData%\Microsoft\Windows\INetCache" "C:\Evidence\INetCache" /E
robocopy "%LocalAppData%\Microsoft\Windows\INetCache\Content.IE5" "C:\Evidence\INetCache_IE5" /E
```

### 2.40 Volume Shadow Copies
**What:** VSS snapshots of entire volumes. Point-in-time copies that may preserve deleted/modified evidence.
**Use:** Recover deleted files, compare current vs. previous state, access ntds.dit copies, recover registry hives pre-attack.
**Retrieval:**
```powershell
# List shadow copies
vssadmin list shadows

# Mount with VSCMount
.\VSCMount.exe --dl C:\VSS_Mount -f C:\Evidence\disk.dd

# Or via mklink
mklink /d C:\VSS_Mount \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

### 2.41 DNS Hosts File
**What:** `C:\Windows\System32\drivers\etc\hosts` — static DNS resolution overrides.
**Use:** Attackers modify to redirect traffic (phishing, block AV updates, redirect C2 to new IPs).
**Retrieval:**
```powershell
copy "C:\Windows\System32\drivers\etc\hosts" "C:\Evidence\"
type "C:\Windows\System32\drivers\etc\hosts"
```

### 2.42 Files, Chat and Call History Logs (Teams, Zoom…)
**What:** Microsoft Teams logs (`%AppData%\Microsoft\Teams\`), Zoom logs (`%AppData%\Zoom\logs\`), Slack logs.
**Use:** Communication evidence, file sharing history, meeting recordings metadata.
**Retrieval:**
```powershell
robocopy "%AppData%\Microsoft\Teams" "C:\Evidence\Teams" *.log /S
robocopy "%AppData%\Zoom\logs" "C:\Evidence\Zoom" *.log /S
```

### 2.43 Other Specific Files
**What:** Any other forensically relevant files specific to the case — malware samples, configuration files, dropped tools, attacker notes.
**Use:** Case-dependent evidence collection.

---

## 3. REGISTRY (Yellow)

### 3.1 Tracing Key
**What:** `HKLM\SOFTWARE\Microsoft\Tracing\` — tracks DLL/API usage for diagnostics on RAS, MAPI, and network components.
**Use:** Identify network-facing applications that were active; can indicate C2 or exfiltration tools.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\SOFTWARE" --key "Microsoft\Tracing" --csv C:\Output --csvf tracing.csv
```

### 3.2 COMPONENTS Hive
**What:** `C:\Windows\System32\config\COMPONENTS` — Component Based Servicing (CBS) database tracking Windows feature/update installations.
**Use:** Determine installed features, updates, rollback history — identify if security patches were removed.
**Retrieval:**
```powershell
.\RegistryExplorer.exe  # Load C:\Windows\System32\config\COMPONENTS
```

### 3.3 DRIVER Hive
**What:** Registry hive tracking installed device drivers and their configuration.
**Use:** Identify malicious drivers loaded, BYOVD attacks, rootkit driver installations.
**Retrieval:**
```powershell
.\RegistryExplorer.exe  # Load SYSTEM hive, navigate to CurrentControlSet\Services (Type=1 for kernel drivers)
```

### 3.4 BBI Hive
**What:** `C:\Windows\System32\config\BBI` — Broadband Interface / Bridge Bus Interface hive. Related to hardware/firmware data.
**Use:** Niche — hardware configuration forensics.
**Retrieval:**
```powershell
.\RegistryExplorer.exe  # Load C:\Windows\System32\config\BBI
```

### 3.5 FirewallPolicy
**What:** `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\` — Windows Firewall rules and profiles (Domain/Private/Public).
**Use:** Detect disabled firewall profiles, attacker-added allow rules, port openings.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\SYSTEM" --key "ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy" --csv C:\Output --csvf fwpolicy.csv
```

### 3.6 TypedURLs
**What:** `NTUSER.DAT\Software\Microsoft\Internet Explorer\TypedURLs\` (and Edge legacy). URLs manually typed in the address bar.
**Use:** User browsing intent, C2 panel access, attacker-visited URLs.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Microsoft\Internet Explorer\TypedURLs" --csv C:\Output --csvf typedurls.csv
```

### 3.7 SysInternals (EULAs Accepted)
**What:** `NTUSER.DAT\Software\Sysinternals\` — EULA acceptance entries for Sysinternals tools. Each tool gets a key with EulaAccepted=1.
**Use:** Evidence that an attacker used specific Sysinternals tools (PsExec, Procdump, etc.) — the EULA key is created on first run.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Sysinternals" --csv C:\Output --csvf sysinternals.csv
```

### 3.8 Tasks & TaskCache
**What:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\` — registry mirror of all scheduled tasks with metadata (triggers, actions, creation dates).
**Use:** Persistence detection, identify tasks created by attackers even if XML definition was deleted.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\SOFTWARE" --key "Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache" --csv C:\Output --csvf taskcache.csv
```

### 3.9 OpenSave / LastVisited MRU
**What:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\` and `LastVisitedPidlMRU\`.
**Use:** Tracks files opened/saved via common dialogs. Shows file paths and applications used — evidence of file access and exfiltration staging.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32" --csv C:\Output --csvf opensave.csv
```

### 3.10 Service Keys
**What:** `HKLM\SYSTEM\CurrentControlSet\Services\` — all Windows services including drivers. Each key has ImagePath, Start type, ObjectName (account), Description.
**Use:** Detect malicious services (persistence), PsExec service creation, modified service binaries.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\SYSTEM" --key "ControlSet001\Services" --csv C:\Output --csvf services.csv
# Or use RegistryExplorer for interactive browsing
```

### 3.11 TypedPaths
**What:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths\` — UNC paths and local paths typed into Explorer address bar.
**Use:** Evidence of network share access, lateral movement target identification.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" --csv C:\Output --csvf typedpaths.csv
```

### 3.12 Explorer FeatureUsage
**What:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\` — tracks taskbar pinned apps, app launches, app switches.
**Use:** Evidence of execution and user activity via Explorer shell interaction counters.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage" --csv C:\Output --csvf featureusage.csv
```

### 3.13 Search History / WordWheelQuery
**What:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery\` — searches performed via Explorer search bar.
**Use:** What the user/attacker searched for on the filesystem — reconnaissance, file hunting.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" --csv C:\Output --csvf wordwheel.csv
```

### 3.14 Office MRU
**What:** `NTUSER.DAT\Software\Microsoft\Office\<version>\<app>\File MRU\` — recently opened Office documents per application.
**Use:** Track document access, identify phishing attachments opened, staged exfiltration documents.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Microsoft\Office" --csv C:\Output --csvf office_mru.csv
```

### 3.15 LogonUI
**What:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\` — last logged-on user, session data, background settings.
**Use:** Identify last interactive logon user on a system.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\SOFTWARE" --key "Microsoft\Windows\CurrentVersion\Authentication\LogonUI" --csv C:\Output --csvf logonui.csv
```

### 3.16 SAM Hive
**What:** `C:\Windows\System32\config\SAM` — Security Account Manager. Contains local user accounts, password hashes (NTLM), group memberships, last logon timestamps, account creation dates.
**Use:** Identify local backdoor accounts, password hash extraction, account enable/disable timestamps.
**Retrieval:**
```powershell
# Parse with RECmd
.\RECmd.exe --hive "C:\Evidence\SAM" --csv C:\Output --csvf sam.csv
# Or RegistryExplorer for interactive view
.\RegistryExplorer.exe  # Load SAM hive

# Extract hashes (requires SAM + SYSTEM)
# Use pypykatz or secretsdump on the DFIRWS VM
```

### 3.17 Other Relevant Registry Keys
**What:** Additional registry keys scattered across hives that hold forensic value — Run/RunOnce, Image File Execution Options (IFEO), AppInit_DLLs, Winlogon, etc.
**Use:** Persistence mechanisms, accessibility feature backdoors (IFEO debugger for sethc.exe/narrator.exe), DLL injection.
**Retrieval:**
```powershell
# Run/RunOnce persistence
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Microsoft\Windows\CurrentVersion\Run" --csv C:\Output --csvf run.csv
.\RECmd.exe --hive "C:\Evidence\SOFTWARE" --key "Microsoft\Windows\CurrentVersion\Run" --csv C:\Output --csvf run_machine.csv

# IFEO
.\RECmd.exe --hive "C:\Evidence\SOFTWARE" --key "Microsoft\Windows NT\CurrentVersion\Image File Execution Options" --csv C:\Output --csvf ifeo.csv
```

### 3.18 FileHistory DB
**What:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\FileHistory\` — File History backup configuration and status.
**Use:** Determine if backups exist (and where), recover previous file versions for evidence.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\SOFTWARE" --key "Microsoft\Windows\CurrentVersion\FileHistory" --csv C:\Output --csvf filehistory.csv
```

### 3.19 SOFTWARE Hive
**What:** `C:\Windows\System32\config\SOFTWARE` — machine-wide software configuration, installed programs, policies, network profiles, run keys.
**Use:** Central artifact for persistence, installed software inventory, network connection history (NetworkList), autostart entries.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\SOFTWARE" --bn RECmd\BatchExamples\RegistryASEPs.reb --csv C:\Output --csvf software_aseps.csv
.\RegistryExplorer.exe  # Load SOFTWARE hive
```

### 3.20 Application AssociationToasts
**What:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\` and ApplicationAssociationToasts. Records file extension associations and user choices.
**Use:** Identify which applications opened which file types — evidence of execution context.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts" --csv C:\Output --csvf fileexts_assoc.csv
```

### 3.21 Registry Transaction Files
**What:** `.LOG1` and `.LOG2` files alongside each registry hive. Transaction logs for crash recovery that may contain data not yet committed to the main hive.
**Use:** Recover deleted keys/values, find evidence the attacker tried to clean from the registry.
**Retrieval:**
```powershell
# Collect transaction logs alongside hives
copy "C:\Windows\System32\config\SYSTEM.LOG1" "C:\Evidence\"
copy "C:\Windows\System32\config\SYSTEM.LOG2" "C:\Evidence\"
# RegistryExplorer auto-applies transaction logs (dirty hive recovery)
.\RegistryExplorer.exe  # Load hive with .LOG files in same directory
```

### 3.22 SYSTEM Hive
**What:** `C:\Windows\System32\config\SYSTEM` — boot configuration, services, drivers, CurrentControlSet, network interfaces, USB history, computer name, timezone.
**Use:** Core hive for services persistence, network config, USB history, timezone (critical for timestamp correlation), computer name identification.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\SYSTEM" --bn RECmd\BatchExamples\RegistryASEPs.reb --csv C:\Output --csvf system_aseps.csv
# Get timezone
.\RECmd.exe --hive "C:\Evidence\SYSTEM" --key "ControlSet001\Control\TimeZoneInformation" --csv C:\Output --csvf timezone.csv
# Get computer name
.\RECmd.exe --hive "C:\Evidence\SYSTEM" --key "ControlSet001\Control\ComputerName\ComputerName" --csv C:\Output --csvf hostname.csv
```

### 3.23 ELAM Hive
**What:** `C:\Windows\System32\config\ELAM` — Early Launch Anti-Malware hive. Records driver classification decisions made during early boot.
**Use:** Verify boot-start driver integrity, detect rootkits that loaded before ELAM.
**Retrieval:**
```powershell
.\RegistryExplorer.exe  # Load ELAM hive
```

### 3.24 SECURITY Hive
**What:** `C:\Windows\System32\config\SECURITY` — LSA secrets, cached domain credentials, audit policy configuration, security policy settings.
**Use:** Extract cached domain credentials (requires SYSTEM hive for decryption), verify audit policy state (was auditing disabled?).
**Retrieval:**
```powershell
.\RegistryExplorer.exe  # Load SECURITY hive (many values encrypted)
# Decrypt LSA secrets with pypykatz
& "C:\venv\default\Scripts\python.exe" -m pypykatz registry --sam "C:\Evidence\SAM" --system "C:\Evidence\SYSTEM" --security "C:\Evidence\SECURITY"
```

### 3.25 DEFAULT Hive
**What:** `C:\Windows\System32\config\DEFAULT` — default user profile registry template. New user profiles are seeded from this hive.
**Use:** Detect persistence via default profile (affects all new users), verify baseline configuration.
**Retrieval:**
```powershell
.\RegistryExplorer.exe  # Load DEFAULT hive
```

### 3.26 NTUSER.DAT
**What:** `C:\Users\<user>\NTUSER.DAT` — per-user registry hive (HKCU). Contains Run keys, MRUs, typed paths, software preferences, UserAssist, shell bags, desktop configuration.
**Use:** Central per-user artifact for execution evidence, persistence, file/folder access, application usage.
**Retrieval:**
```powershell
# Parse with batch for all forensic artifacts
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --bn RECmd\BatchExamples\RegistryASEPs.reb --csv C:\Output --csvf ntuser_aseps.csv

# UserAssist (execution counts/timestamps)
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" --csv C:\Output --csvf userassist.csv
```

### 3.27 userdiff Hive
**What:** `C:\Windows\System32\config\userdiff` — used during domain profile migration. Contains differences between local and domain user profiles.
**Use:** Rarely forensically significant; niche profile migration investigations.

### 3.28 UsrClass.dat
**What:** `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` — extension of NTUSER.DAT containing COM class registrations, file type associations, and ShellBags.
**Use:** ShellBags analysis — complete folder browsing history including network shares, USB paths, and deleted folders.
**Retrieval:**
```powershell
# ShellBags
.\SBECmd.exe -d "C:\Evidence" --csv C:\Output --csvf shellbags.csv
# Or GUI
.\ShellBagsExplorer.exe  # Load UsrClass.dat
```

### 3.29 App Paths
**What:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\` — application path registration used by the shell to resolve application names.
**Use:** Persistence via App Paths hijack (attacker registers malicious EXE under a legitimate app name).
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\SOFTWARE" --key "Microsoft\Windows\CurrentVersion\App Paths" --csv C:\Output --csvf apppaths.csv
```

### 3.30 Uninstall
**What:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\` and `HKCU\Software\...` — installed program metadata (name, publisher, install date, location).
**Use:** Identify attacker-installed tools, timeline of software installation.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\SOFTWARE" --key "Microsoft\Windows\CurrentVersion\Uninstall" --csv C:\Output --csvf uninstall.csv
```

### 3.31 FileExts
**What:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\` — user file extension handler choices and OpenWithList.
**Use:** Evidence of what applications the user associated with file types — indicates tool usage.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts" --csv C:\Output --csvf fileexts.csv
```

### 3.32 FirstFolder
**What:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\FirstFolder\` — first folder the user navigated to in Explorer.
**Use:** Minor user activity indicator.

### 3.33 Syscache.hve
**What:** `C:\System Volume Information\Syscache.hve` — tracks file hashes (SHA-1) of files on the volume. Present on non-boot volumes.
**Use:** Obtain SHA-1 hashes of files that were present on a volume — can identify malware even if deleted.
**Retrieval:**
```powershell
.\RegistryExplorer.exe  # Load Syscache.hve
```

### 3.34 Autoruns (Tracing key / Run key / RunOnce)
**What:** Multiple autostart extensibility points across the registry: `Run`, `RunOnce`, `RunServices`, `Winlogon\Shell`, `Winlogon\Userinit`, `AppInit_DLLs`, etc.
**Use:** Primary persistence investigation — comprehensive autostart point enumeration.
**Retrieval:**
```powershell
# Batch parse all ASEPs
.\RECmd.exe --hive "C:\Evidence\SOFTWARE" --bn RECmd\BatchExamples\RegistryASEPs.reb --csv C:\Output --csvf machine_aseps.csv
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --bn RECmd\BatchExamples\RegistryASEPs.reb --csv C:\Output --csvf user_aseps.csv
```

---

## 4. FILES — NTFS (Blue)

### 4.1 $MFT
**What:** Master File Table — the core NTFS metadata structure. Every file and directory on an NTFS volume has an MFT record with timestamps (MACB — Modified, Accessed, Changed, Born), file size, parent directory, data runs.
**Use:** Complete file system timeline, detect timestomping (compare $SI vs $FN timestamps), recover metadata for deleted files.
**Retrieval:**
```powershell
# Extract with KAPE
.\kape.exe --tsource C: --tdest C:\Evidence\NTFS --target FileSystem

# Parse with MFTECmd
.\MFTECmd.exe -f "C:\Evidence\$MFT" --csv C:\Output --csvf mft.csv

# View in TimelineExplorer
.\TimelineExplorer.exe C:\Output\mft.csv
```

### 4.2 $SDS
**What:** Security Descriptor Stream — stores ACLs (DACLs/SACLs) for all files and directories.
**Use:** Identify permission changes, files with unusual access rights (attacker modifying ACLs for persistence).
**Retrieval:**
```powershell
.\MFTECmd.exe -f "C:\Evidence\$MFT" --csv C:\Output --csvf mft.csv
# $SDS analysis is specialized — use Autopsy for deeper ACL analysis
```

### 4.3 $Boot
**What:** Boot sector and BPB (BIOS Parameter Block). Defines volume geometry, cluster size, MFT location.
**Use:** Detect boot sector modification, bootkit/rootkit analysis, partition layout verification.
**Retrieval:**
```powershell
.\MFTECmd.exe -f "C:\Evidence\$Boot" --csv C:\Output --csvf boot.csv
```

### 4.4 $LogFile
**What:** NTFS transaction log. Records all metadata changes to the file system in a circular buffer.
**Use:** Recover recently deleted file operations, detect anti-forensics, reconstruct file system changes within the log window.
**Retrieval:**
```powershell
.\MFTECmd.exe -f "C:\Evidence\$LogFile" --csv C:\Output --csvf logfile.csv
```

### 4.5 $T ($TXF_DATA)
**What:** Transactional NTFS log (TxF). Records atomic file operations within transactions.
**Use:** Identify transacted file operations — some malware uses TxF for process doppelganging or transacted hollowing.
**Retrieval:**
```powershell
# Niche analysis — typically examined in Autopsy or hex editor
.\HxD.exe  # Open $T for hex inspection
```

### 4.6 $I30
**What:** Index allocation attribute for directories. Contains directory entries including timestamps and names of files (including deleted entries not yet overwritten).
**Use:** Recover deleted file names and timestamps from directory indexes even after MFT record reuse.
**Retrieval:**
```powershell
# Extract $I30 entries via MFTECmd (processes index entries)
.\MFTECmd.exe -f "C:\Evidence\$MFT" --csv C:\Output --csvf mft_with_i30.csv
# For deep $I30 carving, use INDXParse or Autopsy
```

### 4.7 $UsnJrnl / $J
**What:** USN Journal (Update Sequence Number Journal) at `$Extend\$UsnJrnl:$J`. Records every change to files/directories (create, delete, rename, modify, etc.) with timestamps.
**Use:** Extremely high-volume file system change log — detect file creation/deletion/renaming even if the file is gone. Ransomware activity shows as massive rename operations.
**Retrieval:**
```powershell
# Parse USN Journal
.\MFTECmd.exe -f "C:\Evidence\$J" --csv C:\Output --csvf usnjrnl.csv
```

---

## 5. FILES — DATABASES (Purple/Pink)

### 5.1 Prefetch
**What:** `C:\Windows\Prefetch\*.pf` — Windows Prefetch files. Created when an executable runs, recording the executable name, run count, up to 8 last run timestamps, and loaded file paths (DLLs, data files).
**Use:** Evidence of execution — prove a program ran, when it ran, and how many times. Critical for proving attacker tool execution.
**Retrieval:**
```powershell
# Parse all Prefetch files
.\PECmd.exe -d "C:\Evidence\Prefetch" --csv C:\Output --csvf prefetch.csv

# Or single file
.\PECmd.exe -f "C:\Evidence\Prefetch\MIMIKATZ.EXE-12345678.pf" --csv C:\Output --csvf mimi_pf.csv
```

### 5.2 Program Compatibility Assistant (PCA)
**What:** `C:\Windows\appcompat\pca\PcaAppLaunchDic.txt` and PCA database. Records programs that triggered compatibility checks.
**Use:** Evidence of execution — even if Prefetch is disabled or cleared, PCA may record the execution.
**Retrieval:**
```powershell
copy "C:\Windows\appcompat\pca\PcaAppLaunchDic.txt" "C:\Evidence\"
copy "C:\Windows\appcompat\pca\PcaGeneralDb0.txt" "C:\Evidence\"
type "C:\Evidence\PcaAppLaunchDic.txt"
```

### 5.3 RecentDocs
**What:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\` — MRU list of recently opened documents per file extension.
**Use:** Track document access by file type — what documents were opened and in what order.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" --csv C:\Output --csvf recentdocs.csv
```

### 5.4 Autoruns Programs (RUN/RUNONCE)
**What:** Registry Run/RunOnce keys plus Startup folders, services, drivers, scheduled tasks — all autostart extensibility points.
**Use:** Comprehensive persistence analysis.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --bn RECmd\BatchExamples\RegistryASEPs.reb --csv C:\Output --csvf aseps.csv
```

### 5.5 AppCompatCache (ShimCache)
**What:** `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\` — cached file metadata (path, size, last modified time) for executables processed by the Application Compatibility framework. Ordered list.
**Use:** Evidence of file presence (and possibly execution on Win7). Proves a file existed at a path with a specific timestamp. Persists across reboots.
**Retrieval:**
```powershell
.\AppCompatCacheParser.exe -f "C:\Evidence\SYSTEM" --csv C:\Output --csvf shimcache.csv
```

### 5.6 SRUM (System Resource Usage Monitor)
**What:** `C:\Windows\System32\sru\SRUDB.dat` — ESE database tracking per-application resource usage: network bytes sent/received, CPU time, battery usage, app foreground time. Rolls back 30-60 days.
**Use:** Identify data exfiltration volumes (high bytes sent), network-connected applications, application usage duration, user SID correlation.
**Retrieval:**
```powershell
.\SrumECmd.exe -f "C:\Evidence\SRUDB.dat" -r "C:\Evidence\SOFTWARE" --csv C:\Output --csvf srum.csv
```

### 5.7 SUM (UAL — User Access Logging)
**What:** `C:\Windows\System32\LogFiles\Sum\*.mdb` — server-only. Tracks client access to server roles (user, source IP, role accessed, access date).
**Use:** Identify all clients that accessed the server, lateral movement sources, service abuse.
**Retrieval:**
```powershell
.\SumECmd.exe -d "C:\Evidence\Sum" --csv C:\Output --csvf sum.csv
```

### 5.8 Amcache.hve
**What:** `C:\Windows\appcompat\Programs\Amcache.hve` — registry hive recording SHA-1 hashes, file paths, sizes, publisher, version info, and timestamps for executed or installed files. Also records driver and device installs.
**Use:** Evidence of execution with file hash — correlate with threat intel. Proves a specific binary version ran on the system.
**Retrieval:**
```powershell
.\AmcacheParser.exe -f "C:\Evidence\Amcache.hve" --csv C:\Output --csvf amcache.csv -i  # -i includes SHA-1 hashes
```

### 5.9 BAM / DAM
**What:** Background Activity Moderator / Desktop Activity Moderator — `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` (Win10 1709+). Records full executable paths with last execution timestamps.
**Use:** Evidence of execution with timestamps — lightweight and reliable execution artifact.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\SYSTEM" --key "ControlSet001\Services\bam\State\UserSettings" --csv C:\Output --csvf bam.csv
```

### 5.10 WMI WBEM Files (OBJECTS.DATA)
**What:** `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` — WMI repository database containing all WMI class definitions, including persistent event subscriptions.
**Use:** Detect WMI event subscription persistence — CommandLineEventConsumer, ActiveScriptEventConsumer bindings.
**Retrieval:**
```powershell
# Copy WBEM repository
robocopy "C:\Windows\System32\wbem\Repository" "C:\Evidence\WBEM" /E

# Parse with PyWMIPersistenceFinder (download from GitHub)
# Or string search for event consumers
.\bstrings.exe -f "C:\Evidence\WBEM\OBJECTS.DATA" -o C:\Output\wbem_strings.txt --ls 10
# Search for "CommandLineEventConsumer", "ActiveScriptEventConsumer"
```

### 5.11 UpdateStore.db
**What:** `C:\Windows\SoftwareDistribution\DataStore\DataStore.edb` — Windows Update database tracking installed updates, pending updates, and update history.
**Use:** Identify missing patches (vulnerability assessment), confirm update history, detect removed updates.
**Retrieval:**
```powershell
.\ESEDatabaseView.exe "C:\Windows\SoftwareDistribution\DataStore\DataStore.edb"
```

### 5.12 Recall Database (ukg.db)
**What:** Windows Recall database (Win11 24H2+ with Copilot+). Stores periodic screenshots and OCR text of everything on screen.
**Use:** (If present) Reconstruction of complete user activity including what was displayed on screen.
**Retrieval:**
```powershell
# Location: %LocalAppData%\CoreAIPlatform.00\UKP\ukg.db
copy "%LocalAppData%\CoreAIPlatform.00\UKP\ukg.db" "C:\Evidence\"
.\SQLECmd.exe -f "C:\Evidence\ukg.db" --csv C:\Output --csvf recall.csv
```

### 5.13 IconCache.db
**What:** `%LocalAppData%\IconCache.db` — cached icons for files/applications. Contains embedded file paths and icon data.
**Use:** Evidence of file presence — if an icon was cached, the file existed on the system at some point.
**Retrieval:**
```powershell
copy "%LocalAppData%\IconCache.db" "C:\Evidence\"
.\bstrings.exe -f "C:\Evidence\IconCache.db" -o C:\Output\iconcache_strings.txt
```

### 5.14 Browsers DB
**What:** Chrome, Edge, Firefox SQLite databases — History, Downloads, Cookies, Login Data, Web Data, Favicons, Top Sites, Bookmarks.
**Use:** Comprehensive browsing history, download history, stored credentials investigation.
**Retrieval:**
```powershell
.\SQLECmd.exe -d "C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default" --csv C:\Output --csvf chrome_all.csv
.\SQLECmd.exe -d "C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default" --csv C:\Output --csvf edge_all.csv
```

### 5.15 JumpLists
**What:** `%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\` (.automaticDestinations-ms) and `CustomDestinations\` (.customDestinations-ms). Per-application recent file lists stored in structured storage.
**Use:** Track files opened per application, pinned items, application usage frequency, timestamps.
**Retrieval:**
```powershell
.\JLECmd.exe -d "C:\Evidence\Recent\AutomaticDestinations" --csv C:\Output --csvf jumplists_auto.csv
.\JLECmd.exe -d "C:\Evidence\Recent\CustomDestinations" --csv C:\Output --csvf jumplists_custom.csv
# Or GUI
.\JumpListExplorer.exe
```

### 5.16 LNK Files
**What:** Windows shortcut files (.lnk) at `%AppData%\Microsoft\Windows\Recent\` and Startup folders. Contain target path, timestamps (of both the LNK and target), volume serial number, MAC address (if on network share), working directory.
**Use:** Prove file access, recover metadata about deleted files, network share access, volume serial number for USB correlation.
**Retrieval:**
```powershell
.\LECmd.exe -d "C:\Evidence\Recent" --csv C:\Output --csvf lnk_files.csv
```

### 5.17 UserAssist
**What:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\` — ROT13-encoded entries tracking GUI-launched program execution counts, last run times, and focus time.
**Use:** Evidence of execution — specifically applications launched via Explorer (double-click, Start menu, taskbar).
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" --csv C:\Output --csvf userassist.csv
# RECmd auto-decodes ROT13 values
```

### 5.18 MUICache
**What:** `NTUSER.DAT\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache\` — caches the "friendly name" (executable description from version info) of programs that have been run.
**Use:** Evidence of execution — program name and description cached even after file deletion.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\UsrClass.dat" --key "Local Settings\Software\Microsoft\Windows\Shell\MuiCache" --csv C:\Output --csvf muicache.csv
```

### 5.19 RunMRU
**What:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\` — commands typed into the Win+R Run dialog.
**Use:** Direct evidence of user/attacker commands — what they typed to launch programs.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" --csv C:\Output --csvf runmru.csv
```

### 5.20 RecentApps
**What:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\` — tracks recently used applications with launch counts and last access times.
**Use:** Evidence of execution with frequency data.
**Retrieval:**
```powershell
.\RECmd.exe --hive "C:\Evidence\NTUSER.DAT" --key "Software\Microsoft\Windows\CurrentVersion\Search\RecentApps" --csv C:\Output --csvf recentapps.csv
```

### 5.21 ActivitiesCache.db
**What:** `C:\Users\<user>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` — Windows Timeline database (Win10 1803+). SQLite database recording application usage, document access, web browsing with timestamps.
**Use:** Rich activity timeline with clipboard history, application usage, and cross-device activity (if Microsoft account connected).
**Retrieval:**
```powershell
.\WxTCmd.exe -f "C:\Evidence\ActivitiesCache.db" --csv C:\Output --csvf timeline.csv
```

### 5.22 Application Compatibility Database (SDB Files)
**What:** Custom shim databases (.sdb) at `C:\Windows\AppPatch\Custom\` and `CustomSDB\`. Shims can redirect DLL loads, disable security features, inject code.
**Use:** Persistence and defense evasion via application compatibility shims — attackers install malicious SDB files.
**Retrieval:**
```powershell
.\SDBExplorer.exe  # Load .sdb files for analysis
dir "C:\Windows\AppPatch\Custom\*.sdb"
dir "C:\Windows\AppPatch\CustomSDB\*.sdb"
```

### 5.23 Windows Notification DB
**What:** `%LocalAppData%\Microsoft\Windows\Notifications\wpndatabase.db` — SQLite database storing Windows notification history.
**Use:** Contains notification text from all apps — may include message snippets, email previews, calendar alerts.
**Retrieval:**
```powershell
.\SQLECmd.exe -f "C:\Evidence\wpndatabase.db" --csv C:\Output --csvf notifications.csv
```

### 5.24 ShellBags
**What:** Stored in `UsrClass.dat` and `NTUSER.DAT`. Record folder viewing preferences, which inherently tracks every folder the user browsed — including folders on network shares, USB drives, and folders that have since been deleted.
**Use:** Complete folder browsing history — prove access to network shares, USB paths, ZIP contents, and deleted folders.
**Retrieval:**
```powershell
.\SBECmd.exe -d "C:\Evidence" --csv C:\Output --csvf shellbags.csv
.\ShellBagsExplorer.exe  # GUI browser
```

### 5.25 $Recycle.Bin ($I / $R)
**What:** `C:\$Recycle.Bin\<SID>\$I<id>` (metadata: original path, deletion time, file size) and `$R<id>` (actual file content). Per-user SID subfolders.
**Use:** Recover deleted files and their original locations, correlate deletion timestamps with incident timeline.
**Retrieval:**
```powershell
.\RBCmd.exe -d "C:\$Recycle.Bin" --csv C:\Output --csvf recyclebin.csv
```

### 5.26 Windows Index Search (Windows.edb)
**What:** `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb` — ESE database used by Windows Search indexer. Contains indexed content, file metadata, email excerpts, and more.
**Use:** Search for keywords across all indexed content, recover document fragments, file metadata from deleted files.
**Retrieval:**
```powershell
.\ESEDatabaseView.exe "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb"
```

### 5.27 EventTranscript.db
**What:** `C:\ProgramData\Microsoft\Diagnosis\EventTranscript\EventTranscript.db` — SQLite database containing Windows Diagnostic Data (telemetry). Records application usage, crashes, device info.
**Use:** Rich execution evidence and system state data collected by Windows telemetry.
**Retrieval:**
```powershell
.\SQLECmd.exe -f "C:\Evidence\EventTranscript.db" --csv C:\Output --csvf eventtranscript.csv
```

### 5.28 ThumbCache
**What:** `%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db` — cached thumbnail images of viewed files (images, videos, documents).
**Use:** Prove a file was viewed (thumbnail generated), recover thumbnail even after file deletion — critical for proving access to deleted images/documents.
**Retrieval:**
```powershell
# Collect thumbcache databases
robocopy "%LocalAppData%\Microsoft\Windows\Explorer" "C:\Evidence\Thumbcache" thumbcache_*.db
# Use Thumbcache Viewer (download) or Autopsy for rendering
```

### 5.29 RecentFileCache
**What:** `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` — lists programs that have been recently run (older Win versions).
**Use:** Evidence of execution — lightweight file listing recent executables.
**Retrieval:**
```powershell
.\RecentFileCacheParser.exe -f "C:\Evidence\RecentFileCache.bcf" --csv C:\Output --csvf recentfilecache.csv
```

---

## 6. MEMORY (Orange)

### 6.1 Memory Dumps
**What:** Full physical memory dump (RAM capture). Contains running processes, network connections, loaded modules, encryption keys, command history, malware in memory only.
**Use:** Volatile data analysis — detect fileless malware, extract credentials, recover encryption keys, analyze injected code, reconstruct process activity.
**Retrieval:**
```powershell
# Capture live memory (use DumpIt, WinPMEM, Belkasoft RAM Capturer)
# Analyze with Volatility 2.6
.\volatility_2.6_win64_standalone.exe -f "C:\Evidence\memory.dmp" --profile=Win10x64_19041 pslist
.\volatility_2.6_win64_standalone.exe -f "C:\Evidence\memory.dmp" --profile=Win10x64_19041 netscan
.\volatility_2.6_win64_standalone.exe -f "C:\Evidence\memory.dmp" --profile=Win10x64_19041 malfind

# With Volatility 3
& "C:\Tools\VolatilityWorkbench\vol.exe" -f "C:\Evidence\memory.dmp" windows.pslist
& "C:\Tools\VolatilityWorkbench\vol.exe" -f "C:\Evidence\memory.dmp" windows.netscan
& "C:\Tools\VolatilityWorkbench\vol.exe" -f "C:\Evidence\memory.dmp" windows.malfind

# String extraction
.\bstrings.exe -f "C:\Evidence\memory.dmp" -o C:\Output\mem_strings.txt --ls 8
```

### 6.2 Pagefile (pagefile.sys)
**What:** `C:\pagefile.sys` — virtual memory paging file. Contains memory pages swapped to disk from RAM.
**Use:** Recover data from processes that have since exited — may contain credentials, command output, malware fragments, decrypted data.
**Retrieval:**
```powershell
# Must collect from offline/mounted disk (locked while OS running)
# String search
.\bstrings.exe -f "C:\Evidence\pagefile.sys" -o C:\Output\pagefile_strings.txt --ls 10

# Or use Volatility on pagefile
# Carve with PhotoRec for embedded files
.\photorec_win.exe  # Select pagefile.sys as input
```

### 6.3 Hiberfile (hiberfil.sys)
**What:** `C:\hiberfil.sys` — hibernation file containing a compressed snapshot of RAM at the time of hibernation. Also used for Fast Startup (hybrid shutdown).
**Use:** Contains a full or partial memory image — analyze as a memory dump after decompression.
**Retrieval:**
```powershell
# Decompress and analyze with Volatility
.\volatility_2.6_win64_standalone.exe -f "C:\Evidence\hiberfil.sys" --profile=Win10x64 imagecopy -O C:\Evidence\hiberfil_raw.dmp
# Then analyze the decompressed image
& "C:\Tools\VolatilityWorkbench\vol.exe" -f "C:\Evidence\hiberfil_raw.dmp" windows.pslist
```

### 6.4 Swapfile (swapfile.sys)
**What:** `C:\swapfile.sys` — UWP/modern app swap file (Win8+). Separate from pagefile, used for suspending Store/UWP apps.
**Use:** Recover data from suspended UWP applications.
**Retrieval:**
```powershell
.\bstrings.exe -f "C:\Evidence\swapfile.sys" -o C:\Output\swapfile_strings.txt --ls 10
```

### 6.5 WER Dumps (Windows Error Reporting)
**What:** `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\` and `ReportArchive\`. Contains crash dump files (.dmp) and report metadata for crashed applications.
**Use:** Crash dumps of exploited processes may contain exploit artifacts, post-exploitation shellcode, or memory state at time of crash.
**Retrieval:**
```powershell
robocopy "C:\ProgramData\Microsoft\Windows\WER" "C:\Evidence\WER" /E
# Analyze minidumps with x64dbg or WinDbg
```

### 6.6 Minidump Files
**What:** `C:\Windows\Minidump\*.dmp` — kernel minidumps from BSODs. Also application minidumps from WER.
**Use:** BSOD analysis (rootkit crashes), process crash analysis, LSASS minidump (credential theft via procdump/comsvcs.dll).
**Retrieval:**
```powershell
robocopy "C:\Windows\Minidump" "C:\Evidence\Minidumps" *.dmp
# Check for LSASS dumps (credential theft indicator)
Get-ChildItem "C:\Users" -Recurse -Include "lsass*.dmp","procdump*" -ErrorAction SilentlyContinue
# Analyze LSASS dump for credentials
& "C:\venv\default\Scripts\python.exe" -m pypykatz lsa minidump "C:\Evidence\lsass.dmp"
```

---

## 7. ADDITIONAL ARTIFACTS FROM THE MINDMAP

### 7.1 Winget Activity
Already covered in Section 2.38.

### 7.2 Windows Search History / WordWheelQuery
Already covered in Section 3.13.

### 7.3 $Recycle.Bin
Already covered in Section 5.25.

---

## Quick-Reference: KAPE Collection Targets

For rapid triage collection of the most important artifacts:

```powershell
# Comprehensive triage collection
.\kape.exe --tsource C: --tdest E:\Evidence --target !SANS_Triage --vss

# Process with EZ Tools modules
.\kape.exe --msource E:\Evidence --mdest E:\Processed --module !EZParser

# Specific collections
.\kape.exe --tsource C: --tdest E:\Evidence --target EventLogs,RegistryHives,Prefetch,Amcache,RecycleBin,SRUM,WebBrowsers,LnkFilesAndJumpLists
```

## Quick-Reference: Super-Timeline Creation

```powershell
# Create super-timeline with Plaso from disk image or evidence folder
.\log2timeline.exe --storage-file C:\Output\supertimeline.plaso C:\Evidence\

# Export to CSV for TimelineExplorer
.\psort.exe --output-time-zone UTC -o l2tcsv C:\Output\supertimeline.plaso -w C:\Output\supertimeline.csv

# Open in TimelineExplorer
.\TimelineExplorer.exe C:\Output\supertimeline.csv
```
