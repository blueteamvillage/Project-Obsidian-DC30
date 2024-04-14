# Kill Chain 1 - Endpoint Forensics Walkthrough

## TimeLine:

| Endpoint | Timestamp | Activity |
| -- | -- | -- |
| WKST02 | ??/??/???? ??:??:?? | powershell.exe PID: 7036 Connected to 3.132.192.16 (malwarelove[.]xyz) |
| WKST02 | 02/09/2022 01:58:25 +0000 | Malicious Document Sent via Email: MagnumTempus-Policy-Violation-karen.metuens@magnumtempusfinancial.com.doc |
| WKST02 | 02/09/2022 03:12:57 +0000 | Malicious Document Sent via Email: MagnumTempus-Policy-Violation-karen.metuens@magnumtempusfinancial.com.doc |
| WKST02 | 02/09/2022 23:26:38 +0000 | Malicious Document Sent via Email: MagnumTempus-Policy-Violation-karen.metuens@magnumtempusfinancial.com.doc |
| WKST02 | 02/09/2022 23:35:18 +0000 | Malicious Document Sent via Email: MagnumTempus-Policy-Violation-karen.metuens@magnumtempusfinancial.com.doc |
| WKST02 | 02/10/2022 02:14:00 +0000 | Malicious Document Sent via Email: MagnumTempus-Policy-Violation-karen.metuens@magnumtempusfinancial.com.doc |
| WKST02 | 02/11/2022 04:40:34 +0000 | Malicious Document Sent via Email: MagnumTempus-Policy-Violation-karen.metuens@magnumtempusfinancial.com.doc |
| WKST01 | 02/12/2022 21:10:06 +0000 | Malicious Email Received |
| WKST02 | 02/12/2022 21:10:06 +0000 | Malicious Document Sent via Email: MagnumTempus-Policy-Violation-karen.metuens@magnumtempusfinancial.com.doc |
| WKST02 | 02/12/2022 21:11:41 +0000 | Powershell Encoded Malware Executed |
| WKST01 | 02/12/2022 21:12:12 +0000 | Macros Enabled |
| WKST01 | 02/12/2022 21:12:12 +0000 | Malicious Powershell Payload Executed |
| WKST02 | 02/12/2022 21:12:37 +0000 | Local Accounts Discovery, Whoami Execution: "C:\Windows\system32\whoami.exe" |
| WKST02 | 02/12/2022 21:13:46 +0000 | Net.exe Execution: C:\Windows\system32\net.exe localgroup Administrators |
| WKST02 | 02/12/2022 21:15:59 +0000 | Suspicious File: C:\Windows\Temp\cleanup.exe Malware Created |
| WKST02 | 20160716-022321 | Persistence (Daily MagnumTempus IT Cleanup) for cleanup.exe added to Task Scheduler |
| WKST06 | 02/12/2022 21:30 +0000 | Karen.Meteuns logged on from 172.16.50.131 via Domain Account MAGNUMTEMPUS.FINANCIAL |
| WKST06 | 02/12/2022 21:31 +0000 | IT department grabbed a file from the IT Department on "Data Breach Response", a Guide for Business |
| WKST02 | 02/12/2022 21:33:26 +0000 | Suspicious File: C:\Windows\Temp\p.exe (PingCastle) Created |
| WKST02 | 02/12/2022 21:34:15 +0000 | Suspicious File: C\Windows\Temp\met64.exe (Metasploit) Created |
| WKST02 | 02/12/2022 21:38:59 +0000 | Net.exe Execution: C:\Windows\System32\net.exe net accounts /domain
| WKST02 | 02/12/2022 21:39:00 +0000 | Net.exe Execution: C:\Windows\System32\net.exe net accounts /domain
| WKST06 | 02/12/2022 21:54 +0000 | Brad received an email from safe-documents@magnumtempus.financial (different from magnumtempusfinancial.com) |
| WKST02 | 02/12/2022 22:00:45 +0000 | Suspicious Shells Spawn by WinRM, Covenant Launcher Indicators, Base64 Encoded Powershell Malware |
| WKST01 | 02/12/2022 22:31:57 +0000 | Connection from explorer.exe to 3.132.192[.]16 (malwarelove[.]xyz) |
| WKST02 | 02/12/2022 22:51:31 +0000 | Suspicious (Password) File: C:\Users\karen.metuens\Desktop\hotmail password.docx Accessed |
| WKST02 | 02/12/2022 23:12:23 +0000 | Suspicious File: C:\Windows\Temp\leavemehere.dat (Obfuscated version of the original loader: uses syscalls) Created |
| WKST06 | 02/12/2022 23:14 +0000 | Brad sent the email to Estevan McNullen, warning him not to open but to analyze the contents |
| WKST06 | 02/12/2022 23:16 +0000 | Richard Natu sent an email planning to drop off the hard drive of all marketing materials with a reqeust for data recovery. |
| WKST06 | 02/12/2022 23:18 +0000 | Estevan McNullen agreed that something was not right and would take a look at the document. |


---

## Slide 1 (WKST01 & WKST02)

* Evidence of Malicious Email
  - Source(s): Amanda Nuensis Thunderbird Inbox, Karen MetuensThunderbird Inbox 
  - Tool: Text Editor

* Extract Obfuscated PowerShell
  - filename=MagnumTempus-Policy-Violation-[User]@magnumtempusfinancial.com.doc

---

## Slide 2 (WKST01 & WKST02)

* Deobfuscate Powershell using CyberChef
  - Source: Extracted MIME (Base64) Attachment from Slide 1
  - Tool: CyberChef

* IOCs for sweeping the environemnt
  - Domain: Malwarelove[.]xyz
  - NSLOOKUP: 3.132.192[.]16

---

## Slide 3 (WKST01)

* Evidence of Enabled Macros for Maldoc
  - Source: Amanda Nuensis NTUSER.DAT, Sysmon: Windows Registry Trust Record Modification
  - Tools: Registry Viewer (NTUSER.DAT), Event Viewer (Sysmon Log)

---

## Slide 4 (WKST01 & WKST02)

* Evidence of Active Connection to 3.132.192.16:443 / malwarelove[.]xyz
  - Source: Velociraptor Netstat
  - Tools: Velociraptor (Windows.Network.Netstat.json)
  - Found in Memory Analysis and Velociraptor Netstat
  - Parsed into CSV (Cports.csv)

---

## Slide 5 (WKST02)

* Additional Malware found on Disk:
  - C:\Windows\Temp\met64.exe (Metasploit)
  - C:\Windows\Temp\cleanup.exe (Covenant agent)
  - C:\Windows\Temp\p.exe (PingCastle)

* Malware cleanup.exe added to Task Scheduler for Persistence
  - Source: Velociraptor (Windows.Sysinternals.Autoruns.json)
  - Converted to Autorun.dat

---

## Slide 6 (WKST02)

* Malicious Powershell CommandLine (PID 7036) found in Memory
  - Source: Volatility
  - Tools: Volatility (windows.cmdline.CmdLine)
  - Volatility commandline for PID 7036 (obfuscated Malware)

---

## Slide 7 (WKST02)

* Lateral Movement in Sysmon Logs (EventID 1):
  - C:\Windows\system32\whoami.exe
  - C:\Windows\system32\net1 localgroup Administrators
  - C:\Windows\system32\net1 accounts /domain

---

## Slide 8 (WKST06)

* No Indication of Compromise

---

