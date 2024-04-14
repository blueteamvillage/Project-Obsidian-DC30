# Findings for DC

In order to determine the modifications and find indications of compromise on the device, it is important to establish the baseline on the machine.

| System Name | IP Address | Assigned User |
| ----   | ---- | ---- |
| DC | 172.16.50.100 | N/A |

**SUMMARY:** The actor was able to create a new user, combosecurity, who was then granted the permissions of local administrator. The actor covered their tracks by clearing the Application, System, and Security logs, but Sysmon was able to track their activities.

## Timeline of Events 19 February 2022

* **20:59:36 UTC:** First indication of PSexec used via PSEXEVC.exe (EventID 11 Sysmon) 
* **20:59:57 UTC:** Attacker created combosecurity on DC  (EventID 1 Sysmon)
* **21:15:28 UTC:** Attacker put combo security in the local admin on DC (EventID 1 Sysmon)
* **21:27:04 UTC:** Attacker cleared logs (EventID 1) via Powershell.
* **21:30:24 UTC:** Log cleared via Powershell again (EventID 10)
* **21:31:48 UTC:** User account (combosecurity) was changed (Event ID 4738)
* **22:40:47 UTC:** Downloading of WinTriage *[Incident Response Phase]*
* **22:45:01 UTC:** Execution of WinTriage *[Incident Response Phase]*

## Windows Event Log Review
**SOURCE: Microsoft-Windows-Sysmon/Operational**
* **20:59:57 UTC:** Over 10 events at this time, first was the use of PSEXEC (EventID 12) under HLKM/System/CurrentControlSet\Services\PSEXESVC with (C:\Windows\PSEXEC-RDP01-903C33C0.key as EventID 11) left behind. Then there is the activity of the net use adding combosecurity as EventID 1
* **21:15:28 UTC:** combosecurity was added into the local admin group (EventID 1)
* **21:27:04 UTC:** the attacker used powershell to clear the eventlogs for Application, System, and Security ("powershell.exe" "& {Clear-EventLog -Log Application,System,Security}") as MAGNUMTEMPUS\Administrator (EventID 1)
* **21:30:24 UTC:** repeat of above (EventID 1)

Filtering to Event 11 and PSEXEC-RDP01 (6x keys found)

* **20:59:57 UTC:** C:\Windows\PSEXEC-RDP01-F837DBB7.key
* **21:15:28 UTC:** C:\Windows\PSEXEC-RDP01-DF1AC576.key
* **21:15:49 UTC:** C:\Windows\PSEXEC-RDP01-2A8A0530.key
* **21:27:04 UTC:** C:\Windows\PSEXEC-RDP01-84FBF79E.key
* **21:28:38 UTC:**  C:\Windows\PSEXEC-RDP01-2FBFC8B1.key
* **21:30:24 UTC:** C:\Windows\PSEXEC-RDP01-903C33C0.key

**SOURCE: Security Windows Event Log**
*  **21:30:24 UTC:** Log was cleared as EventID 1102
```
The audit log was cleared.
Subject:
	Security ID:	S-1-5-21-2370586174-1517003462-1142029260-500
	Account Name:	Administrator
	Domain Name:	MAGNUMTEMPUS
	Logon ID:	13E4C300
```

* 21:31:48Z, User Account Management Category, EventID 4738, User account was changed for combosecurity.


**SOURCE: System Log**
* **21:30:24 UTC:** EventID 104, The System log file was cleared, user S-1-5-21-2370586174-1517003462-1142029260-500.
* **21:30:24 UTC:** EventID 7045, Service Name: PSEXESVC demand start.

**SOURCE: System Log** (Suspect, but cannot prove)

* **21:35:42 UTC:** EventID 37, Microsoft-Windows-Kerberos-Key-Distribution-Center could not be found. Following information: DC02, MAGNUMTEMPUS.FINANCIAL, WKST13$, krbtgt

## Additional Indicators

**SOURCE: Windows.Sys.Users.json**
```
{
  "Uid": 1179,
  "Gid": 513,
  "Name": "server.admin",
  "Description": "<Auto Generated> The password for this account is: AutoGenPassword123! #PLEASE CHANGE THIS#",
  "Directory": null,
  "UUID": "S-1-5-21-2370586174-1517003462-1142029260-1179",
  "Mtime": null,
  "Type": "local"
}
{
  "Uid": 1187,
  "Gid": 513,
  "Name": "combosecurity",
  "Description": "",
  "Directory": null,
  "UUID": "S-1-5-21-2370586174-1517003462-1142029260-1187",
  "Mtime": null,
  "Type": "local"
}
```


**SOURCE: [Chainsaw](https://github.com/countercept/chainsaw)**

Chainsaw is a tool developed by [F-Secure Labs](https://labs.f-secure.com/tools/chainsaw/) to enable blue teamers the ability to rapidly collect and identify threat indicators within the logs.

```
├─────────────────────┼────┼─────────────────────────────────┼─────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┤
│ 2022-02-19 20:59:57 │ 1  │ ‣ Net.exe Execution             │ "dc.magnumtempus.financial" │ C:\Windows\System32\net.exe              │ "net" user combosecurity B4bymeta! /ADD  │
│                     │    │ ‣ Net.exe User Account          │                             │                                          │                                          │
│                     │    │ Creation                        │                             │                                          │                                          │
├─────────────────────┼────┼─────────────────────────────────┼─────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┤
│ 2022-02-19 20:59:57 │ 1  │ ‣ Net.exe Execution             │ "dc.magnumtempus.financial" │ C:\Windows\System32\net1.exe             │ C:\Windows\system32\net1 user combosecur │
│                     │    │ ‣ Net.exe User Account          │                             │                                          │ ity B4bymeta! /ADD                       │
│                     │    │ Creation                        │                             │                                          │                                          │
├─────────────────────┼────┼─────────────────────────────────┼─────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┤
│ 2022-02-19 21:15:28 │ 1  │ ‣ Hurricane Panda Activity      │ "dc.magnumtempus.financial" │ C:\Windows\System32\net.exe              │ "net" localgroup administrators combosec │
│                     │    │ ‣ Net.exe Execution             │                             │                                          │ urity /ADD                               │
├─────────────────────┼────┼─────────────────────────────────┼─────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┤
│ 2022-02-19 21:15:28 │ 1  │ ‣ Hurricane Panda Activity      │ "dc.magnumtempus.financial" │ C:\Windows\System32\net1.exe             │ C:\Windows\system32\net1 localgroup admi │
│                     │    │ ‣ Net.exe Execution             │                             │                                          │ nistrators combosecurity /ADD            │
└─────────────────────┴────┴─────────────────────────────────┴─────────────────────────────┴──────────────────────────────────────────┴──────────────────────────────────────────┘
```

**SOURCE: Windows.Forensics.Usn.json**
```
{
  "Usn": 291097360,
  "Timestamp": "2022-02-19T20:59:36.0886145Z",
  "Filename": "PSEXESVC.exe",
  "FullPath": "Windows/PSEXESVC.exe",
  "FileAttributes": [
    "ARCHIVE"
  ],
  "Reason": [
    "FILE_CREATE"
  ],
  "SourceInfo": [
    "ARCHIVE"
  ],
  "_FileMFTID": 253004,
  "_FileMFTSequence": 3379,
  "_ParentMFTID": 1779,
  "_ParentMFTSequence": 1
}
{
  "Usn": 291097448,
  "Timestamp": "2022-02-19T20:59:36.0925922Z",
  "Filename": "PSEXESVC.exe",
  "FullPath": "Windows/PSEXESVC.exe",
  "FileAttributes": [
    "ARCHIVE"
  ],
  "Reason": [
    "FILE_CREATE",
    "DATA_EXTEND"
  ],
  "SourceInfo": [
    "ARCHIVE"
  ],
  "_FileMFTID": 253004,
  "_FileMFTSequence": 3379,
  "_ParentMFTID": 1779,
  "_ParentMFTSequence": 1
}
{
  "Usn": 291097536,
  "Timestamp": "2022-02-19T20:59:36.0955892Z",
  "Filename": "PSEXESVC.exe",
  "FullPath": "Windows/PSEXESVC.exe",
  "FileAttributes": [
    "ARCHIVE"
  ],
  "Reason": [
    "DATA_EXTEND",
    "FILE_CREATE",
    "DATA_OVERWRITE"
  ],
  "SourceInfo": [
    "ARCHIVE"
  ],
  "_FileMFTID": 253004,
  "_FileMFTSequence": 3379,
  "_ParentMFTID": 1779,
  "_ParentMFTSequence": 1
}
{
  "Usn": 291097624,
  "Timestamp": "2022-02-19T20:59:36.0985982Z",
  "Filename": "PSEXESVC.exe",
  "FullPath": "Windows/PSEXESVC.exe",
  "FileAttributes": [
    "ARCHIVE"
  ],
  "Reason": [
    "DATA_EXTEND",
    "FILE_CREATE",
    "CLOSE",
    "DATA_OVERWRITE"
  ],
  "SourceInfo": [
    "ARCHIVE"
  ],
  "_FileMFTID": 253004,
  "_FileMFTSequence": 3379,
  "_ParentMFTID": 1779,
  "_ParentMFTSequence": 1
}
-
  "Usn": 291100792,
  "Timestamp": "2022-02-19T20:59:57.3316327Z",
  "Filename": "PSEXEC-RDP01-903C33C0.key",
  "FullPath": "Windows/PSEXEC-RDP01-903C33C0.key",
  "FileAttributes": [
    "ARCHIVE"
  ],
  "Reason": [
    "FILE_CREATE"
  ],
  "SourceInfo": [
    "ARCHIVE"
--
 {
  "Usn": 291100792,
  "Timestamp": "2022-02-19T20:59:57.3316327Z",
  "Filename": "PSEXEC-RDP01-903C33C0.key",
  "FullPath": "Windows/PSEXEC-RDP01-903C33C0.key",
  "FileAttributes": [
    "ARCHIVE"
  ],
  "Reason": [
    "FILE_CREATE"
  ],
  "SourceInfo": [
    "ARCHIVE"
  ],
  "_FileMFTID": 253029,
  "_FileMFTSequence": 110,
  "_ParentMFTID": 1779,
  "_ParentMFTSequence": 1
}
{
  "Usn": 291100904,
  "Timestamp": "2022-02-19T20:59:57.3316327Z",
  "Filename": "PSEXEC-RDP01-903C33C0.key",
  "FullPath": "Windows/PSEXEC-RDP01-903C33C0.key",
  "FileAttributes": [
    "ARCHIVE"
  ],
  "Reason": [
    "DATA_EXTEND",
    "FILE_CREATE"
  ],
  "SourceInfo": [
    "ARCHIVE"
  ],
  "_FileMFTID": 253029,
  "_FileMFTSequence": 110,
  "_ParentMFTID": 1779,
  "_ParentMFTSequence": 1
}
{
  "Usn": 291101016,
  "Timestamp": "2022-02-19T20:59:57.3316327Z",
  "Filename": "PSEXEC-RDP01-903C33C0.key",
  "FullPath": "Windows/PSEXEC-RDP01-903C33C0.key",
  "FileAttributes": [
    "ARCHIVE"
  ],
  "Reason": [
    "DATA_EXTEND",
    "FILE_CREATE",
    "CLOSE",
    "FILE_DELETE"
  ],
  "SourceInfo": [
    "ARCHIVE"
  ],
  "_FileMFTID": 253029,
  "_FileMFTSequence": 110,
  "_ParentMFTID": 1779,
  "_ParentMFTSequence": 1
}
{
  "Usn": 291101128,
  "Timestamp": "2022-02-19T20:59:57.583386Z",
  "Filename": "PSEXESVC.exe",
  "FullPath": "Windows/PSEXESVC.exe",
  "FileAttributes": [
    "ARCHIVE"
  ],
  "Reason": [
    "FILE_DELETE",
    "CLOSE"
  ],
  "SourceInfo": [
    "ARCHIVE"
  ],
  "_FileMFTID": 253004,
  "_FileMFTSequence": 3379,
  "_ParentMFTID": 1779,
  "_ParentMFTSequence": 1
}
```

## ADDITIONAL CONSIDERATIONS

The commands may not fall within the scope of the attack, but never forget the ConsoleHost_history!
> C\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline

