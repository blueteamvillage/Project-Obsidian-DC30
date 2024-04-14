# Findings for DC02

In order to determine the modifications and find indications of compromise on the device, it is important to establish the baseline on the machine.

| System Name | IP Address | Assigned User |
| ----   | ---- | ---- |
| DC02 | 172.16.50.101 | N/A |


**SUMMARY:** Based on the activity, the threat actor managed to gain access into DC02 from RDP01 through a Pass-the-(Over)hash technique, forcing the authentication into NTLM rather than the normal Kerberos authentication method. The actor was able to create a new user, combosecurity, who was then granted the permissions of local administrator.

## Timeline of Events 19 February 2022

* **20:59:57 UTC:** Connection from RDP01 (172.16.44.110) through NTLM V1, rather than Kerberos [Security Event logs]
* **20:59:57 UTC:** Use of PSEXESVC.exe on the host *[Microsoft-Windows-Sysmon/Operational Event logs]*
* **21:00:18 UTC:** key PSEXEC-RDP01-C7722F14.key *[Microsoft-Windows-Sysmon/Operational Event logs]*
* **21:00:18 UTC:** EventID 1, creating combosecurity *[Microsoft-Windows-Sysmon/Operational Event logs]*
* **21:15:28 UTC:** EventID 11, use of PSEXESVC PSEXEC-RDP01-53271E0B.key *[Microsoft-Windows-Sysmon/Operational Event logs]*
* **21:15:49 UTC:** EventID 1, adding combosecurity into the local administrator group *[Microsoft-Windows-Sysmon/Operational Event logs]*
* **22:48:44 UTC:** Incident response point of downloading WinTriage

## Windows Event Log Review

**SOURCE: Security Windows Event**
20:59:57 UTC: A notable EventID appeared, 4776. A computer attempted to validate credentials for an account

The computer attempted to validate the credentials for an account. There are consistent, multiple activities related to this event between 20:59 UTC - 21:39 UTC.
```
Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:	administrator
Source Workstation:	RDP01
Error Code:	0000
```

 Then it showed up as norma.gene from BTV workstation.

```
The computer attempted to validate the credentials for an account.

Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:	norma.gene
Source Workstation:	btv
Error Code:	0000
```


**SOURCE: Security Windows Event**

There was a consistent login from 20:59:57Z to 21:27:06Z with EventID 4624 on a Domain Controller (DC02) using NTLM V1. The host was RDP01 (172.16.44.110) Connecting to the Domain Controller should normally consist with Kerberos.
```
An account was successfully logged on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		00000000

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		S-1-5-21-2370586174-1517003462-1142029260-500
	Account Name:		Administrator
	Account Domain:		MAGNUMTEMPUS
	Logon ID:		0792EED8
	Linked Logon ID:		00000000
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{00000000-0000-0000-0000-000000000000}

Process Information:
	Process ID:		00000000
	Process Name:		-

Network Information:
	Workstation Name:	RDP01
	Source Network Address:	172.16.55.110
	Source Port:		51058

Detailed Authentication Information:
	Logon Process:		NtLmSsp 
	Authentication Package:	NTLM
	Transited Services:	-
	Package Name (NTLM only):	NTLM V1
	Key Length:		128
```

## Additional Indicators

**SOURCE: Windows.Sys.Users.json**

One set of users was created along with another account that may have some concerns due to its description.
```
{
  "Uid": 1179,
  "Gid": 513,
  "Name": "server.admin",
  "Description": "<Auto Generated> The password for this account is: AutoGenPassword123
! #PLEASE CHANGE THIS#",
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
├─────────────────────┼────┼─────────────────────────────────┼───────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┤
│ 2022-02-19 21:00:18 │ 1  │ ‣ Net.exe Execution             │ "dc02.magnumtempus.financial" │ C:\Windows\System32\net.exe              │ "net" user combosecurity B4bymeta! /ADD  │
│                     │    │ ‣ Net.exe User Account          │                               │                                          │                                          │
│                     │    │ Creation                        │                               │                                          │                                          │
├─────────────────────┼────┼─────────────────────────────────┼───────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┤
│ 2022-02-19 21:00:18 │ 1  │ ‣ Net.exe Execution             │ "dc02.magnumtempus.financial" │ C:\Windows\System32\net1.exe             │ C:\Windows\system32\net1 user combosecur │
│                     │    │ ‣ Net.exe User Account          │                               │                                          │ ity B4bymeta! /ADD                       │
│                     │    │ Creation                        │                               │                                          │                                          │
├─────────────────────┼────┼─────────────────────────────────┼───────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┤
│ 2022-02-19 21:15:49 │ 1  │ ‣ Hurricane Panda Activity      │ "dc02.magnumtempus.financial" │ C:\Windows\System32\net.exe              │ "net" localgroup administrators combosec │
│                     │    │ ‣ Net.exe Execution             │                               │                                          │ urity /ADD                               │
├─────────────────────┼────┼─────────────────────────────────┼───────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────┤
│ 2022-02-19 21:15:49 │ 1  │ ‣ Hurricane Panda Activity      │ "dc02.magnumtempus.financial" │ C:\Windows\System32\net1.exe             │ C:\Windows\system32\net1 localgroup admi │
│                     │    │ ‣ Net.exe Execution             │                               │                                          │ nistrators combosecurity /ADD            │
└─────────────────────┴────┴─────────────────────────────────┴───────────────────────────────┴──────────────────────────────────────────┴──────────────────────────────────────────┘
```
---

## Additional Analyst Comments - Kerberos Attacks

## Kerberoasting
Had a helpful guide on detecting Kerberoasting Activity comes from [AdSecurity](https://adsecurity.org/?p=3458).

An approach that an analyst can take is to review the Security Windows Event Logs for EventIDs 4768, 4769, and 4770. You'll want to look for the Ticket Encryption Type field within the 'Additional Information' Section. The typical Encryption Type is 0x12 as it's associated with AES256-cts-hmac-SHA1-96. However, Kerberoasting will push the encryption down to RC4-HMAC (0x17).

It may be easier to set the search for 'Additional Information\Ticket Encryption Type' NOT EQUALS to 0x12.

The goal was to find Ticket Encryption Type: 0x17 is what I am looking for.

**VERDICT: No indicators of Kerberoasting occurred on DC02.**

## Pass-The-(Over)Hash (PtH)

Normally, the domain authentication are handled through Kerberos. It can revert to NTLM if Kerberos is not available. PtH can also bypass NTLM being disabled.

**VERDICT: There was an indication of the PtH at 20:59Z, based on the NTLM V1 connection.**
