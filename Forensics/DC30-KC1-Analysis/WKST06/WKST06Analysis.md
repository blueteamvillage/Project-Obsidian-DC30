# WKST06 Analysis

This document details the analysis done from the investigation of the device. 
## Baseline 
The objective is to review and identify indicators of the host being compromised.  In order to present the findings, we'll establish the baseline.

| System Name | IP Address | Assigned User |
| ----- | ---- | ---|
| WKST06 | 172.16.50.135| brad.cudo |


One important part is to review the users.

| Name | Last Activity Date| Security Identifier (SID)|
| -- | -- | -- |
| (LOCAL) Administrator | 2022-02-12T20:14:56.1305084Z | S-1-5-21-1513105513-169651639-2097894882-500 |
|kama.suppetia | 2022-02-12T20:18:34.4050974Z | S-1-5-21-2370586174-1517003462-1142029260-1139
| Brad.cudo | 2022-02-12T20:56:30.3725828Z |S-1-5-21-2370586174-1517003462-1142029260-1136
|administrator.MAGNUMTEMPUS | 2022-02-13T00:04:33.4741776Z |S-1-5-21-2370586174-1517003462-1142029260-500 |


## Timeline For 12 February 2022
* **21:30 UTC:** Karen.Meteuns logged on from 172.16.50.131 via Domain Account MAGNUMTEMPUS.FINANCIAL (while brad was MAGNUMTEMPUS) *[Security Event Logs]*
* **21:31 UTC:** , the IT department grabbed a file from the IT Department on  "Data Breach Response", a Guide for Business
* **21:54 UTC:** Brad received an email from safe-documents@magnumtempus.financial (different from magnumtempusfinancial.com) *[E-Mail Comms]*
* **23:14 UTC:** Brad sent the email to Estevan McNullen, warning him not to open but to analyze the contents of the malicious document within a sandbox and confirm it's malicious nature *[E-Mail Comms]*
* **23:16 UTC:** Richard Natu sent an email planning to drop off the hard drive of all marketing materials with a reqeust for data recovery. *[E-Mail Comms]*
* **23:18 UTC:** Estevan McNullen agreed that something was not right and would take a look at the document. *[E-Mail Comms]*
* **2022-02-13 00:02:42 UTC:** WinTriage was downloaded from the Google drive. *[Microsoft-Windows-Sysmon/Operational Event Logs]*

## Artifact & Properties

### **Malicious Document**

| FileName |  Safe-Documents-Confidential-Data-brad.cudo@magnumtempusfinancial.com.xls |
| ------- | ---------|
| Filesize | 390144 (381 KB) | 
| MD5 |  85BAA15EB76431AD3FD3157F46816B4E |
| SHA1 |  10D33BF66021E1DB4CAD6CDE308D63953F1043D8 |
| SHA256 |   DCD941DF0F4FA9C8BE610164DEDA88422776EBE67DADADAA490759911C6157FD |
File Details | Composite Document File V2 Document, Little Endian, Os: Windows, Version 10.0, Code page: 1252, Author: Administrator, Last Saved By: Administrator, Name of Creating Application: Microsoft Excel, Create Time/Date: Sat Feb 12 05:04:34 2022, Last Saved Time/Date: Sat Feb 12 05:07:06 2022, Security: 0 |

**EXIF Details**

**SOURCE: exiftools command**
```
File Size                       : 381 KiB
File Modification Date/Time     : 2022:03:26 12:09:29+02:00
File Access Date/Time           : 2022:03:26 12:09:29+02:00
File Inode Change Date/Time     : 2022:03:27 10:18:08+03:00
File Permissions                : rw-r--r--
File Type                       : XLS
File Type Extension             : xls
MIME Type                       : application/vnd.ms-excel
Author                          : Administrator
Last Modified By                : Administrator
Software                        : Microsoft Excel
Create Date                     : 2022:02:12 05:04:34
Modify Date                     : 2022:02:12 05:07:06
Security                        : None
Code Page                       : Windows Latin 1 (Western European)
Company                         : 
App Version                     : 16.0000
Scale Crop                      : No
Links Up To Date                : No
Shared Doc                      : No
Hyperlinks Changed              : No
Title Of Parts                  : Sheet1, Macro1
Heading Pairs                   : Worksheets, 1, Excel 4.0 Macros, 1
```

### **Log Review**
**SOURCE: Windows Event Logs (SECURITY)**

21:30:00Z, EventID 4624, Karen.Meteuns logged on from 172.16.50.131 via Domain Account MAGNUMTEMPUS.FINANCIAL (while brad was MAGNUMTEMPUS)

Multiple times of successful logins, EventID 4624, into brad.cudo account from 172.16.21.100 under Workstation name 'kali'. This is found in the Network Information section.
* 35 events found (4 failures and 31 successes)

**ASSESSMENT:** Probably suspicious, but nothing substantial correlated to indicate compromise.



**SOURCE: Custom.Windows.System.Services.json**

MS Defender was still running, so it is likely that the threat actor did not attempt to leverage malware as a point of entry. 

```Offset: 0x22773bbb6c0
Order: 477
Start: SERVICE_AUTO_START
Process ID: 1956
Service Name: WinDefend
Display Name: Windows Defender Service
Service Type: SERVICE_WIN32_OWN_PROCESS
Service State: SERVICE_RUNNING
Binary Path: "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2201.10-0\MsMpEng.exe"
ServiceDll: 
ImagePath: "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2201.10-0\MsMpEng.exe"
FailureCommand:
``` 

**ASSESSMENT:** It is unlikely that malware was used on the device.


### Memory Forensics
For conducting memory forensics on the .raw file, only three profiles were viable to use.
* Win10x64_14393
* Win10x64_10586
* Win2016x64_14393

**ASSESSMENT:** No strange activity was found


### **Miscallaneous Concern**

Brad had a LNK of passwords.txt within the Desktop. C:\Users\brad.cudo\AppData\Roaming\Microsoft\Windows\Recent. The password appears to be in clear text. Other potential noteworthy Lnk files: Marketing Template, New Text Document

Tool Used: IEF Report Viewer v6.48.0.25872 - Investigator Mode (Free)
file:///C:/Users/Administrator/Desktop/passwords.txt was found associated with Administrator. It was accessed on 02/12/2022 18:46:46 UTC


**SOURCE: Windows.Forensics.Lnk.json:**
```
{"FullPath":"C:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\passwords.lnk","_Parsed":{"HeaderSize":76,"LinkClsID":"0114020000000000c000000000000046","LinkFlags":["DisableKnownFolderTracking","HasLinkInfo","HasLinkTargetIDList","HasRelativePath","HasWorkingDir","IsUnicode"],"FileAttributes":["FILE_ATTRIBUTE_ARCHIVE"],"CreationTime":"2022-02-12T18:46:41Z","AccessTime":"2022-02-12T18:46:41Z","WriteTime":"2022-02-12T18:46:41Z","FileSize":0,"IconIndex":0,"ShowCommand":1,"HotKey":0,"LinkTargetIDList":{"IDListSize":106,"IDList":[{"ItemIDSize":104,"Offset":78,"Type":48,"Subtype":0,"ShellBag":{"Size":104,"Type":50,"SubType":["File","Unicode"],"LastModificationTime":"2022-02-12T18:46:42Z","ShortName":"PASSWO~1.TXT","Extension":{"Size":76,"Version":9,"Signature":"0xbeef0004","CreateDate":"2022-02-12T18:46:42Z","LastAccessed":"2022-02-12T18:46:42Z","MFTReference":{"MFTID":82146,"SequenceNumber":1688849860263936},"LongName":"passwords.txt"},"Description":{"Type":["File","Unicode"],"Modified":"2022-02-12T18:46:42Z","LastAccessed":"2022-02-12T18:46:42Z","CreateDate":"2022-02-12T18:46:42Z","ShortName":"PASSWO~1.TXT","LongName":"passwords.txt","MFTID":82146,"MFTSeq":1688849860263936}}}]},"LinkInfo":{"Offset":184,"LinkInfoSize":91,"LinkInfoFlags":["VolumeIDAndLocalBasePath"],"Target":{"path":"C:\\Users\\Administrator\\Desktop\\passwords.txt","volume_info":{"DriveType":"DRIVE_FIXED","DriveSerialNumber":3993596985,"VolumeLabel":""}}},"NameInfo":{},"RelativePathInfo":{"Offset":275,"RelativePathInfoSize":72,"RelativePath":"..\\..\\..\\..\\..\\Desktop\\passwords.txt"},"WorkingDirInfo":{"Offset":349,"WorkingDirInfoSize":60,"WorkingDir":"C:\\Users\\Administrator\\Desktop"},"ArgumentInfo":{},"IconInfo":{}},"Mtime":"2022-02-12T18:46:46.452428Z","Atime":"2022-02-12T18:46:46.4514278Z","Ctime":"2022-02-12T18:46:46.452428Z","_TargetIDInfo":[{"Type":["File","Unicode"],"Modified":"2022-02-12T18:46:42Z","LastAccessed":"2022-02-12T18:46:42Z","CreateDate":"2022-02-12T18:46:42Z","ShortName":"PASSWO~1.TXT","LongName":"passwords.txt","MFTID":82146,"MFTSeq":1688849860263936}],"HeaderCreationTime":"2022-02-12T18:46:41Z","HeaderAccessTime":"2022-02-12T18:46:41Z","HeaderWriteTime":"2022-02-12T18:46:41Z","FileSize":0,"Target":{"path":"C:\\Users\\Administrator\\Desktop\\passwords.txt","volume_info":{"DriveType":"DRIVE_FIXED","DriveSerialNumber":3993596985,"VolumeLabel":""}},"Name":null,"RelativePath":"..\\..\\..\\..\\..\\Desktop\\passwords.txt","WorkingDir":"C:\\Users\\Administrator\\Desktop","Arguments":null,"Icons":null,"Upload":null}
```


**Tool Used: LECmd.exe**
```
Processing 
'E:\CASE\DC30\Capstone-KillChain1\WKST06\Collection-wkst06_magnumtempus_financial-2022-02-13T00_04_40Z\data\C\Users\brad.cudo\AppData\Roaming\Microsoft\Windows\Recent\passwords.lnk'


Source file: E:\CASE\DC30\Capstone-KillChain1\WKST06\Collection-wkst06_magnumtempus_financial-2022-02-13T00_04_40Z\data\C\Users\brad.cudo\AppData\Roaming\Microsoft\Windows\Recent\passwords.lnk
  Source created:  2/22/2022 5:35:01 PM +00:00
  Source modified: 2/12/2022 10:35:39 PM +00:00
  Source accessed: 3/12/2022 3:49:23 PM +00:00

--- Header ---
  Target created:  2/12/2022 8:17:16 PM +00:00
  Target modified: 2/12/2022 8:17:16 PM +00:00
  Target accessed: 2/12/2022 9:06:23 PM +00:00

  File size: 118
  Flags: HasTargetIdList, HasLinkInfo, HasRelativePath, HasWorkingDir, IsUnicode, DisableKnownFolderTracking
  File attributes: FileAttributeArchive
  Icon index: 0
  Show window: SwNormal (Activates and displays the window. The window is restored to its original size and position if the window is minimized or maximized.)

Relative Path: ..\..\..\..\..\Desktop\passwords.txt
Working Directory: C:\Users\brad.cudo\Desktop
--- Link information ---
Flags: VolumeIdAndLocalBasePath

>>Volume information
  Drive type: Fixed storage media (Hard drive)
  Serial number: EE097439
  Label: (No label)
  Local path: C:\Users\brad.cudo\Desktop\passwords.txt

--- Target ID information (Format: Type ==> Value) ---

  Absolute path: passwords.txt

  -File ==> passwords.txt
    Short name: PASSWO~1.TXT
    Modified: 2/12/2022 9:06:24 PM +00:00
    Extension block count: 1

    --------- Block 0 (Beef0004) ---------
    Long name: passwords.txt
    Created: 2/12/2022 8:17:18 PM +00:00
    Last access: 2/12/2022 8:17:18 PM +00:00
    MFT entry/sequence #: 265403/7 (0x40CBB/0x7)

--- End Target ID information ---
```


--- 

## Investigation Guide

**Premise:** Magnum Tempus Financial uses Thunderbird as their eMail Client, the more formal name, Mail User Agent (MUA) to access and manage their emails.

### Data Collection - Email

To access the data, it requires understanding where the received emails will go:

> %USER%%AppData%\Roaming\Thunderbird\Profiles

1. There are a few profiles, but you want to follow the data, which leads to '4y9ghybh.default-release'
2. There are two options to consider: 'Mail' or 'ImapMail'. In this case, since it's tied to the organization, you'll want to go in the path that is collected on behalf of the organization, and it's where most of the data lies.
3. Follow the path until you're finally here:

> %USERNAME%\%AppData%\Roaming\Thunderbird\Profiles\4y9ghybh.default-release\ImapMail\imap.magnumtempusfinancial.com

This leads to a collection of files, one has the .msf and the other is without an extension. The ones with the data are without the extension, referred to as MBOX.

Summary of the trick is that after installing Thunderbird, cancel out of creating an email, but instead creating an account via 'Feeds' button. You then point the feed to the folder within the 'Access the Data' procedure.

**REFERENCE FOR STEP-BY-STEP:** [Hoffman, C. 2021, January 16. How to Open an MBOX File (Using Mozilla Thunderbird). How-To Geek.](https://www.howtogeek.com/709718/how-to-open-an-mbox-file-in-mozilla-thunderbird/)
