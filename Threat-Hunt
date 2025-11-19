Primary Objective:
> Has any user installed *or* used TOR Browser on a corporate workstation?

## Table of Contents
1. [Steps Taken]()
2. [Response and Recommendations]()
3. [Chronological Event Timeline]()
4. [IOCs]()
## Steps Taken

### Searching DeviceFileEvents
I started my search using `DeviceFileEvents` to find any file or artefacts that contained the word `tor` in its name. This immediately discovered a single workstation, `fasi-threat-hun`, with TOR related activities beginning at `2025-11-12T23:36:37.6787105Z`

```kusto
DeviceFileEvents
| where FileName contains "tor"
| order by TimeGenerated asc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

To focus on this host, I refined my query:

```kusto
DeviceFileEvents
| where DeviceName contains "fasi-threat"
| where FileName contains "tor"
| order by TimeGenerated asc
| where TimeGenerated >= todatetime('2025-11-12T23:36:37.6787105Z')
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

The first recorded log showed the user, `john.doe` , downloading the TOR browser to their Downloads directory. 

Account: `john.doe`
Workstation: `fasi-threat-hun`
Timestamp: `2025-11-12T23:36:37.6787105Z`
File: `tor-browser-windows-x86_64-portable-15.0.1.exe`
Folder Path: `C:\Users\john.doe\Downloads\tor-browser-windows-x86_64-portable-15.0.1.exe`
File hash (SHA256): `66793f7208919a15087bac96d8e31151ff53f9620d9fd7bfd340794fa6d5f86c`

![[Screenshot_1.png]]

This confirmed that `john.doe` downloaded a TOR browser installer onto `fasi-threat-hun`
### Searching DeviceProcessEvents
Following the download, logs showed additional files being created on the desktop under a new Tor Browser folder, including the main executable and shortcut: 
- `C:\Users\john.doe\Desktop\Tor Browser\Browser\firefox.exe`
- `C:\Users\john.doe\Desktop\Tor Browser\Browser\TorBrowser\Tor\Tor.exe`
- `C:\Users\john.doe\Desktop\Tor Browser\Tor Browser.lnk`

This strongly suggests that the installer successfully unpacked and installed TOR.

To confirm the installer was executed, I pivoted to `DeviceProcessEvents` and searched for any process command line referencing the TOR Browser installer:
```kusto
DeviceProcessEvents
| where DeviceName contains "Fasi-Threat"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.1.exe"
| where TimeGenerated >= todatetime('2025-11-12T23:36:37.6787105Z') 
| project TimeGenerated, DeviceName, ActionType, ProcessCommandLine, FileName, FolderPath, Account = InitiatingProcessAccountName, SHA256
```

Results showed the user `john.doe` executed the installer using the following command:
- `tor-browser-windows-x86_64-portable-15.0.1.exe /S`

![[Screenshot_2.png]]

Timestamp: `2025-11-12T23:36:57.2105635Z`
ProcessCommandLine: `tor-browser-windows-x86_64-portable-15.0.1.exe  /S`
File Name: `tor-browser-windows-x86_64-portable-15.0.1.exe`
SHA 256: `66793f7208919a15087bac96d8e31151ff53f9620d9fd7bfd340794fa6d5f86c`

Both the FilePath and SHA256 hash matched the installer recorded from `DeviceFileEvents`, confirming the downloaded file was used to perform  a silent installation (using /S flag) of TOR browser onto their Desktop. 
### Searching DeviceNetworkEvents
With the installer , must search for indication of the user actually opening the TOR browser. 

```kusto
DeviceProcessEvents
| where DeviceName contains "Fasi-Threat"
| where FileName has_any ("tor.exe", "tor-browser.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine, FileName, FolderPath, SHA256
| order by Timestamp desc 
```
