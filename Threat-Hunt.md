# Threat Hunt
**Primary Objective**:
> Has any user installed *or* used TOR Browser on a corporate workstation?

Table of Contents
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
```

To focus on this host, I refined my query:

```kusto
DeviceFileEvents
| where DeviceName contains "fasi-threat"
| where FileName contains "tor"
| where TimeGenerated >= todatetime('2025-11-12T23:36:37.6787105Z')
| order by TimeGenerated asc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

The first recorded log showed the user, `john.doe`, downloading the TOR browser to their Downloads directory. 

Account: `john.doe`
<br>
Workstation: `fasi-threat-hun`
<br>
Timestamp: `2025-11-12T23:36:37.6787105Z`
<br>
File: `tor-browser-windows-x86_64-portable-15.0.1.exe`
<br>
Folder Path: `C:\Users\john.doe\Downloads\tor-browser-windows-x86_64-portable-15.0.1.exe`
<br>
File hash (SHA256): `66793f7208919a15087bac96d8e31151ff53f9620d9fd7bfd340794fa6d5f86c`

<p align="center">
  <img width="1552" height="303" alt="Screenshot_1" src="https://github.com/user-attachments/assets/4b0da1a8-bea6-4b00-86d6-875b22e87c57" />
</p>

This confirmed that `john.doe` downloaded an installer for the TOR browser onto the workstation, `fasi-threat-hun`

### Searching DeviceProcessEvents
Following the download, logs showed additional files being created on the desktop under a new Tor Browser folder, including executables and a shortcut: 
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

<p align="center">
  <img width="1958" height="238" alt="Screenshot_2" src="https://github.com/user-attachments/assets/66d7dae4-e7a3-44c7-ae56-5f6a47458b0c" />
</p>

Timestamp: `2025-11-12T23:36:57.2105635Z` <br>
ProcessCommandLine: `tor-browser-windows-x86_64-portable-15.0.1.exe  /S` <br>
File Name: `tor-browser-windows-x86_64-portable-15.0.1.exe` <br>
SHA 256: `66793f7208919a15087bac96d8e31151ff53f9620d9fd7bfd340794fa6d5f86c` <br>

Both the FilePath and SHA256 hash matched the installer recorded from `DeviceFileEvents`, confirming the downloaded file was used to perform a silent installation (using /S flag) of TOR browser onto their Desktop. 

### Searching DeviceNetworkEvents
