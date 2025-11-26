# Threat Hunt
**Primary Objective**:
> Has any user installed *or* used TOR Browser on a corporate workstation?

## Searching for TOR-related artifacts
I started my search using `DeviceFileEvents` to find any file or artifacts that contained the word `tor` in its name. This immediately discovered a single workstation, `fasi-threat-hun`, with TOR related activities beginning at `2025-11-12T23:36:37.6787105Z`

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

Account: `john.doe` <br>
Workstation: `fasi-threat-hun` <br>
Timestamp: `2025-11-12T23:36:37.6787105Z` <br>
File: `tor-browser-windows-x86_64-portable-15.0.1.exe` <br>
Folder Path: `C:\Users\john.doe\Downloads\tor-browser-windows-x86_64-portable-15.0.1.exe` <br>
File hash (SHA256): `66793f7208919a15087bac96d8e31151ff53f9620d9fd7bfd340794fa6d5f86c`

<p align="center">
  <img width="1552" height="303" alt="Screenshot_1" src="https://github.com/user-attachments/assets/4b0da1a8-bea6-4b00-86d6-875b22e87c57" />
</p>

This confirmed that `john.doe` downloaded an installer for the TOR browser onto the workstation, `fasi-threat-hun`

## Confirming TOR installation
Following the download, logs showed additional files being created on the desktop such as `tor goodies hehe.txt`, and a new Tor Browser folder, that included an executable and shortcut: 
- `C:\Users\john.doe\Desktop\tor goodies hehe.txt`
- `C:\Users\john.doe\Desktop\Tor Browser\Browser\firefox.exe`
- `C:\Users\john.doe\Desktop\Tor Browser\Browser\TorBrowser\Tor\Tor.exe`
- `C:\Users\john.doe\Desktop\Tor Browser\Tor Browser.lnk`

This strongly suggests that the downloaded installer successfully unpacked and installed TOR.

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

## Searching for TOR network activity
With the installer execution confirmed, the next step was to determine whether the user actually launched the TOR browser. I searched `DeviceProcessEvents` for processes commonly associated with the TOR browser and related Firefox-engine:
```kusto
DeviceProcessEvents
| where DeviceName contains "Fasi-Threat"
| where FileName has_any ("tor.exe", "tor-browser.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine, FileName, FolderPath, SHA256
| order by Timestamp desc 
```

From this query, an event starting from `2025-11-12T23:39:06.0286837Z` showed TOR-related processes executing from the Tor directory on the Desktop. This confirms that the user launched an unauthorized application on their workstation. 

Timestamp: `2025-11-12T23:39:06.0286837Z` <br>
Account: `john.doe` <br>
Device Name: `fasi-threat-hun` <br>
File: `tor.exe` <br>
Folder Path: `C:\Users\john.doe\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe` <br> 
File Hash (SHA256): `f78d87ff967bbdebbc43c58c2b5376522d2bbc975c98727c75bf28e2eb23ffd0` <br>

<p align="center">
  <img width="1952" height="533" alt="Pasted image 20251119214301" src="https://github.com/user-attachments/assets/ffb123a7-40cd-4901-a217-86a7798c841a" />
</p>

After confirming the execution of TOR, the next step was to determine if any network traffic was generated that correlated to TOR usage. 

From my understanding, TOR browser uses the common ports:
- 9001, 9030, 9040, 9050, 9051, 9150

To look for this type of network activity, I searched `DeviceNetworkEvents` for connections initiated by the applications over these common ports:
```kusto
DeviceNetworkEvents
| where DeviceName contains "Fasi-Threat"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe") 
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```

Timestamp: `2025-11-12T23:39:17.1257628Z` <br>
Remote IP: `75.145.166.75` <br>
Remote Port: `9001` <br>
RemoteURL: `https://www.hgojzjwmxtq5zb7zgcd2f2h.com` <br>
InitiaingProcessFile: `tor.exe` <br>

<p align="center">
  <img width="2103" height="604" alt="Pasted image 20251119222948" src="https://github.com/user-attachments/assets/6a6c2d49-e6e5-4315-9c45-c43f18f160cc" />
</p>

Multiple `ConnectionSuccess` events from `tor.exe` to different IPs on ports `9001` and `9050` that contain obfuscated URLs indicate user `john.doe` successfully connected to the dark web. 

## Response
TOR usage was confirmed on endpoint `fasi-threat-hun` under the account `john.doe`. 
The device was isolated from the network and scheduled for forensic analysis and reimaging to ensure no additional tools or malware were present. 

Management and HR were notified of the incident, and the user's account activity was reviewed in line with the company's acceptable-use and disciplinary policies.
