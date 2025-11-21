# Threat Hunting: Unauthorized TOR Usage
## Background and Overview
The security team was alerted by HR that some employees were considering using TOR to bypass company web filters and access restricted sites during work hours. Because corporate policy prohibits third party browsers such as TOR due to the risk of bypassing web filters, hiding user activity, and exfiltrating company data, leadership views this as a potential security and compliance issue. The security team is tasked with quietly confirming whether any employee has installed or used TOR on corporate workstations.

The full incident walkthrough can be found [here](). 
<br>
The Investigation Report can be read [here](). 

## Tech Stack
<img width="50" height="50" alt="azure" src="https://github.com/user-attachments/assets/fd2866b6-d2fa-4e61-bf55-0b20d63fca5e" />
<img width="50" height="50" alt="windows logo" src="https://github.com/user-attachments/assets/5b714048-8f2e-4753-b68a-7aa699b5ef38" />
<img width="50" height="50" alt="icons8-windows-defender-48" src="https://github.com/user-attachments/assets/41507be1-eadc-440c-b577-ccbf835e91e3" />
<img width="50" height="50" alt="icons8-tor-browser-48" src="https://github.com/user-attachments/assets/b46620b6-5445-4c7c-bc0c-4ea2173a61b3" />
<img width="50" height="50" alt="MaterialIconThemeKusto" src="https://github.com/user-attachments/assets/7e9d871a-0391-43be-a826-08486ef1d562" />

- Microsoft Azure
- Windows 10 VM
- Microsoft Defender for Endpoint
- TOR Browser
- KQL

## Executive Summary

During this threat hunt, endpoint logs confirmed that user `john.doe` downloaded and silently installed TOR on a company workstation. The user then launched the browser establishing outbound connections to the TOR network while on the company network. 

Shortly after this activity, TOR-related files were deleted from the workstation and recycling bin. Based on the collected events, this activity is assessed as unauthorized TOR usage in violation of the company’s acceptable-use and security policies.

The Investigation Report can be read [here](). 
<p align="center">
  <img width="793" height="463" alt="Screenshot 2025-11-16 at 9 00 12 PM" src="https://github.com/user-attachments/assets/43c22924-5bb7-44f3-8fb8-bc7564a5bbd9" />
</p> 

## Recommendations

- Application Whitelist
- Network Detection Controls
- User & HR Handling
