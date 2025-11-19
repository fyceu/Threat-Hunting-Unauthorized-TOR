# Threat Hunting: Unauthorized TOR Usage
## Background and Overview
The security team was alerted by HR that some employees were considering using TOR to bypass company web filters and access restricted sites during work hours. Because corporate policy prohibits third party browsers such as TOR due to the risk of bypassing web filters, hiding user activity, and exfiltrating company data, leadership views this as a potential security and compliance issue. The security team is tasked with quietly confirming whether any employee has installed or used TOR on corporate workstations.

The full incident walkthrough can be found [here](). 
<br>
The Incident Response write-up can be read [here](). 

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

Employee `John.Doe` was recorded to have downloaded and silently install the TOR browser on their workstation. They proceeded to launch the browser, establishing connections with the TOR network using the company network. Once they completed browsing the dark web, the user proceeded to delete any associated files from their computer and recycle bin. Based on the sequence of these activities, it is confirmed the user violated the company's usage policy. 
<img width="793" height="463" alt="Screenshot 2025-11-16 at 9 00 12 PM" src="https://github.com/user-attachments/assets/43c22924-5bb7-44f3-8fb8-bc7564a5bbd9" />


## Recommendations
