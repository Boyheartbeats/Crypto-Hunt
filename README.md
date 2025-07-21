# Crypto-Hunt

**Date Started:** July 12, 2025  
**Objective:** This threat hunt tracks an attacker targeting crypto-related financial data, leveraging LOLBins, PowerShell downgrade techniques, and anti-forensic measures. The investigation was performed entirely within **Microsoft Defender for Endpoint (MDE)** using advanced hunting queries.

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
