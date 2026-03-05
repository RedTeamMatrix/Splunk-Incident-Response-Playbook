# Splunk Incident Response Playbook

Practical Splunk investigation techniques for SOC analysts and incident responders.

---

## Overview

This repository contains practical Splunk investigation techniques, queries, and workflows for SOC analysts and incident responders. It focuses on reconstructing attacker activity, identifying root cause, and determining scope of compromise using log data, with methods developed while preparing for the OSIR certification.

---

## What This Repository Covers

• Incident investigation workflows  
• Timeline reconstruction techniques  
• Endpoint telemetry analysis  
• Process and network correlation  
• Detection engineering examples

---

## Who This Is For

This repository is designed for:

- SOC Analysts  
- Incident Responders  
- Threat Hunters  
- Detection Engineers  
- Security Engineers working with Splunk

---

## Repository Structure
---
splunk-ir-playbook
│
├── README.md
│
├── investigation-playbooks
│   ├── compromised_host.md
│   ├── suspicious_powershell.md
│   ├── lateral_movement.md
│   └── ransomware_investigation.md
│
├── splunk-detections
│   ├── encoded_powershell.md
│   ├── suspicious_service_creation.md
│   ├── unusual_parent_child.md
│
├── threat-hunting
│   ├── sysmon_hunts.md
│   ├── persistence_hunting.md
│   ├── credential_access.md
│
├── splunk-queries
│   ├── sysmon_queries.md
│   ├── authentication_queries.md
│   └── network_queries.md
│
└── timeline-analysis
    └── building_attack_timeline.md

    ---
