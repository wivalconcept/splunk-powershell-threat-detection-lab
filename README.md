# Splunk PowerShell Threat Detection Lab

A hands-on SOC and detection-engineering lab that uses **Sysmon**
telemetry and **Splunk Enterprise** to detect suspicious PowerShell
activity, classify detections by severity, map activity to **MITRE
ATT&CK**, generate scheduled alerts, and support analyst investigation
through an interactive dashboard.

![Splunk PowerShell Threat Detection
Dashboard](screenshots/dashboard-overview.png)

## Project Overview

PowerShell is widely used by administrators, but it is also commonly
abused during malicious activity. This project demonstrates how Windows
process-creation telemetry can be transformed into practical security
detections and SOC workflows.

The lab monitors **Sysmon Event ID 1 (Process Creation)** and identifies
selected PowerShell behaviours based on command-line characteristics.
Detected activity is enriched with severity and MITRE ATT&CK information
before being presented through dashboards and scheduled alerts.

## Detection Coverage

  Detection                             Severity   MITRE ATT&CK
  ------------------------------------- ---------- -----------------------
  Encoded PowerShell Command            High       T1059.001
  Scheduled Task PowerShell Execution   High       T1053.005 / T1059.001
  PowerShell Execution Policy Bypass    Medium     T1059.001

## Architecture

``` text
Windows Endpoint
      |
      v
    Sysmon
(Event ID 1)
      |
      v
Splunk Ingestion
      |
      v
SPL Detection Logic
      |
      +----------------------+
      |                      |
      v                      v
Severity + MITRE        Scheduled Alerts
Enrichment              High / Medium
      |
      v
SOC Dashboard
      |
      v
Investigation Drilldown
```

## Core Detection Logic

``` spl
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*powershell.exe"
| eval DetectionName=case(
    like(CommandLine,"%scheduled-check.ps1%"), "Scheduled Task PowerShell Execution",
    like(CommandLine,"%EncodedCommand%"), "Encoded PowerShell Command",
    like(CommandLine,"%ExecutionPolicy Bypass%"), "PowerShell Execution Policy Bypass"
)
| where isnotnull(DetectionName)
| eval Severity=case(
    DetectionName="Scheduled Task PowerShell Execution", "High",
    DetectionName="Encoded PowerShell Command", "High",
    DetectionName="PowerShell Execution Policy Bypass", "Medium"
)
| eval MITRE_Technique=case(
    DetectionName="Scheduled Task PowerShell Execution", "T1053.005 / T1059.001",
    DetectionName="Encoded PowerShell Command", "T1059.001",
    DetectionName="PowerShell Execution Policy Bypass", "T1059.001"
)
| eval MITRE_Name=case(
    DetectionName="Scheduled Task PowerShell Execution", "Scheduled Task + PowerShell",
    DetectionName="Encoded PowerShell Command", "Command and Scripting Interpreter: PowerShell",
    DetectionName="PowerShell Execution Policy Bypass", "Command and Scripting Interpreter: PowerShell"
)
| table _time Computer User DetectionName Severity MITRE_Technique MITRE_Name ParentImage CommandLine
| sort - _time
```

## Dashboard

The **Splunk PowerShell Threat Detection Lab** dashboard provides total,
high, and medium detection KPIs; severity distribution; detections by
type; a detection timeline; unified and recent event tables; MITRE
ATT&CK enrichment; a MITRE technique visualization; and drilldown into
Search & Reporting.

## Alerting

Two scheduled alerts were configured and tested.

**High Severity PowerShell Detection**

``` spl
| where Severity="High"
```

**Medium Severity PowerShell Detection**

``` spl
| where Severity="Medium"
```

Both alerts were configured on a five-minute schedule during the lab and
validated using controlled PowerShell test activity.

## Investigation Workflow

1.  Review dashboard KPIs and the detection trend.
2.  Identify the detection type and severity.
3.  Review the affected computer and user.
4.  Check the MITRE ATT&CK technique.
5.  Examine `ParentImage` and `CommandLine`.
6.  Use the dashboard drilldown to open related Sysmon events in Search
    & Reporting.
7.  Correlate surrounding endpoint activity before deciding whether
    escalation is required.

## Validation

The project validates the following end-to-end workflow:

``` text
PowerShell activity
        ↓
Sysmon Event ID 1
        ↓
Splunk ingestion
        ↓
SPL detection
        ↓
Severity classification
        ↓
MITRE ATT&CK enrichment
        ↓
Scheduled alert
        ↓
Dashboard / analyst investigation
```

High- and medium-severity alert trigger histories were used to confirm
that the scheduled searches fired successfully.

## Skills Demonstrated

Splunk Enterprise, SPL, Windows Sysmon, Windows event-log analysis,
PowerShell threat detection, detection engineering, SIEM alert
development, MITRE ATT&CK mapping, SOC dashboard development,
security-event triage, investigation drilldowns, and detection testing.

## Repository Structure

``` text
splunk-powershell-threat-detection-lab/
├── README.md
├── detections/
│   ├── powershell_detection.spl
│   ├── high_severity_alert.spl
│   └── medium_severity_alert.spl
├── dashboard/
│   └── powershell_threat_dashboard.xml
├── screenshots/
│   └── dashboard-overview.png
└── docs/
    └── investigation-workflow.md
```

## Key Takeaways

This project demonstrates the lifecycle of a small detection-engineering
use case: collecting endpoint telemetry, writing SPL detection logic,
enriching detections with severity and ATT&CK context, validating rules
with controlled tests, visualizing activity, generating alerts, and
providing an investigation path for a SOC analyst.

The rules are intentionally focused on a lab environment. In production,
command-line indicators should be combined with additional context,
baselining, allow-listing, process ancestry, user behaviour, and other
telemetry to reduce false positives.

## Disclaimer

This repository documents a controlled cybersecurity lab created for
defensive security learning and portfolio demonstration. Test activity
was performed only within the lab environment.
