# 🛡️ Mini SOC Report – Elastic SIEM (Redacted)

## Executive Summary

In this project I built and ran a mini-SOC based on Elastic SIEM to reproduce a realistic SOC workflow.  
I deployed and hardened Elasticsearch and Kibana on Linux, then ingested Windows logs through Winlogbeat.  
I configured advanced security auditing to collect critical process and authentication events.  
The analysis focused on detecting elevated PowerShell executions and brute-force scenarios.  
I correlated events over time to spot suspicious behavior rather than isolated logs.  
Each detection was assessed by user, machine, and privilege context.  
The project includes a full rollback phase to return the system to a clean state.  
This work shows practical understanding of SOC operations and behavior-based detection.

---

## Recommendations

- Set up automatic correlation rules to prioritize high-risk sequences  
- Restrict and monitor PowerShell usage through appropriate security policies  
- Use dedicated accounts and roles for SIEM agents (least privilege)  
- Centralize network and Linux logs to enrich multi-source correlations  
- Document every detection and incident to improve SOC maturity

All sensitive data has been **anonymized / redacted** so this report can be published on GitHub.

---

## Objectives

- Deploy a working SIEM (Elastic Stack)
- Collect real Windows logs
- Understand security events (authentication, processes)
- Set up **context-based SOC detections**
- Document the analysis as in a professional environment

---

## Technical environment

### Infrastructure
| System | Role |
|------|------|
| Kali Linux | SIEM server (Elasticsearch, Kibana) |
| Windows 11 | Monitored host |

### Technologies used
- Elasticsearch
- Kibana
- Winlogbeat
- Elastic Common Schema (ECS)

---

## Installation and setup

### 1️⃣ Setting up the SIEM on Kali Linux

I installed and configured **Elasticsearch** and **Kibana** on Kali Linux using the official Elastic repository.

Key installation points:
- Enabling Elastic security (HTTPS + authentication)
- Starting and checking the services
- Secure connection to Kibana
- Verifying the Elasticsearch cluster is healthy

The SIEM was ready to receive logs once:
- Elasticsearch was reachable over HTTPS
- Kibana was working and authenticated

---

### 2️⃣ Configuring the Windows host

On the Windows host I installed **Winlogbeat** to ship the security logs to Elasticsearch.

Actions taken:
- Installing Winlogbeat
- Configuring the secure Elasticsearch output
- Installing Winlogbeat as a **Windows service**
- Verifying logs were arriving in Kibana

---

### 3️⃣ Enabling Windows security auditing

To get logs relevant to a SOC, I enabled advanced auditing:

- **Process creation** (Event ID 4688)
- **Logon logging** (Event ID 4624 / 4625)
- **Audit policy change logging** (Event ID 4719)
- Including the process command line

These settings make it possible to detect suspicious behavior such as:
- elevated PowerShell executions
- brute-force attempts
- security configuration changes

---

## Collected data

### Main events observed

| Event ID | Description |
|------|-----------|
| 4719 | Audit policy change |
| 4688 | Process creation |
| 4625 | Authentication failure |
| 4624 | Successful authentication |

---

## Incident timeline (simulated scenario)

### 🟡 Step 1 – Configuration change
- **Event ID 4719**
- Process creation auditing enabled
- Critical event for a SOC (security policy change)

### 🟠 Step 2 – Suspicious PowerShell execution
- **Event ID 4688**
- `powershell.exe` launched from `cmd.exe`
- Executed with elevated privileges
- Dual-use tool that requires contextual analysis

### 🔴 Step 3 – Brute-force attempts (scenario)
- Several **4625** (failures)
- Followed by a **4624** (success)
- Typical pattern of a brute-force attack

---

## Detection logic

### Example KQL rule used

```kql
event.code:4688 and
process.name:"powershell.exe" and
process.parent.name:"cmd.exe" and
winlog.event_data.TokenElevationType:"Type d’élévation de jeton complet (2)"
```

SOC reasoning:

- PowerShell is a legitimate tool but often used in attacks

- Privilege elevation raises the risk level

- A cmd.exe parent is frequently seen in post-exploitation

- An isolated event is flagged suspicious; the sequence increases the severity

## SOC methodology applied

In this project I applied a realistic SOC methodology:

- Analysis based on event correlation

- Reasoning by sequence, not by isolated log

- Prioritization based on user / machine context

- Distinguishing legitimate activity from suspicious activity

## Severity assessment
Scenario	                          |  Severity
Isolated elevated PowerShell	               Medium
PowerShell with encoded command	     High
Brute-force followed by a success	       High

## Cleanup and restoration

After the tests, I performed a full rollback:

- Removing Winlogbeat

- Disabling advanced auditing

- Removing PowerShell logging

- Uninstalling Elasticsearch and Kibana on Kali

- This step is essential to guarantee a clean and controlled environment.

## Skills demonstrated

- Deploying and hardening an Elastic SIEM

- Collecting and normalizing Windows logs

- Configuring advanced security auditing

- Analyzing Windows events (4688, 4719, 4625, 4624)

- SOC correlation and Blue Team reasoning

- Writing detection rules (KQL)

- Writing a professional SOC report

## Conclusion

This mini-SOC let me reproduce a realistic SOC workflow, from installing the SIEM through analyzing and documenting security events.
The project emphasizes SOC reasoning, correlation, and understanding context rather than just reading raw logs.
