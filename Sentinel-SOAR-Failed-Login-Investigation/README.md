# SOC Automation & SOAR Lab

### Microsoft Sentinel · Azure Logic Apps · Shuffle SOAR · Python · AbuseIPDB

A hands-on SOC lab that detects repeated Windows failed-login attempts,
creates a Microsoft Sentinel incident, sends it to Shuffle SOAR,
enriches the source IP with AbuseIPDB, classifies its reputation risk,
and notifies a SOC analyst by email.

> **Project type:** Personal learning / portfolio lab\
> **Status:** Core workflow implemented and tested\
> **Focus:** SIEM detection, incident handling, enrichment, workflow
> automation, and analyst notification

------------------------------------------------------------------------

## 1. Project Overview

The goal of this project is to demonstrate how a SIEM and a SOAR
platform can work together to automate the initial investigation of
suspicious login activity.

The lab uses Windows Security Event ID **4625** (failed logon).
Microsoft Sentinel identifies repeated failures, generates an incident,
and sends it through an Azure Logic App to a Shuffle webhook. Shuffle
then processes the incident, checks the severity, extracts the source
IP, queries AbuseIPDB, classifies the IP reputation, and sends an email
notification.

## 2. Architecture

``` text
Windows Server
    |
    | Security Event ID 4625
    v
Azure Monitor Agent / Log Analytics
    |
    v
Microsoft Sentinel
    |
    | Analytics rule creates incident
    v
Azure Logic App
    |
    | HTTP POST to Shuffle webhook
    v
Shuffle SOAR
    |
    +--> Receive and inspect incident
    |
    +--> Add investigation status
    |
    +--> Route based on incident severity
    |
    +--> Extract source IP using Python
    |
    +--> Query AbuseIPDB API
    |
    +--> Classify IP reputation using Python
    |
    +--> Route by IP risk
    |
    v
SOC Analyst Email Notification
```

## 3. Technologies Used

  Technology                  Purpose
  --------------------------- ---------------------------------------------------
  Windows Server              Generates Windows security events
  Microsoft Sentinel          SIEM detection and incident creation
  Azure Monitor Agent (AMA)   Collects Windows event data
  Log Analytics Workspace     Stores and queries security events
  Azure Logic Apps            Forwards Sentinel incidents to Shuffle
  Shuffle SOAR                Orchestrates the investigation workflow
  Python                      Extracts IP information and classifies reputation
  AbuseIPDB                   Provides external IP reputation information
  Email integration           Sends incident notifications to the analyst

## 4. Detection Logic

The Sentinel analytics rule looks for at least three failed logon events
within a five-minute window.

Example KQL:

``` kusto
SecurityEvent
| where EventID == 4625
| where TimeGenerated >= ago(5m)
| summarize FailedAttempts = count()
    by Account, Computer, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 3
```

**Rule configuration used in the lab:** - Rule name:
`Multiple Failed Logins - 4625` - Severity: Medium - Frequency: Every 5
minutes - Lookup period: 5 minutes - Incident creation: Enabled - Entity
mappings: Account, IP address, and Host

The exact query and rule configuration may need adjustment for a
different environment or data source.

## 5. Shuffle Workflow

The Shuffle workflow is named **SOC - Suspicious Login**.

  ----------------------------------------------------------------------------
  Workflow step                       What it does
  ----------------------------------- ----------------------------------------
  `Test-Repeat_Back`                  Displays the incoming Sentinel incident
                                      payload for inspection

  `Set-Investigation-Status`          Adds
                                      `investigation_status: Pending Review`
                                      to the workflow data

  Severity branches                   Routes High severity incidents to urgent
                                      review and other severities to standard
                                      review

  `Extract-Sentinel-IP`               Finds the IP entity in `relatedEntities`
                                      and extracts its address

  `AbuseIPDB-IP-Reputation-Check`     Sends the extracted IP to the AbuseIPDB
                                      API

  `Analyze-IP-Reputation`             Classifies the AbuseIPDB confidence
                                      score

  IP-risk branches                    Routes the workflow based on the
                                      calculated risk

  `SOC-Analyst-Email-Notification`    Sends incident and enrichment details to
                                      the analyst
  ----------------------------------------------------------------------------

### IP extraction

Sentinel incident payloads contain nested entity data. The IP address is
stored in the `relatedEntities` array, alongside other entities such as
the host and account.

The Python action searches for the entity whose `kind` is `Ip`, then
reads its `properties.address` value. This avoids assuming that the IP
entity will always appear at a fixed array position.

### Reputation classification

The lab uses these configurable thresholds:

    AbuseIPDB confidence score Workflow classification
  ---------------------------- -------------------------
                         0--24 Low
                        25--74 Suspicious
                       75--100 High

These are thresholds chosen for this lab's workflow. They are not
official AbuseIPDB verdict categories. A low score does not prove that
an IP is safe; it only indicates that AbuseIPDB has limited
abuse-confidence information for it.

## 6. Testing and Validation

The workflow was tested using failed-login activity and Sentinel
incidents. Validation included:

-   Confirming Windows failed-login events were collected by Sentinel.
-   Confirming the analytics rule generated an incident.
-   Confirming the Logic App delivered the incident to the Shuffle
    webhook.
-   Confirming incident severity routing.
-   Confirming Python extracted the IP address from Sentinel's incident
    entities.
-   Confirming the AbuseIPDB API returned a reputation result.
-   Confirming Python classified the reputation score.
-   Confirming the email notification was delivered.

Screenshots or a demonstration video can be added to this repository to
show the working workflow and execution results.

## 7. Setup Notes

This repository documents the lab workflow. To recreate it, you will
need appropriately configured Azure and Shuffle environments, plus an
AbuseIPDB API key.

At a high level:

1.  Configure a Windows machine to send Security events to a Log
    Analytics workspace using Azure Monitor Agent.
2.  Enable Microsoft Sentinel on the workspace.
3.  Create an analytics rule for repeated Event ID 4625 events.
4.  Map the Account, IP, and Host entities in the analytics rule.
5.  Create an Azure Logic App with the Microsoft Sentinel incident
    trigger.
6.  Add an HTTP action that sends the incident payload to a Shuffle
    webhook.
7.  Create the Shuffle workflow and configure its actions, branches, API
    integration, and email notification.
8.  Test the complete path using controlled failed-login events.

Exact connector screens and configuration options may change between
product versions.

## 8. Security Considerations

-   **Never commit API keys, passwords, webhook URLs, tokens, or other
    secrets to GitHub.**
-   Store credentials in the relevant platform's secure configuration or
    secret-management facility.
-   The Shuffle webhook used in a learning lab may be accessible to
    anyone who obtains its URL. Do not expose it publicly or use an
    unauthenticated lab webhook for sensitive production incidents.
-   Restrict remote access to lab virtual machines. Do not expose RDP to
    the entire internet.
-   Use a controlled test environment and avoid repeated failed logins
    against accounts that could be locked out.
-   Review reputation results before taking action. An IP reputation
    score alone is not sufficient evidence to block an address.

## 9. Current Scope and Limitations

This project automates **detection, enrichment, risk classification,
routing, and notification**.

It does **not** currently: - Automatically block source IP addresses. -
Disable or lock user accounts. - Confirm that an IP is malicious solely
from its reputation score. - Replace human analyst investigation and
decision-making.

The investigation status added by Shuffle is workflow data; it does not
automatically change the incident status inside Microsoft Sentinel.

## 10. Possible Future Improvements

-   Make webhook delivery authenticated and validate incoming requests.
-   Handle missing, malformed, private, or unsupported IP addresses
    gracefully.
-   Add error handling and retry logic for API failures and rate limits.
-   Improve email formatting and include reliable incident context.
-   Add automated enrichment from additional threat-intelligence
    sources.
-   Add analyst approval before any containment action.
-   Document test cases, expected results, and screenshots.


------------------------------------------------------------------------

**Disclaimer:** This is an educational SOC automation lab built for
hands-on learning and portfolio demonstration. It is not a
production-ready security response system.
