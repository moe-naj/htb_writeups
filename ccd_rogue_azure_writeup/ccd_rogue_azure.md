# Rogue Azure Lab

![image.png](image.png)

# Context

**Lab link**: [https://cyberdefenders.org/blueteam-ctf-challenges/rogue-azure/](https://cyberdefenders.org/blueteam-ctf-challenges/rogue-azure/)

**Suggested tools**: Microsoft Sentinel, Azure Monitor, KQL Query Editor, Azure AD Sign-in Logs

**Tactics**: Initial Access, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration

# Scenario

On November 14, 2025, security monitoring detected suspicious authentication activity in the Azure tenant, with anomalous sign-in patterns from multiple geographic locations. Shortly after, automated alerts flagged unauthorized administrative actions and configuration changes within the environment.

You have been provided with Azure sign-in logs, audit logs, and storage access logs from the affected tenant. Your mission is to investigate the incident, determine how the attacker gained initial access, identify what persistence mechanisms were established, document any privilege changes, and confirm whether sensitive data was accessed or exfiltrated.

# Initial Access

Q1- The investigation begins by analyzing a password spray attack that targeted several users in the primary tenant. What IP address did the attacker originate the password spray attack from?

**Answer**: 52.59.240.166

**Explanation**: Sorting the Azure sign-in logs highlights repeated failed authentication attempts originating from a single external IP address.

```sql
InteractiveSignIns_CL
| order by IPAddress
```

![image.png](image%201.png)

Q2- After numerous failed attempts, the attacker successfully gained access to an account. What is the username of the first account that was compromised?

**Answer**: `mharmon@compliantsecure.store`

**Explanation**: Filtering for successful sign-ins from the spray source IP surfaces the first confirmed compromise (UTC 2026-04-20 00:46).

```sql
InteractiveSignIns_CL
| where IPAddress == '52.59.240.166' and Status contains "Success"
```

![image.png](image%202.png)

# Command and Control

Q3- Following the initial compromise, the attacker began using a new infrastructure for post-exploitation activities. What is the second IP address used by the attacker?

**Answer**: 52.221.180.165

**Explanation**: Excluding the initial spray IP reveals subsequent successful sign-ins from new infrastructure. The `UserAgent` values help distinguish the attacker’s activity (e.g., Python-based clients vs. standard browsers). While 18.192.125.237 appears in the dataset, it shows mixed user agents and is not uniquely attributable, whereas 52.221.180.165 is more consistent with the attacker’s post-compromise activity.

```sql
InteractiveSignIns_CL
| where Username contains "mharmon@compliantsecure.store" and IPAddress !contains "52.59.240.166" and Status contains "Success"
```

![image.png](image%203.png)

Q4- From which country did the successful sign-in originate when the attacker pivoted to their secondary infrastructure for post-exploitation activities?

**Answer**: Singapore

**Explanation**: This is derived from the `Location` field returned by the previous query for the secondary infrastructure sign-in.

# Persistence

Q5- To establish persistence, the attacker registered malicious applications. What is the name of the first application they created?

**Answer**: `OfficeRead`

**Explanation**: Filtering Azure audit logs for application-creation events identifies the first app registration performed by the attacker.

```sql
AuditLogs_CL
| where IPAddress contains "52.221.180.165" and Activity contains "Create application"
```

![image.png](image%204.png)

Q6- The attacker created a second application to ensure persistent access, this one intended to access directory information. What is the name of this second application?

**Answer**: `VaultApp`

**Explanation**: The second event returned by the prior KQL query shows the additional app registration: `VaultApp`.

![image.png](image%205.png)

# Privilege Escalation

Q7- To create a redundant backdoor, the attacker used the compromised administrator account to elevate the privileges of another user. What is the User Principal Name of the account that had its privileges escalated?

**Answer**: `lwilliams@compliantsecure.store`

**Explanation**: Filtering audit events for role membership changes shows the attacker adding this account to the Global Administrator role.

```sql
AuditLogs_CL
| where IPAddress contains "52.221.180.165" and Activity contains "Add member"
```

![image.png](image%206.png)

Q8- What highly privileged role was assigned to the second user account to grant it administrative control over the tenant?

**Answer**: Global Administrator

**Explanation**: The assigned role is confirmed in the `NewRule` field from the previous query output.

# Collection and Exfiltration

Q9- The attacker's final objective was data exfiltration. They targeted a specific storage resource to access sensitive files. What is the name of the storage account they accessed?

**Answer**: `mainstoragestore01`

**Explanation**: Filtering Storage Blob logs to the secondary IP and projecting `AccountName` reveals the targeted storage account, which appears multiple times in the activity.

```sql
StorageBlobLogs_CL
| where CallerIpAddress contains "52.221.180.165"
| project AccountName
```

![image.png](image%207.png)

Q10- The attacker successfully downloaded a sensitive file from the storage account. What is the name of the exfiltrated file?

**Answer**: `Confidintal.png`

**Explanation**: The `GetBlob` operation records the object retrieved from storage. Filtering these events to the same secondary IP reveals the specific filename downloaded (misspelled, and likely exfiltrated): `Confidintal.png`.

```sql
StorageBlobLogs_CL
| where CallerIpAddress contains "52.221.180.165" and OperationName contains "GetBlob"
```

![image.png](image%208.png)