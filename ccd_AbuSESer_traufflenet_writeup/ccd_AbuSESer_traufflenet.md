# AbuSESer - Trufflenet Lab

CCD Lab link: [https://cyberdefenders.org/blueteam-ctf-challenges/abuseser-trufflenet/](https://cyberdefenders.org/blueteam-ctf-challenges/abuseser-trufflenet/)

![image.png](image.png)

# Scenario

On January 23, 2026, Maromalix's finance department received an alarming call from TechCorp Industries, a long-standing client. TechCorp's accounts payable team reported they had processed a wire transfer to what they believed was Maromalix's bank account after receiving an invoice for services rendered. However, Maromalix had not issued any such invoice to TechCorp.

During the week prior to the incident, Maromalix onboarded a new cloud administrator. During this transition period, several IAM permission adjustments were made as users reported access issues with various services. Some of these changes may have resulted in overly permissive policies—activity related to these legitimate administrative actions may appear in the logs.

As a cloud security analyst, you have been engaged to investigate this potential Business Email Compromise (BEC) attack. Your primary investigation tool will be AWS CloudWatch Logs Insights—use it to query CloudTrail and Lambda execution logs, reconstruct the attack timeline, and identify indicators of compromise.

# **Reconnaissance**

Q1 - During the initial threat hunting phase, analysis of CloudTrail logs revealed API calls from multiple source IP addresses. One IP address stood out as highly suspicious due to its association with multiple identities and offensive security tooling. What is this attacker's IP address?

**Answer: 52.59.194.168**

- The first query filters out **RFC1918 private ranges** and **loopback** traffic (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8), then ranks the remaining **public source IPs** by request volume and shows the most recent `userAgent` seen for each IP.
- The second query searches for the specific IP `52.59.194.168` in CloudTrail events and counts results by `userIdentity.type`, confirming the same source IP is being used across multiple identity types (a strong indicator of malicious automation).
- **Note:** In Logs Insights, `@message` is the **raw log event payload** (often the full CloudTrail JSON) exactly as it was ingested.
    
    ```sql
    filter ispresent(sourceIPAddress) and sourceIPAddress not like /^10\./ and sourceIPAddress not like /^172\.(1[6-9]|2[0-9]|3[0-1])\./ and sourceIPAddress not like /^192\.168\./ and sourceIPAddress not like /^127\./ 
    | stats count(*) as requestCount, latest(userAgent) as latestUserAgent by sourceIPAddress 
    | sort requestCount desc
    ```
    
    ```sql
    filter @message like "52.59.194.168" 
    | fields @timestamp, @message, @logStream, @log
    | stats count(*) by userIdentity.type
    ```
    

![**Suspicious user agents, coupled with multiple identity types below from the same external address**](image%201.png)

**Suspicious user agents, coupled with multiple identity types below from the same external address**

![image.png](image%202.png)

Q2- The attacker's first action was to probe for publicly accessible resources. What is the full name of the S3 bucket they discovered?

**Answer: maromalix-website-assets-prod-83c9fdc8**

- This query narrows CloudTrail to events that contain **both** the attacker IP `52.59.194.168` and the keyword **bucket** (case-insensitive), which is a quick way to isolate **S3 bucket enumeration/access** from that source.
- In the matching CloudTrail JSON, the bucket name is typically in **`requestParameters.bucketName`** (and sometimes also in `resources[].ARN`, e.g., `arn:aws:s3:::<bucket-name>`).

```sql
filter @message like "52.59.194.168" and @message like /bucket/i
```

![**List bucket reveals the existing bucket and its name**](image%203.png)

**List bucket reveals the existing bucket and its name**

# **Initial Access**

Q3- The attacker used a tool designed to scan repositories and file systems for exposed secrets, then automatically validate any discovered credentials. What is the name of this tool?

**Answer: `TruffleHo**g`

- `TruffleHog` appears alongside `GetCallerIdentity` because a common “verification” step after finding AWS keys is to call **STS `GetCallerIdentity`**. It’s a low-noise, read-only API that answers two questions:
    - **Are these credentials valid?** (the call succeeds)
    - **Who do they belong to?** (returns the AWS account and principal ARN/user/role)
- In CloudTrail this looks like `eventSource: sts.amazonaws.com`, `eventName: GetCallerIdentity`, `requestParameters: null` (normal), and a `userAgent` that identifies the tool (here: `TruffleHog`).
    
    ```sql
    fields @timestamp, @message, sourceIPAddress
    | filter sourceIPAddress = "52.59.194.168"
    | filter @message like /[Tt]ruffle/
    | sort @timestamp desc
    | limit 100
    
    # Output
    {
        "eventVersion": "1.11",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAYT723HMDXNF3QCNRN",
            "arn": "arn:aws:iam::592694688519:user/service-accounts/svc-jenkins",
            "accountId": "592694688519",
            "accessKeyId": "AKIAYT723HMDSAE2OSWV",
            "userName": "svc-jenkins"
        },
        "eventTime": "2026-01-23T12:48:55Z",
        "eventSource": "sts.amazonaws.com",
        "eventName": "GetCallerIdentity",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "52.59.194.168",
        "userAgent": "TruffleHog",
        "requestParameters": null,
        "responseElements": null,
        "additionalEventData": {
            "ExtendedRequestId": "MTp1cy1lYXN0LTE6UzoxNzY5MTcyNTM1OTU3OlI6T3NGS2pXZ0M=",
            "RequestDetails": {
                "endpointType": "regional",
                "awsServingRegion": "us-east-1"
            }
        },
        "requestID": "59f5364a-2927-48ee-8826-4d04bd6b4c13",
        "eventID": "9e52356b-c1d7-4723-894f-2ac4535334f2",
        "readOnly": true,
        "eventType": "AwsApiCall",
        "managementEvent": true,
        "recipientAccountId": "592694688519",
        "eventCategory": "Management",
        "tlsDetails": {
            "tlsVersion": "TLSv1.3",
            "cipherSuite": "TLS_AES_128_GCM_SHA256",
            "clientProvidedHostHeader": "sts.us-east-1.amazonaws.com"
        }
    }
    ```
    

Q4- The credentials discovered by the attacker belonged to a service account. What is the name of this initially compromised user?

Answer: `svc-jenkins`

- This is also shown in the same JSON output above (in question #3) under `"userIdentity.userName": "svc-jenkins”`

# **Discovery**

Q5- To systematically enumerate the AWS environment and discover potential privilege escalation paths, the attacker used an open-source cloud exploitation framework. Provide the name and version of this tool as recorded in the logs.

**Answer:`Pacu/1.5.2`**

- In CloudTrail, this stands out when you group/filter by `userAgent` because Pacu makes many rapid **enumeration** calls across services.

```json
filter sourceIPAddress = "52.59.194.168" and userAgent like /[pP]acu/
```

![Pacu present in the `userAgent` field](image%204.png)

Pacu present in the `userAgent` field

# **Privilege Escalation**

Q6- The attacker discovered an overly permissive trust policy and escalated their privileges. What is the name of the first role the attacker successfully assumed?

**Answer: `Maromalix-DevOps-Role`**

- Filter CloudTrail for STS role assumption events (`AssumeRole`) from the attacker IP to identify the first successful escalation.

```json
filter sourceIPAddress = "52.59.194.168" and eventName like /[Aa]ssume/
```

![Assumed role](image%205.png)

Assumed role

Q7- When assuming the new role, the attacker specified a custom session name to identify their session. What was this session name?

**Answer: `DevOpsing_maromalix`**

- This appears in the same fields output in question #6.

![Custom session name = `assumedRoleId`](image%206.png)

Custom session name = `assumedRoleId`

# **Discovery**

Q8- With elevated privileges, the attacker enumerated several AWS services looking for sensitive data. Which AWS service did they successfully query to discover stored credentials and secrets?

**Answer: Secrets Manager**

- CloudTrail shows the attacker querying **AWS Secrets Manager** (e.g., `ListSecrets`, `DescribeSecret`, `GetSecretValue`), indicating they found a central store of credentials/secrets.

![image.png](image%207.png)

# **Credential Access**

Q9- After discovering the secrets inventory, the attacker began exfiltrating credentials. What is the ID of the first secret the attacker retrieved?

**Answer: `maromalix/automation/ssm-credentials`**

- This shows when querying for getting a secret value from AWS Secrets Manager:

```json
filter sourceIPAddress = "52.59.194.168" and eventName like "GetSecretValue"
```

![image.png](image%208.png)

![**Timestamps for `GetSecretValue`**](image%209.png)

**Timestamps for `GetSecretValue`**

Q10- What is the MITRE ATT&CK technique ID that corresponds to this credential exfiltration behavior?

Answer: **T1555.006**

- This aligns with **T1555.006 (Cloud Secrets Management Stores)** because the attacker is retrieving credentials directly from Secrets Manager.

# **Lateral Movement**

Q11- Using credentials obtained from the exfiltrated secrets, the attacker pivoted to a different IAM role. What is the full name of this role?

**Answer: `Maromalix-SSM-Automation-Role`**

- CloudTrail shows the attacker using their current role’s permissions to assume `Maromalix-SSM-Automation-Role`. (From the logs shown here, the assumption itself is clear; whether the `ssm-credentials` secret directly enabled this step isn’t explicitly tied in a single event.)

```sql
fields @timestamp, @message
| filter @message like /Maromalix-SSM-Automation-Role/ and @message like /AssumeRole/
| sort @timestamp desc
| limit 100
```

![**DevOps role used to assume another role (SSM automation role)**](image%2010.png)

**DevOps role used to assume another role (SSM automation role)**

# **Credential Access**

Q12- The attacker used their new role to remotely execute commands on an EC2 instance and steal its IAM credentials via the Instance Metadata Service (IMDS). Provide the API call used to execute commands and the instance ID of the compromised machine, separated by a comma.

**Answer: `SendCommand`, `i-0afb277aeec0e6fa4`**

- This is the AWS Systems Manager (SSM) API call used to remotely execute commands on EC2 instances — which is exactly why the attacker pivoted to `Maromalix-SSM-Automation-Role` in the first place. SSM permissions were the goal.
- The EC2 instance likely has an IAM role with permissions to access other AWS resources — S3 buckets, other EC2s, RDS databases, etc. By stealing those temporary keys the attacker can **act as that EC2's IAM role** from anywhere on the internet without ever touching the OS.
- `SendCommand` is the **API call** that triggers remote execution — the actual shell depends on the **Document** used: #aws-ssm
- AWS intentionally redacts the actual command contents from CloudTrail logs for `SendCommand` because parameters could contain sensitive data like passwords or tokens.

**Common SSM Documents:**

| Document | Shell | Example |
| --- | --- | --- |
| `AWS-RunShellScript` | **Bash/Linux** | `curl`, `wget`, `cat` |
| `AWS-RunPowerShellScript` | **PowerShell/Windows** | `Get-Process`, `Invoke-WebRequest` |
| `AWS-RunCommand` | Generic | varies |

![**`SendCommand` dispatch record**](image%2011.png)

**`SendCommand` dispatch record**

# **Discovery**

Q13- With EC2 instance credentials, the attacker enumerated Lambda functions by downloading their configurations and code. What is the name of the first Lambda function the attacker retrieved?

**Answer: `maromalix-daily-backup`**

- Pulling Lambda configurations/code is a common cloud discovery tactic: attackers often look for **hardcoded secrets**, internal endpoints, or credentials embedded in environment variables or deployment packages.

```sql
filter sourceIPAddress = "52.59.194.168" and eventSource like "lambda.amazonaws.com" and userIdentity.arn like "Maromalix-EC2-WebApp-Role"
```

![**First attacked Lambda function**](image%2012.png)

**First attacked Lambda function**

Q14- After examining multiple functions, the attacker identified one suitable for their attack. What is the name of the Lambda function he used to send fraudulent emails?

**Answer: `maromalix-email-notifications`**

- Filtering for email-related log content within the `maromalix-email-notifications` Lambda execution logs surfaces the function used to send the fraudulent messages.

# **Impact**

Q15- The attacker sent fraudulent emails to two recipients. Provide both email addresses separated by a comma, with the internal recipient first. #aws-lambda

**Answer: billing@maromalix.cloud, billing@techcorp.live**

- Filter for Lambda execution logs using the compromised function above with a suspicious subject line: **`maromalix-email-notifications`**

```sql
fields @timestamp, @message
| filter @log like /maromalix-email-notifications/
| filter @message like /@/ and subject like "Invoice"
| stats count(*) by to
| sort @timestamp asc
| limit 100
```

![**Targeted recipients**](image%2013.png)

**Targeted recipients**

Q16- The fraudulent invoice included attacker-controlled contact email addresses. What are the two domains used for these contact addresses? (Provide both domains separated by a comma, in alphabetical order)

**Answer: cfp-impactaction.com, zoominfopay.com**

- These domains appear in the **email body/contact details** of the fraudulent invoice messages.

![**Attacker controlled domains**](image%2014.png)

**Attacker controlled domains**

Q17- The attacker's ultimate goal was to deceive the victim into transferring funds via a fraudulent invoice. What is the MITRE ATT&CK technique ID that corresponds to this impact?

**Answer: T1657** 

- **T1657 – Financial Theft**: the attacker’s impact objective is to induce an unauthorized funds transfer (classic invoice/BEC-style fraud).

Q18- Based on the tools, TTPs, and infrastructure patterns observed in this investigation, this incident matches a known threat campaign. What is the name of this campaign?

**Answer: Trufflenet**

- Trufflenet is a cloud-focused intrusion pattern where attackers **find exposed AWS credentials** (secret scanning), **validate and enumerate** the environment (automation frameworks), then **abuse AWS services** (Secrets Manager, SSM, Lambda) to pivot and ultimately execute **financial fraud/BEC-style invoice manipulation**.
