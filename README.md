# AI-Assisted Cloud Security Posture Management Platform

## AI-Assisted Cloud Security Posture Management Platform for Detecting and Remediating AWS Misconfigurations

An academic and testing-focused **Cloud Security Posture Management (CSPM)** platform designed to detect AWS security misconfigurations, assess their risk, map findings to security/compliance requirements, and provide AI-assisted remediation guidance.

The current MVP focuses exclusively on **Amazon Web Services (AWS)**.

---

## 1. Project Overview

Cloud environments are highly configurable, and incorrect security settings can expose sensitive resources to unauthorized access, data loss, or other security threats.

The purpose of this project is to develop a lightweight CSPM platform that continuously examines AWS resources for common security misconfigurations and presents actionable security findings.

The platform follows this general workflow:

```text
                    AWS Account
                        │
                        ▼
                  AWS API / Boto3
                        │
                        ▼
                  AWS Client Layer
                        │
                        ▼
                    Scanners
          ┌─────────────┼─────────────┐
          │             │             │
         IAM           S3        Security Groups
          │             │             │
          ├────────── CloudTrail ─────┤
          │             │             │
          ├──────────── RDS ──────────┤
          │             │             │
          └──────────── EBS ──────────┘
                        │
                        ▼
                     Findings
                        │
                        ▼
                 Risk Scoring Engine
                        │
                        ▼
                 Compliance Mapping
                        │
                        ▼
              AI Remediation Assistant
                        │
                        ▼
                     Dashboard
```

The scanner layer is responsible for detecting misconfigurations. Later components process those findings to determine risk, compliance impact, and remediation guidance.

---

# 2. Project Objectives

The main objectives of the project are:

1. Detect common AWS security misconfigurations.
2. Scan multiple AWS services through a unified architecture.
3. Generate structured security findings.
4. Assign preliminary severity levels to detected issues.
5. Develop a custom risk scoring engine.
6. Map security findings to relevant compliance/security controls.
7. Provide AI-assisted explanations and remediation instructions.
8. Present security findings through a simple web-based dashboard.
9. Provide an academic/testing environment for evaluating AWS security posture.
10. Maintain a modular architecture that can be extended with additional AWS services.

---

# 3. Current AWS Scope

The current implementation focuses on AWS.

### AWS services currently covered

| Service             | Scanner            | Status        |
| ------------------- | ------------------ | ------------- |
| IAM                 | IAM Scanner        | ✅ Implemented |
| S3                  | S3 Scanner         | ✅ Implemented |
| EC2 Security Groups | EC2 Scanner        | ✅ Implemented |
| CloudTrail          | CloudTrail Scanner | ✅ Implemented |
| RDS                 | RDS Scanner        | ✅ Implemented |
| EBS                 | EBS Scanner        | ✅ Implemented |

Azure is **not part of the current MVP**.

Potential multi-cloud support can be considered as future work.

---

# 4. Security Checks

## 4.1 IAM Scanner

The IAM scanner checks account and user-level security configurations.

### Current checks

* MFA enabled for IAM users
* Minimum password length
* Uppercase characters required
* Lowercase characters required
* Numbers required
* Symbols required
* Password reuse prevention
* Password expiration

The scanner generates a `Finding` whenever an insecure configuration is detected.

---

## 4.2 S3 Scanner

The S3 scanner evaluates bucket security configurations.

### Current checks

* S3 Public Access Block
* Server-side encryption
* Bucket versioning
* Server access logging

Example findings include:

```text
S3 PUBLIC ACCESS BLOCK
S3 ENCRYPTION
S3 VERSIONING
S3 ACCESS LOGGING
```

---

## 4.3 EC2 / Security Group Scanner

The EC2 scanner currently focuses on security-group exposure.

### Current checks

* SSH open to the world
* RDP open to the world
* All ports open to the world
* Dangerous ports open to the world
* SSH open to the world over IPv6

Dangerous ports currently checked include:

```text
21     FTP
23     Telnet
3306   MySQL
5432   PostgreSQL
6379   Redis
27017  MongoDB
```

The scanner detects rules exposing these ports through:

```text
0.0.0.0/0
```

and SSH exposure through:

```text
::/0
```

for IPv6.

---

# 4.4 CloudTrail Scanner

The CloudTrail scanner evaluates logging and auditing configurations.

### Current checks

1. CloudTrail logging enabled
2. Multi-region trail
3. Log file validation
4. S3 log destination
5. CloudWatch Logs integration
6. Management events enabled

The scanner uses the appropriate CloudTrail APIs, including:

```text
describe_trails()
get_trail_status()
get_event_selectors()
```

Management events are checked through CloudTrail event selectors.

---

# 4.5 RDS Scanner

The RDS scanner evaluates database security and availability configurations.

### Current checks

* Public accessibility
* Storage encryption
* Deletion protection
* Backup retention
* Multi-AZ deployment

Examples:

```text
RDS PUBLIC ACCESS
RDS ENCRYPTION
RDS DELETION PROTECTION
RDS BACKUP RETENTION
RDS MULTI-AZ DEPLOYMENT
```

The scanner retrieves database instances through:

```text
describe_db_instances()
```

---

# 4.6 EBS Scanner

The EBS scanner evaluates storage protection and lifecycle configurations.

### Current checks

* EBS volume encryption
* Volume attachment status
* Delete-on-termination configuration

The scanner uses the EC2 API because EBS volumes are managed through EC2 APIs.

The relevant API is:

```text
describe_volumes()
```

The EBS scanner does **not** assume that a particular volume type, such as `gp3`, is inherently more secure than every other type. Volume type selection depends on workload and infrastructure requirements.

---

# 5. Architecture

The project follows a modular scanner-based architecture.

```text
                         ┌─────────────────┐
                         │    AWS Account  │
                         └────────┬────────┘
                                  │
                                  ▼
                         ┌─────────────────┐
                         │    AWSClient    │
                         │     Boto3       │
                         └────────┬────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
        ┌──────────┐        ┌──────────┐       ┌──────────┐
        │   IAM    │        │    S3    │       │   EC2    │
        │ Scanner  │        │ Scanner  │       │ Scanner  │
        └────┬─────┘        └────┬─────┘       └────┬─────┘
             │                   │                  │
             └───────────────────┼──────────────────┘
                                 │
                    ┌────────────┼────────────┐
                    │            │            │
                    ▼            ▼            ▼
              ┌──────────┐ ┌──────────┐ ┌──────────┐
              │CloudTrail│ │   RDS    │ │   EBS    │
              │ Scanner  │ │ Scanner  │ │ Scanner  │
              └────┬─────┘ └────┬─────┘ └────┬─────┘
                   │             │            │
                   └─────────────┼────────────┘
                                 ▼
                         ┌─────────────────┐
                         │    Findings     │
                         └────────┬────────┘
                                  │
                                  ▼
                         ┌─────────────────┐
                         │  Risk Scoring   │
                         └────────┬────────┘
                                  │
                                  ▼
                         ┌─────────────────┐
                         │    Compliance   │
                         │     Mapping     │
                         └────────┬────────┘
                                  │
                                  ▼
                         ┌─────────────────┐
                         │ AI Remediation  │
                         │    Assistant    │
                         └────────┬────────┘
                                  │
                                  ▼
                         ┌─────────────────┐
                         │    Dashboard    │
                         └─────────────────┘
```

---

# 6. AWS Client Layer

The project uses a centralized AWS client layer.

The client provides service-specific Boto3 clients to the scanners.

Conceptually:

```text
AWSClient
│
├── IAM
├── S3
├── EC2
├── CloudTrail
└── RDS
```

EBS uses the EC2 client because EBS resources are accessed through the EC2 API.

This design provides **dependency injection** to scanners.

For example:

```text
AWSClient
     │
     ▼
IAMScanner(AWSClient)
```

This approach also makes testing easier because fake AWS clients can be supplied instead of making real AWS API calls.

---

# 7. Finding Model

All scanners produce standardized `Finding` objects.

A finding contains information such as:

```text
Resource Type
Resource Name
Check
Severity
Recommendation
```

Example:

```text
Resource Type:
S3 Bucket

Resource Name:
example-bucket

Check:
S3 ENCRYPTION

Severity:
High

Recommendation:
Enable encryption for the S3 bucket to enhance security.
```

Standardizing scanner output allows all findings to be processed by the same downstream components.

---

# 8. Risk Scoring Engine

The scanner severity values are currently preliminary.

The planned risk scoring engine will provide a more detailed and consistent assessment.

The proposed risk model considers factors such as:

```text
Severity
Exposure
Asset Sensitivity
Exploitability
```

Conceptually:

```text
Finding
   │
   ├── Severity
   ├── Exposure
   ├── Asset Sensitivity
   └── Exploitability
            │
            ▼
      Risk Score
            │
            ▼
       Risk Level
```

The purpose is to avoid treating every `High` finding as equally dangerous.

For example, a publicly exposed sensitive database may receive a different risk score from an internal configuration issue with limited exposure.

---

# 9. Compliance Mapping

A planned component of the platform is compliance mapping.

Detected findings will be mapped to relevant security/compliance controls.

The general flow will be:

```text
AWS Finding
     ↓
Security Check
     ↓
Compliance Control
     ↓
Compliance Status
```

This will help users understand not only that a configuration is insecure, but also which security requirement or control it affects.

---

# 10. AI-Assisted Remediation

One of the main project features is the planned AI-assisted remediation component.

Instead of simply displaying:

```text
S3 encryption disabled
```

the platform will provide understandable remediation guidance.

The intended workflow is:

```text
Finding
   ↓
AI Remediation Assistant
   ↓
Explain the issue
   ↓
Explain the security impact
   ↓
Provide remediation steps
   ↓
Provide AWS-specific guidance
```

For example:

```text
Finding:
S3 bucket encryption is disabled.

AI Explanation:
The bucket does not have server-side encryption configured.

Recommended Action:
1. Open the S3 service.
2. Select the affected bucket.
3. Open Properties.
4. Navigate to Default Encryption.
5. Enable server-side encryption.
6. Save the configuration.
```

The AI component is intended to **assist users with understanding and remediation**, rather than blindly applying potentially destructive changes.

---

# 11. Web Dashboard

A simple web-based dashboard is planned as the primary user interface.

The dashboard will eventually display:

* Total findings
* Findings by severity
* Findings by AWS service
* Risk scores
* Affected resources
* Security recommendations
* Compliance mappings
* AI remediation guidance

A possible dashboard structure:

```text
┌───────────────────────────────────────────┐
│              AWS CSPM Dashboard            │
├────────────┬────────────┬─────────────────┤
│ Findings   │ High Risk  │ AWS Resources   │
│    42      │     12     │      86         │
├────────────┴────────────┴─────────────────┤
│                                           │
│             Risk Overview                 │
│                                           │
├───────────────────────────────────────────┤
│ Service      Findings      Risk            │
│ IAM              8         High            │
│ S3              12         High            │
│ EC2              9         Medium          │
│ RDS               7         High            │
│ CloudTrail        4         Medium         │
│ EBS               2         Medium         │
└───────────────────────────────────────────┘
```

---

# 12. Testing Strategy

The project uses unit testing with fake AWS clients.

The scanners are designed so that AWS API calls can be replaced with fake implementations during testing.

Example:

```text
Real AWS:

Scanner
   ↓
AWSClient
   ↓
Boto3
   ↓
AWS


Testing:

Scanner
   ↓
FakeAWSClient
   ↓
Fake Service
   ↓
Fake AWS Response
```

This prevents tests from depending on live AWS resources.

---

# 13. Fake AWS Clients

Each scanner can use fake service responses.

For example, an EBS test can provide:

```text
vol-secure
    Encrypted = True

vol-insecure
    Encrypted = False
```

The scanner can then be tested without making an actual AWS API request.

This approach provides:

* Faster tests
* Repeatable tests
* No AWS resource modification
* No unnecessary AWS charges
* Predictable test data
* Easier debugging

---

# 14. Testing the Scanner Workflow

Testing occurs at multiple levels.

### Individual check tests

Each security check is tested independently.

Example:

```text
check_encryption()
check_public_access()
check_backup_retention()
```

### Scanner-level tests

The complete `scan()` method is tested.

Example:

```text
AWS resources
     ↓
list resources
     ↓
run all checks
     ↓
generate findings
     ↓
return findings
```

This verifies that individual checks are correctly integrated into the scanner.

---

# 15. Current Test Coverage

The project currently contains tests for the implemented scanners.

Current scanner testing includes:

```text
IAM
├── Individual security checks
└── Scanner scan()

S3
├── Individual security checks
└── Scanner scan()

EC2 / Security Groups
├── Individual security checks
└── Scanner scan()

CloudTrail
├── Individual security checks
└── Scanner scan()

RDS
├── Individual security checks
└── Scanner scan()

EBS
├── Individual security checks
└── Scanner scan()
```

Tests use fake AWS responses rather than requiring live cloud resources.

---

# 16. Technology Stack

## Backend

* Python
* Boto3
* Pytest

## AWS

* AWS IAM
* Amazon S3
* Amazon EC2
* AWS CloudTrail
* Amazon RDS
* Amazon EBS

## Planned Application Layer

* Web-based dashboard
* Risk scoring engine
* Compliance mapping
* AI-assisted remediation

## Development Tools

* Visual Studio Code
* Git
* GitHub
* AWS CLI
* Python virtual environment

---

# 17. Project Structure

The backend follows a modular structure similar to:

```text
FYP/
│
├── backend/
│   │
│   ├── app/
│   │   ├── api/
│   │   │
│   │   ├── clients/
│   │   │   └── aws_client.py
│   │   │
│   │   ├── core/
│   │   │
│   │   ├── database/
│   │   │
│   │   ├── models/
│   │   │   └── finding.py
│   │   │
│   │   ├── scanners/
│   │   │   ├── iam_scanner.py
│   │   │   ├── s3_scanner.py
│   │   │   ├── ec2_scanner.py
│   │   │   ├── cloudtrail_scanner.py
│   │   │   ├── rds_scanner.py
│   │   │   └── ebs_scanner.py
│   │   │
│   │   ├── schemas/
│   │   │
│   │   ├── services/
│   │   │
│   │   ├── utils/
│   │   │
│   │   ├── __init__.py
│   │   └── main.py
│   │
│   ├── tests/
│   │   ├── test_iam_scanner.py
│   │   ├── test_s3_scanner.py
│   │   ├── test_ec2_scanner.py
│   │   ├── test_cloudtrail_scanner.py
│   │   ├── test_rds_scanner.py
│   │   └── test_ebs_scanner.py
│   │
│   ├── requirements.txt
│   └── .env
│
└── README.md
```

Additional files and directories may be added as the project develops.

---

# 18. Prerequisites

Before running the project, install:

* Python 3.x
* AWS CLI
* Git
* Visual Studio Code or another Python IDE
* An AWS account

Verify Python:

```bash
python --version
```

Verify AWS CLI:

```bash
aws --version
```

Verify AWS identity:

```bash
aws sts get-caller-identity
```

---

# 19. Setup

## 19.1 Clone the Repository

```bash
git clone https://github.com/Moizu1/AI-Assisted-AWS-CSPM.git
```

Move into the project:

```bash
cd AI-Assisted-AWS-CSPM
```

Then enter the backend:

```bash
cd backend
```

---

# 20. Create a Virtual Environment

Windows PowerShell:

```powershell
py -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

You should see something similar to:

```text
(.venv)
```

in the terminal.

---

# 21. Install Dependencies

Install the project dependencies:

```powershell
pip install -r requirements.txt
```

The project currently relies on packages such as:

```text
boto3
pytest
```

Additional dependencies will be added as the web dashboard, database, AI integration, and other components are implemented.

---

# 22. AWS Configuration

Configure the AWS CLI:

```powershell
aws configure
```

Provide the required AWS credentials and default region.

Verify the configuration:

```powershell
aws sts get-caller-identity
```

The AWS identity should be displayed if the credentials are valid.

---

# 23. Running Tests

Make sure the virtual environment is active.

From the `backend` directory:

```powershell
python -m pytest
```

To run a specific scanner:

```powershell
python -m pytest tests/test_rds_scanner.py
```

For EBS:

```powershell
python -m pytest tests/test_ebs_scanner.py
```

A successful test run should report that all tests have passed.

---

# 24. Development Workflow

The project follows an incremental development workflow.

For each AWS service:

```text
1. Add AWS client/API
        ↓
2. Create scanner
        ↓
3. Implement individual security check
        ↓
4. Write unit test
        ↓
5. Implement scanner scan()
        ↓
6. Create fake AWS data
        ↓
7. Test complete scanner
        ↓
8. Integrate into application
```

This makes the project easier to debug and allows each component to be validated independently.

---

# 25. Security Considerations

AWS credentials should never be hardcoded into source code.

Do not commit:

```text
AWS Access Key
AWS Secret Access Key
Passwords
API keys
Tokens
Private credentials
```

Sensitive configuration should be handled using appropriate AWS credential mechanisms or environment configuration.

The `.gitignore` file should prevent sensitive files such as `.env` from being committed when appropriate.

---

# 26. Design Principles

The project follows several software engineering principles.

### Modularity

Each AWS service has its own scanner.

```text
IAMScanner
S3Scanner
EC2Scanner
CloudTrailScanner
RDSScanner
EBSScanner
```

### Separation of Concerns

AWS communication is separated from security-check logic.

```text
AWSClient
    ↓
Scanner
    ↓
Finding
```

### Dependency Injection

Scanners receive an AWS client instead of creating their own clients internally.

This makes them easier to test.

### Reusability

All scanners produce standardized `Finding` objects.

### Testability

Fake AWS clients allow security checks to be tested without requiring live AWS infrastructure.

---

# 27. Planned Development Roadmap

The remaining development is planned in the following stages.

## Phase 1 — AWS Scanner Layer

* [x] IAM scanner
* [x] S3 scanner
* [x] EC2/Security Group scanner
* [x] CloudTrail scanner
* [x] RDS scanner
* [x] EBS scanner

## Phase 2 — Finding Processing

* [ ] Improve Finding model
* [ ] Risk scoring engine
* [ ] Risk levels
* [ ] Exposure calculation
* [ ] Asset sensitivity
* [ ] Exploitability assessment

## Phase 3 — Compliance

* [ ] Compliance control model
* [ ] Finding-to-control mapping
* [ ] Compliance status
* [ ] Compliance reporting

## Phase 4 — AI Remediation

* [ ] AI remediation service
* [ ] Finding explanation
* [ ] Security impact explanation
* [ ] Step-by-step remediation
* [ ] AWS-specific remediation guidance

## Phase 5 — Dashboard

* [ ] Backend API
* [ ] Dashboard UI
* [ ] Finding overview
* [ ] Severity visualization
* [ ] Risk visualization
* [ ] Resource details
* [ ] Remediation interface

## Phase 6 — Integration & Testing

* [ ] End-to-end testing
* [ ] AWS lab testing
* [ ] Error handling
* [ ] Performance testing
* [ ] Security testing
* [ ] Final documentation

---

# 28. Future Work

Potential future enhancements include:

* Additional AWS services
* AWS Config integration
* Automated remediation workflows
* Scheduled scans
* Historical security posture tracking
* Security posture trends
* Additional compliance frameworks
* Notification systems
* Role-based dashboard access
* Multi-account AWS scanning
* AWS Organizations support
* Multi-cloud support

Azure support is considered **future work** and is not part of the current AWS MVP.

---

# 29. Project Differentiation

The project is designed not only to identify misconfigurations but also to help users understand and remediate them.

The planned platform combines:

```text
AWS Configuration Scanning
          +
Custom Risk Scoring
          +
Compliance Mapping
          +
AI-Assisted Remediation
          +
Web Dashboard
```

This provides a complete workflow from **detection to understanding and remediation guidance**.

---

# 30. Example End-to-End Finding

A simplified example of the intended final workflow:

```text
AWS S3 Bucket
      │
      ▼
S3 Scanner
      │
      ▼
Encryption Disabled
      │
      ▼
Finding
      │
      ▼
Risk Scoring
      │
      ├── Severity
      ├── Exposure
      ├── Asset Sensitivity
      └── Exploitability
      │
      ▼
Risk Score
      │
      ▼
Compliance Mapping
      │
      ▼
AI Remediation
      │
      ▼
Dashboard
```

The user ultimately receives a finding containing:

```text
Resource:
S3 Bucket

Issue:
Encryption Disabled

Risk:
Calculated by the risk engine

Compliance:
Relevant security control

Impact:
Explanation of the potential security consequence

Remediation:
Step-by-step AWS remediation guidance
```

---

# 31. Academic Context

This project is being developed as a **Final Year Project (FYP)** in Software Engineering.

The project combines concepts from:

* Cloud Computing
* AWS
* Cybersecurity
* Cloud Security
* Software Engineering
* Python
* API Integration
* Automated Security Testing
* Risk Assessment
* Compliance
* Artificial Intelligence

The implementation emphasizes modularity, testability, and practical AWS security assessment.

---

# 32. Author

**Abdul Moiz**

Software Engineering
2022–2027

Islamabad, Pakistan

GitHub:

https://github.com/Moizu1

---

# 33. License

This project is developed for academic and educational purposes.

A formal open-source license can be added if the project is later released for public distribution.

---

# 34. Disclaimer

This project is intended for authorized security assessment, academic research, and controlled AWS testing environments.

Only scan AWS accounts and resources for which you have appropriate authorization.

The project should not be used to access, modify, or assess AWS resources without permission.

---

## Project Status

**Current status:** Active development

### Implemented

```text
✅ AWS Client
✅ IAM Scanner
✅ S3 Scanner
✅ EC2/Security Group Scanner
✅ CloudTrail Scanner
✅ RDS Scanner
✅ EBS Scanner
✅ Individual scanner tests
✅ Scanner-level tests
```

### In Development

```text
🔄 Risk Scoring Engine
🔄 Compliance Mapping
🔄 AI Remediation Assistant
🔄 Web Dashboard
```

The project is being developed incrementally, with each scanner and security check tested independently before integration.
