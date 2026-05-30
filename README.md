
# Cloud Security CI/CD & DevSecOps Sandbox

Welcome to the **Cloud Security CI/CD & DevSecOps Sandbox**! This interactive project is designed to demonstrate modern DevSecOps practices, pipeline security gates, and AWS secure deployment patterns. 

It provides a hands-on learning environment where you can deliberately inject security vulnerabilities, observe pipeline failures, apply remediation patches, and see how security compliance is enforced before code is deployed.

---

## Project Architecture Overview

The sandbox comprises a Flask web application, a local pipeline simulator, IaC configurations, and an interactive CLI management dashboard.

```
cloud-security-cicd/
├── .github/workflows/    # Real GitHub Actions DevSecOps workflow
├── app/                  # Flask Web Application & Unit Tests
│   ├── app.py            # Main application (with security headers & vuln hooks)
│   ├── requirements.txt  # Python package dependencies
│   ├── templates/        # HTML Login page
│   └── tests/            # Pytest suite
├── scripts/              # Pipeline Simulation & Verification Scripts
│   ├── simulate_pipeline.py  # Local CI/CD pipeline simulator
│   └── verify_devsecops.py   # Automated gate verifier
├── terraform/            # AWS Infrastructure as Code (IaC)
│   ├── main.tf           # EC2 instance and Security Group rules
│   ├── iam.tf            # IAM OIDC Role configuration (least-privilege)
│   └── outputs.tf / variables.tf
└── devops-dashboard.py   # CLI TUI control center (Inject / Fix / Monitor)
```

---

## DevSecOps Pipeline Security Gates

The CI/CD pipeline (both local simulator and GitHub Actions) enforces five key security gates:

| Gate | Scanner | Vulnerability Type / Objective |
| :--- | :--- | :--- |
| **1. Unit Tests** | `pytest` | Standard functional validation and build regression testing. |
| **2. SAST** | `Bandit` | **Static Application Security Testing** scanning code for injection vulnerabilities. |
| **3. SCA** | `pip-audit` | **Software Composition Analysis** checking Python dependencies for known CVEs. |
| **4. Secrets Scan** | Regular Expressions / `Gitleaks` | Checking commits and files for hardcoded API keys and credentials. |
| **5. IaC Scan** | Custom Parser / `Trivy` | Scanning Terraform files for cloud misconfigurations (e.g. open SSH port 22). |

---

## Getting Started

### Prerequisites

- Python 3.12+
- Git

### Installation & Execution

1. Clone or navigate to the project directory:
   ```bash
   cd cloud-security-cicd
   ```

2. Run the interactive CLI Control Center:
   ```bash
   python devops-dashboard.py
   ```
   *Note: On your first run, selecting the Pipeline Simulator (Option 1) will automatically set up a local virtual environment (`.venv_pipeline/`) and install all required scanning tools.*

---

## Step-by-Step Walkthrough

Follow this workflow in the dashboard to see the DevSecOps lifecycle in action:

### 1. Run Clean Pipeline
Select **Option 1** (`Run DevSecOps Pipeline Simulator`) in the dashboard.
- The simulator starts.
- It runs pytest, Bandit, pip-audit, secret detection, and IaC scanning.
- Under a clean state, **all gates pass**, and the simulator executes a secure AWS deployment!

### 2. Inject Security Vulnerabilities
Select **Option 2** (`Inject Security Vulnerabilities`) in the dashboard. You can inject specific vulnerabilities or all of them at once:
- **OS Command Injection:** Injects vulnerable code execution in the `/diagnostics` endpoint (`app.py`).
- **SQL Injection:** Injects vulnerable string concatenation in the `/login` endpoint (`app.py`).
- **Hardcoded Secrets:** Injects a mock active AWS Secret Key inside the source code (`app.py`).
- **Vulnerable Libraries (SCA):** Downgrades `requests` to an older version containing CVEs (`requirements.txt`).
- **Insecure Security Group (IaC):** Opens ingress TCP Port 22 (SSH) to the public internet `0.0.0.0/0` (`main.tf`).

### 3. Run Pipeline with Vulnerabilities
Return to the main menu and select **Option 1** to run the pipeline again.
- The pipeline will fail on the respective scanning stage (SAST, SCA, Secrets, or IaC).
- **Deployment is blocked!** Vulnerable code is stopped before it can reach production.

### 4. Remediate & Fix Code
Select **Option 3** (`Apply Security Remediation Patches`) in the dashboard.
- The dashboard automatically replaces the vulnerable snippets with secure, compliant equivalents.
- For example, string interpolation is replaced with SQL parameterized queries, and public SSH access is removed in favor of AWS Systems Manager (SSM) agent access.

### 5. Verify Build Passes
Select **Option 1** again.
- The pipeline is green.
- Secure deployment completes successfully.

---

## Secure AWS Cloud Blueprint Highlights

Selecting **Option 4** in the dashboard renders the secure AWS deployment blueprint:

1. **OIDC Identity Trust:** The GitHub Actions workflow connects to AWS via OpenID Connect (OIDC). This eliminates the need to save long-lived, static credentials in GitHub Secrets.
2. **Zero SSH Exposed:** In `terraform/main.tf`, inbound TCP Port 22 (SSH) is completely blocked. System administration and deployments are instead tunneled securely through the **AWS Systems Manager (SSM) Run Command** client over HTTPS.
3. **Encrypted Storage:** The root EBS volume on the EC2 host is explicitly encrypted at rest using AWS KMS default keys.
4. **Least-Privilege Roles:** The runner assumes a role restricted to triggering specific SSM documents on a single designated instance ID.
