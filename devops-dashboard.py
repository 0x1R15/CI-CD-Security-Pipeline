import os
import sys
import subprocess

# Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
APP_FILE = os.path.join(PROJECT_DIR, 'app', 'app.py')
REQ_FILE = os.path.join(PROJECT_DIR, 'app', 'requirements.txt')
TF_FILE = os.path.join(PROJECT_DIR, 'terraform', 'main.tf')
SIMULATOR_FILE = os.path.join(PROJECT_DIR, 'scripts', 'simulate_pipeline.py')

# SECURE BLOCKS (Reference for remediation)
SECURE_SHELL_BLOCK = """    # VULNERABILITY_SAST_SHELL_START
    # Secure implementation: input validation and subprocess without shell
    # Whitelist check for safety
    clean_ip = "".join(c for c in ip if c.isalnum() or c in '.-')
    try:
        # Run command securely without shell execution
        result = subprocess.run(
            ['ping', '-n', '1', clean_ip] if os.name == 'nt' else ['ping', '-c', '1', clean_ip],
            capture_output=True,
            text=True,
            timeout=5
        )
        output = result.stdout + "\\n" + result.stderr
    except subprocess.TimeoutExpired:
        output = "Diagnostic timed out."
    except Exception as e:
        output = f"Diagnostic failed: {str(e)}"
    # VULNERABILITY_SAST_SHELL_END"""

INSECURE_SHELL_BLOCK = """    # VULNERABILITY_SAST_SHELL_START
    # Insecure implementation: direct command execution via OS shell!
    # Vulnerable to command injection (SAST B605/B607)
    try:
        # DANGEROUS: running user input directly in shell
        cmd = f"ping -n 1 {ip}" if os.name == 'nt' else f"ping -c 1 {ip}"
        result = os.popen(cmd).read()
        output = result
    except Exception as e:
        output = f"Execution failed: {str(e)}"
    # VULNERABILITY_SAST_SHELL_END"""

SECURE_SQL_BLOCK = """        # VULNERABILITY_SAST_SQL_START
        # Secure implementation using parameterized query
        cursor.execute("SELECT username, password_hash FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        # VULNERABILITY_SAST_SQL_END"""

INSECURE_SQL_BLOCK = """        # VULNERABILITY_SAST_SQL_START
        # Insecure implementation: direct string interpolation!
        # Vulnerable to SQL injection (SAST B608)
        query = f"SELECT username, password_hash FROM users WHERE username = '{username}'"
        cursor.execute(query)
        user = cursor.fetchone()
        # VULNERABILITY_SAST_SQL_END"""

SECURE_SECRET_BLOCK = """# VULNERABILITY_SECRET_START
AWS_SECRET_KEY = None
# VULNERABILITY_SECRET_END"""

INSECURE_SECRET_BLOCK = """# VULNERABILITY_SECRET_START
# Leaking AWS Access Key and Secret Key in source code! (Secret Scan Leak)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
# VULNERABILITY_SECRET_END"""

SECURE_IAC_BLOCK = """  # VULNERABILITY_IAC_START
  # VULNERABILITY_IAC_END"""

INSECURE_IAC_BLOCK = """  # VULNERABILITY_IAC_START
  # DANGEROUS: Port 22 (SSH) is wide open to the internet!
  # Violates least privilege network configuration
  ingress {
    description = "INSECURE SSH EXPOSED"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # VULNERABILITY_IAC_END"""


def read_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()

def write_file(filepath, content):
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

def check_status():
    """Checks which vulnerabilities are currently injected."""
    app_content = read_file(APP_FILE)
    req_content = read_file(REQ_FILE)
    tf_content = read_file(TF_FILE)
    
    status = {
        "sast_shell": "Vulnerable [FAIL]" if "Insecure implementation: direct command execution" in app_content else "Secure [PASS]",
        "sast_sql": "Vulnerable [FAIL]" if "Insecure implementation: direct string interpolation" in app_content else "Secure [PASS]",
        "secrets": "Vulnerable [FAIL]" if "AKIAIOSFODNN7EXAMPLE" in app_content else "Secure [PASS]",
        "sca": "Vulnerable [FAIL]" if "requests==2.20.0" in req_content else "Secure [PASS]",
        "iac": "Vulnerable [FAIL]" if "INSECURE SSH EXPOSED" in tf_content else "Secure [PASS]"
    }
    return status

def print_header():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""{BOLD}{CYAN}
+------------------------------------------------------------------------+
|              CLOUD SECURITY CI/CD & DEVSECOPS SANDBOX                  |
+------------------------------------------------------------------------+{RESET}""")
    
    status = check_status()
    print(f"{BOLD}Current Security Posture:{RESET}")
    print(f"  * SAST Shell Ingress:  {status['sast_shell']}")
    print(f"  * SAST SQL Injection: {status['sast_sql']}")
    print(f"  * Secret Detection:    {status['secrets']}")
    print(f"  * Dependency SCA:      {status['sca']}")
    print(f"  * Infrastructure IaC:  {status['iac']}")
    print("-" * 74)

def inject_vulnerabilities_menu():
    while True:
        print_header()
        print(f"{BOLD}{YELLOW}Inject Security Vulnerability Menu{RESET}")
        print("  1. Inject SAST Shell Command Injection (app.py)")
        print("  2. Inject SAST SQL Injection (app.py)")
        print("  3. Inject Hardcoded Cloud Credentials (app.py)")
        print("  4. Inject Outdated/Vulnerable Library (requirements.txt)")
        print("  5. Inject Open SSH Port to Internet (main.tf)")
        print("  6. Inject ALL Vulnerabilities at Once")
        print("  7. Back to Main Menu")
        print("-" * 74)
        choice = input("Select an option (1-7): ").strip()
        
        app_content = read_file(APP_FILE)
        req_content = read_file(REQ_FILE)
        tf_content = read_file(TF_FILE)
        
        modified = False
        
        if choice == '1':
            if "Insecure implementation: direct command execution" not in app_content:
                # Find start and end of the shell block
                start_idx = app_content.find("# VULNERABILITY_SAST_SHELL_START")
                end_idx = app_content.find("# VULNERABILITY_SAST_SHELL_END") + len("# VULNERABILITY_SAST_SHELL_END")
                if start_idx != -1 and end_idx != -1:
                    target = app_content[start_idx:end_idx]
                    app_content = app_content.replace(target, INSECURE_SHELL_BLOCK)
                    write_file(APP_FILE, app_content)
                    print(f"\n{GREEN}[OK] Injected: OS Command Injection vulnerability in /diagnostics endpoint!{RESET}")
                    modified = True
            else:
                print(f"\n{YELLOW}Already vulnerable.{RESET}")
        elif choice == '2':
            if "Insecure implementation: direct string interpolation" not in app_content:
                start_idx = app_content.find("# VULNERABILITY_SAST_SQL_START")
                end_idx = app_content.find("# VULNERABILITY_SAST_SQL_END") + len("# VULNERABILITY_SAST_SQL_END")
                if start_idx != -1 and end_idx != -1:
                    target = app_content[start_idx:end_idx]
                    app_content = app_content.replace(target, INSECURE_SQL_BLOCK)
                    write_file(APP_FILE, app_content)
                    print(f"\n{GREEN}[OK] Injected: SQL Injection vulnerability in /login endpoint!{RESET}")
                    modified = True
            else:
                print(f"\n{YELLOW}Already vulnerable.{RESET}")
        elif choice == '3':
            if "AKIAIOSFODNN7EXAMPLE" not in app_content:
                start_idx = app_content.find("# VULNERABILITY_SECRET_START")
                end_idx = app_content.find("# VULNERABILITY_SECRET_END") + len("# VULNERABILITY_SECRET_END")
                if start_idx != -1 and end_idx != -1:
                    target = app_content[start_idx:end_idx]
                    app_content = app_content.replace(target, INSECURE_SECRET_BLOCK)
                    write_file(APP_FILE, app_content)
                    print(f"\n{GREEN}[OK] Injected: AWS Access Keys hardcoded in app.py!{RESET}")
                    modified = True
            else:
                print(f"\n{YELLOW}Already vulnerable.{RESET}")
        elif choice == '4':
            if "requests==2.20.0" not in req_content:
                req_content = req_content.replace("requests==2.33.0", "requests==2.20.0")
                write_file(REQ_FILE, req_content)
                print(f"\n{GREEN}[OK] Injected: Downgraded requests package to 2.20.0 (contains CVE-2018-18074)!{RESET}")
                modified = True
            else:
                print(f"\n{YELLOW}Already vulnerable.{RESET}")
        elif choice == '5':
            if "INSECURE SSH EXPOSED" not in tf_content:
                start_idx = tf_content.find("# VULNERABILITY_IAC_START")
                end_idx = tf_content.find("# VULNERABILITY_IAC_END") + len("# VULNERABILITY_IAC_END")
                if start_idx != -1 and end_idx != -1:
                    target = tf_content[start_idx:end_idx]
                    tf_content = tf_content.replace(target, INSECURE_IAC_BLOCK)
                    write_file(TF_FILE, tf_content)
                    print(f"\n{GREEN}[OK] Injected: Open Port 22 (SSH) to 0.0.0.0/0 in main.tf!{RESET}")
                    modified = True
            else:
                print(f"\n{YELLOW}Already vulnerable.{RESET}")
        elif choice == '6':
            # SAST Shell
            start_idx = app_content.find("# VULNERABILITY_SAST_SHELL_START")
            end_idx = app_content.find("# VULNERABILITY_SAST_SHELL_END") + len("# VULNERABILITY_SAST_SHELL_END")
            if start_idx != -1 and end_idx != -1:
                target = app_content[start_idx:end_idx]
                app_content = app_content.replace(target, INSECURE_SHELL_BLOCK)
            # SAST SQL
            start_idx = app_content.find("# VULNERABILITY_SAST_SQL_START")
            end_idx = app_content.find("# VULNERABILITY_SAST_SQL_END") + len("# VULNERABILITY_SAST_SQL_END")
            if start_idx != -1 and end_idx != -1:
                target = app_content[start_idx:end_idx]
                app_content = app_content.replace(target, INSECURE_SQL_BLOCK)
            # Secrets
            start_idx = app_content.find("# VULNERABILITY_SECRET_START")
            end_idx = app_content.find("# VULNERABILITY_SECRET_END") + len("# VULNERABILITY_SECRET_END")
            if start_idx != -1 and end_idx != -1:
                target = app_content[start_idx:end_idx]
                app_content = app_content.replace(target, INSECURE_SECRET_BLOCK)
                
            write_file(APP_FILE, app_content)
            
            # SCA
            req_content = req_content.replace("requests==2.33.0", "requests==2.20.0")
            write_file(REQ_FILE, req_content)
            
            # IaC
            start_idx = tf_content.find("# VULNERABILITY_IAC_START")
            end_idx = tf_content.find("# VULNERABILITY_IAC_END") + len("# VULNERABILITY_IAC_END")
            if start_idx != -1 and end_idx != -1:
                target = tf_content[start_idx:end_idx]
                tf_content = tf_content.replace(target, INSECURE_IAC_BLOCK)
                write_file(TF_FILE, tf_content)
                
            print(f"\n{GREEN}[OK] Injected: ALL vulnerabilities injected! The pipeline will now fail at multiple gates.{RESET}")
            modified = True
        elif choice == '7':
            break
        else:
            print(f"\n{RED}Invalid selection.{RESET}")
            
        if modified:
            input("\nPress Enter to continue...")

def apply_remediation(interactive=True):
    print_header()
    print(f"{BOLD}{BLUE}Applying Security Remediation patches...{RESET}\n")
    
    app_content = read_file(APP_FILE)
    req_content = read_file(REQ_FILE)
    tf_content = read_file(TF_FILE)
    
    remediated = False
    
    # Remediate SAST Shell
    if "Insecure implementation: direct command execution" in app_content:
        start_idx = app_content.find("# VULNERABILITY_SAST_SHELL_START")
        end_idx = app_content.find("# VULNERABILITY_SAST_SHELL_END") + len("# VULNERABILITY_SAST_SHELL_END")
        if start_idx != -1 and end_idx != -1:
            target = app_content[start_idx:end_idx]
            app_content = app_content.replace(target, SECURE_SHELL_BLOCK)
            print(f"  {GREEN}[OK] Fixed: Replaced shell invocation with secure subprocess array execution.{RESET}")
            remediated = True

    # Remediate SAST SQL
    if "Insecure implementation: direct string interpolation" in app_content:
        start_idx = app_content.find("# VULNERABILITY_SAST_SQL_START")
        end_idx = app_content.find("# VULNERABILITY_SAST_SQL_END") + len("# VULNERABILITY_SAST_SQL_END")
        if start_idx != -1 and end_idx != -1:
            target = app_content[start_idx:end_idx]
            app_content = app_content.replace(target, SECURE_SQL_BLOCK)
            print(f"  {GREEN}[OK] Fixed: Standardized query using SQL parameterized markers.{RESET}")
            remediated = True

    # Remediate Secrets
    if "AKIAIOSFODNN7EXAMPLE" in app_content:
        start_idx = app_content.find("# VULNERABILITY_SECRET_START")
        end_idx = app_content.find("# VULNERABILITY_SECRET_END") + len("# VULNERABILITY_SECRET_END")
        if start_idx != -1 and end_idx != -1:
            target = app_content[start_idx:end_idx]
            app_content = app_content.replace(target, SECURE_SECRET_BLOCK)
            print(f"  {GREEN}[OK] Fixed: Excised hardcoded API credentials. Configured app to use None (default).{RESET}")
            remediated = True

    if remediated:
        write_file(APP_FILE, app_content)
        
    # Remediate SCA
    if "requests==2.20.0" in req_content:
        req_content = req_content.replace("requests==2.20.0", "requests==2.33.0")
        write_file(REQ_FILE, req_content)
        print(f"  {GREEN}[OK] Fixed: Upgraded requests package to secure v2.33.0.{RESET}")
        remediated = True
        
    # Remediate IaC
    if "INSECURE SSH EXPOSED" in tf_content:
        start_idx = tf_content.find("# VULNERABILITY_IAC_START")
        end_idx = tf_content.find("# VULNERABILITY_IAC_END") + len("# VULNERABILITY_IAC_END")
        if start_idx != -1 and end_idx != -1:
            target = tf_content[start_idx:end_idx]
            tf_content = tf_content.replace(target, SECURE_IAC_BLOCK)
            write_file(TF_FILE, tf_content)
            print(f"  {GREEN}[OK] Fixed: Revoked Port 22 SG ingress. Re-established SSM agent secure tunnel.{RESET}")
            remediated = True

    if remediated:
        print(f"\n{BOLD}{GREEN}[OK] Remediations applied successfully! Your code is now SECURE and compliant.{RESET}")
    else:
        print(f"{YELLOW}No security issues detected. Your code is already secure!{RESET}")
        
    if interactive:
        input("\nPress Enter to continue...")

def view_iac_architecture():
    print_header()
    print(f"{BOLD}{BLUE}Cloud Security Architecture Blueprint (AWS){RESET}\n")
    print(f"""
                      +---------------------------------------+
                      |             GitHub Repo               |
                      |        (Source Code & IaC)            |
                      +---------------------------------------+
                                          |
                                          | git push (trigger)
                                          v
                      +---------------------------------------+
                      |         GitHub Actions CI/CD          |
                      |    (Bandit, pip-audit, Trivy)         |
                      +---------------------------------------+
                                          |
                                          | Authenticate via
                                          | AWS OIDC JWT (No long-lived keys!)
                                          v
                      +---------------------------------------+
                      |          AWS IAM Deploy Role          |
                      |    (Least-Privilege SSM Command)      |
                      +---------------------------------------+
                                          |
                                          | triggers SSM Agent
                                          v
  +-----------------------------------------------------------------------+
  | AWS VPC (10.0.0.0/16)                                                 |
  |                                                                       |
  |  +-----------------------------------------------------------------+  |
  |  | Public Subnet (10.0.1.0/24)                                     |  |
  |  |                                                                 |  |
  |  |  +-----------------------------------------------------------+  |  |
  |  |  | EC2 Instance (Flask Web Application)                      |  |  |
  |  |  |                                                           |  |  |
  |  |  |   - IAM Instance Profile: AmazonSSMManagedInstanceCore    |  |  |
  |  |  |     (Allows secure shell connection, no keypairs required) |  |  |
  |  |  |                                                           |  |  |
  |  |  |   - Security Group Ingress:                               |  |  |
  |  |  |     * Port 80 (HTTP) & 443 (HTTPS) -> Allowed             |  |  |
  |  |  |     * Port 22 (SSH) -> BLOCKED / DENIED INBOUND           |  |  |
  |  |  +-----------------------------------------------------------+  |  |
  |  +-----------------------------------------------------------------+  |
  +-----------------------------------------------------------------------+
  
Security Highlights of this Architecture:
1. OIDC Identity Trust: We avoid storing static AWS Access Keys in GitHub Secrets.
   Instead, GitHub exchanges a short-lived OIDC token for temporary AWS credentials.
2. No Port 22 (SSH) Ingress: The security group completely blocks inbound SSH.
   Administrative access is tunneled through the AWS Systems Manager (SSM) Agent, which
   uses TLS 1.2 and IAM authorization to open terminal sessions.
3. Encrypted Root Storage: In main.tf, the root storage device of the EC2 is 
   explicitly encrypted at rest.
""")
    input("\nPress Enter to continue...")

def run_pipeline():
    print_header()
    print(f"{BOLD}{BLUE}Starting DevSecOps Local Pipeline Runner...{RESET}\n")
    try:
        # Run the simulator script using python
        subprocess.run([sys.executable, SIMULATOR_FILE])
    except Exception as e:
        print(f"{RED}Error running pipeline simulator: {str(e)}{RESET}")
    input("\nPress Enter to continue...")

def main_menu():
    while True:
        print_header()
        print(f"{BOLD}Main Selection Menu:{RESET}")
        print("  1. Run DevSecOps Pipeline Simulator")
        print("  2. Inject Security Vulnerabilities (Test Pipeline Gates)")
        print("  3. Apply Security Remediation Patches (Fix Code)")
        print("  4. View Secure Cloud IaC Architecture Blueprint")
        print("  5. Exit")
        print("-" * 74)
        choice = input("Enter choice (1-5): ").strip()
        
        if choice == '1':
            run_pipeline()
        elif choice == '2':
            inject_vulnerabilities_menu()
        elif choice == '3':
            apply_remediation()
        elif choice == '4':
            view_iac_architecture()
        elif choice == '5':
            print(f"\n{GREEN}Thank you for using the DevSecOps Sandbox. Stay Secure!{RESET}\n")
            sys.exit(0)
        else:
            print(f"\n{RED}Invalid choice. Please choose between 1 and 5.{RESET}")
            import time
            time.sleep(1)

if __name__ == '__main__':
    main_menu()
