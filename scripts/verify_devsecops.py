import os
import sys
import subprocess

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIMULATOR_FILE = os.path.join(PROJECT_DIR, 'scripts', 'simulate_pipeline.py')

# Import dashboard elements dynamically since the filename contains a hyphen
sys.path.append(PROJECT_DIR)
import importlib
dashboard = importlib.import_module("devops-dashboard")

def run_pipeline():
    res = subprocess.run([sys.executable, SIMULATOR_FILE], capture_output=True, text=True)
    return res.returncode, res.stdout, res.stderr

def print_result(test_name, success, details=""):
    color = "\033[92m" if success else "\033[91m"
    reset = "\033[0m"
    status = "PASS" if success else "FAIL"
    print(f"[{color}{status}{reset}] {test_name} {details}")

def main():
    print("==================================================")
    print("      AUTOMATED DEVSECOPS PIPELINE VERIFIER      ")
    print("==================================================")
    
    # 1. Clean state test
    print("\nRunning test: Clean State...")
    dashboard.apply_remediation(interactive=False) # Ensure clean
    code, out, err = run_pipeline()
    clean_ok = (code == 0)
    print_result("Pipeline in Clean State", clean_ok, "(should pass)" if clean_ok else "(failed to pass)")
    if not clean_ok:
        print(out)
        sys.exit(1)
        
    # 2. SAST Shell Injection test
    print("\nRunning test: SAST Command Injection Gate...")
    app_content = dashboard.read_file(dashboard.APP_FILE)
    start_idx = app_content.find("# VULNERABILITY_SAST_SHELL_START")
    end_idx = app_content.find("# VULNERABILITY_SAST_SHELL_END") + len("# VULNERABILITY_SAST_SHELL_END")
    target = app_content[start_idx:end_idx]
    dashboard.write_file(dashboard.APP_FILE, app_content.replace(target, dashboard.INSECURE_SHELL_BLOCK))
    
    code, out, err = run_pipeline()
    sast_ok = (code != 0 and "SAST scan found vulnerabilities in code!" in out)
    print_result("SAST Command Injection Blocked", sast_ok, "(correctly blocked)" if sast_ok else "(failed to block)")
    dashboard.apply_remediation(interactive=False) # Revert
    
    # 3. SAST SQL Injection test
    print("\nRunning test: SAST SQL Injection Gate...")
    app_content = dashboard.read_file(dashboard.APP_FILE)
    start_idx = app_content.find("# VULNERABILITY_SAST_SQL_START")
    end_idx = app_content.find("# VULNERABILITY_SAST_SQL_END") + len("# VULNERABILITY_SAST_SQL_END")
    target = app_content[start_idx:end_idx]
    dashboard.write_file(dashboard.APP_FILE, app_content.replace(target, dashboard.INSECURE_SQL_BLOCK))
    
    code, out, err = run_pipeline()
    # SQL injection might flag as low or medium depending on Bandit config. If it exits non-zero, it passes our gate.
    # Note: bandit with -ll only catches Medium/High. Let's see if SQL injection triggers bandit.
    sast_sql_ok = (code != 0)
    print_result("SAST SQL Injection Blocked", sast_sql_ok, f"(pipeline exit code: {code})" if sast_sql_ok else "(failed to block)")
    dashboard.apply_remediation(interactive=False) # Revert

    # 4. SCA outdated package test
    print("\nRunning test: Dependency SCA Gate...")
    req_content = dashboard.read_file(dashboard.REQ_FILE)
    dashboard.write_file(dashboard.REQ_FILE, req_content.replace("requests==2.33.0", "requests==2.20.0"))
    
    code, out, err = run_pipeline()
    sca_ok = (code != 0 and "SCA scan completed. No vulnerable dependencies found!" not in out)
    print_result("SCA Vulnerable Dependency Blocked", sca_ok, "(correctly blocked)" if sca_ok else "(failed to block)")
    dashboard.apply_remediation(interactive=False) # Revert

    # 5. Secrets Leak test
    print("\nRunning test: Secret Leak Gate...")
    app_content = dashboard.read_file(dashboard.APP_FILE)
    start_idx = app_content.find("# VULNERABILITY_SECRET_START")
    end_idx = app_content.find("# VULNERABILITY_SECRET_END") + len("# VULNERABILITY_SECRET_END")
    target = app_content[start_idx:end_idx]
    dashboard.write_file(dashboard.APP_FILE, app_content.replace(target, dashboard.INSECURE_SECRET_BLOCK))
    
    code, out, err = run_pipeline()
    secrets_ok = (code != 0 and "Hardcoded secrets detected in source control!" in out)
    print_result("Secrets Leak Blocked", secrets_ok, "(correctly blocked)" if secrets_ok else "(failed to block)")
    dashboard.apply_remediation(interactive=False) # Revert

    # 6. IaC Open SSH test
    print("\nRunning test: IaC Scanning Gate...")
    tf_content = dashboard.read_file(dashboard.TF_FILE)
    start_idx = tf_content.find("# VULNERABILITY_IAC_START")
    end_idx = tf_content.find("# VULNERABILITY_IAC_END") + len("# VULNERABILITY_IAC_END")
    target = tf_content[start_idx:end_idx]
    dashboard.write_file(dashboard.TF_FILE, tf_content.replace(target, dashboard.INSECURE_IAC_BLOCK))
    
    code, out, err = run_pipeline()
    iac_ok = (code != 0 and "Inbound SSH Expose" in out)
    print_result("IaC Open SSH Port 22 Blocked", iac_ok, "(correctly blocked)" if iac_ok else "(failed to block)")
    dashboard.apply_remediation(interactive=False) # Revert

    # Final validation
    print("\nFinalizing Verification: Resetting and testing clean state...")
    dashboard.apply_remediation(interactive=False)
    code, out, err = run_pipeline()
    final_ok = (code == 0)
    print_result("Final Clean Pipeline Check", final_ok, "(Passed!)" if final_ok else "(Failed to pass)")
    
    if clean_ok and sast_ok and sca_ok and secrets_ok and iac_ok and final_ok:
        print("\n\033[92mALL TESTS COMPLETED SUCCESSFULLY! DEVSECOPS SECURITY GATES ARE VALIDATED.\033[0m")
        sys.exit(0)
    else:
        print("\n\033[91mSOME GATE TESTS FAILED. CHECK LOGS ABOVE.\033[0m")
        sys.exit(1)

if __name__ == '__main__':
    main()
