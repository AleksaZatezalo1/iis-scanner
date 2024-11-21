"""
Author: Aleksa Zatezalo
Date: November 2024
Version: 1.0
Description: A scanner made to do basic enumeration of Microsoft IIS servers.
"""

import asyncio
import threading
import platform
from impacket.smbconnection import SMBConnection
import asyncio
import aiohttp
import re
import time


############
# String IO#
############
class color:
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

windows_ascii_str = """
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⣶⠟⣉⣤⣢⣄⡪⢝⢦⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢰⡿⢁⣾⠟⠉⠉⠉⠹⣧⣃⢳⡀⠀⠀⠀
⠀⠀⠀⢀⣀⣼⡏⣼⠃⠀⠀⠀⠀⠀⢹⣏⣸⡅⠀⠀⠀
⠀⢀⣴⡿⠿⣿⠃⣿⠀⠀⠀⠀⠀⠀⣸⣷⣿⣶⣄⠀⠀
⠠⠞⠁⠀⢠⣿⠌⣿⠀⠀⠀⠀⠀⠀⣿⡇⣿⠛⠛⠿⣄
⠀⠀⢀⣠⠾⠿⠾⣷⡀⠀⠀⠀⡠⢶⠛⠹⠿⢶⣄⠀⠈
⠀⢠⠋⠀⢀⣁⡀⠘⠙⣦⡀⠘⠈⠀⣠⣤⡀⠀⠻⣦⠀
⠀⢀⠀⠀⢾⣿⣿⠀⠀⢘⣧⠇⡀⠘⢿⣿⠏⠀⠀⡿⠀
⠀⠈⢧⡀⠈⣉⡁⠀⣤⡞⠀⠘⢢⣀⡄⠀⢠⣠⠾⠃⠀
⠀⠀⠀⠉⣷⡖⣶⡛⠉⠀⠀⠀⠀⣿⡏⣿⠋⠁⠀⠀⠀
⠀⠀⠀⠀⢻⡇⣽⢺⣱⡄⠀⠀⠀⣿⢇⡏⠀⠀⣰⡖⣦
⠀⠀⠀⠀⣿⡇⣿⢻⠸⡇⠀⠀⠀⣿⢰⡏⢀⣾⢳⡾⠉
⠀⠀⠀⠀⣿⡄⡿⣿⠘⡁⠀⠀⠐⣿⢸⡇⣾⢇⡿⠀⠀
⠀⠀⠀⠀⣿⠐⣟⣧⢰⠀⠀⠀⢸⣿⢺⠆⣿⢸⡇⠀⠀
⠀⠀⠀⠀⣿⠡⣟⣿⢸⡇⠀⠀⢸⣇⢿⠆⣿⢸⡅⠀⠀
⠀⠀⠀⠀⣿⠡⣏⣿⡸⡅⠀⠀⣼⢏⣼⠆⣿⢸⠃⠀⠀
⠀⠀⠀⠀⣿⠰⣿⠹⣶⣭⣖⣪⣵⡾⠏⢠⣿⢸⡁⠀⠀
⠀⠀⠀⠀⣿⢂⡷⠀⠈⠉⠘⠉⠉⠀⠀⠸⣿⢼⡀⠀⠀
⠀⠀⠀⠀⣿⡍⢿⡀⠀⠀⠀⠀⠀⠀⠀⣸⠇⣼⠀⠀⠀
⠀⠀⠀⠀⠹⣯⡎⡻⢦⣀⣀⣀⣀⡤⠞⣉⣼⠃⠀⠀⠀
⠀⠀⠀⠀⠀⠈⠻⢷⣦⣢⣬⣤⣤⣶⠾⠋⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀
Clippy the Microsoft IIS Scanner by Aleksa Zatezalo
"""

def banner():
    """
    Prints a cool banner.

    ARGUMENTS:
    * None
    """
    
    print(color.BLUE + color.BOLD + windows_ascii_str + color.END)

def printInfo(msg, status='log'):
    """
    Prints various types of logs to standard output.


    ARGUMENTS:
    * msg: String. A message to pring.
    * status: String. The status of the message. Either success, warning, failed, or log.
    """
    
    plus = "[+] "
    exclaim ="[!] "
    fail = "[-] "

    match status:
        case "success":
            print(color.GREEN + plus + msg + color.END)
        case "warning":
            print(color.YELLOW + exclaim + msg + color.END)
        case "failed":
            print(color.RED + fail + msg + color.END)
        case "log":
            print(color.CYAN + exclaim + msg + color.END)

def header():
    """
    Prints a cool hader to standard output.

    ARGUMENTS:
    * None
    """

    banner()
    time.sleep(0.5)
    print(color.BOLD + "EXAMPLE NOTIFICATIONS: " + color.END)
    time.sleep(1)
    printInfo("Warnings are printed like this.", status="warning")
    time.sleep(1)
    printInfo("Errors are printed like this.", status="failed")
    time.sleep(1)
    printInfo("Good news is printed like this.", status="success")
    time.sleep(1)
    printInfo("Logs are printed like this\n.", status="log")
    time.sleep(1)

#################
# Port Scan IO  #
#################
async def test_port_number(host, port, timeout=3):
    """
    Scans a port and prints returns true or false based on status.

    ARGUMENTS

    * host: String. IP address of the host we are connecting too.
    * Port: Port to scan.
    """

    try:
        # Attempt to open a connection with a timeout
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        # Close the connection
        writer.close()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError):
        return False

    
async def scanPorts(host, task_queue, open_ports):
    """
    Scans a port and prints status to STDO.

    ARGUMENTS

    * host: String. IP address of the host we are connecting too.
    * task_queue: Queue. A queue of ports for the function scanPorts to connect to.
    """

    # read tasks forever
    while True:
        # Get a port to scan from the queue
        port = await task_queue.get()
        if port is None:
            # Add the termination signal back for other workers
            await task_queue.put(None)
            task_queue.task_done()
            break
        if await test_port_number(host, port):
            printInfo(f'{host}:{port} [OPEN]')
            open_ports.append(port)
        task_queue.task_done()


async def scanIP(limit=100, host="127.0.0.1", portsToScan=[21, 22, 80, 139, 443, 445]):
    """
    Scans an IP for open ports using async function calls.

    ARGUMENTS
    * host: String. IP address of the host we are connecting too.
    * limit: Integer. The maximum ammount of async coroutines we will have. Defualts to 100. 
    * portsToScan: An arraylist of ports to scan.
    """

    if portsToScan is None:
        # Default ports to scan
        portsToScan = [21, 22, 80, 139, 443, 445]

    task_queue = asyncio.Queue()
    open_ports = []

    # Start the port scanning coroutines
    workers = [
        asyncio.create_task(scanPorts(host, task_queue, open_ports))
        for _ in range(limit)
    ]

    # Add ports to the task queue
    for port in portsToScan:
        await task_queue.put(port)

    # Wait for all tasks to be processed
    await task_queue.join()

    # Signal termination to workers
    await task_queue.put(None)
    await asyncio.gather(*workers)

    return open_ports
        
#################
# Vuln Scan IO  #
#################

async def checkBluekeep():
    """
    """
   
    print("\nChecking for BlueKeep vulnerability...")
    system_version = platform.version()
    system_release = platform.release()
    vulnerable_versions = ["6.1", "6.2", "6.3"]  # Windows 7, Windows Server 2008 R2, etc.

    if any(v in system_version for v in vulnerable_versions):
        print("[!] System is potentially vulnerable to BlueKeep. Check if RDP patches are applied.")
    else:
        print("[+] System version is not vulnerable to BlueKeep.")
    print(f"System version: {system_version}, Release: {system_release}")

async def checkEternalblue(target_ip):
    """
    """
    
    print("\nChecking for EternalBlue vulnerability...")
    try:
        conn = SMBConnection(target_ip, target_ip, timeout=5)
        conn.connectTree("IPC$")
        print("[!] Target might be vulnerable to EternalBlue. Please ensure MS17-010 patch is applied.")
    except Exception as e:
        if "STATUS_ACCESS_DENIED" in str(e):
            print("[+] Target is patched or not vulnerable to EternalBlue.")
        else:
            print(f"[-] Unable to determine vulnerability: {e}")

async def checkScstoragepathfromurl(target_url):
    """
    """
    
    # Prepare the headers and payload for the test
    headers = {
        "Content-Length": "0",
        "Translate": "f",
    }
    payload = "A" * 1000  # Overly long string to test for buffer overflow

    print(f"\nTesting {target_url} for ScStoragePathFromUrl vulnerability...")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.request("PROPFIND", target_url, headers=headers, data=payload) as response:
                # Vulnerable servers may return a 500 Internal Server Error or exhibit unusual behavior
                if response.status == 500:
                    print("[!] Server might be vulnerable to ScStoragePathFromUrl (CVE-2017-7269).")
                    return True
                else:
                    print(f"[+] Server returned status {response.status}. Likely not vulnerable.")
                    return False
    except Exception as e:
        print(f"[-] Error occurred while testing {target_url}: {e}")
        return False

##############################
# Anonymouys Access Scan IO  #
##############################
async def checkAnonymousSmb(target_host):
    """
    """
    
    print(f"\nChecking SMB anonymous access on {target_host}...")
    try:
        conn = SMBConnection(target_host, target_host, timeout=5)
        conn.login('', '')  # Attempt anonymous login
        print(f"[!] Anonymous access is allowed on SMB server {target_host}.")
        conn.logoff()
        return True
    except Exception as e:
        if "STATUS_ACCESS_DENIED" in str(e):
            print(f"[+] Anonymous access is not allowed on SMB server {target_host}.")
        else:
            print(f"[-] Error occurred while checking SMB server {target_host}: {e}")
        return False
    
##############################
# Common IIS Vulnerabilites  #
##############################
async def checkInternalIpDisclosure(target_url):
    """
    """
    
    print(f"\nChecking {target_url} for internal IP address disclosure vulnerability...")
    
    # Headers to simulate a request that might trigger the issue
    headers = {
        "Host": "localhost",
        "User-Agent": "Mozilla/5.0",
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, headers=headers) as response:
                body = await response.text()
                headers = response.headers

                # Regular expression to detect private/internal IP addresses
                ip_pattern = r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})"

                # Search in response body
                body_match = re.search(ip_pattern, body)
                if body_match:
                    print(f"[!] Internal IP address found in response body: {body_match.group()}")
                    return True

                # Search in response headers
                for header, value in headers.items():
                    if re.search(ip_pattern, value):
                        print(f"[!] Internal IP address found in response header {header}: {value}")
                        return True

                print("[+] No internal IP addresses found in the response.")
                return False
    except Exception as e:
        print(f"[-] Error occurred while checking {target_url}: {e}")
        return False

async def check_config_execution(target_url):
    """
    """
    
    print(f"\nChecking {target_url} for .config file execution vulnerability...")
    
    # Construct a URL for testing (e.g., trying to access web.config)
    test_url = f"{target_url.rstrip('/')}/web.config"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(test_url) as response:
                body = await response.text()

                # If the server processes the .config file, it may return a 200 status with unexpected content.
                if response.status == 200:
                    print(f"[!] .config file is accessible at {test_url}.")
                    print(f"Response content (truncated): {body[:200]}...")
                    return True
                elif response.status == 403:
                    print(f"[+] Access to .config files is forbidden at {test_url}.")
                    return False
                else:
                    print(f"[?] Received status {response.status} while testing {test_url}. Likely not vulnerable.")
                    return False
    except Exception as e:
        print(f"[-] Error occurred while checking {test_url}: {e}")
        return False
    

async def checkSourceCodeLeak(target_url, test_file="default.aspx"):
    """
    """
    
    print(f"\nChecking {target_url} for source code leakage with {test_file}...")
    
    # Construct the URL for the test
    test_url = f"{target_url.rstrip('/')}/{test_file}"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(test_url) as response:
                body = await response.text()

                # Look for indicators of source code in the response
                if response.status == 200 and ("<%@ Page" in body or "<script runat" in body):
                    print(f"[!] Source code leakage detected at {test_url}.")
                    print(f"Response content (truncated): {body[:200]}...")
                    return True
                elif response.status == 404:
                    print(f"[+] Test file {test_file} not found on the server.")
                    return False
                else:
                    print(f"[?] Received status {response.status} while testing {test_url}. Likely not vulnerable.")
                    return False
    except Exception as e:
        print(f"[-] Error occurred while checking {test_url}: {e}")
        return False
    
async def checkRootDirectoryFiles(target_url, files=None):
    """
    """

    if files is None:
        # Default sensitive files to check
        files = ["global.asax", "web.config", "connectionstrings.config", "machine.config"]

    print(f"\nChecking {target_url} for sensitive root directory files...")
    results = {}

    async with aiohttp.ClientSession() as session:
        for file in files:
            test_url = f"{target_url.rstrip('/')}/{file}"
            try:
                async with session.get(test_url) as response:
                    body = await response.text()

                    if response.status == 200:
                        print(f"[!] File {file} is accessible at {test_url}.")
                        print(f"Content (truncated): {body[:200]}...")
                        results[file] = {"status": response.status, "content": body[:200]}
                    elif response.status == 404:
                        print(f"[+] File {file} not found at {test_url}.")
                        results[file] = {"status": response.status, "content": None}
                    else:
                        print(f"[?] Unexpected status {response.status} for {file} at {test_url}.")
                        results[file] = {"status": response.status, "content": None}
            except Exception as e:
                print(f"[-] Error occurred while checking {file} at {test_url}: {e}")
                results[file] = {"status": "error", "content": str(e)}

    return results

async def checkIISAuthBypass(target_url, test_usernames=None, test_passwords=None):
    """
    """

    if test_usernames is None:
        # Common usernames to test
        test_usernames = ["admin", "user", "guest", "test"]
    if test_passwords is None:
        # Common passwords to test
        test_passwords = ["password", "12345", "admin", "guest", "test"]

    print(f"\nChecking {target_url} for IIS authentication bypass vulnerability...")

    async with aiohttp.ClientSession() as session:
        for username in test_usernames:
            for password in test_passwords:
                try:
                    auth = aiohttp.BasicAuth(username, password)
                    async with session.get(target_url, auth=auth) as response:
                        if response.status == 200:
                            print(f"[!] Authentication bypass successful with credentials: {username}:{password}")
                            return True
                        elif response.status == 401:
                            print(f"[+] Credentials failed: {username}:{password}")
                        else:
                            print(f"[?] Unexpected status {response.status} with {username}:{password}")
                except Exception as e:
                    print(f"[-] Error occurred while testing {username}:{password}: {e}")
    print("[+] Authentication bypass unsuccessful.")
    return False

async def main():
    """
    Main function to take user input for IP address and scan ports.
    """

    # Get IP address from the user
    ip = input("Enter the target IP address: ")
    ports = [21, 22, 80, 139, 443, 445]
    print(f"Scanning {ip} for open ports...\n")
    open_ports = await scanIP(host=ip, portsToScan=ports)


# Run the script
if __name__ == "__main__":
    header()
    asyncio.run(main())
