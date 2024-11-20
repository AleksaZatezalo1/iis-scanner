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
    # create coroutine for opening a connection
    coro = asyncio.open_connection(host, port)
    # execute the coroutine with a timeout
    try:
        # open the connection and wait for a moment
        _,writer = await asyncio.wait_for(coro, timeout)
        # close connection once opened
        writer.close()
        # indicate the connection can be opened
        return True
    except asyncio.TimeoutError:
        # indicate the connection cannot be opened
        return False
    
async def scanPorts(host, task_queue):
    """
    Scans a port and prints status to STDO.

    ARGUMENTS

    * host: String. IP address of the host we are connecting too.
    * task_queue: Queue. A queue of ports for the function scanPorts to connect to.
    """

    # read tasks forever
    while True:    
        # read one task from the queue
        port = await task_queue.get()
        # check for a request to stop scanning
        if port is None:
            # add it back for the other scanners
            await task_queue.put(port)
            # stop scanning
            break
        # scan the port
        if await test_port_number(str(host), str(port)):
            # report the report if open
            print(f'> {host}:{port} [OPEN]')

        # mark the item as processed
        task_queue.task_done()

async def scanIP(limit=100, host="127.0.0.1", portsToScan=[21, 22, 80, 443]):
    """
    Scans an IP for open ports using async function calls.

    ARGUMENTS
    * host: String. IP address of the host we are connecting too.
    * limit: Integer. The maximum ammount of async coroutines we will have. Defualts to 100. 
    * portsToScan: An arraylist of ports to scan.
    """

    # create the task queue
    task_queue = asyncio.Queue()
    # start the port scanning coroutines
    [asyncio.create_task(scanPorts(host, task_queue)) for _ in range(limit)]

    # issue tasks as fast as possible
    for port in portsToScan:
        # add task to scan this port
        await task_queue.put(port)
    # wait for all tasks to be complete
    await task_queue.join()

    # signal no further tasks
    await task_queue.put(None)
        

async def run(targets):
    """
    Scans a range of IPs based on input added when the class was initialized. Opens a thread for each new IP.

    ARGUMENTS
    * targets: An arraylist of ips to scan.
    """

    # Functions needed to start program
    for ipAddress in targets:
        threading.Thread(target=asyncio.run, args={scanIP(host=ipAddress)}).start()
    return

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
    
async def check_anonymous_smb(target_host):
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
    Check if an IIS server exposes sensitive files in the root directory.

    Args:
        target_url (str): The base URL of the IIS server (e.g., http://example.com).
        files (list): A list of filenames to check for (default includes common sensitive files).

    Returns:
        dict: A dictionary with filenames as keys and access results (status or truncated content) as values.
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
    Check if an IIS server is vulnerable to authentication bypass via cached credentials (CVE-2022-30209).

    Args:
        target_url (str): The URL of the protected resource on the IIS server.
        test_usernames (list): A list of usernames to test.
        test_passwords (list): A list of passwords to test.

    Returns:
        bool: True if authentication bypass is successful, False otherwise.
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