"""
Author: Aleksa Zatezalo
Date: Novemver 2024
Version: 1.0
Description: A vulnerability scanner for Microsoft IIS servers.
"""

import asyncio
import threading

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
 b.
 88b
 888b.
 88888b
 888888b.
 8888P"
 P" `8.
       `8.   IIS Scaner by Aleksa Zatezalo
        `8
"""

def banner():
    """
    Prints a cool banner.
    """
    
    print(color.BLUE + color.BOLD + windows_ascii_str + color.END)

def printInfo(msg, status='log'):
    """
    Prints various types of logs to standard output.
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
    """

    banner()
    print(color.BOLD + "EXAMPLE NOTIFICATIONS: " + color.END)
    printInfo("Warnings are printed like this.", status="warning")
    printInfo("Errors are printed like this.", status="failed")
    printInfo("Good news is printed like this.", status="success")
    printInfo("Logs are printed like this\n.", status="log")



############
# Scan IO  #
############
async def test_port_number(host, port, timeout=3):
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
    Scans a port and prints status to STDO. Adds open ports to the output dictionary.

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

# header()
# asyncio.run(run(['151.101.0.223', '8.8.8.8']))