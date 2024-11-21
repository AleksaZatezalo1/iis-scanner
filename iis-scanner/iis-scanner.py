"""
Author: Aleksa Zatezalo
Date: November 2024
Version: 1.0
Description: A scanner made to do basic enumeration of Microsoft IIS servers.
"""

import asyncio
from struct import pack
from impacket.smbconnection import SMBConnection
import asyncio
import time
import aiohttp

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

    print(color.BLUE + color.BOLD + windows_ascii_str + color.END)

def printInfo(msg, status='log'):
    
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

    try:
        # Attempt to open a connection with a timeout
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        # Close the connection
        writer.close()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError):
        return False

    
async def scanPorts(host, task_queue, open_ports):

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

async def checkBluekeep(target_ip, ports):
    """
    Asynchronously checks for the BlueKeep vulnerability.
    """

    if 3389 in ports:
        printInfo("Checking for the BlueKeep vulnerability...")
    else:
        printInfo("Will not check for BlueKeep vulnerability...")    
        return False
        
    try:
        reader, writer = await asyncio.open_connection(target_ip, 3389)
        pre_auth_pkt = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
        writer.write(pre_auth_pkt)
        await writer.drain()

        data = await reader.read(1024)
        writer.close()
        await writer.wait_closed()

        if b"\x03\x00\x00\x0c" in data:
            printInfo("Target is vulnerable to BlueKeep.", "success")
            return True
        else:
            printInfo("Target may not be vulnerable to BlueKeep.", "warning")
            return False
    except Exception:
        printInfo("Target is not vulnerable to BlueKeep.", "failed")
        return False


async def checkEternalblue(target_ip, ports):
    """
    Asynchronously checks for the EternalBlue vulnerability.
    """

    if 139 in ports:
        printInfo("Checking for the EternalBlue vulnerability...")
    if 445 in ports:
        printInfo("Checking for the EternalBlue vulnerability...")
    else:
        printInfo("Will not check for EternalBlue vulnerability...")    
        return False

    try:
        conn = SMBConnection(target_ip, target_ip, timeout=5)
        conn.connectTree("IPC$")
        TRANS_PEEK_NMPIPE = 0x23
        recvPkt = conn.send_trans(pack('<H', TRANS_PEEK_NMPIPE), maxParameterCount=0xffff, maxDataCount=0x800)
        status = recvPkt.getNTStatus()

        if status == 0xC0000205:  # STATUS_INSUFF_SERVER_RESOURCES
            printInfo("The target is likely vulnerable to EternalBlue.", "success")
            return True
        else:
            printInfo("The target is probably not vulnerable to EternalBlue.", "failed")
            return False
    except Exception:
        printInfo("An error occurred when testing for EternalBlue.", "failed")
        return False


async def checkScstoragepathfromurl(target_ip, ports):
    """
    Asynchronously checks for the ScStoragePathFromURL vulnerability.
    """
    
    if 80 or 443 in ports:
        printInfo("Checking for the ScStoragePathFromURL vulnerability...")
    else:
        printInfo("Will not check for ScStoragePathFromURL vulnerability...")    
        return False
    
    target_url = f"http://{target_ip}"
    headers = {
        "Translate": "f",
    }
    payload = "A" * 40000  # Long string to simulate buffer overflow

    try:
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method="PROPFIND",
                url=target_url,
                headers=headers,
                data=payload,
                timeout=10
            ) as response:
                if response.status == 500:
                    printInfo("Server is likely vulnerable to ScStoragePathFromUrl.", "success")
                    return True
                elif response.status in [403, 404]:
                    printInfo("Server is likely not vulnerable to ScStoragePathFromUrl.", "warning")
                else:
                    printInfo("Server may be vulnerable to ScStoragePathFromUrl.", "warning")
                return False
    except aiohttp.ClientError:
        printInfo("Error occurred testing ScStoragePathFromUrl.", "failed")
        return False
    except Exception:
        printInfo("Error occurred testing ScStoragePathFromUrl.", "failed")
        return False


async def main():
    """
    Main function to take user input for IP address and scan ports.
    """

    # # Get IP address from the user
    ip = input("Enter the target IP address: ")
    ports = [21, 22, 80, 139, 443, 445]
    print("\nScanning for open ports.")
    openPorts = await scanIP(host=ip, portsToScan=ports)

    print("\nScanning for vulns.")
    bluekeep_result, eternalblue_result, scstorage_result = await asyncio.gather(
        checkBluekeep(ip, openPorts),
        checkEternalblue(ip, openPorts),
        checkScstoragepathfromurl(ip, openPorts)
    )

# Run the script
if __name__ == "__main__":
    header()
    asyncio.run(main())
