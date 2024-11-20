"""
Author: Aleksa Zatezalo
Date: November 2024
Version: 1.0
Description: Main method for IIS Scanner package.
"""

# Import Argparse
# Allow Multiple IPs
# Specify specific scans with specific ips
# Specify password attacks, webdav attack, or other attack
# Import sleep for usability

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

header()

# async def main():
#     target_ip = input("Enter the target IP (leave blank for localhost): ") or "127.0.0.1"

#     # Schedule tasks to run concurrently
#     tasks = [
#         check_bluekeep(),
#         check_eternalblue(target_ip),
#         scan_network_for_services(target_ip),
#     ]

#     await asyncio.gather(*tasks)

# if __name__ == "__main__":
#     asyncio.run(main())
# async def main():
#     target_ftp = input("Enter the target FTP server (hostname or IP): ")
#     target_smb = input("Enter the target SMB server (hostname or IP): ")

#     # Run checks concurrently
#     await asyncio.gather(
#         check_anonymous_ftp(target_ftp),
#         check_anonymous_smb(target_smb),
#     )

# if __name__ == "__main__":
#     asyncio.run(main())


# Example usage
# if __name__ == "__main__":
#     target = input("Enter the target URL (e.g., http://example.com): ")
#     asyncio.run(check_internal_ip_disclosure(target))


# # Example usage
# if __name__ == "__main__":
#     target = input("Enter the target URL (e.g., http://example.com): ")
#     asyncio.run(check_config_execution(target))


# # Example usage
# if __name__ == "__main__":
#     target = input("Enter the target URL (e.g., http://example.com): ")
#     test_file = input("Enter the test file (e.g., default.aspx, index.asp) [default: default.aspx]: ") or "default.aspx"
#     asyncio.run(check_source_code_leak(target, test_file))

# if __name__ == "__main__":
#     target = input("Enter the target URL (e.g., http://example.com): ")
#     file_list = input("Enter comma-separated filenames to check [default: global.asax,web.config,connectionstrings.config,machine.config]: ")
#     file_list = [f.strip() for f in file_list.split(",")] if file_list else None
#     results = asyncio.run(check_root_directory_files(target, file_list))

#     print("\nSummary of Results:")
#     for file, info in results.items():
#         print(f"{file}: {info}")