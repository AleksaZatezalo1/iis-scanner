"""
Author: Aleksa Zatezalo
Date: Novemver 2024
Version: 1.0
Description: A vulnerability scanner for Microsoft IIS servers.
"""


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
    """
    
    print(color.BLUE + color.BOLD + windows_ascii_str + color.END)

def printInfo(msg, status='log'):
    """
    """

    pass

def header():
    """
    """

    pass


############
# Scan IO  #
############
async def checkVuln(banner, vuln_db):
    """
    """
    
    pass


async def getBanner(ip, port):
    """
    """

    pass

async def portScan(ip, min, max=0):
    """
    """

    pass

async def ipPortScan(ipList, min, max=0):
    """
    """

    pass

async def dirbust(ipList, port, wordlist):
    """
    """

    pass

banner()