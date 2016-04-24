#!/usr/bin/env python
import subprocess
import sys
import nmap
from socket import gethostbyname
from colorama import init
from colorama import Fore, Back, Style
from datetime import datetime

# Clear the screen
subprocess.call("clear", shell=True)

print Fore.CYAN + "-" * 60
print "Welcome to portipy, a simple tcp port scanning script"
print "-" * 60 + "\n" + Fore.RESET

# Get hostname to scan
remoteServer = raw_input("Enter a remote host to scan: ")
remoteServerIP = gethostbyname(remoteServer)
remotePorts = raw_input("Enter ports to scan: ")

print "\n...Please wait, scanning remote host " + Fore.YELLOW +\
    remoteServerIP + Fore.RESET + "\n"

t1 = datetime.now()

# Init colorama to use this script also on windows (lol)
init()

try:
    nm = nmap.PortScanner()
    nm.scan(remoteServerIP, remotePorts)
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            print "State: " + Fore.GREEN + "up" + Fore.RESET
        else:
            print "State: %s" % nm[host].state()
        for protocol in nm[host].all_protocols():
            print "-" * 60
            print "Protocol: " + Fore.MAGENTA + "%s" % protocol + Fore.WHITE
            lport = nm[host][protocol].keys()
            lport.sort()
            for port in lport:
                print "Port: %s\tState: %s" % (port,
                                               nm[host][protocol][port]
                                                 ["state"])
            print Fore.RESET
            print "-" * 60

except KeyboardInterrupt:
    print "Scan cancelled by user. Bye.\n"
    sys.exit()

t2 = datetime.now()
total = t2 - t1
print "Scanning completed in: ", total
