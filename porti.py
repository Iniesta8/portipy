#!/usr/bin/env python
import subprocess
import sys
import nmap
from time import sleep
from socket import gethostbyname
from colorama import init
from colorama import Fore, Back, Style
from datetime import datetime

# Clear the screen
subprocess.call("clear", shell=True)

# Init colorama to use this script also on windows (lol)
init()

print Fore.CYAN + "-" * 60
print "Welcome to portipy, a simple tcp port scanning script"
print "-" * 60 + "\n" + Fore.RESET

# Get hostname to scan
remote_server = raw_input("Enter a remote host to scan: ")
remote_server_IP = gethostbyname(remote_server)
remote_ports = raw_input("Enter ports to scan: ")

print "\n...Please wait, scanning remote host " + Fore.YELLOW +\
    remote_server_IP + Fore.RESET + "\n"

# t1 = datetime.now()

try:
    while (True):
        nm = nmap.PortScanner()
        time = datetime.now()
        nm.scan(remote_server_IP, remote_ports)
        for host in nm.all_hosts():
            print "Scan time: " + str(time)
            if nm[host].state() == "up":
                print "State: " + Fore.GREEN + "up" + Fore.RESET
            else:
                print "State: %s" % nm[host].state()
            for protocol in nm[host].all_protocols():
                print "-" * 60
                print "Protocol: " + Fore.MAGENTA + "%s" % protocol +\
                    Fore.WHITE
                lport = nm[host][protocol].keys()
                lport.sort()
                for port in lport:
                    print "Port: %s\tState: %s" % (port,
                                                   nm[host][protocol][port]
                                                     ["state"])
                print Fore.RESET
                print "-" * 60
        sleep(60 * 60)  # 1 hour sleep

except KeyboardInterrupt:
    print "Scan cancelled by user. Bye.\n"
    sys.exit()

# t2 = datetime.now()
# total = t2 - t1
# print "Scanning completed in: ", total
