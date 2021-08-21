#!/usr/bin/env python
# -*- coding: utf8 -*-

"""

	=^.^= WEBCAT =^.^=

	webcat is a simple website scanner for interesting
	files / directories. webcat was written while attending
	a pentesting class, therefore it's really quite simple.
		
        Version: 0.2
            + cleanup
        Version: 0.1
            + initial version
		
		Written by Peter Bartels
        
        https://www.kangafoo.de
		
"""

import sys
import argparse
import os
import requests


def clear():
    """
    
    clear() -> no return
    
    just clear screen for linux and windows
    
    """
    os.system("cls" if os.name == "nt" else "clear")
	
def infoheader():
    """
    
    infoheader() -> no return
    
    prints header logo and avatar target name and CID
    
    """
    clear()
    print("=^.^= WEBCAT =^.^=")
    print("-"*50)
    print("->>  Target: %s" %(options.target))
    print("-"*50)



def printhelp():
    """
    
    printhelp() -> no return
    
    prints header logo and displays help parameters
    
    """
    clear();
    print("=^.^= WEBCAT =^.^=")
    parser.print_help()



def createlist(myfile,mytarget):
    """
    
    createlist(string) -> list
    
    reads a file with files / directories and combines it with target for scan.
    returns the resulting list
    
    """
    lines = open(myfile, "r").readlines()
    newlist = []
    for line in lines:
        line = line.replace("\n", "") #rem break
        line = line.replace("\r", "") #rem return
        line = mytarget + "/" + line
        newlist.append(line)
    return newlist
        
    
    
def scantarget(host):
    """
    
    scantarget(string) -> no return
    
    scan for a given file or directory on host and print result
    
    """
    user_agent = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.8',
                    'Accept-Encoding': 'gzip'
        }
    scan = requests.get(host, headers=user_agent)
    if ( scan.status_code == 200 ):
        print("[200] "+host)
    else: #when verbose mode is enabled, print every result
        if (verb):
            print("["+str(scan.status_code)+"] "+host)
	
if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target",default="",help="specify the target host e.g. http://www.google.de")
    parser.add_argument("-f", "--file", dest="file",default="",help="specify the filename with files and directories to scan for")
    parser.add_argument("-v", "--verbose",dest="verbose_switch",default=False, action="store_true",help="show all results")
    options = parser.parse_args()
    if len(sys.argv) < 2:
        printhelp()
        quit()
    else:
        target = options.target
        file = options.file
        verb = options.verbose_switch
        infoheader()
        listtoscan = createlist(file,target)
        for scanitem in listtoscan:
            scantarget(scanitem)
