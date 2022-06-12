## Acarine
Acarine is a Buffer Overflow utility and guide. It is to be used in conjunction with Immunity Debugger and Immunity's Mona module.

## Usage: 
    Acarine.py -t [IP] -p [PORT]

## Dependencies:
    Metasploit Framework Tools

## What does Acarine do?

Acarine has 5 main sections:
- Is a Buffer Overflow Possible?
- Finding the EIP and EIP offset.
- Finding Bad Characters.
- Finding Jump Point.
- The Final Buffer Overflow Exploit (crafts a final exploit payload; either for Netcat or Metasploit's Meterpreter shell).

## Why is this program called "Acarine"?

Acarine is a type of mite that buries itself into bees, eventually killing them. I felt the name worked well because for the Buffer Overflow development process as you're slowly burying yourself deeper into the target program and you're exploiting it for all the nutrients you need (information) until you kill it and get your shell. 

The idea also came from the name of a song which describes the same; "buried deep, inside of me, Acarine" (https://www.youtube.com/watch?v=0xePP-tpwbQ). 

Basically, as acarines are parasitic they also go hand-in-hand with the concept of an offensive exploit that does that same.

## Showcase Screenshots:

- **Menu**:

   ![image](https://raw.githubusercontent.com/vaarg/Acarine/main/screenshots/1_acarine.png)

- **Bad Characters** (with screenshot of final 'unmodified' result):

   ![image](https://raw.githubusercontent.com/vaarg/Acarine/main/screenshots/2_acarine.png)
   ![image](https://raw.githubusercontent.com/vaarg/Acarine/main/screenshots/3_immunitychars.png)

- **Final Exploit** (with screenshot of successful Netcat reverse shell):
    
   ![image](https://raw.githubusercontent.com/vaarg/Acarine/main/screenshots/4_acarine.png)
   ![image](https://raw.githubusercontent.com/vaarg/Acarine/main/screenshots/5_shell.png)
