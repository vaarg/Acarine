## Acarine
Acarine is a Buffer Overflow utility and guide. It is to be used in conjunction with Immunity Debugger and Immunity's Mona module.

## Usage: 
    Acarine.py -t [IP] -p [PORT]

## Dependencies:
    Metasploit Framework Tools

## What does Acarine do:

- Determines if a Buffer Overflow exploit is possible for a given program.
- Guides and automates finding the EIP and EIP offset.
- Finds Bad Characters.
- Finds Jump Points.
- Crafts a final exploit payload (given all prior listed information); either for Netcat or Metasploit's Meterpreter shell.

## Why is this program called "Acarine"?

Acarine is a type of mite that buries itself into bees, eventually killing them. I felt the name worked well because for the Buffer Overflow development process as you're slowly burying yourself deeper into the target program and you're exploiting it for all the nutrients you need (information) until you kill it and get your shell. 

The idea also came from the name of a song which describes the same; "buried deep, inside of me, Acarine" (https://www.youtube.com/watch?v=0xePP-tpwbQ). 

Basically, as acarines are parasitic they also go hand-in-hand with the concept of an offensive exploit that does that same.
