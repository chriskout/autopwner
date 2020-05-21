Auto Pwner Created for solving basic PWN CTF problems. These only work on problems with Partial Relro, No Stack Canary, and "Normal" STDIN buffering. Despite these limitation, the scripts have proven quite adept at PWNing
low level CTF problems on most challenges. I do not take sole responsibility of this work, as Andy Novocin (@AndyNovo) and Landon Jones (@LandonJones) both had significant contributions. 

DEPENDENCIES:

The files are bash scripts, so obviously you need something that can run those.
You need Python3, Radare2, PWNTools, ROPGadget as well as basic command line tools like grep and cat

THEORY:

The script analyzes the file finding offset with Radare2, finding necessary ROPGadgets with ROPGadget (who would have thought!) and writing you a python file. Afterwards it performs a stack smash,
rewriting GOT entries to point to a shell system call. This ignores alot of the puttzing around most ROP problems ask of you.

TO RUN:
First you most hold up your right hand a say "I promise to use this to PWN problems I could already PWN, this a simply a tool to save time". Then find out if the file is a 32bit ELF or 64bit ELF. 

If 32bit run:
./sledgehammer32 [Binary File]

If 64bit run
./sledgehammer64 [Binary File]

 

TODO:

Clean up garbage files created by script.
